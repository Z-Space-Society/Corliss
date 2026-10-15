import json
import tempfile
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase, override_settings

from corliss import signing


def _write_key(path: Path, key):
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


class SigningTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._tmp = tempfile.TemporaryDirectory()
        d = Path(cls._tmp.name)
        cls.ec_path = d / "ec.pem"
        cls.rsa_path = d / "rsa.pem"
        _write_key(cls.ec_path, ec.generate_private_key(ec.SECP256R1()))
        _write_key(
            cls.rsa_path, rsa.generate_private_key(public_exponent=65537, key_size=2048)
        )

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()
        super().tearDownClass()

    def setUp(self):
        signing._load_private_key.cache_clear()
        # The previous paths are pinned blank, not left to the environment: a
        # developer trying a rotation locally has one set in .env.
        self._override = override_settings(
            ATPROTO_EC_PRIVATE_KEY_PATH=str(self.ec_path),
            OIDC_RSA_PRIVATE_KEY_PATH=str(self.rsa_path),
            ATPROTO_EC_PREVIOUS_KEY_PATH="",
            OIDC_RSA_PREVIOUS_KEY_PATH="",
        )
        self._override.enable()

    def tearDown(self):
        self._override.disable()
        signing._load_private_key.cache_clear()

    def test_jwks_has_two_public_keys(self):
        keys = signing.jwks()["keys"]
        self.assertEqual(len(keys), 2)
        self.assertEqual({k["kty"] for k in keys}, {"EC", "RSA"})

    def test_jwks_contains_no_private_material(self):
        blob = json.dumps(signing.jwks())
        for field in ("d", "p", "q", "dp", "dq", "qi"):
            for key in signing.jwks()["keys"]:
                self.assertNotIn(field, key)
        self.assertNotIn('"d"', blob)

    def test_public_jwks_match_configured_keys(self):
        ec_jwk = signing.atproto_public_jwk()
        rsa_jwk = signing.oidc_public_jwk()
        self.assertEqual(ec_jwk["alg"], "ES256")
        self.assertEqual(ec_jwk["use"], "sig")
        self.assertEqual(ec_jwk["crv"], "P-256")
        self.assertEqual(rsa_jwk["alg"], "RS256")
        # kid is the RFC7638 thumbprint and is stable across calls.
        self.assertEqual(ec_jwk["kid"], signing.atproto_kid())
        self.assertEqual(rsa_jwk["kid"], signing.oidc_kid())

    def test_sign_verifies_against_published_jwks(self):
        token = signing.sign_rs256({"hello": "world"})
        key = jwt.PyJWK.from_dict(signing.oidc_public_jwk()).key
        decoded = jwt.decode(token, key=key, algorithms=["RS256"])
        self.assertEqual(decoded["hello"], "world")

        token_es = signing.sign_es256({"foo": "bar"})
        key_es = jwt.PyJWK.from_dict(signing.atproto_public_jwk()).key
        self.assertEqual(jwt.decode(token_es, key=key_es, algorithms=["ES256"])["foo"], "bar")

    def test_missing_key_fails_closed(self):
        with override_settings(ATPROTO_EC_PRIVATE_KEY_PATH=""):
            signing._load_private_key.cache_clear()
            with self.assertRaises(ImproperlyConfigured):
                signing.atproto_public_jwk()

    def test_jwks_endpoint(self):
        resp = self.client.get("/.well-known/jwks.json")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(len(data["keys"]), 2)
        self.assertNotIn('"d"', resp.content.decode())


class KeyRotationTests(TestCase):
    """A previous key beside each current one, set while a rotation is under
    way: published so old tokens still verify, and used by the atproto
    sessions that started on it, since their authorization server accepts no
    other key for them."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._tmp = tempfile.TemporaryDirectory()
        d = Path(cls._tmp.name)
        cls.paths = {}
        for name, key in (
            ("ec", ec.generate_private_key(ec.SECP256R1())),
            ("ec_prev", ec.generate_private_key(ec.SECP256R1())),
            ("rsa", rsa.generate_private_key(public_exponent=65537, key_size=2048)),
            ("rsa_prev", rsa.generate_private_key(public_exponent=65537, key_size=2048)),
        ):
            cls.paths[name] = d / f"{name}.pem"
            _write_key(cls.paths[name], key)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()
        super().tearDownClass()

    def setUp(self):
        signing._load_private_key.cache_clear()
        self._override = override_settings(
            ATPROTO_EC_PRIVATE_KEY_PATH=str(self.paths["ec"]),
            OIDC_RSA_PRIVATE_KEY_PATH=str(self.paths["rsa"]),
            ATPROTO_EC_PREVIOUS_KEY_PATH=str(self.paths["ec_prev"]),
            OIDC_RSA_PREVIOUS_KEY_PATH=str(self.paths["rsa_prev"]),
        )
        self._override.enable()
        self.previous_ec_kid = signing._public_jwk(
            signing.atproto_previous_private_key(), "ES256"
        )["kid"]

    def tearDown(self):
        self._override.disable()
        signing._load_private_key.cache_clear()

    def test_jwks_publishes_the_previous_keys_after_the_current_pair(self):
        keys = signing.jwks()["keys"]
        self.assertEqual(len(keys), 4)
        # The current pair keeps its positions; a reader that took keys[0] for
        # ES256 and keys[1] for RS256 is not broken by a rotation.
        self.assertEqual(keys[0]["kid"], signing.atproto_kid())
        self.assertEqual(keys[1]["kid"], signing.oidc_kid())
        self.assertEqual(keys[2]["kid"], self.previous_ec_kid)
        self.assertEqual(keys[3]["alg"], "RS256")
        self.assertNotIn('"d"', json.dumps(keys))

    def test_no_previous_keys_means_the_usual_two(self):
        with override_settings(
            ATPROTO_EC_PREVIOUS_KEY_PATH="", OIDC_RSA_PREVIOUS_KEY_PATH=""
        ):
            self.assertEqual(len(signing.jwks()["keys"]), 2)

    def test_a_missing_previous_key_file_fails_closed(self):
        with override_settings(ATPROTO_EC_PREVIOUS_KEY_PATH="/nonexistent.pem"):
            with self.assertRaises(ImproperlyConfigured):
                signing.jwks()

    def test_new_signatures_use_the_current_key(self):
        token = signing.sign_es256({"a": 1})
        self.assertEqual(jwt.get_unverified_header(token)["kid"], signing.atproto_kid())
        token = signing.sign_es256({"a": 1}, kid="")
        self.assertEqual(jwt.get_unverified_header(token)["kid"], signing.atproto_kid())
        token = signing.sign_rs256({"a": 1})
        self.assertEqual(jwt.get_unverified_header(token)["kid"], signing.oidc_kid())

    def test_the_previous_kid_signs_with_the_previous_key(self):
        token = signing.sign_es256({"a": 1}, kid=self.previous_ec_kid)
        self.assertEqual(jwt.get_unverified_header(token)["kid"], self.previous_ec_kid)
        previous = signing.jwks()["keys"][2]
        key = jwt.PyJWK.from_dict(previous).key
        self.assertEqual(jwt.decode(token, key=key, algorithms=["ES256"])["a"], 1)

    def test_a_retired_kid_is_refused(self):
        with self.assertRaises(signing.UnknownSigningKey):
            signing.sign_es256({"a": 1}, kid="retired")

    def _token(self, client_kid):
        from corliss import atproto
        from corliss.models import AtprotoToken, User

        user = User.objects.create_user(
            username="alice", did="did:plc:alice", pds_url="https://pds.example"
        )
        return AtprotoToken.objects.create(
            user=user,
            pds_url="https://pds.example",
            issuer="https://auth.example",
            token_endpoint="https://auth.example/token",
            access_token="access-1",
            refresh_token="refresh-1",
            dpop_private_pem=atproto.key_to_pem(atproto.generate_key()),
            client_kid=client_kid,
        )

    def _refresh_assertion_kid(self, token):
        """Refresh `token` against a fake token endpoint; return the kid its
        client assertion was signed with."""
        from unittest.mock import MagicMock, patch

        from corliss import atproto

        resp = MagicMock(status_code=200, ok=True, headers={})
        resp.json.return_value = {"access_token": "access-2", "refresh_token": "r2"}
        with patch.object(atproto.requests, "post", return_value=resp) as post:
            atproto.refresh_session(token)
        assertion = post.call_args[1]["data"]["client_assertion"]
        return jwt.get_unverified_header(assertion)["kid"]

    def test_a_session_on_the_previous_key_refreshes_with_it(self):
        token = self._token(self.previous_ec_kid)
        self.assertEqual(self._refresh_assertion_kid(token), self.previous_ec_kid)

    def test_a_session_from_before_rotation_refreshes_with_the_current_key(self):
        token = self._token("")
        self.assertEqual(self._refresh_assertion_kid(token), signing.atproto_kid())

    def test_a_session_on_a_retired_key_must_sign_in_again(self):
        from corliss import atproto

        token = self._token("retired")
        with self.assertRaises(atproto.NoSession):
            atproto.refresh_session(token)

    def test_a_new_session_records_the_current_kid(self):
        from corliss import atproto, views
        from corliss.models import User

        user = User.objects.create_user(
            username="bob", did="did:plc:bob", pds_url="https://pds.example"
        )
        views._store_tokens(
            user,
            {"access_token": "a", "refresh_token": "r"},
            atproto.generate_key(),
            None,
            {
                "pds_url": "https://pds.example",
                "issuer": "https://auth.example",
                "token_endpoint": "https://auth.example/token",
            },
        )
        user.atproto_token.refresh_from_db()
        self.assertEqual(user.atproto_token.client_kid, signing.atproto_kid())
