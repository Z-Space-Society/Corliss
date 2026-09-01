import tempfile
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from corliss import membership
from corliss import signing
from corliss import oidc
from corliss.models import MembershipCache, OidcAuthCode

User = get_user_model()

DID = "did:plc:ewvi7nxzyoun6zhxrhs64oiz"
ADMIN_DID = "did:plc:hhyrsndukexwr6qucdngcf4r"
CLIENT_ID = "open-webui"
CLIENT_SECRET = "test-secret"
REDIRECT_URI = "https://chat.example.test/oauth/oidc/callback"


def _grant(did, *, tier="level-2"):
    """A cache row as the registry's push would have left it."""
    MembershipCache.objects.create(
        did=did,
        active=True,
        tier=tier,
        last_rkey=f"{did}:3lqxaaaaaaaaa",
        last_event_at="2026-01-01T00:00:00Z",
        author_did=ADMIN_DID,
    )


def _write_keys(d: Path):
    ec_path, rsa_path = d / "ec.pem", d / "rsa.pem"
    ec_path.write_bytes(
        ec.generate_private_key(ec.SECP256R1()).private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    rsa_path.write_bytes(
        rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return ec_path, rsa_path


@override_settings(
    PUBLIC_BASE_URL="https://auth.zai.test",
    OIDC_CLIENT_ID=CLIENT_ID,
    OIDC_CLIENT_SECRET=CLIENT_SECRET,
    OIDC_REDIRECT_URIS=[REDIRECT_URI],
)
class OidcProviderTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._tmp = tempfile.TemporaryDirectory()
        cls.ec_path, cls.rsa_path = _write_keys(Path(cls._tmp.name))

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()
        super().tearDownClass()

    def setUp(self):
        signing._load_private_key.cache_clear()
        self._ov = override_settings(
            ATPROTO_EC_PRIVATE_KEY_PATH=str(self.ec_path),
            OIDC_RSA_PRIVATE_KEY_PATH=str(self.rsa_path),
        )
        self._ov.enable()
        self.user = User.objects.create_user(
            username="alice.bsky.social", did=DID, pds_url="https://pds.example.com"
        )
        # `authorize` is gated on membership (GATE). These tests are about the
        # OIDC mechanics — codes, signatures, claims — so the member is a
        # member; refusal is `test_gate`'s subject.
        _grant(DID)

    def tearDown(self):
        self._ov.disable()
        signing._load_private_key.cache_clear()

    # --- discovery --------------------------------------------------------

    def test_discovery_document(self):
        resp = self.client.get(reverse("openid_configuration"))
        self.assertEqual(resp.status_code, 200)
        doc = resp.json()
        self.assertEqual(doc["issuer"], "https://auth.zai.test")
        self.assertEqual(
            doc["jwks_uri"], "https://auth.zai.test/.well-known/jwks.json"
        )
        self.assertEqual(doc["id_token_signing_alg_values_supported"], ["RS256"])
        self.assertIn("sub", doc["claims_supported"])
        self.assertIn("handle", doc["claims_supported"])
        self.assertIn("name", doc["claims_supported"])
        self.assertIn("email", doc["claims_supported"])
        self.assertIn("email", doc["scopes_supported"])

    # --- id_token mint + verify against JWKS ------------------------------

    def test_id_token_verifies_against_jwks_with_expected_claims(self):
        token = oidc.mint_id_token(self.user, client_id=CLIENT_ID, nonce="n0")
        # Verify exactly as a relying party would: fetch JWKS, pick the key.
        jwks = signing.jwks()
        rsa_jwk = next(k for k in jwks["keys"] if k["kty"] == "RSA")
        key = jwt.PyJWK.from_dict(rsa_jwk).key
        claims = jwt.decode(
            token, key=key, algorithms=["RS256"], audience=CLIENT_ID,
            issuer="https://auth.zai.test",
        )
        self.assertEqual(claims["sub"], DID)
        self.assertEqual(claims["handle"], "alice.bsky.social")
        self.assertEqual(claims["nonce"], "n0")
        self.assertEqual(claims["aud"], CLIENT_ID)
        self.assertIn("exp", claims)

    def test_id_token_omits_email_when_none_on_file(self):
        token = oidc.mint_id_token(self.user, client_id=CLIENT_ID)
        jwks = signing.jwks()
        rsa_jwk = next(k for k in jwks["keys"] if k["kty"] == "RSA")
        claims = jwt.decode(
            token,
            key=jwt.PyJWK.from_dict(rsa_jwk).key,
            algorithms=["RS256"],
            audience=CLIENT_ID,
        )
        self.assertNotIn("email", claims)
        self.assertNotIn("email_verified", claims)

    def test_id_token_carries_email_when_pds_supplied_one(self):
        self.user.email = "alice@example.com"
        self.user.email_confirmed = True
        self.user.save(update_fields=["email", "email_confirmed"])
        token = oidc.mint_id_token(self.user, client_id=CLIENT_ID)
        jwks = signing.jwks()
        rsa_jwk = next(k for k in jwks["keys"] if k["kty"] == "RSA")
        claims = jwt.decode(
            token,
            key=jwt.PyJWK.from_dict(rsa_jwk).key,
            algorithms=["RS256"],
            audience=CLIENT_ID,
        )
        self.assertEqual(claims["email"], "alice@example.com")
        self.assertTrue(claims["email_verified"])

    def test_id_token_omits_name_when_the_member_has_none(self):
        """Absent, never empty: a relying party reading `name` as a display
        name will happily render "" over the username it would otherwise have
        fallen back to."""
        token = oidc.mint_id_token(self.user, client_id=CLIENT_ID)
        jwks = signing.jwks()
        rsa_jwk = next(k for k in jwks["keys"] if k["kty"] == "RSA")
        claims = jwt.decode(
            token,
            key=jwt.PyJWK.from_dict(rsa_jwk).key,
            algorithms=["RS256"],
            audience=CLIENT_ID,
        )
        self.assertNotIn("name", claims)
        # The handle claims are unconditional and stay that way — `name` is who
        # the member is, `preferred_username` is what the RP keys them on.
        self.assertEqual(claims["preferred_username"], "alice.bsky.social")

    def test_id_token_carries_name_when_the_member_has_one(self):
        self.user.display_name = "Alice Example"
        self.user.save(update_fields=["display_name"])
        token = oidc.mint_id_token(self.user, client_id=CLIENT_ID)
        jwks = signing.jwks()
        rsa_jwk = next(k for k in jwks["keys"] if k["kty"] == "RSA")
        claims = jwt.decode(
            token,
            key=jwt.PyJWK.from_dict(rsa_jwk).key,
            algorithms=["RS256"],
            audience=CLIENT_ID,
        )
        self.assertEqual(claims["name"], "Alice Example")
        self.assertEqual(claims["preferred_username"], "alice.bsky.social")

    def test_id_token_for_an_admin_without_a_grant_carries_no_tier(self):
        """The other half of GATE's split, and the reason it is safe.

        A roster admin passes GATE with no cache row — that is what lets them
        into a rebuilt cluster to run reconcile. They must not collect an
        entitlement on the way through: admin is authority over membership, not
        a grant of it, and inventing one here would hand out resources the
        registry never issued.

        No tier claim exists yet (Deploy Plan, What's next §4), so today this
        asserts the absence of something absent. It is written now because the
        claim will be derived from the member's cache row, and the tempting
        shortcut when it lands — reuse the answer GATE already computed — is
        exactly this bug.
        """
        admin = User.objects.create_user(
            username="admin.bsky.social", did=ADMIN_DID
        )
        with patch(
            "corliss.membership.is_cluster_admin", return_value=True
        ):
            self.assertTrue(membership.may_enter(ADMIN_DID))
            self.assertIsNone(membership.membership_for(admin))

            token = oidc.mint_id_token(admin, client_id=CLIENT_ID)

        rsa_jwk = next(k for k in signing.jwks()["keys"] if k["kty"] == "RSA")
        claims = jwt.decode(
            token,
            key=jwt.PyJWK.from_dict(rsa_jwk).key,
            algorithms=["RS256"],
            audience=CLIENT_ID,
        )
        self.assertEqual(claims["sub"], ADMIN_DID)
        for entitlement in ("groups", "tier", "tiers"):
            self.assertNotIn(entitlement, claims)

    def test_id_token_header_advertises_kid(self):
        token = oidc.mint_id_token(self.user, client_id=CLIENT_ID)
        header = jwt.get_unverified_header(token)
        self.assertEqual(header["alg"], "RS256")
        self.assertEqual(header["kid"], signing.oidc_kid())

    # --- authorize endpoint ----------------------------------------------

    def _authorize_params(self, **overrides):
        params = {
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "response_type": "code",
            "scope": "openid profile",
            "state": "rp-state",
            "nonce": "rp-nonce",
        }
        params.update(overrides)
        return params

    def test_authorize_requires_login_then_issues_code(self):
        # Unauthenticated → bounced to atproto login.
        resp = self.client.get(reverse("authorize"), self._authorize_params())
        self.assertEqual(resp.status_code, 302)
        self.assertIn(reverse("login"), resp.url)

        # Authenticated → redirected back to the RP with a code + state.
        self.client.force_login(self.user)
        resp = self.client.get(reverse("authorize"), self._authorize_params())
        self.assertEqual(resp.status_code, 302)
        parsed = urlparse(resp.url)
        self.assertTrue(resp.url.startswith(REDIRECT_URI))
        qs = parse_qs(parsed.query)
        self.assertEqual(qs["state"], ["rp-state"])
        self.assertTrue(OidcAuthCode.objects.filter(code=qs["code"][0]).exists())

    def test_authorize_rejects_unknown_client(self):
        self.client.force_login(self.user)
        resp = self.client.get(
            reverse("authorize"), self._authorize_params(client_id="evil")
        )
        self.assertEqual(resp.status_code, 400)

    def test_authorize_rejects_unregistered_redirect(self):
        self.client.force_login(self.user)
        resp = self.client.get(
            reverse("authorize"),
            self._authorize_params(redirect_uri="https://evil.test/cb"),
        )
        self.assertEqual(resp.status_code, 400)

    # --- token endpoint ---------------------------------------------------

    def _get_code(self):
        return oidc.issue_code(
            self.user,
            client_id=CLIENT_ID,
            redirect_uri=REDIRECT_URI,
            nonce="rp-nonce",
            scope="openid",
        )

    def test_token_exchange_returns_verifiable_id_token(self):
        code = self._get_code()
        resp = self.client.post(
            reverse("token"),
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
            },
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIn("id_token", body)
        self.assertEqual(body["token_type"], "Bearer")
        rsa_jwk = next(k for k in signing.jwks()["keys"] if k["kty"] == "RSA")
        claims = jwt.decode(
            body["id_token"],
            key=jwt.PyJWK.from_dict(rsa_jwk).key,
            algorithms=["RS256"],
            audience=CLIENT_ID,
        )
        self.assertEqual(claims["sub"], DID)
        self.assertEqual(claims["nonce"], "rp-nonce")

    def test_token_rejects_bad_client_secret(self):
        code = self._get_code()
        resp = self.client.post(
            reverse("token"),
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": CLIENT_ID,
                "client_secret": "wrong",
            },
        )
        self.assertEqual(resp.status_code, 401)

    def test_token_code_is_single_use(self):
        code = self._get_code()
        post = lambda: self.client.post(
            reverse("token"),
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
            },
        )
        self.assertEqual(post().status_code, 200)
        # Second redemption of the same code is rejected.
        self.assertEqual(post().status_code, 400)
