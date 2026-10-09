"""Public OAuth clients: Claude, Claude Code and the SCN Sync plugin.

Open WebUI's flow is `test_provider`'s subject and must not change. This
module covers what was added beside it. The load-bearing test is
`AccessTokenContractTests`: scn-sync-relay verifies exactly that shape and
answers anything else with a bare 401.
"""

import json
import tempfile
from pathlib import Path

import jwt
from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse

from corliss import oidc, signing
from corliss.apps import check_oidc_resources_parse
from corliss.tests.test_provider import _write_keys

User = get_user_model()

DID = "did:plc:ewvi7nxzyoun6zhxrhs64oiz"
BASE = "https://auth.zai.test"
PLUGIN = f"{BASE}/clients/scn-obsidian.json"
SYNC = "https://sync.zai.test"
MCP = "https://mcp.zai.test/mcp"
RESOURCES = json.dumps(
    [
        {"url": SYNC, "kind": "sync", "label": "Notes sync"},
        {"url": MCP, "kind": "mcp", "label": "Notes for Claude"},
    ]
)
OWUI = "open-webui"
OWUI_REDIRECT = "https://owui.example.test/oauth/oidc/callback"


class KeysMixin:
    """Signing keys on disk for the life of the class."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._tmp = tempfile.TemporaryDirectory()
        ec_path, rsa_path = _write_keys(Path(cls._tmp.name))
        signing._load_private_key.cache_clear()
        cls._keys = override_settings(
            ATPROTO_EC_PRIVATE_KEY_PATH=str(ec_path),
            OIDC_RSA_PRIVATE_KEY_PATH=str(rsa_path),
        )
        cls._keys.enable()

    @classmethod
    def tearDownClass(cls):
        cls._keys.disable()
        signing._load_private_key.cache_clear()
        cls._tmp.cleanup()
        super().tearDownClass()


@override_settings(PUBLIC_BASE_URL=BASE)
class DiscoveryTests(TestCase):
    def test_both_well_known_paths_serve_the_same_document(self):
        openid = self.client.get("/.well-known/openid-configuration")
        oauth = self.client.get("/.well-known/oauth-authorization-server")
        self.assertEqual(oauth.status_code, 200)
        self.assertEqual(oauth.json(), openid.json())

    def test_the_document_carries_what_an_mcp_client_needs(self):
        doc = self.client.get("/.well-known/oauth-authorization-server").json()
        self.assertEqual(doc["issuer"], BASE)
        self.assertEqual(doc["code_challenge_methods_supported"], ["S256"])
        self.assertIs(doc["client_id_metadata_document_supported"], True)
        self.assertIn("none", doc["token_endpoint_auth_methods_supported"])
        self.assertIn("refresh_token", doc["grant_types_supported"])
        self.assertIn("offline_access", doc["scopes_supported"])

    def test_what_open_webui_reads_is_still_there(self):
        doc = self.client.get("/.well-known/openid-configuration").json()
        self.assertIn("authorization_code", doc["grant_types_supported"])
        for method in ("client_secret_post", "client_secret_basic"):
            self.assertIn(method, doc["token_endpoint_auth_methods_supported"])
        for scope in ("openid", "profile", "email"):
            self.assertIn(scope, doc["scopes_supported"])
        self.assertIs(doc["backchannel_logout_supported"], True)


@override_settings(
    PUBLIC_BASE_URL=BASE, OIDC_CLIENT_ID=OWUI, OIDC_REDIRECT_URIS=[OWUI_REDIRECT]
)
class ResolveClientTests(TestCase):
    def test_the_plugin_document_is_served_at_its_client_id(self):
        resp = self.client.get("/clients/scn-obsidian.json")
        self.assertEqual(resp.status_code, 200)
        doc = resp.json()
        self.assertEqual(doc["client_id"], PLUGIN)
        self.assertEqual(doc["client_name"], "SCN Sync")
        self.assertEqual(doc["redirect_uris"], ["obsidian://scn-obsidian"])
        self.assertEqual(doc["token_endpoint_auth_method"], "none")
        self.assertEqual(doc["grant_types"], ["authorization_code", "refresh_token"])

    def test_open_webui_is_the_confidential_client_from_settings(self):
        client = oidc.resolve_client(OWUI)
        self.assertEqual(client.kind, oidc.CONFIDENTIAL)
        self.assertFalse(client.is_public)
        self.assertEqual(client.redirect_uris, (OWUI_REDIRECT,))
        self.assertEqual(client.host, "")

    def test_the_plugin_resolves_as_a_public_client(self):
        client = oidc.resolve_client(PLUGIN)
        self.assertTrue(client.is_public)
        self.assertEqual(client.redirect_uris, ("obsidian://scn-obsidian",))
        self.assertEqual(client.name, "SCN Sync")
        self.assertEqual(client.host, "auth.zai.test")
        self.assertIn("refresh_token", client.grant_types)

    def test_anything_else_is_an_unauthorized_client(self):
        for client_id in ("evil", "", None, PLUGIN + "x", "http://auth.zai.test/x"):
            with self.subTest(client_id=client_id):
                with self.assertRaises(oidc.ClientError) as caught:
                    oidc.resolve_client(client_id)
                self.assertEqual(caught.exception.error, "unauthorized_client")

    @override_settings(OIDC_CLIENT_ID="")
    def test_a_blank_configured_client_id_matches_nothing(self):
        with self.assertRaises(oidc.ClientError):
            oidc.resolve_client("")


@override_settings(
    PUBLIC_BASE_URL=BASE,
    OIDC_CLIENT_ID=OWUI,
    OIDC_CLIENT_SECRET="",
    OIDC_REDIRECT_URIS=[OWUI_REDIRECT],
)
class BlankSecretTests(KeysMixin, TestCase):
    """A deployment with no secret configured used to accept `open-webui`
    with no secret at all, because "" compared equal to ""."""

    def setUp(self):
        self.user = User.objects.create_user(username="alice.bsky.social", did=DID)

    def _exchange(self, **extra):
        code = oidc.issue_code(
            self.user, client_id=OWUI, redirect_uri=OWUI_REDIRECT, scope="openid"
        )
        return self.client.post(
            reverse("token"),
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": OWUI_REDIRECT,
                "client_id": OWUI,
                **extra,
            },
        )

    def test_no_secret_sent_is_refused(self):
        resp = self._exchange()
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["error"], "invalid_client")

    def test_an_empty_secret_sent_is_refused(self):
        self.assertEqual(self._exchange(client_secret="").status_code, 401)


@override_settings(PUBLIC_BASE_URL=BASE + "/", OIDC_RESOURCES=RESOURCES)
class AccessTokenContractTests(KeysMixin, TestCase):
    """What scn-sync-relay's `CorlissVerifier` checks, in the order it checks
    it. A failure here is a 401 with no body over there."""

    def setUp(self):
        self.user = User.objects.create_user(
            username="alice.bsky.social",
            did=DID,
            email="alice@example.com",
            display_name="Alice Example",
        )

    def _mint(self, resource=SYNC, scope="offline_access"):
        return oidc.mint_access_token(
            self.user, client_id=PLUGIN, resource=resource, scope=scope
        )

    def _verify(self, token, audience):
        """Select the key by `kid` from the published JWKS, as the relay does."""
        header = jwt.get_unverified_header(token)
        jwk = next(k for k in signing.jwks()["keys"] if k["kid"] == header["kid"])
        self.assertEqual(jwk["kty"], "RSA")
        return jwt.decode(
            token,
            key=jwt.PyJWK.from_dict(jwk).key,
            algorithms=["RS256"],
            audience=audience,
            issuer=BASE,
            leeway=0,
            options={"require": ["exp", "iss", "aud", "sub"]},
        )

    def test_the_header_says_access_token(self):
        header = jwt.get_unverified_header(self._mint())
        self.assertEqual(header["alg"], "RS256")
        self.assertEqual(header["typ"], "at+jwt")
        self.assertEqual(header["kid"], signing.oidc_kid())

    def test_it_verifies_against_the_jwks_for_its_own_audience(self):
        claims = self._verify(self._mint(), SYNC)
        self.assertEqual(claims["sub"], DID)
        self.assertEqual(claims["client_id"], PLUGIN)
        self.assertEqual(claims["scope"], "offline_access")

    def test_the_issuer_has_no_trailing_slash(self):
        """PUBLIC_BASE_URL is set with one here; the relay compares exactly."""
        claims = jwt.decode(self._mint(), options={"verify_signature": False})
        self.assertEqual(claims["iss"], BASE)

    def test_the_audience_is_one_string_spelled_as_given(self):
        claims = jwt.decode(self._mint(MCP), options={"verify_signature": False})
        self.assertEqual(claims["aud"], MCP)
        self.assertIsInstance(claims["aud"], str)

    def test_a_token_for_one_resource_does_not_verify_for_the_other(self):
        with self.assertRaises(jwt.InvalidAudienceError):
            self._verify(self._mint(SYNC), MCP)

    def test_it_lasts_fifteen_minutes(self):
        claims = jwt.decode(self._mint(), options={"verify_signature": False})
        self.assertEqual(claims["exp"] - claims["iat"], 900)

    def test_it_says_nothing_about_the_person_beyond_the_did(self):
        claims = jwt.decode(self._mint(), options={"verify_signature": False})
        self.assertEqual(
            set(claims),
            {"iss", "sub", "aud", "iat", "exp", "jti", "scope", "client_id"},
        )

    def test_an_empty_scope_is_carried_as_an_empty_string(self):
        claims = jwt.decode(self._mint(scope=""), options={"verify_signature": False})
        self.assertEqual(claims["scope"], "")

    def test_each_token_has_its_own_jti(self):
        first = jwt.decode(self._mint(), options={"verify_signature": False})
        second = jwt.decode(self._mint(), options={"verify_signature": False})
        self.assertNotEqual(first["jti"], second["jti"])

    def test_an_id_token_is_not_typed_as_an_access_token(self):
        """Same key, so the header is the only thing that tells them apart."""
        header = jwt.get_unverified_header(
            oidc.mint_id_token(self.user, client_id=PLUGIN)
        )
        self.assertNotEqual(header.get("typ", "").lower(), "at+jwt")


class ResourceSettingTests(SimpleTestCase):
    def test_a_valid_value_parses_in_order(self):
        resources, problems = oidc.parse_resources(RESOURCES)
        self.assertEqual(problems, [])
        self.assertEqual([r.kind for r in resources], ["sync", "mcp"])
        self.assertEqual(resources[1].url, MCP)
        self.assertEqual(resources[0].label, "Notes sync")

    def test_blank_is_no_resources_and_no_problem(self):
        self.assertEqual(oidc.parse_resources(""), ([], []))

    def test_a_list_is_accepted_as_well_as_its_json(self):
        resources, problems = oidc.parse_resources(json.loads(RESOURCES))
        self.assertEqual(problems, [])
        self.assertEqual(len(resources), 2)

    def test_each_kind_of_mistake_yields_nothing_and_says_why(self):
        good = {"url": SYNC, "kind": "sync", "label": "Notes sync"}
        cases = {
            "broken JSON": '[{"url": ',
            "not a list": json.dumps(good),
            "entry not an object": json.dumps([SYNC]),
            "no url": json.dumps([{**good, "url": ""}]),
            "url with no scheme": json.dumps([{**good, "url": "sync.zai.test"}]),
            "unknown kind": json.dumps([{**good, "kind": "notes"}]),
            "no label": json.dumps([{**good, "label": " "}]),
            "two of one kind": json.dumps([good, {**good, "url": MCP}]),
            "one good, one bad": json.dumps([good, {**good, "kind": "x"}]),
        }
        for name, raw in cases.items():
            with self.subTest(name):
                resources, problems = oidc.parse_resources(raw)
                self.assertEqual(resources, [])
                self.assertTrue(problems)

    def test_the_deploy_check_passes_a_good_or_blank_value(self):
        for raw in ("", RESOURCES):
            with self.subTest(raw=raw), override_settings(OIDC_RESOURCES=raw):
                self.assertEqual(check_oidc_resources_parse(None), [])

    @override_settings(OIDC_RESOURCES='[{"url": "https://sync.zai.test", "kind": "snyc"}]')
    def test_the_deploy_check_fails_a_bad_value_and_names_the_entry(self):
        errors = check_oidc_resources_parse(None)
        self.assertEqual([e.id for e in errors], ["corliss.E004"])
        self.assertIn("entry 1", errors[0].msg)

    @override_settings(OIDC_RESOURCES='[{"url": ')
    def test_an_unreadable_value_issues_for_nothing(self):
        self.assertEqual(oidc.resources(), [])
