"""The Beszel hub: a second confidential client, which only roster admins finish.

The load-bearing test is a member who is not an admin getting no code. GATE
alone would let them through, because Beszel is reached through the same
`/oidc/authorize` as Open WebUI and they are a member.

The second is the Django superuser. `User.is_cluster_admin` says yes to one
for the pages here, and `authorize` must not ask that property.
"""

import tempfile
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import jwt
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from corliss import oidc, signing
from corliss.apps import check_confidential_client_ids_differ
from corliss.models import OidcAuthCode
from corliss.tests.test_gate import ADMIN, MEMBER, NoRosterMixin, _grant
from corliss.tests.test_provider import _write_keys

User = get_user_model()

OWUI_ID = "open-webui"
OWUI_SECRET = "owui-secret"
OWUI_REDIRECT = "https://owui.example.test/oauth/oidc/callback"

BESZEL_ID = "beszel"
BESZEL_SECRET = "beszel-secret"
BESZEL_REDIRECT = "https://monitor.example.test/api/oauth2-redirect"

CLIENTS = dict(
    PUBLIC_BASE_URL="https://auth.zai.test",
    OIDC_CLIENT_ID=OWUI_ID,
    OIDC_CLIENT_SECRET=OWUI_SECRET,
    OIDC_REDIRECT_URIS=[OWUI_REDIRECT],
    BESZEL_OIDC_CLIENT_ID=BESZEL_ID,
    BESZEL_OIDC_CLIENT_SECRET=BESZEL_SECRET,
    BESZEL_OIDC_REDIRECT_URIS=[BESZEL_REDIRECT],
)


def _authorize_params(**overrides):
    params = {
        "client_id": BESZEL_ID,
        "redirect_uri": BESZEL_REDIRECT,
        "response_type": "code",
        "scope": "openid email profile",
        "state": "pb-state",
    }
    params.update(overrides)
    return params


@override_settings(**CLIENTS)
class BeszelAuthorizeTests(NoRosterMixin, TestCase):
    """`/oidc/authorize` for the hub: GATE first, then the roster."""

    def setUp(self):
        super().setUp()
        self.admin = User.objects.create_user(username="admin.bsky.social", did=ADMIN)
        self.member = User.objects.create_user(username="alice.bsky.social", did=MEMBER)

    def test_a_roster_admin_gets_a_code(self):
        self.as_roster_admin(ADMIN)
        self.client.force_login(self.admin)
        resp = self.client.get(reverse("authorize"), _authorize_params())
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(resp.url.startswith(BESZEL_REDIRECT + "?"))
        qs = parse_qs(urlparse(resp.url).query)
        self.assertEqual(qs["state"], ["pb-state"])
        code = OidcAuthCode.objects.get(code=qs["code"][0])
        self.assertEqual(code.client_id, BESZEL_ID)

    def test_a_member_who_is_not_an_admin_is_refused_with_no_code(self):
        """**The load-bearing test.** GATE passes them; the roster does not."""
        _grant()
        self.client.force_login(self.member)
        resp = self.client.get(reverse("authorize"), _authorize_params())
        self.assertEqual(resp.status_code, 403)
        self.assertContains(resp, "access_denied", status_code=403)
        self.assertEqual(OidcAuthCode.objects.count(), 0)

    def test_the_same_member_still_gets_into_open_webui(self):
        # The roster question belongs to the Beszel client, not to authorize.
        _grant()
        self.client.force_login(self.member)
        resp = self.client.get(
            reverse("authorize"),
            _authorize_params(client_id=OWUI_ID, redirect_uri=OWUI_REDIRECT),
        )
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(resp.url.startswith(OWUI_REDIRECT))

    def test_a_non_member_is_sent_home_as_for_open_webui(self):
        self.client.force_login(self.member)  # signed in, never granted
        resp = self.client.get(reverse("authorize"), _authorize_params())
        self.assertRedirects(resp, reverse("home"))
        self.assertEqual(OidcAuthCode.objects.count(), 0)

    def test_a_django_superuser_off_the_roster_is_refused(self):
        """`User.is_cluster_admin` says yes to a superuser; the roster does not."""
        _grant()
        self.member.is_superuser = True
        self.member.save()
        self.client.force_login(self.member)
        resp = self.client.get(reverse("authorize"), _authorize_params())
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(OidcAuthCode.objects.count(), 0)

    def test_an_anonymous_visitor_is_bounced_through_login(self):
        resp = self.client.get(reverse("authorize"), _authorize_params())
        self.assertEqual(resp.status_code, 302)
        self.assertIn(reverse("login"), resp.url)

    def test_an_unregistered_redirect_is_refused(self):
        self.as_roster_admin(ADMIN)
        self.client.force_login(self.admin)
        resp = self.client.get(
            reverse("authorize"),
            _authorize_params(redirect_uri="https://evil.example/api/oauth2-redirect"),
        )
        self.assertEqual(resp.status_code, 400)

    @override_settings(BESZEL_OIDC_CLIENT_SECRET="")
    def test_a_blank_secret_leaves_the_client_unregistered(self):
        self.as_roster_admin(ADMIN)
        self.client.force_login(self.admin)
        resp = self.client.get(reverse("authorize"), _authorize_params())
        self.assertEqual(resp.json()["error"], "unauthorized_client")


@override_settings(**CLIENTS)
class BeszelTokenTests(NoRosterMixin, TestCase):
    """The token endpoint picks the client by `client_id` and its own secret."""

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
        super().setUp()
        signing._load_private_key.cache_clear()
        keys = override_settings(
            ATPROTO_EC_PRIVATE_KEY_PATH=str(self.ec_path),
            OIDC_RSA_PRIVATE_KEY_PATH=str(self.rsa_path),
        )
        keys.enable()
        self.addCleanup(keys.disable)
        self.addCleanup(signing._load_private_key.cache_clear)
        self.admin = User.objects.create_user(username="admin.bsky.social", did=ADMIN)

    def _code(self, client_id=BESZEL_ID, redirect_uri=BESZEL_REDIRECT):
        return oidc.issue_code(
            self.admin, client_id=client_id, redirect_uri=redirect_uri, scope="openid"
        )

    def _redeem(self, code, *, client_id=BESZEL_ID, secret=BESZEL_SECRET,
                redirect_uri=BESZEL_REDIRECT):
        return self.client.post(
            reverse("token"),
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": client_id,
                "client_secret": secret,
            },
        )

    def test_its_own_secret_gets_an_id_token_addressed_to_it(self):
        resp = self._redeem(self._code())
        self.assertEqual(resp.status_code, 200)
        claims = jwt.decode(
            resp.json()["id_token"], options={"verify_signature": False}
        )
        # PocketBase checks `aud` against its client id and reads the user
        # from these claims, having no userinfo endpoint to ask.
        self.assertEqual(claims["aud"], BESZEL_ID)
        self.assertEqual(claims["sub"], ADMIN)
        self.assertEqual(claims["iss"], "https://auth.zai.test")

    def test_a_wrong_secret_is_refused(self):
        resp = self._redeem(self._code(), secret="guess")
        self.assertEqual(resp.status_code, 401)

    def test_open_webuis_secret_does_not_open_beszel(self):
        resp = self._redeem(self._code(), secret=OWUI_SECRET)
        self.assertEqual(resp.status_code, 401)

    def test_a_beszel_code_cannot_be_redeemed_as_open_webui(self):
        resp = self._redeem(
            self._code(), client_id=OWUI_ID, secret=OWUI_SECRET,
        )
        self.assertEqual(resp.json()["error"], "invalid_grant")


class ClientIdCheckTests(TestCase):
    """corliss.E005: two confidential clients under one id."""

    @override_settings(OIDC_CLIENT_ID="open-webui", BESZEL_OIDC_CLIENT_ID="open-webui",
                       BESZEL_OIDC_CLIENT_SECRET="s")
    def test_a_shared_id_fails_the_check(self):
        errors = check_confidential_client_ids_differ(None)
        self.assertEqual([e.id for e in errors], ["corliss.E005"])

    @override_settings(OIDC_CLIENT_ID="open-webui", BESZEL_OIDC_CLIENT_ID="beszel",
                       BESZEL_OIDC_CLIENT_SECRET="s")
    def test_distinct_ids_pass(self):
        self.assertEqual(check_confidential_client_ids_differ(None), [])

    @override_settings(OIDC_CLIENT_ID="open-webui", BESZEL_OIDC_CLIENT_ID="open-webui",
                       BESZEL_OIDC_CLIENT_SECRET="")
    def test_an_unconfigured_hub_is_not_a_clash(self):
        self.assertEqual(check_confidential_client_ids_differ(None), [])
