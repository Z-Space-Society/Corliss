"""CORS for browser clients (#69, #74).

Public documents are readable from any origin. The token endpoint answers browser
clients by name: loopback over `http`, and any well-formed `https` origin — a
client may bring its own deployment, and CORS is not the access control here.
Nothing that runs on the session cookie answers cross-origin at all, and nothing
ever allows credentials.
"""

from django.test import SimpleTestCase, TestCase, override_settings

from corliss import oidc
from corliss.tests.test_public_clients import BASE, KeysMixin

LOCAL = "http://127.0.0.1:5173"
REMOTE = "https://boris.tngl.io"


@override_settings(PUBLIC_BASE_URL=BASE)
class PublicDocumentTests(KeysMixin, TestCase):
    PATHS = (
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
        "/.well-known/jwks.json",
        "/clients/scn-obsidian.json",
        "/clients/scn-local.json",
    )

    def test_any_origin_may_read_a_public_document(self):
        for path in self.PATHS:
            with self.subTest(path=path):
                resp = self.client.get(path, HTTP_ORIGIN=LOCAL)
                self.assertEqual(resp.status_code, 200)
                self.assertEqual(resp["Access-Control-Allow-Origin"], "*")
                self.assertNotIn("Access-Control-Allow-Credentials", resp)


@override_settings(PUBLIC_BASE_URL=BASE)
class TokenEndpointTests(TestCase):
    def test_a_loopback_preflight_is_answered(self):
        resp = self.client.options(
            "/oidc/token",
            HTTP_ORIGIN=LOCAL,
            HTTP_ACCESS_CONTROL_REQUEST_METHOD="POST",
        )
        self.assertEqual(resp.status_code, 204)
        self.assertEqual(resp["Access-Control-Allow-Origin"], LOCAL)
        self.assertIn("POST", resp["Access-Control-Allow-Methods"])
        self.assertNotIn("Access-Control-Allow-Credentials", resp)

    def test_a_loopback_post_can_read_the_answer(self):
        """Even a refusal: the client has to read the error to act on it."""
        resp = self.client.post(
            "/oidc/token", {"grant_type": "authorization_code"}, HTTP_ORIGIN=LOCAL
        )
        self.assertEqual(resp["Access-Control-Allow-Origin"], LOCAL)
        self.assertIn("Origin", resp["Vary"])

    def test_an_https_preflight_is_answered(self):
        """A client may be deployed anywhere, not only on loopback (#74)."""
        resp = self.client.options(
            "/oidc/token",
            HTTP_ORIGIN=REMOTE,
            HTTP_ACCESS_CONTROL_REQUEST_METHOD="POST",
        )
        self.assertEqual(resp.status_code, 204)
        self.assertEqual(resp["Access-Control-Allow-Origin"], REMOTE)
        self.assertIn("POST", resp["Access-Control-Allow-Methods"])
        self.assertNotIn("Access-Control-Allow-Credentials", resp)

    def test_an_https_post_can_read_the_answer(self):
        resp = self.client.post(
            "/oidc/token", {"grant_type": "authorization_code"}, HTTP_ORIGIN=REMOTE
        )
        self.assertEqual(resp["Access-Control-Allow-Origin"], REMOTE)
        self.assertEqual(resp["Vary"], "Origin")

    def test_what_is_not_a_browser_origin_gets_nothing(self):
        for origin in ("null", "http://example.test:5173", "https://evil.example/path"):
            with self.subTest(origin=origin):
                pre = self.client.options("/oidc/token", HTTP_ORIGIN=origin)
                self.assertEqual(pre.status_code, 405)
                self.assertNotIn("Access-Control-Allow-Origin", pre)
                post = self.client.post(
                    "/oidc/token", {"grant_type": "x"}, HTTP_ORIGIN=origin
                )
                self.assertNotIn("Access-Control-Allow-Origin", post)

    def test_the_session_pages_do_not_answer_cross_origin(self):
        for path in ("/oidc/authorize", "/account/"):
            with self.subTest(path=path):
                resp = self.client.get(path, HTTP_ORIGIN=LOCAL)
                self.assertNotIn("Access-Control-Allow-Origin", resp)


class BrowserOriginTests(SimpleTestCase):
    def test_https_origins_are_browser_clients(self):
        for origin in (
            "https://boris.tngl.io",
            "https://example.test:8443",
            "https://xn--bcher-kva.example",
            "https://[2001:db8::1]:8443",
        ):
            with self.subTest(origin=origin):
                self.assertTrue(oidc.is_browser_origin(origin))

    def test_loopback_is_a_browser_client(self):
        for origin in (
            "http://127.0.0.1:5173",
            "http://localhost:8000",
            "http://[::1]:3000",
        ):
            with self.subTest(origin=origin):
                self.assertTrue(oidc.is_browser_origin(origin))

    def test_what_is_not_an_origin_is_refused(self):
        for origin in (
            "",
            None,
            "null",
            "https://",
            "https://example.test/path",
            "https://example.test?x",
            "https://example.test#x",
            "https://user@example.test",
            "https://example.test:notaport",
            "http://example.test:5173",
        ):
            with self.subTest(origin=origin):
                self.assertFalse(oidc.is_browser_origin(origin))


class LoopbackOriginTests(SimpleTestCase):
    def test_loopback_origins_on_any_port(self):
        for origin in (
            "http://127.0.0.1:5173",
            "http://127.0.0.1",
            "http://localhost:8000",
            "http://[::1]:3000",
        ):
            with self.subTest(origin=origin):
                self.assertTrue(oidc.is_loopback_origin(origin))

    def test_everything_else_is_refused(self):
        for origin in (
            "",
            None,
            "null",
            "https://127.0.0.1:5173",
            "http://127.0.0.1.evil.example",
            "http://example.test:5173",
            "http://127.0.0.1:5173/path",
            "http://user@127.0.0.1:5173",
            "http://127.0.0.1:notaport",
        ):
            with self.subTest(origin=origin):
                self.assertFalse(oidc.is_loopback_origin(origin))
