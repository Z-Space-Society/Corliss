"""CORS for browser clients on loopback (#69).

Public documents are readable from any origin. The token endpoint answers
loopback origins only, by name. Nothing that runs on the session cookie
answers cross-origin at all, and nothing ever allows credentials.
"""

from django.test import SimpleTestCase, TestCase, override_settings

from corliss import oidc
from corliss.tests.test_public_clients import BASE, KeysMixin

LOCAL = "http://127.0.0.1:5173"


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

    def test_any_other_origin_gets_nothing(self):
        for origin in ("https://evil.example", "null", "http://example.test:5173"):
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
