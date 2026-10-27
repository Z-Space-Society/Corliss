"""Client ID Metadata Documents: when they are fetched, how, and the cache.

Fetching a document is the one request Corliss makes to an address somebody
else chose. These tests never touch the network: name resolution and the HTTP
session are both stood in for, and what is asserted is what the code asked
them for and what it did with the answer.
"""

import json
import socket
from datetime import timedelta
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import requests
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from corliss import oidc
from corliss.models import OidcClientDocument
from corliss.tests.test_provider import _grant
from corliss.tests.test_public_clients import (
    BASE,
    DID,
    MCP,
    PLUGIN,
    RESOURCES,
    VERIFIER,
    challenge_for,
)
from corliss.views import POST_LOGIN_REDIRECT

User = get_user_model()

URL = "https://claude.ai/oauth/claude-code-client-metadata"
PUBLIC_IP = "160.79.104.10"

DOCUMENT = {
    "client_id": URL,
    "client_name": "Claude Code",
    "client_uri": "https://claude.ai",
    "redirect_uris": ["http://localhost/callback", "http://127.0.0.1/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "none",
}


def _answers(*addresses):
    """What `getaddrinfo` returns for a name with these addresses."""
    return [
        (
            socket.AF_INET6 if ":" in address else socket.AF_INET,
            socket.SOCK_STREAM,
            6,
            "",
            (address, 443),
        )
        for address in addresses
    ]


class FakeResponse:
    def __init__(self, body=None, *, status=200, headers=None, chunks=None):
        if body is None:
            body = DOCUMENT
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.status_code = status
        self.headers = headers or {}
        self._chunks = chunks if chunks is not None else [raw]
        self.closed = False

    def iter_content(self, size):
        yield from self._chunks

    def close(self):
        self.closed = True


class FakeSession:
    """Stands in for the pinned `requests.Session`, and records the request."""

    def __init__(self, outcome):
        self.outcome = outcome
        self.calls = []
        self.trust_env = True

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome

    def close(self):
        pass


class Network:
    """Patch resolution and the session for the length of a `with` block."""

    def __init__(self, outcome=None, *, addresses=(PUBLIC_IP,)):
        self.session = FakeSession(FakeResponse() if outcome is None else outcome)
        self.hostnames = []
        self._addresses = addresses

    def __enter__(self):
        def pinned(hostname):
            self.hostnames.append(hostname)
            return self.session

        self._patches = [
            patch("corliss.oidc.socket.getaddrinfo", return_value=_answers(*self._addresses)),
            patch("corliss.oidc._pinned_session", pinned),
        ]
        self.resolve = self._patches[0].start()
        self._patches[1].start()
        return self

    def __exit__(self, *exc):
        for p in self._patches:
            p.stop()

    @property
    def fetches(self):
        return len(self.session.calls)


class FetchTests(SimpleTestCase):
    def test_a_good_document_is_fetched_from_the_checked_address(self):
        with Network() as net:
            document, fresh_for = oidc.fetch_client_document(URL)

        self.assertEqual(document["client_id"], URL)
        self.assertEqual(document["client_name"], "Claude Code")
        self.assertEqual(document["redirect_uris"], DOCUMENT["redirect_uris"])
        self.assertIn("refresh_token", document["grant_types"])
        self.assertEqual(fresh_for, oidc.CIMD_FRESH_DEFAULT)

        url, kwargs = net.session.calls[0]
        # The address that was checked, with TLS and Host for the real name.
        self.assertEqual(url, f"https://{PUBLIC_IP}:443/oauth/claude-code-client-metadata")
        self.assertEqual(kwargs["headers"]["Host"], "claude.ai")
        self.assertEqual(net.hostnames, ["claude.ai"])
        self.assertIs(kwargs["allow_redirects"], False)
        self.assertIs(kwargs["stream"], True)
        self.assertEqual(kwargs["timeout"], oidc.CIMD_STEP_TIMEOUT_SECONDS)
        self.assertTrue(net.session.outcome.closed)

    def test_the_session_takes_no_proxy_from_the_environment(self):
        session = oidc._pinned_session("claude.ai")
        self.assertIs(session.trust_env, False)
        session.close()

    def test_only_what_corliss_uses_is_kept(self):
        with Network():
            document, _ = oidc.fetch_client_document(URL)
        self.assertEqual(
            set(document), {"client_id", "client_name", "redirect_uris", "grant_types"}
        )

    def test_urls_that_are_never_fetched(self):
        for url in (
            "http://claude.ai/doc",
            "https://claude.ai",
            "https://claude.ai/",
            "https://user:pw@claude.ai/doc",
            "https://claude.ai/doc#frag",
            "https://claude.ai:notaport/doc",
        ):
            with self.subTest(url), Network() as net:
                with self.assertRaises(oidc.ClientDocumentError):
                    oidc.fetch_client_document(url)
                self.assertEqual(net.fetches, 0)

    def test_a_name_resolving_to_an_internal_address_is_never_connected_to(self):
        for address in (
            "127.0.0.1",
            "10.1.1.5",
            "192.168.6.99",
            "172.16.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "::1",
            "fe80::1",
            "fd00::1",
            "ff02::1",
            "::ffff:10.1.1.5",
        ):
            with self.subTest(address), Network(addresses=(address,)) as net:
                with self.assertRaises(oidc.ClientDocumentError):
                    oidc.fetch_client_document(URL)
                self.assertEqual(net.fetches, 0)

    def test_one_internal_answer_among_public_ones_refuses_the_name(self):
        with Network(addresses=(PUBLIC_IP, "10.1.1.5")) as net:
            with self.assertRaises(oidc.ClientDocumentError):
                oidc.fetch_client_document(URL)
            self.assertEqual(net.fetches, 0)

    def test_a_name_that_does_not_resolve(self):
        with Network() as net:
            net.resolve.side_effect = socket.gaierror("no such host")
            with self.assertRaises(oidc.ClientDocumentError):
                oidc.fetch_client_document(URL)

    def test_an_ipv6_address_is_bracketed(self):
        with Network(addresses=("2606:4700::6810:1",)) as net:
            oidc.fetch_client_document(URL)
        self.assertTrue(net.session.calls[0][0].startswith("https://[2606:4700::6810:1]:443/"))

    def test_a_redirect_is_a_failure(self):
        response = FakeResponse(status=302, headers={"Location": "https://evil.test/"})
        with Network(response) as net:
            with self.assertRaises(oidc.ClientDocumentError):
                oidc.fetch_client_document(URL)
            self.assertEqual(net.fetches, 1)

    def test_any_status_but_200_is_a_failure(self):
        for status in (204, 404, 500):
            with self.subTest(status), Network(FakeResponse(status=status)):
                with self.assertRaises(oidc.ClientDocumentError):
                    oidc.fetch_client_document(URL)

    def test_reading_stops_once_the_body_is_too_large(self):
        served = []

        def chunks():
            for _ in range(100):
                served.append(1)
                yield b"x" * 8192

        with Network(FakeResponse(chunks=chunks())):
            with self.assertRaises(oidc.ClientDocumentError):
                oidc.fetch_client_document(URL)
        # 64 KB is eight chunks; the ninth is the one that trips it.
        self.assertEqual(len(served), 9)

    def test_a_slow_body_is_abandoned_at_the_deadline(self):
        clock = [1000.0]

        def chunks():
            for _ in range(10):
                clock[0] += 2
                yield b" "

        with Network(FakeResponse(chunks=chunks())), patch(
            "corliss.oidc.time.monotonic", lambda: clock[0]
        ):
            with self.assertRaises(oidc.ClientDocumentError):
                oidc.fetch_client_document(URL)
        self.assertLessEqual(clock[0] - 1000.0, oidc.CIMD_DEADLINE_SECONDS + 2)

    def test_a_server_that_times_out_or_refuses(self):
        for failure in (requests.Timeout("slow"), requests.ConnectionError("refused")):
            with self.subTest(failure=failure), Network(failure):
                with self.assertRaises(oidc.ClientDocumentError):
                    oidc.fetch_client_document(URL)

    def test_a_body_that_is_not_a_json_object(self):
        for body in (b"<html>", b"[]", b'"text"', b""):
            with self.subTest(body=body), Network(FakeResponse(body)):
                with self.assertRaises(oidc.ClientDocumentError):
                    oidc.fetch_client_document(URL)

    def test_documents_that_are_not_valid(self):
        cases = {
            "client_id is another URL": {"client_id": "https://claude.ai/other"},
            "client_id differs by a slash": {"client_id": URL + "/"},
            "no client_id": {"client_id": None},
            "no redirect_uris": {"redirect_uris": []},
            "redirect_uris not a list": {"redirect_uris": "http://localhost/callback"},
            "a redirect that is not a string": {"redirect_uris": [1]},
            "client_name missing": {"client_name": None},
            "a client secret method": {"token_endpoint_auth_method": "client_secret_post"},
            "a custom scheme": {"redirect_uris": ["obsidian://scn-obsidian"]},
            "http off loopback": {"redirect_uris": ["http://example.test/cb"]},
            "one bad redirect among good": {
                "redirect_uris": ["https://claude.ai/cb", "javascript:alert(1)"]
            },
            "grant_types not a list": {"grant_types": "refresh_token"},
        }
        for name, change in cases.items():
            document = {k: v for k, v in {**DOCUMENT, **change}.items() if v is not None}
            with self.subTest(name), Network(FakeResponse(document)):
                with self.assertRaises(oidc.ClientDocumentError):
                    oidc.fetch_client_document(URL)

    def test_no_auth_method_stated_is_accepted(self):
        document = {k: v for k, v in DOCUMENT.items() if k != "token_endpoint_auth_method"}
        with Network(FakeResponse(document)):
            oidc.fetch_client_document(URL)

    def test_max_age_moves_freshness_within_its_bounds(self):
        cases = {
            "max-age=7200": timedelta(hours=2),
            "public, max-age=60": oidc.CIMD_FRESH_MIN,
            "max-age=0": oidc.CIMD_FRESH_MIN,
            "max-age=9999999": oidc.CIMD_FRESH_MAX,
            "no-cache": oidc.CIMD_FRESH_DEFAULT,
            "": oidc.CIMD_FRESH_DEFAULT,
        }
        for header, expected in cases.items():
            response = FakeResponse(headers={"Cache-Control": header})
            with self.subTest(header), Network(response):
                self.assertEqual(oidc.fetch_client_document(URL)[1], expected)


@override_settings(
    PUBLIC_BASE_URL=BASE,
    OIDC_CLIENT_ID="open-webui",
)
class ResolveAndCacheTests(TestCase):
    def setUp(self):
        cache.clear()

    def _expire(self, *, ago=timedelta(seconds=1)):
        OidcClientDocument.objects.update(expires_at=timezone.now() - ago)

    def test_a_client_is_fetched_once_and_then_cached(self):
        with Network() as net:
            client = oidc.resolve_client(URL)
            again = oidc.resolve_client(URL)

        self.assertEqual(net.fetches, 1)
        self.assertTrue(client.is_public)
        self.assertEqual(client.host, "claude.ai")
        self.assertEqual(client.name, "Claude Code")
        self.assertEqual(
            client.redirect_uris,
            ("http://localhost/callback", "http://127.0.0.1/callback"),
        )
        self.assertEqual(again, client)
        row = OidcClientDocument.objects.get(client_id=URL)
        self.assertEqual(row.last_error, "")
        self.assertTrue(row.is_fresh)

    def test_the_plugins_own_document_is_never_fetched(self):
        with Network() as net:
            client = oidc.resolve_client(PLUGIN)
            self.assertEqual(net.fetches, 0)
            net.resolve.assert_not_called()
        self.assertEqual(client.redirect_uris, ("obsidian://scn-obsidian",))

    def test_a_stale_document_is_refetched(self):
        with Network():
            oidc.resolve_client(URL)
        self._expire()
        renamed = {**DOCUMENT, "client_name": "Claude Code 2"}
        with Network(FakeResponse(renamed)) as net:
            client = oidc.resolve_client(URL)
        self.assertEqual(net.fetches, 1)
        self.assertEqual(client.name, "Claude Code 2")

    def test_a_failed_refetch_serves_the_stale_document_and_says_so(self):
        with Network():
            oidc.resolve_client(URL)
        self._expire()
        with Network(requests.ConnectionError("down")), self.assertLogs(
            "corliss.oidc", level="WARNING"
        ):
            client = oidc.resolve_client(URL)
        self.assertEqual(client.name, "Claude Code")
        self.assertIn("down", OidcClientDocument.objects.get(client_id=URL).last_error)

    def test_while_stale_is_served_the_refetch_is_not_retried_on_every_request(self):
        with Network():
            oidc.resolve_client(URL)
        self._expire()
        with Network(requests.ConnectionError("down")) as net, self.assertLogs(
            "corliss.oidc", level="WARNING"
        ):
            oidc.resolve_client(URL)
            oidc.resolve_client(URL)
            oidc.resolve_client(URL)
        self.assertEqual(net.fetches, 1)

    def test_a_document_too_stale_is_not_served(self):
        with Network():
            oidc.resolve_client(URL)
        self._expire(ago=oidc.CIMD_STALE_LIMIT + timedelta(minutes=1))
        with Network(requests.ConnectionError("down")), self.assertLogs(
            "corliss.oidc", level="WARNING"
        ):
            with self.assertRaises(oidc.ClientError) as caught:
                oidc.resolve_client(URL)
        self.assertEqual(caught.exception.error, "invalid_client")
        self.assertIsNone(oidc.known_client(URL))

    def test_a_failed_first_fetch_is_remembered_and_not_retried(self):
        with Network(FakeResponse(status=404)) as net, self.assertLogs(
            "corliss.oidc", level="WARNING"
        ):
            for _ in range(3):
                with self.assertRaises(oidc.ClientError) as caught:
                    oidc.resolve_client(URL)
            self.assertEqual(net.fetches, 1)
        self.assertEqual(caught.exception.error, "invalid_client")
        row = OidcClientDocument.objects.get(client_id=URL)
        self.assertEqual(row.document, {})
        self.assertIn("404", row.last_error)

    def test_a_remembered_failure_is_tried_again_once_it_expires(self):
        with Network(FakeResponse(status=404)), self.assertLogs("corliss.oidc", level="WARNING"):
            with self.assertRaises(oidc.ClientError):
                oidc.resolve_client(URL)
        self._expire()
        with Network() as net:
            client = oidc.resolve_client(URL)
        self.assertEqual(net.fetches, 1)
        self.assertEqual(client.name, "Claude Code")

    def test_the_token_endpoint_reads_the_cache_and_fetches_nothing(self):
        with Network():
            oidc.resolve_client(URL)
        self._expire(ago=timedelta(days=30))
        with Network() as net:
            self.assertTrue(oidc.issues_refresh_tokens(URL))
            self.assertEqual(net.fetches, 0)
            net.resolve.assert_not_called()


@override_settings(
    PUBLIC_BASE_URL=BASE,
    OIDC_RESOURCES=RESOURCES,
    OIDC_CLIENT_ID="open-webui",
)
class AuthorizeWithAFetchedClientTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user(username="alice.bsky.social", did=DID)
        _grant(DID)

    def _authorize(self, **overrides):
        params = {
            "client_id": URL,
            "redirect_uri": "http://127.0.0.1:53124/callback",
            "response_type": "code",
            "code_challenge": challenge_for(VERIFIER),
            "code_challenge_method": "S256",
            "resource": MCP,
            "state": "s",
        }
        params.update(overrides)
        return self.client.get(reverse("authorize"), params)

    def test_claude_code_reaches_the_consent_screen(self):
        self.client.force_login(self.user)
        with Network():
            resp = self._authorize()
        self.assertEqual(resp.status_code, 200)
        self.assertTemplateUsed(resp, "consent.html")
        self.assertEqual(resp.context["client_host"], "claude.ai")
        self.assertEqual(resp.context["client_name"], "Claude Code")
        self.assertTrue(resp.context["loopback"])

    def test_a_stranger_fetches_nothing_and_is_sent_to_sign_in_with_the_request_kept(self):
        with Network() as net:
            resp = self._authorize()
            self.assertEqual(net.fetches, 0)
            net.resolve.assert_not_called()
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp["Location"], reverse("login"))
        stored = self.client.session[POST_LOGIN_REDIRECT]
        self.assertEqual(parse_qs(urlsplit(stored).query)["client_id"], [URL])
        self.assertFalse(OidcClientDocument.objects.exists())

    def test_any_client_is_fetched_for_a_member_and_reaches_consent(self):
        other = "https://opencode.ai/oauth/opencode/client.json"
        self.client.force_login(self.user)
        with Network(FakeResponse(body={**DOCUMENT, "client_id": other})) as net:
            resp = self._authorize(client_id=other)
            self.assertEqual(net.fetches, 1)
        self.assertTemplateUsed(resp, "consent.html")
        self.assertEqual(resp.context["client_host"], "opencode.ai")

    def test_a_signed_in_non_member_fetches_nothing_and_is_sent_home(self):
        outsider = User.objects.create_user(
            username="mallory.bsky.social", did="did:plc:notamember"
        )
        self.client.force_login(outsider)
        # Only the fetch is counted. GATE reads the admin roster for a DID
        # with no grant, and that lookup resolves a name of its own.
        with Network() as net:
            resp = self._authorize()
            self.assertEqual(net.fetches, 0)
        self.assertRedirects(resp, reverse("home"), fetch_redirect_response=False)
        self.assertFalse(OidcClientDocument.objects.exists())

    def test_a_client_id_that_could_never_be_fetched_is_a_page_before_sign_in(self):
        for bad in (
            "https://evil.test",
            "https://user@evil.test/c.json",
            "https://evil.test/c.json#frag",
            "https://evil.test:notaport/c.json",
        ):
            with self.subTest(bad), Network() as net:
                resp = self._authorize(client_id=bad)
                self.assertEqual(net.fetches, 0)
                self.assertEqual(resp.status_code, 400)
                self.assertTemplateUsed(resp, "oauth_error.html")
                self.assertNotIn(POST_LOGIN_REDIRECT, self.client.session)

    def test_a_stranger_with_a_request_too_long_to_resume_gets_a_page_not_a_redirect(self):
        with Network() as net:
            resp = self._authorize(state="s" * 2100)
            self.assertEqual(net.fetches, 0)
        self.assertEqual(resp.status_code, 400)
        self.assertTemplateUsed(resp, "oauth_error.html")
        self.assertNotIn(POST_LOGIN_REDIRECT, self.client.session)

    def test_a_document_that_cannot_be_fetched_is_an_error_page(self):
        self.client.force_login(self.user)
        with Network(FakeResponse(status=500)), self.assertLogs(
            "corliss.oidc", level="WARNING"
        ):
            resp = self._authorize()
        self.assertEqual(resp.status_code, 400)
        self.assertTemplateUsed(resp, "oauth_error.html")
        self.assertEqual(resp.context["error"], "invalid_client")

    def test_a_client_id_that_is_not_a_url_still_gets_json(self):
        resp = self._authorize(client_id="evil")
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.json()["error"], "unauthorized_client")
