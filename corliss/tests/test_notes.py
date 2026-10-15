"""The Obsidian page, and the sync relay client behind it.

The property that matters most: **the relay is only ever asked about the
signed-in member.** The service token can list and create vaults for any DID,
so a request that could choose one would hand out other members' vault names
and let anybody plant a vault in somebody else's account.

The relay is stood in for at `requests.request`. Its JSON shapes and error
codes are the ones pinned in scn-sync-relay's spec, section Z3.
"""

import json
from unittest.mock import patch

import requests
from django.contrib.auth import get_user_model
from django.test import Client as HttpClient
from django.test import TestCase, override_settings
from django.urls import reverse

from corliss import sync_relay
from corliss.models import MembershipCache
from corliss.tests.test_provider import _grant

User = get_user_model()

DID = "did:plc:ewvi7nxzyoun6zhxrhs64oiz"
OTHER = "did:plc:someoneelsexxxxxxxxxxxxx"
RELAY = "http://10.1.1.50:7030"
TOKEN = "service-token"
SYNC = "https://sync.zai.test"
MCP = "https://mcp.zai.test/mcp"
RESOURCES = json.dumps(
    [
        {"url": SYNC, "kind": "sync", "label": "Notes sync"},
        {"url": MCP, "kind": "mcp", "label": "Notes for Claude"},
    ]
)


def vault(name, *, last_change="2026-10-08T17:03:11.123456789Z"):
    return {
        "root_doc_id": "4NMNnkMhL8jXrdJ9jamS58PAVdXu",
        "url": "automerge:4NMNnkMhL8jXrdJ9jamS58PAVdXu",
        "name": name,
        "created_at": "2026-10-08T16:00:00Z",
        "last_change_at": last_change,
    }


def answer(status=200, body=None, *, text=None):
    response = requests.Response()
    response.status_code = status
    if text is not None:
        response._content = text.encode()
    else:
        response._content = json.dumps({} if body is None else body).encode()
    return response


class Relay:
    """Stand in for the relay for the length of a `with` block."""

    def __init__(self, *, listing=None, created=None, list_answer=None, create_answer=None):
        # `is None`, not `or`: a `requests.Response` is falsy when its status
        # is an error, which is exactly the answer these stand in for.
        self._list = (
            answer(200, {"vaults": listing or []}) if list_answer is None else list_answer
        )
        self._create = (
            answer(201, created or vault("Notes")) if create_answer is None else create_answer
        )
        self.calls = []

    def _request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        outcome = self._list if method == "GET" else self._create
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def __enter__(self):
        self._patch = patch("corliss.sync_relay.requests.request", self._request)
        self._patch.start()
        return self

    def __exit__(self, *exc):
        self._patch.stop()

    def made(self, method):
        return [call for call in self.calls if call[0] == method]


@override_settings(
    SYNC_RELAY_URL=RELAY, SYNC_RELAY_SERVICE_TOKEN=TOKEN, OIDC_RESOURCES=RESOURCES
)
class VaultsCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice.bsky.social", did=DID)
        _grant(DID)
        self.client.force_login(self.user)

    def get(self, **params):
        return self.client.get(reverse("notes"), params)

    def create(self, name="Notes", **extra):
        return self.client.post(reverse("notes"), {"name": name, **extra})


class RelayClientTests(VaultsCase):
    """`corliss.sync_relay` on its own: what it sends and what it accepts."""

    def test_listing_asks_the_internal_address_with_the_service_token(self):
        with Relay(listing=[vault("Notes")]) as relay:
            vaults = sync_relay.list_vaults(DID)

        method, url, kwargs = relay.calls[0]
        self.assertEqual((method, url), ("GET", f"{RELAY}/internal/vaults"))
        self.assertEqual(kwargs["params"], {"did": DID})
        self.assertEqual(kwargs["headers"], {"Authorization": f"Bearer {TOKEN}"})
        self.assertEqual(kwargs["timeout"], 5)
        self.assertIs(kwargs["allow_redirects"], False)
        self.assertEqual(vaults[0]["name"], "Notes")

    def test_creating_posts_the_did_and_the_name(self):
        with Relay(created=vault("Journal")) as relay:
            created = sync_relay.create_vault(DID, "Journal")

        method, url, kwargs = relay.calls[0]
        self.assertEqual((method, url), ("POST", f"{RELAY}/internal/vaults"))
        self.assertEqual(kwargs["json"], {"did": DID, "name": "Journal"})
        self.assertEqual(kwargs["headers"], {"Authorization": f"Bearer {TOKEN}"})
        self.assertIs(kwargs["allow_redirects"], False)
        self.assertEqual(created["name"], "Journal")

    @override_settings(SYNC_RELAY_URL=RELAY + "/")
    def test_a_trailing_slash_on_the_setting_does_not_double_up(self):
        with Relay() as relay:
            sync_relay.list_vaults(DID)
        self.assertEqual(relay.calls[0][1], f"{RELAY}/internal/vaults")

    def test_timestamps_are_parsed_and_a_vault_never_written_to_has_none(self):
        with Relay(listing=[vault("A"), vault("B", last_change=None)]):
            first, second = sync_relay.list_vaults(DID)
        self.assertEqual(first["created_at"].isoformat(), "2026-10-08T16:00:00+00:00")
        self.assertEqual(first["last_change_at"].minute, 3)
        self.assertIsNone(second["last_change_at"])

    def test_the_relays_order_is_kept(self):
        with Relay(listing=[vault("First"), vault("Second")]):
            names = [v["name"] for v in sync_relay.list_vaults(DID)]
        self.assertEqual(names, ["First", "Second"])

    def test_a_duplicate_name_is_its_own_error(self):
        with Relay(create_answer=answer(409, {"error": "name_taken"})):
            with self.assertRaises(sync_relay.NameTaken):
                sync_relay.create_vault(DID, "Notes")

    def test_every_other_way_of_failing_is_one_error(self):
        failures = [
            answer(400, {"error": "invalid_name"}),
            answer(400, {"error": "invalid_did"}),
            answer(401, text="unauthorized\n"),
            answer(500, {"error": "internal"}),
            answer(302),
            answer(200, vault("Notes")),
            answer(201, text="not json"),
            answer(201, {"name": 5}),
            requests.ConnectionError("refused"),
            requests.Timeout("slow"),
        ]
        for failure in failures:
            with self.subTest(failure=failure), Relay(create_answer=failure):
                with patch.object(sync_relay.log, "warning"):
                    with self.assertRaises(sync_relay.SyncRelayError) as caught:
                        sync_relay.create_vault(DID, "Notes")
                self.assertNotIsInstance(caught.exception, sync_relay.NameTaken)

    def test_a_listing_that_is_not_the_expected_shape_is_an_error(self):
        for body in ([], {"vaults": "none"}, {"vaults": [5]}, {"vaults": [{"name": None}]}):
            with self.subTest(body=body), Relay(list_answer=answer(200, body)):
                with self.assertRaises(sync_relay.SyncRelayError):
                    sync_relay.list_vaults(DID)

    def test_configured_needs_both_the_address_and_the_token(self):
        self.assertTrue(sync_relay.is_configured())
        with override_settings(SYNC_RELAY_SERVICE_TOKEN=""):
            self.assertFalse(sync_relay.is_configured())
        with override_settings(SYNC_RELAY_URL=""):
            self.assertFalse(sync_relay.is_configured())


class WhoseVaultsTests(VaultsCase):
    def test_the_list_is_asked_for_the_signed_in_member(self):
        with Relay() as relay:
            self.get()
        self.assertEqual(relay.calls[0][2]["params"], {"did": DID})

    def test_a_did_in_the_query_string_is_ignored(self):
        with Relay() as relay:
            self.get(did=OTHER)
        self.assertEqual([c[2]["params"] for c in relay.calls], [{"did": DID}])

    def test_a_did_in_the_form_is_ignored_for_create_and_for_the_list(self):
        with Relay() as relay:
            self.create("Notes", did=OTHER)
            self.client.post(reverse("notes") + f"?did={OTHER}", {"name": "More"})
        for _, _, kwargs in relay.made("POST"):
            self.assertEqual(kwargs["json"]["did"], DID)
        for _, _, kwargs in relay.made("GET"):
            self.assertEqual(kwargs["params"], {"did": DID})

    def test_a_non_member_is_refused_on_get_and_on_post_and_the_relay_is_not_asked(self):
        MembershipCache.objects.filter(did=DID).update(active=False)
        with Relay() as relay:
            for resp in (self.get(), self.create()):
                self.assertRedirects(resp, reverse("home"), fetch_redirect_response=False)
        self.assertEqual(relay.calls, [])

    def test_a_signed_out_visitor_is_sent_to_sign_in(self):
        self.client.logout()
        with Relay() as relay:
            for resp in (self.get(), self.create()):
                self.assertRedirects(resp, reverse("login"), fetch_redirect_response=False)
        self.assertEqual(relay.calls, [])


class PageStateTests(VaultsCase):
    FORM = 'name="name"'

    def assertInstructions(self, resp):
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.context["sync_url"], SYNC)
        self.assertEqual(resp.context["mcp_url"], MCP)
        self.assertContains(resp, SYNC)
        self.assertContains(resp, MCP)

    def test_answered_with_vaults_lists_them_and_offers_the_form(self):
        with Relay(listing=[vault("Notes"), vault("Journal", last_change=None)]):
            resp = self.get()
        self.assertInstructions(resp)
        self.assertTrue(resp.context["configured"])
        self.assertTrue(resp.context["reachable"])
        self.assertContains(resp, "Notes")
        self.assertContains(resp, "Journal")
        self.assertContains(resp, self.FORM)

    def test_answered_with_none_still_offers_the_form(self):
        with Relay(listing=[]):
            resp = self.get()
        self.assertInstructions(resp)
        self.assertEqual(resp.context["vaults"], [])
        self.assertTrue(resp.context["reachable"])
        self.assertContains(resp, self.FORM)

    def test_not_configured_shows_the_instructions_and_no_form(self):
        for blank in ("SYNC_RELAY_SERVICE_TOKEN", "SYNC_RELAY_URL"):
            with self.subTest(blank=blank), override_settings(**{blank: ""}):
                with Relay() as relay:
                    resp = self.get()
                    posted = self.create()
                self.assertEqual(relay.calls, [])
                self.assertInstructions(resp)
                self.assertFalse(resp.context["configured"])
                self.assertNotContains(resp, self.FORM)
                self.assertEqual(posted.status_code, 200)
                self.assertNotContains(posted, self.FORM)

    def test_unreachable_or_a_bad_answer_shows_the_instructions_and_no_form(self):
        for failure in (
            requests.ConnectionError("refused"),
            answer(502, text="bad gateway"),
            answer(401, text="unauthorized\n"),
            answer(200, text="<html>"),
        ):
            with self.subTest(failure=failure), Relay(list_answer=failure):
                with patch.object(sync_relay.log, "warning"):
                    resp = self.get()
                self.assertInstructions(resp)
                self.assertTrue(resp.context["configured"])
                self.assertFalse(resp.context["reachable"])
                self.assertNotContains(resp, self.FORM)

    @override_settings(OIDC_RESOURCES="")
    def test_with_no_resources_configured_the_page_still_renders(self):
        with Relay(listing=[vault("Notes")]):
            resp = self.get()
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.context["sync_url"], "")
        self.assertEqual(resp.context["mcp_url"], "")

    def test_the_page_names_no_ai_product(self):
        """The site is AI agnostic. The MCP address is offered as an MCP
        service, for whatever the member uses."""
        with Relay(listing=[vault("Notes")]):
            resp = self.get()
        self.assertNotContains(resp, "Claude")
        self.assertContains(resp, MCP)

    def test_the_nav_offers_the_page_to_a_member_and_closes_it_to_a_non_member(self):
        with Relay():
            html = self.get().content.decode()
        self.assertIn(f'href="{reverse("notes")}"', html)

        MembershipCache.objects.filter(did=DID).update(active=False)
        html = self.client.get(reverse("home")).content.decode()
        self.assertNotIn(f'href="{reverse("notes")}"', html)
        self.assertIn(">Notes</span>", html)

    @override_settings(ENABLE_NOTES=False)
    def test_the_nav_hides_the_page_when_notes_are_off(self):
        with Relay():
            html = self.get().content.decode()
        self.assertNotIn(f'href="{reverse("notes")}"', html)

        MembershipCache.objects.filter(did=DID).update(active=False)
        html = self.client.get(reverse("home")).content.decode()
        self.assertNotIn(">Notes</span>", html)


class CreateTests(VaultsCase):
    def test_creating_redirects_to_the_page_which_then_lists_it(self):
        with Relay(listing=[vault("Notes")]) as relay:
            resp = self.create("Notes")
            self.assertRedirects(resp, reverse("notes"))
        self.assertEqual(len(relay.made("POST")), 1)

    def test_the_name_is_trimmed(self):
        with Relay() as relay:
            self.create("  Notes  ")
        self.assertEqual(relay.made("POST")[0][2]["json"]["name"], "Notes")

    def test_an_empty_or_overlong_name_never_reaches_the_relay(self):
        for name in ("", "   ", "n" * 101):
            with self.subTest(name=name), Relay() as relay:
                resp = self.create(name)
                self.assertEqual(relay.made("POST"), [])
                self.assertEqual(resp.status_code, 200)
                self.assertTrue(resp.context["name_error"])

    def test_a_hundred_characters_is_allowed(self):
        with Relay() as relay:
            resp = self.create("n" * 100)
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(len(relay.made("POST")), 1)

    def test_a_duplicate_name_says_so_beside_the_form_and_keeps_the_name(self):
        taken = answer(409, {"error": "name_taken"})
        with Relay(listing=[vault("Notes")], create_answer=taken):
            resp = self.create("notes")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("already", resp.context["name_error"])
        self.assertEqual(resp.context["name"], "notes")
        self.assertContains(resp, 'value="notes"')
        self.assertContains(resp, resp.context["name_error"])

    def test_any_other_failure_says_it_could_not_be_created_and_does_not_retry(self):
        for failure in (answer(500, {"error": "internal"}), requests.ConnectionError("down")):
            with self.subTest(failure=failure), Relay(create_answer=failure) as relay:
                with self.assertLogs("corliss.sync_relay", level="WARNING"):
                    resp = self.create("Notes")
                self.assertEqual(resp.status_code, 200)
                self.assertTrue(resp.context["name_error"])
                self.assertNotIn("already", resp.context["name_error"])
                self.assertEqual(resp.context["name"], "Notes")
                self.assertEqual(len(relay.made("POST")), 1)

    def test_creating_needs_a_csrf_token(self):
        browser = HttpClient(enforce_csrf_checks=True)
        browser.force_login(self.user)
        with Relay() as relay:
            resp = browser.post(reverse("notes"), {"name": "Notes"})
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(relay.calls, [])
