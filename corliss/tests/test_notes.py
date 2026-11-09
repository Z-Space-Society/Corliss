"""The Obsidian page, and the sync relay client behind it.

The property that matters most: **the relay is only ever asked about the
signed-in member.** The service token can list, and so make, workspaces for
any DID, so a request that could choose one would hand out other members'
workspace details.

The relay is stood in for at `requests.request`, answering in the shapes
scn-notes serves under `/internal/workspaces` from v0.7.0.
"""

import json
from datetime import timedelta
from unittest.mock import patch

import requests
from django.contrib.auth import get_user_model
from django.contrib.staticfiles import finders
from django.test import Client as HttpClient
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from corliss import oidc, sync_relay
from corliss.models import (
    MembershipCache,
    OidcClientDocument,
    OidcConsent,
    OidcRefreshToken,
    Workspace,
)
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


def notes_workspace(name, *, last_change="2026-10-08T17:03:11.123456789Z", **extra):
    """A workspace as the relay sends it. A name of None is a member's Private
    workspace, at the path `Private`; give `group_id` for a group's."""
    group_id = extra.pop("group_id", None)
    return {
        "root_doc_id": "4NMNnkMhL8jXrdJ9jamS58PAVdXu",
        "url": "automerge:4NMNnkMhL8jXrdJ9jamS58PAVdXu",
        "name": name,
        "group_id": group_id,
        "path": f"Workspaces/{name}" if group_id else "Private",
        "created_at": "2026-10-08T16:00:00Z",
        "last_change_at": last_change,
        **extra,
    }


def private(**extra):
    return notes_workspace(None, **extra)


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

    def __init__(self, *, listing=None, list_answer=None, workspace_answer=None):
        # `is None`, not `or`: a `requests.Response` is falsy when its status
        # is an error, which is exactly the answer these stand in for.
        self._list = (
            answer(200, {"workspaces": [private()] if listing is None else listing})
            if list_answer is None
            else list_answer
        )
        self._workspace = workspace_answer
        self.calls = []

    def _request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        if method == "GET":
            outcome = self._list
        elif method == "PUT":
            outcome = self._workspace
            if outcome is None:
                sent = kwargs["json"]
                outcome = answer(
                    200, notes_workspace(sent["name"], group_id=sent["group_id"])
                )
        else:
            raise AssertionError(f"the relay has no {method} route Corliss uses")
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
class NotesCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice.bsky.social", did=DID)
        _grant(DID)
        self.client.force_login(self.user)

    def get(self, **params):
        return self.client.get(reverse("notes"), params)


class RelayClientTests(NotesCase):
    """`corliss.sync_relay` on its own: what it sends and what it accepts."""

    def test_listing_asks_the_internal_address_with_the_service_token(self):
        with Relay() as relay:
            found = sync_relay.list_workspaces(DID)

        method, url, kwargs = relay.calls[0]
        self.assertEqual((method, url), ("GET", f"{RELAY}/internal/workspaces"))
        self.assertEqual(kwargs["params"], {"did": DID})
        self.assertEqual(kwargs["headers"], {"Authorization": f"Bearer {TOKEN}"})
        self.assertEqual(kwargs["timeout"], 5)
        self.assertIs(kwargs["allow_redirects"], False)
        self.assertIsNone(found[0]["name"])
        self.assertEqual(found[0]["path"], "Private")

    def test_groups_are_named_by_id_in_the_groups_parameter(self):
        with Relay() as relay:
            sync_relay.list_workspaces(DID, groups=[7, 9])
        self.assertEqual(relay.calls[0][2]["params"], {"did": DID, "groups": "7,9"})

    def test_the_private_workspace_is_the_one_with_no_group(self):
        shared = notes_workspace("Garden Club", group_id="7")
        with Relay(listing=[shared, private(note_count=3)]):
            found = sync_relay.private_workspace(DID)
        self.assertIsNone(found["group_id"])
        self.assertEqual(found["note_count"], 3)

    def test_a_listing_with_no_private_workspace_is_an_error(self):
        with Relay(listing=[]):
            with self.assertRaises(sync_relay.SyncRelayError):
                sync_relay.private_workspace(DID)

    @override_settings(SYNC_RELAY_URL=RELAY + "/")
    def test_a_trailing_slash_on_the_setting_does_not_double_up(self):
        with Relay() as relay:
            sync_relay.list_workspaces(DID)
        self.assertEqual(relay.calls[0][1], f"{RELAY}/internal/workspaces")

    def test_timestamps_are_parsed_and_a_workspace_never_written_to_has_none(self):
        with Relay(listing=[private(), private(last_change=None)]):
            first, second = sync_relay.list_workspaces(DID)
        self.assertEqual(first["created_at"].isoformat(), "2026-10-08T16:00:00+00:00")
        self.assertEqual(first["last_change_at"].minute, 3)
        self.assertIsNone(second["last_change_at"])

    def test_counts_are_read_and_anything_but_an_integer_is_none(self):
        listing = [
            private(note_count=3, bytes=1234),
            private(note_count=0, bytes=0),
            private(note_count=None, bytes=None),
            private(),
            private(note_count="3", bytes=True),
        ]
        with Relay(listing=listing):
            found = sync_relay.list_workspaces(DID)
        self.assertEqual(
            [(w["note_count"], w["bytes"]) for w in found],
            [(3, 1234), (0, 0), (None, None), (None, None), (None, None)],
        )

    def test_the_relays_order_is_kept(self):
        listing = [
            notes_workspace("First", group_id="1"),
            notes_workspace("Second", group_id="2"),
        ]
        with Relay(listing=listing):
            names = [w["name"] for w in sync_relay.list_workspaces(DID)]
        self.assertEqual(names, ["First", "Second"])

    def test_a_listing_that_is_not_the_expected_shape_is_an_error(self):
        for body in (
            [],
            {"workspaces": "none"},
            {"workspaces": [5]},
            {"workspaces": [{"name": 5}]},
            # The shape before v0.7.0 is not read.
            {"vaults": [private()]},
        ):
            with self.subTest(body=body), Relay(list_answer=answer(200, body)):
                with self.assertRaises(sync_relay.SyncRelayError):
                    sync_relay.list_workspaces(DID)

    def test_configured_needs_both_the_address_and_the_token(self):
        self.assertTrue(sync_relay.is_configured())
        with override_settings(SYNC_RELAY_SERVICE_TOKEN=""):
            self.assertFalse(sync_relay.is_configured())
        with override_settings(SYNC_RELAY_URL=""):
            self.assertFalse(sync_relay.is_configured())


class WorkspaceRelayClientTests(NotesCase):
    """The workspace half of `corliss.sync_relay`."""

    def setUp(self):
        super().setUp()
        self.workspace = Workspace.objects.create(name="Garden Club")

    def test_asking_puts_the_member_the_group_id_and_its_name(self):
        with Relay() as relay:
            found = sync_relay.group_workspace(DID, self.workspace)
        method, url, kwargs = relay.calls[0]
        self.assertEqual((method, url), ("PUT", f"{RELAY}/internal/workspaces"))
        self.assertEqual(
            kwargs["json"],
            {"did": DID, "group_id": str(self.workspace.pk), "name": "Garden Club"},
        )
        self.assertEqual(kwargs["headers"], {"Authorization": f"Bearer {TOKEN}"})
        self.assertIs(kwargs["allow_redirects"], False)
        self.assertEqual(found["group_id"], str(self.workspace.pk))
        self.assertEqual(found["path"], "Workspaces/Garden Club")

    def test_the_name_is_cut_to_fit(self):
        self.workspace.name = "x" * 150
        with Relay() as relay:
            sync_relay.group_workspace(DID, self.workspace)
        self.assertEqual(relay.made("PUT")[0][2]["json"]["name"], "x" * 100)

    def test_every_way_of_failing_is_one_error(self):
        failures = [
            answer(400, {"error": "invalid_name"}),
            answer(401, text="unauthorized\n"),
            answer(404, text="not found"),
            answer(500, {"error": "internal"}),
            answer(302),
            answer(200, text="not json"),
            answer(200, {"name": 5}),
            requests.ConnectionError("refused"),
            requests.Timeout("slow"),
        ]
        for failure in failures:
            with self.subTest(failure=failure), Relay(workspace_answer=failure):
                with patch.object(sync_relay.log, "warning"):
                    with self.assertRaises(sync_relay.SyncRelayError):
                        sync_relay.group_workspace(DID, self.workspace)


class WhoseWorkspacesTests(NotesCase):
    def test_the_workspace_is_asked_for_the_signed_in_member(self):
        with Relay() as relay:
            self.get()
        self.assertEqual([c[2]["params"] for c in relay.calls], [{"did": DID}])

    def test_the_notes_page_names_none_of_the_members_workspaces(self):
        """Shared workspaces are on the workspace's page, never here."""
        Workspace.objects.create(name="Garden Club").members.add(self.user)
        with Relay() as relay:
            self.get()
        self.assertEqual([c[2]["params"] for c in relay.calls], [{"did": DID}])

    def test_a_did_in_the_query_string_is_ignored(self):
        with Relay() as relay:
            self.get(did=OTHER)
        self.assertEqual([c[2]["params"] for c in relay.calls], [{"did": DID}])

    def test_the_page_takes_no_post_and_the_relay_is_not_asked(self):
        with Relay() as relay:
            resp = self.client.post(reverse("notes"), {"name": "Notes", "did": OTHER})
        self.assertEqual(resp.status_code, 405)
        self.assertEqual(relay.calls, [])

    def test_a_non_member_is_refused_and_the_relay_is_not_asked(self):
        MembershipCache.objects.filter(did=DID).update(active=False)
        with Relay() as relay:
            resp = self.get()
        self.assertRedirects(resp, reverse("home"), fetch_redirect_response=False)
        self.assertEqual(relay.calls, [])

    def test_a_signed_out_visitor_is_sent_to_sign_in(self):
        self.client.logout()
        with Relay() as relay:
            resp = self.get()
        self.assertRedirects(resp, reverse("login"), fetch_redirect_response=False)
        self.assertEqual(relay.calls, [])


class PageStateTests(NotesCase):
    def assertInstructions(self, resp):
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.context["sync_url"], SYNC)
        self.assertEqual(resp.context["mcp_url"], MCP)
        self.assertContains(resp, SYNC)
        self.assertContains(resp, MCP)

    def test_answered_shows_the_private_workspace(self):
        with Relay(listing=[private(note_count=42, bytes=1234)]):
            resp = self.get()
        self.assertInstructions(resp)
        self.assertTrue(resp.context["configured"])
        self.assertTrue(resp.context["reachable"])
        self.assertEqual(resp.context["private"]["path"], "Private")
        self.assertEqual(resp.context["private"]["note_count"], 42)

    def test_not_configured_shows_the_instructions_and_asks_nothing(self):
        for blank in ("SYNC_RELAY_SERVICE_TOKEN", "SYNC_RELAY_URL"):
            with self.subTest(blank=blank), override_settings(**{blank: ""}):
                with Relay() as relay:
                    resp = self.get()
                self.assertEqual(relay.calls, [])
                self.assertInstructions(resp)
                self.assertFalse(resp.context["configured"])
                self.assertIsNone(resp.context["private"])

    def test_unreachable_or_a_bad_answer_shows_the_instructions(self):
        for failure in (
            requests.ConnectionError("refused"),
            answer(502, text="bad gateway"),
            answer(401, text="unauthorized\n"),
            answer(200, text="<html>"),
            answer(200, {"workspaces": []}),
        ):
            with self.subTest(failure=failure), Relay(list_answer=failure):
                with patch.object(sync_relay.log, "warning"):
                    resp = self.get()
                self.assertInstructions(resp)
                self.assertTrue(resp.context["configured"])
                self.assertFalse(resp.context["reachable"])

    @override_settings(OIDC_RESOURCES="")
    def test_with_no_resources_configured_the_page_still_renders(self):
        with Relay():
            resp = self.get()
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.context["sync_url"], "")
        self.assertEqual(resp.context["mcp_url"], "")

    def test_the_page_links_the_connect_script_at_its_published_path(self):
        with Relay():
            resp = self.get()
        self.assertContains(resp, 'href="/static/help/scripts/connect-opencode.sh"')

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


OPENCODE = "https://opencode.ai/oauth/opencode/client.json"
CLAUDE = "https://claude.ai/oauth/mcp-oauth-client-metadata"


def _cache_document(client_id, name):
    now = timezone.now()
    OidcClientDocument.objects.create(
        client_id=client_id,
        document={
            "client_id": client_id,
            "client_name": name,
            "redirect_uris": ["http://127.0.0.1/callback"],
            "grant_types": ["authorization_code", "refresh_token"],
        },
        fetched_at=now,
        expires_at=now + timedelta(hours=1),
    )


@override_settings(
    SYNC_RELAY_URL=RELAY, SYNC_RELAY_SERVICE_TOKEN=TOKEN, OIDC_RESOURCES=RESOURCES
)
class ConnectedAppsTests(NotesCase):
    def setUp(self):
        super().setUp()
        _cache_document(OPENCODE, "opencode")
        _cache_document(CLAUDE, "Claude")

    def connect(self, client_id, *, user=None, resource=MCP):
        raw, row = OidcRefreshToken.issue(
            user=user or self.user,
            client_id=client_id,
            resource=resource,
            scope="",
            ttl=oidc.REFRESH_TOKEN_TTL,
        )
        return raw, row

    def apps(self):
        with Relay():
            resp = self.get()
        self.assertEqual(resp.status_code, 200)
        return resp, resp.context["connected_apps"]

    def disconnect(self, client_id):
        return self.client.post(reverse("notes_disconnect"), {"client_id": client_id})

    def test_an_app_with_a_live_token_is_listed_by_host_with_its_own_name(self):
        _, row = self.connect(OPENCODE)
        resp, apps = self.apps()
        self.assertEqual(len(apps), 1)
        self.assertEqual(apps[0]["host"], "opencode.ai")
        self.assertEqual(apps[0]["name"], "opencode")
        self.assertEqual(apps[0]["resources"], ["Notes for Claude"])
        self.assertEqual(apps[0]["last_used_at"], row.created_at)
        self.assertContains(resp, "opencode.ai")
        self.assertContains(resp, "Disconnect")

    def test_both_resources_are_one_row_and_the_newest_token_is_the_last_use(self):
        self.connect(OPENCODE, resource=SYNC)
        _, newest = self.connect(OPENCODE)
        _, apps = self.apps()
        self.assertEqual(len(apps), 1)
        self.assertEqual(apps[0]["resources"], ["Notes sync", "Notes for Claude"])
        self.assertEqual(apps[0]["last_used_at"], newest.created_at)

    def test_newest_use_first_and_a_consent_alone_last(self):
        OidcConsent.record(self.user, client_id=CLAUDE, resource=MCP)
        _, old = self.connect(OPENCODE)
        OidcRefreshToken.objects.filter(pk=old.pk).update(
            created_at=timezone.now() - timedelta(days=2)
        )
        plugin = oidc.plugin_client_id()
        self.connect(plugin, resource=SYNC)
        _, apps = self.apps()
        self.assertEqual([app["client_id"] for app in apps], [plugin, OPENCODE, CLAUDE])
        self.assertEqual(apps[1]["name"], "opencode")
        self.assertEqual(apps[0]["name"], "SCN Sync")
        self.assertIsNone(apps[2]["last_used_at"])

    def test_spent_superseded_and_expired_tokens_list_nothing(self):
        now = timezone.now()
        for change in (
            {"used_at": now},
            {"superseded_at": now},
            {"expires_at": now - timedelta(seconds=1)},
        ):
            with self.subTest(change):
                OidcRefreshToken.objects.all().delete()
                _, row = self.connect(OPENCODE)
                OidcRefreshToken.objects.filter(pk=row.pk).update(**change)
                resp, apps = self.apps()
                self.assertEqual(apps, [])
                self.assertContains(resp, "No apps are connected.")

    def test_an_app_whose_document_is_gone_is_listed_by_host_alone(self):
        OidcClientDocument.objects.filter(client_id=OPENCODE).delete()
        self.connect(OPENCODE)
        _, apps = self.apps()
        self.assertEqual(apps[0]["host"], "opencode.ai")
        self.assertEqual(apps[0]["name"], "")

    def test_another_members_apps_never_appear(self):
        other = User.objects.create_user(username="bob.bsky.social", did=OTHER)
        self.connect(OPENCODE, user=other)
        OidcConsent.record(other, client_id=CLAUDE, resource=MCP)
        _, apps = self.apps()
        self.assertEqual(apps, [])

    def test_disconnect_ends_that_app_for_this_member_and_nothing_else(self):
        other = User.objects.create_user(username="bob.bsky.social", did=OTHER)
        raw, _ = self.connect(OPENCODE)
        self.connect(OPENCODE, resource=SYNC)
        OidcConsent.record(self.user, client_id=OPENCODE, resource=MCP)
        self.connect(CLAUDE)
        self.connect(OPENCODE, user=other)
        OidcConsent.record(other, client_id=OPENCODE, resource=MCP)

        resp = self.disconnect(OPENCODE)

        self.assertRedirects(resp, reverse("notes"), fetch_redirect_response=False)
        self.assertFalse(
            OidcRefreshToken.objects.filter(user=self.user, client_id=OPENCODE).exists()
        )
        self.assertFalse(
            OidcConsent.objects.filter(user=self.user, client_id=OPENCODE).exists()
        )
        self.assertTrue(
            OidcRefreshToken.objects.filter(user=self.user, client_id=CLAUDE).exists()
        )
        self.assertTrue(OidcRefreshToken.objects.filter(user=other).exists())
        self.assertTrue(OidcConsent.objects.filter(user=other).exists())

        refreshed = self.client.post(
            reverse("token"),
            {
                "grant_type": "refresh_token",
                "refresh_token": raw,
                "client_id": OPENCODE,
            },
        )
        self.assertEqual(refreshed.status_code, 400)
        self.assertEqual(refreshed.json()["error"], "invalid_grant")

    def test_disconnecting_an_app_the_member_never_connected_changes_nothing(self):
        self.connect(OPENCODE)
        resp = self.disconnect("https://nobody.test/c.json")
        self.assertRedirects(resp, reverse("notes"), fetch_redirect_response=False)
        self.assertEqual(OidcRefreshToken.objects.count(), 1)

    def test_disconnect_answers_only_a_post(self):
        self.connect(OPENCODE)
        resp = self.client.get(reverse("notes_disconnect"), {"client_id": OPENCODE})
        self.assertEqual(resp.status_code, 405)
        self.assertEqual(OidcRefreshToken.objects.count(), 1)

    def test_disconnect_needs_a_csrf_token(self):
        self.connect(OPENCODE)
        browser = HttpClient(enforce_csrf_checks=True)
        browser.force_login(self.user)
        resp = browser.post(reverse("notes_disconnect"), {"client_id": OPENCODE})
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(OidcRefreshToken.objects.count(), 1)

    def test_a_non_member_cannot_disconnect(self):
        self.connect(OPENCODE)
        MembershipCache.objects.filter(did=DID).update(active=False)
        resp = self.disconnect(OPENCODE)
        self.assertRedirects(resp, reverse("home"), fetch_redirect_response=False)
        self.assertEqual(OidcRefreshToken.objects.count(), 1)


class ConnectScriptTests(TestCase):
    """`/static/help/scripts/connect-opencode.sh` is an address members are
    told to fetch. Moving the file passes every page test and breaks those
    instructions, so its path is pinned here."""

    def test_the_connect_script_is_at_its_published_path(self):
        self.assertIsNotNone(finders.find("help/scripts/connect-opencode.sh"))


ALL = f"{RELAY}/internal/workspaces/all"
BOB = "did:plc:bobbobbobbobbobbobbobbob"


def held(name, owner, *, group_id=None, path=None, **sizes):
    return notes_workspace(name, **sizes) | {
        "owner_did": owner,
        "group_id": group_id,
        "path": path or (f"Workspaces/{name}" if group_id else f"Private/{name}"),
    }


class AllWorkspacesClientTests(NotesCase):
    """`sync_relay.all_workspaces`: the admin listing, on its own."""

    def test_it_asks_the_all_route_with_the_service_token_and_no_parameters(self):
        body = {"workspaces": [held("Notes", DID)], "unfiled": []}
        with Relay(list_answer=answer(200, body)) as relay:
            found, unfiled = sync_relay.all_workspaces()

        method, url, kwargs = relay.calls[0]
        self.assertEqual((method, url), ("GET", ALL))
        self.assertNotIn("params", kwargs)
        self.assertEqual(kwargs["headers"], {"Authorization": f"Bearer {TOKEN}"})
        self.assertIs(kwargs["allow_redirects"], False)
        self.assertEqual(found[0]["owner_did"], DID)
        self.assertEqual(found[0]["path"], "Private/Notes")
        self.assertEqual(unfiled, [])

    def test_unfiled_is_read_and_null_stays_none(self):
        entry = {"did": DID, "docs": 3, "bytes": 900}
        with Relay(list_answer=answer(200, {"workspaces": [], "unfiled": [entry]})):
            self.assertEqual(sync_relay.all_workspaces(), ([], [entry]))
        with Relay(list_answer=answer(200, {"workspaces": [], "unfiled": None})):
            self.assertEqual(sync_relay.all_workspaces(), ([], None))

    def test_anything_but_a_good_answer_is_an_error(self):
        failures = [
            answer(401, text="unauthorized\n"),
            answer(404, text=""),
            answer(200, text="<html>"),
            answer(200, {"workspaces": "none"}),
            answer(200, {"workspaces": [notes_workspace("Notes")], "unfiled": []}),
            answer(200, {"workspaces": [], "unfiled": "none"}),
            answer(200, {"workspaces": [], "unfiled": [{"docs": 1}]}),
            answer(200, {"vaults": [], "unfiled": []}),
            requests.ConnectionError("refused"),
        ]
        for failure in failures:
            with self.subTest(failure=failure), Relay(list_answer=failure):
                with patch.object(sync_relay.log, "warning"):
                    with self.assertRaises(sync_relay.SyncRelayError):
                        sync_relay.all_workspaces()


@override_settings(SYNC_RELAY_URL=RELAY, SYNC_RELAY_SERVICE_TOKEN=TOKEN)
class SystemsNotesTests(TestCase):
    """`/systems/notes/`: every workspace, for cluster admins only."""

    def setUp(self):
        self.user = User.objects.create_user(username="alice.bsky.social", did=DID)
        User.objects.create_user(username="bob.bsky.social", did=BOB)
        self.workspace = Workspace.objects.create(name="Garden Club")
        self.client.force_login(self.user)
        self._admin(False)

    def _admin(self, value):
        patcher = patch("corliss.membership.is_cluster_admin", return_value=value)
        patcher.start()
        self.addCleanup(patcher.stop)

    def get(self, body=None, *, failure=None):
        listing = failure or answer(200, body or {"workspaces": [], "unfiled": []})
        with Relay(list_answer=listing) as relay:
            with patch.object(sync_relay.log, "warning"):
                resp = self.client.get(reverse("systems_notes"))
        return resp, relay

    def test_a_member_who_is_not_an_admin_gets_a_404_and_the_relay_is_not_asked(self):
        _grant(DID)
        resp, relay = self.get()
        self.assertEqual(resp.status_code, 404)
        self.assertEqual(relay.calls, [])

    def test_a_signed_out_visitor_is_sent_to_sign_in_and_the_relay_is_not_asked(self):
        self.client.logout()
        resp, relay = self.get()
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(relay.calls, [])

    def test_an_admin_sees_every_workspace_with_its_holder_and_each_members_total(self):
        self._admin(True)
        body = {
            "workspaces": [
                held("Notes", DID, note_count=4, bytes=1000),
                held("Work", DID, note_count=1, bytes=500),
                held("Private", BOB, note_count=2, bytes=300),
                held(
                    "Garden Club",
                    DID,
                    group_id=str(self.workspace.pk),
                    note_count=9,
                    bytes=7000,
                ),
                held("Gone", BOB, group_id="999", note_count=0, bytes=10),
            ],
            "unfiled": [
                {"did": BOB, "docs": 2, "bytes": 50},
                {"did": OTHER, "docs": 1, "bytes": 20},
            ],
        }
        resp, relay = self.get(body)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual([c[1] for c in relay.calls], [ALL])

        holders = [(w["path"], w["holder"]) for w in resp.context["workspaces"]]
        self.assertEqual(
            holders,
            [
                ("Private/Notes", "alice.bsky.social"),
                ("Private/Work", "alice.bsky.social"),
                ("Private/Private", "bob.bsky.social"),
                ("Workspaces/Garden Club", "Garden Club"),
                ("Workspaces/Gone", ""),
            ],
        )

        rows = {
            row["did"]: (
                row["workspaces"],
                row["notes"],
                row["workspace_bytes"],
                row["unfiled_docs"],
                row["unfiled_bytes"],
                row["total_bytes"],
            )
            for row in resp.context["members"]
        }
        # Alice made the group's workspace; it is not in her total.
        self.assertEqual(rows[DID], (2, 5, 1500, 0, 0, 1500))
        self.assertEqual(rows[BOB], (1, 2, 300, 2, 50, 350))
        # Holds only unfiled documents, and has never signed in here.
        self.assertEqual(rows[OTHER], (0, 0, 0, 1, 20, 20))
        self.assertEqual(
            [row["did"] for row in resp.context["members"]], [DID, BOB, OTHER]
        )
        self.assertFalse(resp.context["indexing"])

    def test_while_the_relay_is_indexing_the_unfiled_figures_are_unknown(self):
        self._admin(True)
        body = {
            "workspaces": [held("Notes", DID, note_count=1, bytes=100)],
            "unfiled": None,
        }
        resp, _ = self.get(body)
        self.assertTrue(resp.context["indexing"])
        (row,) = resp.context["members"]
        self.assertIsNone(row["unfiled_docs"])
        self.assertIsNone(row["total_bytes"])
        self.assertEqual(row["workspace_bytes"], 100)

    def test_unreachable_or_not_configured_renders_rather_than_failing(self):
        self._admin(True)
        resp, _ = self.get(failure=requests.ConnectionError("refused"))
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.context["configured"])
        self.assertFalse(resp.context["reachable"])

        with override_settings(SYNC_RELAY_URL=""):
            resp, relay = self.get()
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.context["configured"])
        self.assertEqual(relay.calls, [])
