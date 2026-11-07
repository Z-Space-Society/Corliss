"""Workspace rosters and members' names reach the sync relay.

`corliss.signals` pushes them after each change commits, and
`sync_relay_rosters` sends them all again. These check what reaches the relay,
not how the receivers are wired.
"""

from io import StringIO
from unittest.mock import patch

import requests
from django.core.management import CommandError, call_command
from django.db import transaction
from django.test import TestCase, override_settings

from corliss.models import User, Workspace

RELAY = "http://10.1.1.50:7030"


class Relay:
    """Stand in for the relay's push routes, answering `status`."""

    def __init__(self, status=204):
        self.status = status
        self.pushes = []

    def _request(self, method, url, **kwargs):
        assert method == "PUT", method
        self.pushes.append((url.removeprefix(RELAY), kwargs["json"]))
        if isinstance(self.status, Exception):
            raise self.status
        response = requests.Response()
        response.status_code = self.status
        return response

    def __enter__(self):
        self._patch = patch("corliss.sync_relay.requests.request", self._request)
        self._patch.start()
        return self

    def __exit__(self, *exc):
        self._patch.stop()

    def rosters(self):
        return [
            (url, body["members"]) for url, body in self.pushes if "/workspaces/" in url
        ]

    def names(self):
        return [(url, body) for url, body in self.pushes if "/members/" in url]


@override_settings(SYNC_RELAY_URL=RELAY, SYNC_RELAY_SERVICE_TOKEN="service-token")
class PushTests(TestCase):
    def setUp(self):
        self.alice = User.objects.create_user(
            username="alice.test", did="did:plc:alice"
        )
        self.bob = User.objects.create_user(username="bob.test", did="did:plc:bob")
        self.garden = Workspace.objects.create(name="Garden")
        self.garden.members.add(self.alice)

    def roster(self, workspace):
        return f"/internal/workspaces/{workspace.pk}/members"

    def test_adding_from_either_side_pushes_the_whole_roster(self):
        with Relay() as relay, self.captureOnCommitCallbacks(execute=True):
            self.garden.members.add(self.bob)
        self.assertEqual(
            relay.rosters(),
            [(self.roster(self.garden), ["did:plc:alice", "did:plc:bob"])],
        )

        kiln = Workspace.objects.create(name="Kiln")
        with Relay() as relay, self.captureOnCommitCallbacks(execute=True):
            self.bob.workspaces.add(kiln)
        self.assertEqual(relay.rosters(), [(self.roster(kiln), ["did:plc:bob"])])

    def test_removing_from_either_side_pushes_what_is_left(self):
        self.garden.members.add(self.bob)
        with Relay() as relay, self.captureOnCommitCallbacks(execute=True):
            self.garden.members.remove(self.alice)
        self.assertEqual(relay.rosters(), [(self.roster(self.garden), ["did:plc:bob"])])

        with Relay() as relay, self.captureOnCommitCallbacks(execute=True):
            self.bob.workspaces.remove(self.garden)
        self.assertEqual(relay.rosters(), [(self.roster(self.garden), [])])

    def test_clearing_from_either_side_pushes_every_workspace_touched(self):
        kiln = Workspace.objects.create(name="Kiln")
        kiln.members.add(self.alice)
        with Relay() as relay, self.captureOnCommitCallbacks(execute=True):
            self.alice.workspaces.clear()
        self.assertCountEqual(
            relay.rosters(), [(self.roster(self.garden), []), (self.roster(kiln), [])]
        )

        kiln.members.add(self.bob)
        with Relay() as relay, self.captureOnCommitCallbacks(execute=True):
            kiln.members.clear()
        self.assertEqual(relay.rosters(), [(self.roster(kiln), [])])

    def test_deleting_a_workspace_or_a_user_pushes_the_rosters_they_leave(self):
        url = self.roster(self.garden)
        with Relay() as relay, self.captureOnCommitCallbacks(execute=True):
            self.garden.delete()
        self.assertEqual(relay.rosters(), [(url, [])])

        kiln = Workspace.objects.create(name="Kiln")
        kiln.members.add(self.alice, self.bob)
        with Relay() as relay, self.captureOnCommitCallbacks(execute=True):
            self.bob.delete()
        self.assertEqual(relay.rosters(), [(self.roster(kiln), ["did:plc:alice"])])

    def test_a_rolled_back_change_pushes_nothing(self):
        with Relay() as relay, self.captureOnCommitCallbacks(execute=True):
            try:
                with transaction.atomic():
                    self.garden.members.add(self.bob)
                    self.alice.display_name = "Alice"
                    self.alice.save()
                    raise RuntimeError("roll back")
            except RuntimeError:
                pass
        self.assertEqual(relay.pushes, [])

    def test_a_new_member_or_a_changed_name_pushes_their_names(self):
        with Relay() as relay, self.captureOnCommitCallbacks(execute=True):
            User.objects.create_user(username="carol.test", did="did:plc:carol")
        self.assertEqual(
            relay.names(),
            [("/internal/members/did:plc:carol", {"handle": "carol.test", "name": ""})],
        )

        with Relay() as relay, self.captureOnCommitCallbacks(execute=True):
            self.alice.display_name = "Alice Liddell"
            self.alice.save(update_fields=["display_name"])
            self.bob.username = "robert.test"
            self.bob.save()
        self.assertEqual(
            relay.names(),
            [
                (
                    "/internal/members/did:plc:alice",
                    {"handle": "alice.test", "name": "Alice Liddell"},
                ),
                (
                    "/internal/members/did:plc:bob",
                    {"handle": "robert.test", "name": ""},
                ),
            ],
        )

    def test_a_save_that_changes_no_name_pushes_nothing(self):
        with Relay() as relay, self.captureOnCommitCallbacks(execute=True):
            self.alice.touch_last_seen()
            self.alice.save()
        self.assertEqual(relay.pushes, [])

    def test_a_failed_push_leaves_the_change_standing(self):
        for failure in (500, requests.ConnectionError("down")):
            with self.subTest(failure=failure):
                with Relay(failure), self.captureOnCommitCallbacks(execute=True):
                    self.garden.members.add(self.bob)
                self.assertTrue(self.garden.members.filter(pk=self.bob.pk).exists())
                self.garden.members.remove(self.bob)

    @override_settings(SYNC_RELAY_URL="")
    def test_nothing_is_pushed_without_a_relay(self):
        with Relay() as relay, self.captureOnCommitCallbacks(execute=True):
            self.garden.members.add(self.bob)
        self.assertEqual(relay.pushes, [])

    def test_the_resend_pushes_every_roster_and_name(self):
        Workspace.objects.create(name="Empty")
        with Relay() as relay:
            call_command("sync_relay_rosters", stdout=StringIO())
        self.assertEqual(len(relay.rosters()), 2)
        self.assertIn((self.roster(self.garden), ["did:plc:alice"]), relay.rosters())
        self.assertEqual(
            sorted(url for url, _ in relay.names()),
            ["/internal/members/did:plc:alice", "/internal/members/did:plc:bob"],
        )

    def test_the_resend_fails_when_a_push_does(self):
        with Relay(503), self.assertRaises(CommandError):
            call_command("sync_relay_rosters", stdout=StringIO())

    @override_settings(SYNC_RELAY_URL="")
    def test_the_resend_refuses_without_a_relay(self):
        with self.assertRaises(CommandError):
            call_command("sync_relay_rosters", stdout=StringIO())
