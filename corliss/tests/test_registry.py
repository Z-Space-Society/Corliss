"""`MembershipRegistry` — reading membership back out of the registry.

The load-bearing test is the envelope adapter. The registry returns
`{rkey, authorDid, record}` with no `did` and no `event`; the push sends both.
If this adapter fills them in differently from the way the push does, the two
transports become two shapes for one lexicon and the shared parser stops being
shared — which is the whole thing the envelope was designed to avoid.

Nothing here touches the network: `requests.post` is mocked at the boundary.
"""

import json
from datetime import datetime
from io import StringIO
from unittest.mock import patch

import requests
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase, override_settings

from corliss import membership
from corliss.models import MembershipCache

URL = "https://registry.example"
CLIENT_KEY = "hvc_testkey"
TOKEN = "test-reconcile-token"

MEMBER = "did:plc:ewvi7nxzyoun6zhxrhs64oiz"
OTHER = "did:plc:2cxgdrgtsmrbqnjkwyplmp43"
ADMIN = "did:plc:hhyrsndukexwr6qucdngcf4r"

TID_1 = "3lqx7qzabc2de"
TID_2 = "3lqx7qzabc2df"

REGISTRY_SETTINGS = {
    "MEMBERSHIP_REGISTRY_URL": URL,
    "MEMBERSHIP_REGISTRY_CLIENT_KEY": CLIENT_KEY,
    "MEMBERSHIP_REGISTRY_TOKEN": TOKEN,
}


def space_grant(did=MEMBER, tid=TID_1, tier="level-2", author=ADMIN,
                at="2026-03-01T00:00:00Z"):
    """A grant exactly as `atproto.spaces.query` hands it back — no `did`."""
    return {
        "rkey": f"{did}:{tid}",
        "authorDid": author,
        "record": {"status": "active", "grantedAt": at, "tier": tier},
    }


def space_revocation(did=MEMBER, tid=TID_2, author=ADMIN,
                     at="2026-03-02T00:00:00Z"):
    return {
        "rkey": f"{did}:{tid}",
        "authorDid": author,
        "record": {"revokedAt": at},
    }


def payload(grants=(), revocations=()):
    return {"grants": list(grants), "revocations": list(revocations)}


class FakeResponse:
    def __init__(self, body, status_code=200):
        self._body = body
        self.status_code = status_code
        self.text = body if isinstance(body, str) else json.dumps(body)

    def json(self):
        if isinstance(self._body, str):
            raise ValueError("not json")
        return self._body


def registry():
    return membership.MembershipRegistry(URL, CLIENT_KEY, TOKEN)


def roster(*dids, added="2026-01-01T00:00:00Z"):
    return membership.Roster(
        [
            membership.AdminEntry(
                did, datetime.fromisoformat(added.replace("Z", "+00:00"))
            )
            for did in dids
        ]
    )


class DidOfTests(TestCase):
    """`did_of`, the half of the rkey the registry does not send as a field."""

    def test_splits_on_the_last_colon_like_tid_of(self):
        rkey = f"{MEMBER}:{TID_1}"
        self.assertEqual(membership.did_of(rkey), MEMBER)
        self.assertEqual(membership.tid_of(rkey), TID_1)

    def test_round_trips_the_whole_rkey(self):
        rkey = f"{MEMBER}:{TID_1}"
        self.assertEqual(
            f"{membership.did_of(rkey)}:{membership.tid_of(rkey)}", rkey
        )

    def test_an_rkey_with_no_subject_is_refused(self):
        for bad in [TID_1, f":{TID_1}"]:
            with self.subTest(bad):
                with self.assertRaises(membership.PushError):
                    membership.did_of(bad)


class EnvelopeTests(TestCase):
    """The adapter: space record in, push envelope out."""

    def test_a_grant_becomes_the_push_envelope_the_parser_expects(self):
        envelope = membership.MembershipRegistry._to_envelope(
            space_grant(), membership.GRANT
        )

        self.assertEqual(envelope["event"], "grant")
        self.assertEqual(envelope["did"], MEMBER)
        self.assertEqual(envelope["rkey"], f"{MEMBER}:{TID_1}")
        self.assertEqual(envelope["authorDid"], ADMIN)
        # And it survives the real parser — the point of filling the shape in.
        parsed = membership.parse(envelope)
        self.assertEqual(parsed["tier"], "level-2")

    def test_a_revocation_is_labelled_by_the_array_it_arrived_in(self):
        """`event` is not in the record; it is which collection it came from."""
        envelope = membership.MembershipRegistry._to_envelope(
            space_revocation(), membership.REVOKE
        )

        self.assertEqual(envelope["event"], "revoke")
        self.assertEqual(membership.parse(envelope)["tier"], "")

    def test_a_tierless_pre_e0_grant_is_carried_through_not_repaired(self):
        """It must reach `reconcile` intact so it can be reported unresolved."""
        entry = space_grant()
        del entry["record"]["tier"]

        envelope = membership.MembershipRegistry._to_envelope(
            entry, membership.GRANT
        )

        self.assertEqual(envelope["did"], MEMBER)
        self.assertNotIn("tier", envelope["record"])
        with self.assertRaises(membership.PushError):
            membership.parse(envelope)

    def test_an_unreadable_rkey_leaves_the_did_absent_rather_than_invented(self):
        envelope = membership.MembershipRegistry._to_envelope(
            {"rkey": "nonsense", "authorDid": ADMIN, "record": {}},
            membership.GRANT,
        )

        self.assertNotIn("did", envelope)


@override_settings(**REGISTRY_SETTINGS)
class FetchEventsTests(TestCase):
    def test_posts_the_token_in_the_body_with_the_client_key_header(self):
        """Body, not query string: a token in a URL lands in access logs."""
        with patch.object(
            requests, "post", return_value=FakeResponse(payload())
        ) as post:
            registry().fetch_events()

        args, kwargs = post.call_args
        self.assertTrue(args[0].endswith(f"/xrpc/{membership.SYNC_MEMBERS_NSID}"))
        self.assertEqual(kwargs["json"], {"token": TOKEN})
        self.assertEqual(kwargs["headers"]["x-client-key"], CLIENT_KEY)

    def test_both_collections_are_returned_as_one_ordered_stream(self):
        body = payload([space_grant()], [space_revocation()])

        with patch.object(requests, "post", return_value=FakeResponse(body)):
            events = registry().fetch_events()

        self.assertEqual([e["event"] for e in events], ["grant", "revoke"])
        self.assertEqual({e["did"] for e in events}, {MEMBER})

    def test_an_unconfigured_registry_refuses_before_any_request(self):
        with patch.object(requests, "post") as post:
            with self.assertRaises(membership.RegistryError):
                membership.MembershipRegistry("", "", "").fetch_events()
        post.assert_not_called()

    def test_a_rejected_token_surfaces_the_registrys_own_message(self):
        """The Lua's error text is the half an operator needs.

        Shaped like the real thing: a Lua `error()` comes back as HTTP **500**
        with `script_error`, not a 4xx — confirmed against production. Which is
        why the check here is `!= 200` rather than a status allowlist.
        """
        body = {
            "error": "script_error",
            "errorType": "runtime",
            "message": (
                "runtime error: src/lua/execute.rs:954:9: forbidden: invalid "
                "service token\nstack traceback:\n\t[C]: in function 'error'"
            ),
            "method": membership.SYNC_MEMBERS_NSID,
        }
        with patch.object(requests, "post", return_value=FakeResponse(body, 500)):
            with self.assertRaises(membership.RegistryError) as caught:
                registry().fetch_events()

        self.assertIn("500", str(caught.exception))
        self.assertIn("invalid service token", str(caught.exception))

    def test_the_client_key_is_sent_when_set_and_omitted_when_not(self):
        """Not required, because HappyView dispatches without it.

        Verified against production: a bare XRPC call with no session and no
        client key still reaches the Lua's `handle()`. Requiring the key would
        tie reconciliation — the recovery path — to the console having been
        configured, which is the coupling this must not have.
        """
        with patch.object(
            requests, "post", return_value=FakeResponse(payload())
        ) as post:
            registry().fetch_events()
        self.assertEqual(post.call_args.kwargs["headers"]["x-client-key"], CLIENT_KEY)

        with patch.object(
            requests, "post", return_value=FakeResponse(payload())
        ) as post:
            membership.MembershipRegistry(URL, "", TOKEN).fetch_events()
        self.assertEqual(post.call_args.kwargs["headers"], {})

    def test_transport_failure_raises_registry_error_not_the_raw_exception(self):
        with patch.object(
            requests, "post", side_effect=requests.ConnectionError("refused")
        ):
            with self.assertRaises(membership.RegistryError):
                registry().fetch_events()

    def test_a_response_missing_a_collection_is_refused(self):
        """Half an answer must not read as "no revocations"."""
        with patch.object(
            requests, "post", return_value=FakeResponse({"grants": []})
        ):
            with self.assertRaises(membership.RegistryError):
                registry().fetch_events()

    def test_a_non_json_response_is_refused(self):
        with patch.object(
            requests, "post", return_value=FakeResponse("<html>gateway</html>")
        ):
            with self.assertRaises(membership.RegistryError):
                registry().fetch_events()


@override_settings(**REGISTRY_SETTINGS)
class ReconcileTests(TestCase):
    """Fetch plus resolve, the one path every trigger shares."""

    def test_end_to_end_fills_the_cache_from_the_space(self):
        body = payload(
            [space_grant(did=MEMBER), space_grant(did=OTHER, tier="level-0")]
        )

        with patch.object(requests, "post", return_value=FakeResponse(body)):
            with patch.object(membership, "fetch_roster", return_value=roster(ADMIN)):
                report = membership.MembershipRegistry.from_settings().reconcile()

        self.assertTrue(report.is_complete)
        self.assertEqual(sorted(report.applied), sorted([MEMBER, OTHER]))
        self.assertEqual(MembershipCache.objects.get(did=OTHER).tier, "level-0")

    def test_a_revocation_beats_an_earlier_grant_across_the_two_arrays(self):
        """Ordering is by TID across both collections, not per-collection."""
        body = payload([space_grant(tid=TID_1)], [space_revocation(tid=TID_2)])

        with patch.object(requests, "post", return_value=FakeResponse(body)):
            with patch.object(membership, "fetch_roster", return_value=roster(ADMIN)):
                membership.MembershipRegistry.from_settings().reconcile()

        self.assertFalse(MembershipCache.objects.get(did=MEMBER).active)

    def test_dry_run_reports_without_writing(self):
        body = payload([space_grant()])

        with patch.object(requests, "post", return_value=FakeResponse(body)):
            with patch.object(membership, "fetch_roster", return_value=roster(ADMIN)):
                report = membership.MembershipRegistry.from_settings().reconcile(
                    dry_run=True
                )

        self.assertEqual(report.applied, [MEMBER])
        self.assertFalse(MembershipCache.objects.exists())

    def test_a_roster_failure_raises_rather_than_discarding_every_event(self):
        """`fetch_roster` is called directly *because* it raises.

        Going through `is_cluster_admin` would fail closed to "nobody is an
        admin", and every event would be dropped as unauthorised while the
        report claimed a clean run.
        """
        body = payload([space_grant()])

        with patch.object(requests, "post", return_value=FakeResponse(body)):
            with patch.object(
                membership,
                "fetch_roster",
                side_effect=membership.RosterError("PDS down"),
            ):
                with self.assertRaises(membership.RosterError):
                    membership.MembershipRegistry.from_settings().reconcile()

        self.assertFalse(MembershipCache.objects.exists())


@override_settings(**REGISTRY_SETTINGS)
class CommandTests(TestCase):
    """`manage.py reconcile_membership`.

    The exit status is the contract. A scheduled run that reported success over
    an incomplete cache would be worse than not running at all, so "incomplete"
    has to be as loud as "could not run".
    """

    def _run(self, report=None, **opts):
        out = StringIO()
        with patch.object(
            membership.MembershipRegistry,
            "reconcile",
            return_value=report if report is not None else membership.ReconcileReport(),
        ):
            call_command("reconcile_membership", stdout=out, **opts)
        return out.getvalue()

    def test_a_complete_run_succeeds(self):
        report = membership.ReconcileReport()
        report.unchanged.append(MEMBER)

        output = self._run(report)

        self.assertIn("complete", output)

    def test_an_incomplete_run_raises_rather_than_reporting_success(self):
        report = membership.ReconcileReport()
        report.orphans.append(
            {"did": MEMBER, "active": True, "tier": "level-2", "author_did": ADMIN}
        )

        with self.assertRaises(CommandError) as caught:
            self._run(report)

        self.assertIn("orphans", str(caught.exception))

    def test_unresolved_alone_is_enough_to_fail(self):
        report = membership.ReconcileReport()
        report.unresolved.append({"did": MEMBER, "rkey": "r", "error": "no tier"})

        with self.assertRaises(CommandError):
            self._run(report)

    def test_a_registry_failure_is_a_command_error(self):
        with patch.object(
            membership.MembershipRegistry,
            "reconcile",
            side_effect=membership.RegistryError("unreachable"),
        ):
            with self.assertRaises(CommandError):
                call_command("reconcile_membership", stdout=StringIO())

    def test_dry_run_is_passed_through_and_announced(self):
        out = StringIO()
        with patch.object(
            membership.MembershipRegistry,
            "reconcile",
            return_value=membership.ReconcileReport(),
        ) as run:
            call_command("reconcile_membership", "--dry-run", stdout=out)

        run.assert_called_once_with(dry_run=True)
        self.assertIn("dry run", out.getvalue())


class ConfigurationTests(TestCase):
    def test_is_configured_needs_the_url_and_token_but_not_the_client_key(self):
        self.assertTrue(
            membership.MembershipRegistry(URL, CLIENT_KEY, TOKEN).is_configured
        )
        # The recovery case: a cluster rebuilt before `zai-set-console
        # client_key` has been run must still be able to reconcile.
        self.assertTrue(membership.MembershipRegistry(URL, "", TOKEN).is_configured)

        for args in [("", CLIENT_KEY, TOKEN), (URL, CLIENT_KEY, "")]:
            with self.subTest(args):
                self.assertFalse(membership.MembershipRegistry(*args).is_configured)

    def test_a_trailing_slash_on_the_url_does_not_double_up(self):
        self.assertEqual(
            membership.MembershipRegistry(f"{URL}/", CLIENT_KEY, TOKEN).url, URL
        )

    @override_settings(**REGISTRY_SETTINGS)
    def test_from_settings_reads_all_three(self):
        built = membership.MembershipRegistry.from_settings()
        self.assertEqual((built.url, built.client_key, built.token),
                         (URL, CLIENT_KEY, TOKEN))
