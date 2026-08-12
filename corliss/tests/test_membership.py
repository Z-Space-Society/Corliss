"""The membership push: payload contract, event ordering, and the endpoint.

The ordering tests are the load-bearing ones. Everything else here is input
validation, but ordering is where a plausible-looking implementation silently
re-admits a revoked member.
"""

import json
from datetime import datetime, timezone as dt_timezone

from django.test import TestCase, override_settings
from django.urls import reverse

from corliss import membership
from corliss.models import MembershipCache

DID = "did:plc:ewvi7nxzyoun6zhxrhs64oiz"
ADMIN = "did:plc:hhyrsndukexwr6qucdngcf4r"
TOKEN = "test-push-token"

# Real 13-character atproto TIDs, in ascending order.
TID_1 = "3lqx7qzabc2de"
TID_2 = "3lqx7qzabc2df"
TID_3 = "3lqx7qzabc2dg"


def grant(did=DID, tier="level-2", tid=TID_1, author=ADMIN, at="2026-08-12T18:20:09Z"):
    return {
        "event": "grant",
        "did": did,
        "rkey": f"{did}:{tid}",
        "authorDid": author,
        "record": {"status": "active", "grantedAt": at, "tier": tier},
    }


def revoke(did=DID, tid=TID_2, author=ADMIN, at="2026-08-12T18:25:00Z"):
    return {
        "event": "revoke",
        "did": did,
        "rkey": f"{did}:{tid}",
        "authorDid": author,
        "record": {"revokedAt": at},
    }


class TidTests(TestCase):
    def test_tid_split_on_last_colon(self):
        """DIDs contain colons; the TID is whatever follows the final one."""
        self.assertEqual(membership.tid_of(f"{DID}:{TID_1}"), TID_1)

    def test_tid_ordering_is_lexicographic(self):
        """The base32-sortable alphabet makes string order chronological."""
        self.assertLess(TID_1, TID_2)
        self.assertLess(TID_2, TID_3)

    def test_rkey_without_a_tid_is_refused(self):
        """Refused rather than applied in an order that cannot be trusted."""
        for bad in [DID, f"{DID}:", f"{DID}:short", f"{DID}:NOTBASE32XXXX"]:
            with self.assertRaises(membership.PushError):
                membership.tid_of(bad)


class ParseTests(TestCase):
    def test_valid_grant(self):
        parsed = membership.parse(grant())
        self.assertEqual(parsed["event"], "grant")
        self.assertEqual(parsed["did"], DID)
        self.assertEqual(parsed["tier"], "level-2")
        self.assertEqual(parsed["author_did"], ADMIN)
        self.assertEqual(
            parsed["event_at"],
            datetime(2026, 8, 12, 18, 20, 9, tzinfo=dt_timezone.utc),
        )

    def test_valid_revoke_carries_no_tier(self):
        parsed = membership.parse(revoke())
        self.assertEqual(parsed["event"], "revoke")
        self.assertEqual(parsed["tier"], "")

    def test_grant_without_tier_is_refused(self):
        """A tierless grant is the fail-open case the registry exists to stop."""
        payload = grant()
        del payload["record"]["tier"]
        with self.assertRaises(membership.PushError):
            membership.parse(payload)

    def test_unknown_tier_is_accepted(self):
        """Shape is checked; the vocabulary deliberately is not.

        Validating against a known list here would mean adding a tier upstream
        makes every push 400 while the Lua logs and returns success — admins
        would see approvals that never reach Corliss.
        """
        parsed = membership.parse(grant(tier="level-42"))
        self.assertEqual(parsed["tier"], "level-42")

    def test_rkey_subject_must_match_did(self):
        """An envelope disagreeing with its own rkey is refused, not guessed."""
        payload = grant()
        payload["rkey"] = f"did:plc:someoneelse:{TID_1}"
        with self.assertRaises(membership.PushError):
            membership.parse(payload)

    def test_rejects_bad_input(self):
        cases = {
            "not a dict": [],
            "unknown event": {**grant(), "event": "delete"},
            "bad did": {**grant(), "did": "not-a-did"},
            "missing author": {k: v for k, v in grant().items() if k != "authorDid"},
            "missing record": {k: v for k, v in grant().items() if k != "record"},
            "bad timestamp": {**grant(), "record": {"tier": "level-0", "grantedAt": "nope"}},
        }
        for name, payload in cases.items():
            with self.subTest(name):
                with self.assertRaises(membership.PushError):
                    membership.parse(payload)


class ApplyTests(TestCase):
    def test_grant_creates_the_row(self):
        self.assertTrue(membership.apply_event(membership.parse(grant())))
        row = MembershipCache.objects.get(did=DID)
        self.assertTrue(row.active)
        self.assertEqual(row.tier, "level-2")
        self.assertEqual(row.author_did, ADMIN)

    def test_revoke_deactivates_but_keeps_the_tier(self):
        """Tier is retained for audit; readers gate on `active`."""
        membership.apply_event(membership.parse(grant()))
        membership.apply_event(membership.parse(revoke()))
        row = MembershipCache.objects.get(did=DID)
        self.assertFalse(row.active)
        self.assertEqual(row.tier, "level-2")

    def test_replayed_event_is_a_noop_not_an_error(self):
        """A best-effort push retries; a duplicate must not look like failure."""
        self.assertTrue(membership.apply_event(membership.parse(grant())))
        self.assertFalse(membership.apply_event(membership.parse(grant())))
        self.assertEqual(MembershipCache.objects.filter(did=DID).count(), 1)

    def test_stale_grant_cannot_resurrect_a_revoked_member(self):
        """The whole reason ordering is by TID and not by the timestamps.

        A grant retried after a revocation arrives late but carries the earlier
        TID, so it must lose — even though its `grantedAt` may be seconds apart
        from the revocation and could not break the tie on its own.
        """
        membership.apply_event(membership.parse(grant(tid=TID_1)))
        membership.apply_event(membership.parse(revoke(tid=TID_2)))

        applied = membership.apply_event(membership.parse(grant(tid=TID_1)))

        self.assertFalse(applied)
        self.assertFalse(MembershipCache.objects.get(did=DID).active)

    def test_same_second_events_still_order_correctly(self):
        """Second-resolution timestamps cannot separate these; TIDs can."""
        same = "2026-08-12T18:20:09Z"
        membership.apply_event(membership.parse(grant(tid=TID_1, at=same)))
        membership.apply_event(membership.parse(revoke(tid=TID_2, at=same)))
        self.assertFalse(MembershipCache.objects.get(did=DID).active)

    def test_regrant_after_revoke_reactivates(self):
        membership.apply_event(membership.parse(grant(tid=TID_1)))
        membership.apply_event(membership.parse(revoke(tid=TID_2)))
        membership.apply_event(membership.parse(grant(tid=TID_3, tier="level-5")))
        row = MembershipCache.objects.get(did=DID)
        self.assertTrue(row.active)
        self.assertEqual(row.tier, "level-5")

    def test_is_active_member_fails_closed(self):
        """No cached row is a no, never a default-allow."""
        self.assertFalse(membership.is_active_member(DID))
        membership.apply_event(membership.parse(grant()))
        self.assertTrue(membership.is_active_member(DID))
        membership.apply_event(membership.parse(revoke()))
        self.assertFalse(membership.is_active_member(DID))


@override_settings(MEMBERSHIP_PUSH_TOKEN=TOKEN)
class PushEndpointTests(TestCase):
    def post(self, payload, token=TOKEN):
        headers = {"HTTP_AUTHORIZATION": f"Bearer {token}"} if token else {}
        return self.client.post(
            reverse("membership_push"),
            data=json.dumps(payload),
            content_type="application/json",
            **headers,
        )

    def test_accepts_a_valid_grant(self):
        res = self.post(grant())
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json(), {"ok": True, "applied": True})
        self.assertTrue(MembershipCache.objects.filter(did=DID, active=True).exists())

    def test_replay_returns_200_not_an_error(self):
        """The Lua logs any non-2xx, so a duplicate must not read as failure."""
        self.post(grant())
        res = self.post(grant())
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json(), {"ok": True, "applied": False})

    def test_rejects_a_wrong_token(self):
        res = self.post(grant(), token="wrong")
        self.assertEqual(res.status_code, 401)
        self.assertFalse(MembershipCache.objects.exists())

    def test_rejects_a_missing_token(self):
        res = self.post(grant(), token=None)
        self.assertEqual(res.status_code, 401)

    @override_settings(MEMBERSHIP_PUSH_TOKEN="")
    def test_unconfigured_refuses_everything(self):
        """Blank config must close the endpoint, not open it.

        Comparing an empty expected token against an empty presented one would
        succeed, leaving any deployment that had not configured this wide open.
        """
        for token in [None, "", "anything"]:
            with self.subTest(token=token):
                res = self.post(grant(), token=token)
                self.assertEqual(res.status_code, 503)
        self.assertFalse(MembershipCache.objects.exists())

    def test_rejects_malformed_json(self):
        res = self.client.post(
            reverse("membership_push"),
            data="{not json",
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {TOKEN}",
        )
        self.assertEqual(res.status_code, 400)

    def test_invalid_payload_explains_itself(self):
        """The message is the useful half — it lands in HappyView's script log."""
        payload = grant()
        del payload["record"]["tier"]
        res = self.post(payload)
        self.assertEqual(res.status_code, 400)
        self.assertIn("tier", res.json()["error"])

    def test_get_is_not_allowed(self):
        res = self.client.get(reverse("membership_push"))
        self.assertEqual(res.status_code, 405)
