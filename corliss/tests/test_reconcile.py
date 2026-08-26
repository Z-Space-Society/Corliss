"""Reconciliation: re-deriving the cache from the registry space.

The load-bearing tests here are the ones where a plausible implementation is
quietly wrong rather than broken:

- **Authority is asked at the event's timestamp.** Asking "is this DID an admin
  now" passes every test written with a current admin and de-members everyone a
  departed admin ever approved.
- **Filter before ordering.** Ordering first lets a forged event with a later
  TID suppress the real grant underneath it.
- **A tierless pre-E0 grant that wins is `unresolved`, not skipped.** Skipping
  it reads as a clean run while a real member is absent from the cache — the
  one failure the gate must never be handed.
- **Orphans are the stolen-token signal.** A cache row with no admin-authored
  event behind it is what a leaked push token leaves.
"""

from datetime import datetime, timezone as dt_timezone

from django.test import TestCase

from corliss import membership
from corliss.models import MembershipCache

MEMBER = "did:plc:ewvi7nxzyoun6zhxrhs64oiz"
OTHER = "did:plc:2cxgdrgtsmrbqnjkwyplmp43"
JACOB = "did:plc:hhyrsndukexwr6qucdngcf4r"
SCOTT = "did:plc:tmxbvcho3zysvtadtextctxw"
OUTSIDER = "did:plc:n4mzxx6z4ehnswc7znswtfr2"

# Real 13-character atproto TIDs, in ascending order.
TID_1 = "3lqx7qzabc2de"
TID_2 = "3lqx7qzabc2df"
TID_3 = "3lqx7qzabc2dg"


def grant(did=MEMBER, tier="level-2", tid=TID_1, author=JACOB, at="2026-03-01T00:00:00Z"):
    return {
        "event": "grant",
        "did": did,
        "rkey": f"{did}:{tid}",
        "authorDid": author,
        "record": {"status": "active", "grantedAt": at, "tier": tier},
    }


def tierless_grant(**kwargs):
    """One of the five pre-E0 grants that are permanently in the space.

    `parse` rejects these by design, and they cannot be deleted from an
    append-only log, so every reconciliation has to survive meeting one.
    """
    payload = grant(**kwargs)
    del payload["record"]["tier"]
    return payload


def revoke(did=MEMBER, tid=TID_2, author=JACOB, at="2026-03-02T00:00:00Z"):
    return {
        "event": "revoke",
        "did": did,
        "rkey": f"{did}:{tid}",
        "authorDid": author,
        "record": {"revokedAt": at},
    }


def entry(did, added="2026-01-01T00:00:00Z", removed=None):
    out = {"did": did, "addedAt": added}
    if removed is not None:
        out["removedAt"] = removed
    return out


def roster(*admins):
    return membership.Roster.from_record({"admins": list(admins)})


def cache_row(did=MEMBER, active=True, tier="level-2", tid=TID_1, author=JACOB):
    return MembershipCache.objects.create(
        did=did,
        active=active,
        tier=tier,
        last_rkey=f"{did}:{tid}",
        last_event_at=datetime(2026, 3, 1, tzinfo=dt_timezone.utc),
        author_did=author,
    )


class AuthorityTests(TestCase):
    """Whose grants count, asked at the moment they were written."""

    def test_a_departed_admins_past_grants_still_count(self):
        """Removing an admin ends their authority forward, not backward.

        The other reading makes membership a function of the roster's current
        state: remove one admin and everyone they ever approved silently loses
        access, with nothing in the event log to show for it.
        """
        report = membership.reconcile(
            [grant(author=SCOTT, at="2026-03-01T00:00:00Z")],
            roster(entry(SCOTT, removed="2026-06-01T00:00:00Z")),
        )

        self.assertEqual(report.applied, [MEMBER])
        self.assertTrue(report.is_complete)
        self.assertTrue(MembershipCache.objects.get(did=MEMBER).active)

    def test_a_grant_written_after_removal_does_not_count(self):
        """The same admin, the same member, one day past their term."""
        report = membership.reconcile(
            [grant(author=SCOTT, at="2026-06-02T00:00:00Z")],
            roster(entry(SCOTT, removed="2026-06-01T00:00:00Z")),
        )

        self.assertEqual(report.applied, [])
        self.assertFalse(MembershipCache.objects.filter(did=MEMBER).exists())

    def test_a_re_added_admin_holds_two_separate_terms(self):
        """Both terms confer authority; the gap between them does not.

        A DID with more than one entry is why every question is asked of all of
        them — matching on the first entry found gets this wrong in whichever
        direction the roster happens to be ordered.
        """
        two_terms = roster(
            entry(SCOTT, added="2026-01-01T00:00:00Z", removed="2026-02-01T00:00:00Z"),
            entry(SCOTT, added="2026-05-01T00:00:00Z"),
        )

        first_term = membership.reconcile(
            [grant(author=SCOTT, at="2026-01-15T00:00:00Z")], two_terms
        )
        self.assertEqual(first_term.applied, [MEMBER])

        MembershipCache.objects.all().delete()
        second_term = membership.reconcile(
            [grant(author=SCOTT, at="2026-05-15T00:00:00Z")], two_terms
        )
        self.assertEqual(second_term.applied, [MEMBER])

        MembershipCache.objects.all().delete()
        in_the_gap = membership.reconcile(
            [grant(author=SCOTT, at="2026-03-15T00:00:00Z")], two_terms
        )
        self.assertEqual(in_the_gap.applied, [])

    def test_an_event_from_a_did_that_was_never_an_admin_is_discarded(self):
        report = membership.reconcile([grant(author=OUTSIDER)], roster(entry(JACOB)))

        self.assertEqual(report.applied, [])
        self.assertEqual(report.unresolved, [])
        self.assertFalse(MembershipCache.objects.filter(did=MEMBER).exists())

    def test_a_forged_event_cannot_suppress_the_real_grant_beneath_it(self):
        """Why authority is filtered *before* events are ordered.

        The forgery carries the later TID, so ordering first would elect it,
        and discarding it afterwards would leave the member with no winning
        event — a real grant erased by a record anyone could write.
        """
        report = membership.reconcile(
            [
                grant(tid=TID_1, author=JACOB, tier="level-2"),
                revoke(tid=TID_3, author=OUTSIDER),
            ],
            roster(entry(JACOB)),
        )

        self.assertEqual(report.applied, [MEMBER])
        row = MembershipCache.objects.get(did=MEMBER)
        self.assertTrue(row.active)
        self.assertEqual(row.tier, "level-2")

    def test_a_malformed_roster_refuses_the_whole_run(self):
        """An admin we cannot parse is authority we cannot evaluate.

        Running anyway would discard their grants as unauthorised and report a
        clean run while doing it.
        """
        half_understood = membership.Roster.from_record(
            {"admins": [entry(JACOB), {"did": SCOTT, "addedAt": "not-a-date"}]}
        )

        with self.assertRaises(membership.ReconcileError):
            membership.reconcile([grant()], half_understood)


class OrderingTests(TestCase):
    """Latest-event-wins, by TID, across both collections."""

    def test_a_stale_grant_replayed_after_a_revocation_stays_revoked(self):
        """The reason ordering is by TID and never by the timestamps.

        The grant is handed to reconcile *after* the revocation and carries a
        later `grantedAt`, but an earlier TID. Ordering by either timestamp —
        or by arrival — re-admits a revoked member.
        """
        report = membership.reconcile(
            [
                revoke(tid=TID_2, at="2026-03-02T00:00:00Z"),
                grant(tid=TID_1, at="2026-03-03T00:00:00Z"),
            ],
            roster(entry(JACOB)),
        )

        self.assertEqual(report.applied, [MEMBER])
        self.assertFalse(MembershipCache.objects.get(did=MEMBER).active)

    def test_a_regrant_after_a_revocation_wins(self):
        membership.reconcile(
            [grant(tid=TID_1), revoke(tid=TID_2), grant(tid=TID_3, tier="level-5")],
            roster(entry(JACOB)),
        )

        row = MembershipCache.objects.get(did=MEMBER)
        self.assertTrue(row.active)
        self.assertEqual(row.tier, "level-5")

    def test_an_unorderable_rkey_is_unresolved_not_guessed(self):
        broken = grant()
        broken["rkey"] = f"{MEMBER}:not-a-tid"

        report = membership.reconcile([broken], roster(entry(JACOB)))

        self.assertEqual(len(report.unresolved), 1)
        self.assertEqual(report.unresolved[0]["did"], MEMBER)
        self.assertFalse(report.is_complete)

    def test_a_second_member_is_resolved_independently(self):
        report = membership.reconcile(
            [grant(did=MEMBER, tid=TID_1), grant(did=OTHER, tid=TID_1, tier="level-0")],
            roster(entry(JACOB)),
        )

        self.assertEqual(sorted(report.applied), sorted([MEMBER, OTHER]))
        self.assertEqual(MembershipCache.objects.get(did=OTHER).tier, "level-0")


class UnresolvedTests(TestCase):
    """The tierless pre-E0 grants, and why they must not be skipped."""

    def test_a_winning_tierless_grant_is_unresolved(self):
        """Reported, never repaired. Inventing a tier hands out an entitlement
        the registry never granted; skipping it reports a clean run while a
        real member is missing from the cache."""
        report = membership.reconcile([tierless_grant()], roster(entry(JACOB)))

        self.assertEqual(report.applied, [])
        self.assertEqual(report.unchanged, [])
        self.assertEqual(len(report.unresolved), 1)
        self.assertEqual(report.unresolved[0]["did"], MEMBER)
        self.assertIn("tier", report.unresolved[0]["error"])
        self.assertFalse(report.is_complete)
        self.assertFalse(MembershipCache.objects.filter(did=MEMBER).exists())

    def test_a_losing_tierless_grant_never_reaches_the_parser(self):
        """Parse the winner, not the log.

        The tierless grant is real history and stays in the space forever. As
        long as something newer supersedes it, it must cost nothing — replaying
        every event blindly would fail on a record that can never be removed.
        """
        report = membership.reconcile(
            [tierless_grant(tid=TID_1), grant(tid=TID_2, tier="level-3")],
            roster(entry(JACOB)),
        )

        self.assertEqual(report.applied, [MEMBER])
        self.assertEqual(report.unresolved, [])
        self.assertTrue(report.is_complete)
        self.assertEqual(MembershipCache.objects.get(did=MEMBER).tier, "level-3")

    def test_an_unresolved_did_is_not_also_an_orphan(self):
        """Its row is stale, not unaccounted for — two different repairs."""
        cache_row(did=MEMBER)

        report = membership.reconcile([tierless_grant()], roster(entry(JACOB)))

        self.assertEqual(len(report.unresolved), 1)
        self.assertEqual(report.orphans, [])


class OrphanTests(TestCase):
    """Cache rows the registry does not account for."""

    def test_a_row_with_no_registry_event_is_an_orphan(self):
        cache_row(did=OTHER, tier="level-9")

        report = membership.reconcile([grant(did=MEMBER)], roster(entry(JACOB)))

        self.assertEqual(len(report.orphans), 1)
        self.assertEqual(report.orphans[0]["did"], OTHER)
        self.assertEqual(report.orphans[0]["tier"], "level-9")
        self.assertFalse(report.is_complete)

    def test_a_row_whose_author_was_never_an_admin_is_an_orphan(self):
        """What a leaked push token actually leaves behind.

        The token can name a real admin in the envelope, but it cannot put the
        matching record in the space — so the row survives with no event that
        an admin ever authored.
        """
        cache_row(did=MEMBER, author=OUTSIDER)

        report = membership.reconcile([grant(author=OUTSIDER)], roster(entry(JACOB)))

        self.assertEqual(len(report.orphans), 1)
        self.assertEqual(report.orphans[0]["did"], MEMBER)
        self.assertFalse(report.is_complete)

    def test_orphans_are_reported_never_pruned(self):
        cache_row(did=OTHER)

        membership.reconcile([], roster(entry(JACOB)))

        self.assertTrue(MembershipCache.objects.filter(did=OTHER).exists())

    def test_a_revoked_row_backed_by_a_real_revocation_is_not_an_orphan(self):
        report = membership.reconcile(
            [grant(tid=TID_1), revoke(tid=TID_2)], roster(entry(JACOB))
        )

        self.assertEqual(report.orphans, [])
        self.assertTrue(report.is_complete)

    def test_a_declined_application_survives_a_reconcile(self):
        """A decline writes a revocation with **no grant before it**, which is
        an unusual shape for this log and the one that would quietly undo the
        decision if reconcile only accounted for grants.

        It does not: the revocation is an admin-authored event, so the DID is
        accounted for rather than orphaned, and it is that DID's winning event,
        so the row comes back revoked. That matters beyond tidiness — the
        application queue reads "already decided" off this row, so a rebuild
        that dropped it would put every declined applicant back in the queue as
        though nobody had ever looked at them.
        """
        report = membership.reconcile([revoke(tid=TID_1)], roster(entry(JACOB)))

        self.assertEqual(report.applied, [MEMBER])
        self.assertEqual(report.orphans, [])
        self.assertEqual(report.unresolved, [])
        self.assertTrue(report.is_complete)

        row = MembershipCache.objects.get(did=MEMBER)
        self.assertFalse(row.active)
        # No tier was ever granted, and reconcile does not invent one.
        self.assertEqual(row.tier, "")


class ReportTests(TestCase):
    """What the report claims, and what a caller may conclude from it."""

    def test_a_second_run_over_the_same_events_is_all_unchanged(self):
        """The healthy steady state, and the shape the gate's proof wants."""
        events = [grant(tid=TID_1), grant(did=OTHER, tid=TID_1, tier="level-0")]
        admins = roster(entry(JACOB))

        first = membership.reconcile(events, admins)
        second = membership.reconcile(events, admins)

        self.assertEqual(len(first.applied), 2)
        self.assertEqual(second.applied, [])
        self.assertEqual(sorted(second.unchanged), sorted([MEMBER, OTHER]))
        self.assertTrue(second.is_complete)

    def test_an_empty_registry_and_an_empty_cache_is_complete(self):
        """Nothing to do is a complete run, not a suspicious one."""
        report = membership.reconcile([], roster(entry(JACOB)))

        self.assertTrue(report.is_complete)
        self.assertEqual(repr(report).count("=0"), 4)

    def test_dry_run_reports_the_same_answer_and_writes_nothing(self):
        cache_row(did=OTHER)

        report = membership.reconcile(
            [grant(did=MEMBER)], roster(entry(JACOB)), dry_run=True
        )

        self.assertEqual(report.applied, [MEMBER])
        self.assertEqual(len(report.orphans), 1)
        self.assertFalse(MembershipCache.objects.filter(did=MEMBER).exists())

    def test_dry_run_distinguishes_would_change_from_already_current(self):
        """The dry-run guard has to match `apply_event`'s, not approximate it."""
        events = [grant(tid=TID_1)]
        admins = roster(entry(JACOB))
        membership.reconcile(events, admins)

        report = membership.reconcile(events, admins, dry_run=True)

        self.assertEqual(report.applied, [])
        self.assertEqual(report.unchanged, [MEMBER])
