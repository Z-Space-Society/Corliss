"""The admin roster: parsing, the point-in-time authorship rule, caching, and
the handle resolution the console displays instead of DIDs.

The load-bearing test here is `was_admin_at`. Reading it as "is an admin now"
is the plausible-looking implementation that silently de-members everyone a
departed admin ever approved, so the departed-admin and re-added cases are the
ones worth breaking on.
"""

from datetime import datetime, timezone as dt_timezone
from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase, override_settings

from corliss import atproto, membership

SERVICE_DID = "did:plc:n4mzxx6z4ehnswc7znswtfr2"
JACOB = "did:plc:hhyrsndukexwr6qucdngcf4r"
SCOTT = "did:plc:tmxbvcho3zysvtadtextctxw"
BORIS = "did:plc:2cxgdrgtsmrbqnjkwyplmp43"
OUTSIDER = "did:plc:ewvi7nxzyoun6zhxrhs64oiz"


def at(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def record(*admins, updated="2026-08-12T00:00:00Z"):
    return {"admins": list(admins), "updatedAt": updated}


def entry(did, added="2026-01-01T00:00:00Z", removed=None):
    out = {"did": did, "addedAt": added}
    if removed is not None:
        out["removedAt"] = removed
    return out


class RosterParsingTests(TestCase):
    def test_parses_current_and_departed_entries(self):
        roster = membership.Roster.from_record(
            record(
                entry(JACOB),
                entry(SCOTT, removed="2026-06-01T00:00:00Z"),
            )
        )
        self.assertEqual(len(roster), 2)
        self.assertEqual(roster.current_admins, frozenset({JACOB}))
        self.assertEqual(roster.ever_admins, frozenset({JACOB, SCOTT}))
        self.assertEqual(roster.malformed, [])

    def test_is_current_admin(self):
        roster = membership.Roster.from_record(
            record(entry(JACOB), entry(SCOTT, removed="2026-06-01T00:00:00Z"))
        )
        self.assertTrue(roster.is_current_admin(JACOB))
        self.assertFalse(roster.is_current_admin(SCOTT))
        self.assertFalse(roster.is_current_admin(OUTSIDER))

    def test_empty_roster_confers_nothing(self):
        roster = membership.Roster.from_record(record())
        self.assertEqual(len(roster), 0)
        self.assertFalse(roster.is_current_admin(JACOB))

    def test_rejects_a_record_that_is_not_a_roster(self):
        with self.assertRaises(membership.RosterError):
            membership.Roster.from_record({"updatedAt": "2026-08-12T00:00:00Z"})
        with self.assertRaises(membership.RosterError):
            membership.Roster.from_record("not an object")

    # An entry we cannot parse is an admin whose authority cannot be
    # evaluated. Collecting them means reconciliation can refuse to run rather
    # than quietly discarding that admin's grants as unauthored.
    def test_collects_malformed_entries_instead_of_dropping_them(self):
        roster = membership.Roster.from_record(
            record(
                entry(JACOB),
                {"did": "not-a-did", "addedAt": "2026-01-01T00:00:00Z"},
                {"did": SCOTT, "addedAt": "whenever"},
                {"did": BORIS},  # addedAt is required by the lexicon
                "a string, somehow",
            )
        )
        self.assertEqual(roster.current_admins, frozenset({JACOB}))
        self.assertEqual(len(roster.malformed), 4)
        # A malformed entry never reads as current — the entry is unusable,
        # which is not the same as an admin in good standing.
        self.assertFalse(roster.is_current_admin(SCOTT))
        self.assertFalse(roster.is_current_admin(BORIS))

    def test_an_unparseable_removed_at_makes_the_entry_malformed(self):
        roster = membership.Roster.from_record(
            record({"did": JACOB, "addedAt": "2026-01-01T00:00:00Z",
                    "removedAt": "sometime last year"})
        )
        self.assertFalse(roster.is_current_admin(JACOB))
        self.assertEqual(roster.malformed, [JACOB])


class WasAdminAtTests(TestCase):
    """The point-in-time rule: on or after addedAt, before any removedAt."""

    def setUp(self):
        self.roster = membership.Roster.from_record(
            record(
                entry(JACOB, added="2026-01-01T00:00:00Z"),
                entry(
                    SCOTT,
                    added="2026-01-01T00:00:00Z",
                    removed="2026-06-01T00:00:00Z",
                ),
            )
        )

    def test_false_before_they_were_added(self):
        self.assertFalse(
            self.roster.was_admin_at(JACOB, at("2025-12-31T23:59:59Z"))
        )

    def test_true_at_the_moment_they_were_added(self):
        self.assertTrue(self.roster.was_admin_at(JACOB, at("2026-01-01T00:00:00Z")))

    def test_true_while_current(self):
        self.assertTrue(self.roster.was_admin_at(JACOB, at("2026-08-12T00:00:00Z")))

    # The whole point. A grant Scott wrote in March is still a real grant in
    # August, even though he left in June.
    def test_a_departed_admin_was_still_an_admin_before_they_left(self):
        self.assertTrue(self.roster.was_admin_at(SCOTT, at("2026-03-01T00:00:00Z")))
        self.assertFalse(self.roster.is_current_admin(SCOTT))

    def test_false_after_they_were_removed(self):
        self.assertFalse(self.roster.was_admin_at(SCOTT, at("2026-07-01T00:00:00Z")))

    def test_false_at_the_moment_of_removal(self):
        self.assertFalse(self.roster.was_admin_at(SCOTT, at("2026-06-01T00:00:00Z")))

    def test_false_for_someone_never_on_the_roster(self):
        self.assertFalse(
            self.roster.was_admin_at(OUTSIDER, at("2026-03-01T00:00:00Z"))
        )

    # A DID can hold more than one term. Asking only the first entry found
    # would answer the wrong term's question.
    def test_a_re_added_admin_has_a_gap_between_terms(self):
        roster = membership.Roster.from_record(
            record(
                entry(
                    SCOTT,
                    added="2026-01-01T00:00:00Z",
                    removed="2026-03-01T00:00:00Z",
                ),
                entry(SCOTT, added="2026-07-01T00:00:00Z"),
            )
        )
        self.assertTrue(roster.was_admin_at(SCOTT, at("2026-02-01T00:00:00Z")))
        self.assertFalse(roster.was_admin_at(SCOTT, at("2026-05-01T00:00:00Z")))
        self.assertTrue(roster.was_admin_at(SCOTT, at("2026-08-01T00:00:00Z")))
        self.assertTrue(roster.is_current_admin(SCOTT))


@override_settings(SCN_SERVICE_DID=SERVICE_DID)
class FetchRosterTests(TestCase):
    def setUp(self):
        cache.clear()

    def test_fetches_from_the_service_dids_repo(self):
        with patch.object(
            atproto, "find_record", return_value=record(entry(JACOB))
        ) as get:
            roster = membership.fetch_roster()
        get.assert_called_once_with(
            SERVICE_DID, membership.ROSTER_COLLECTION, membership.ROSTER_RKEY
        )
        self.assertTrue(roster.is_current_admin(JACOB))

    def test_second_call_is_served_from_cache(self):
        with patch.object(
            atproto, "find_record", return_value=record(entry(JACOB))
        ) as get:
            membership.fetch_roster()
            membership.fetch_roster()
        self.assertEqual(get.call_count, 1)

    def test_refresh_bypasses_the_cache(self):
        with patch.object(
            atproto, "find_record", return_value=record(entry(JACOB))
        ) as get:
            membership.fetch_roster()
            membership.fetch_roster(refresh=True)
        self.assertEqual(get.call_count, 2)

    def test_unreachable_repo_raises(self):
        with patch.object(
            atproto, "find_record", side_effect=atproto.OAuthError("pds down")
        ):
            with self.assertRaises(membership.RosterError):
                membership.fetch_roster()

    # Without a negative cache an unreachable PDS costs a full request timeout
    # on every login, since ELEVATE is asked on each one.
    def test_a_failure_is_cached_briefly_rather_than_retried_every_call(self):
        with patch.object(
            atproto, "find_record", side_effect=atproto.OAuthError("pds down")
        ) as get:
            for _ in range(3):
                with self.assertRaises(membership.RosterError):
                    membership.fetch_roster()
        self.assertEqual(get.call_count, 1)

    def test_a_success_clears_a_cached_failure(self):
        with patch.object(
            atproto, "find_record", side_effect=atproto.OAuthError("pds down")
        ):
            with self.assertRaises(membership.RosterError):
                membership.fetch_roster()
        with patch.object(
            atproto, "find_record", return_value=record(entry(JACOB))
        ):
            self.assertTrue(membership.fetch_roster(refresh=True).is_current_admin(JACOB))
        # And the cleared failure means no further network call is needed.
        with patch.object(atproto, "find_record", side_effect=AssertionError):
            self.assertTrue(membership.fetch_roster().is_current_admin(JACOB))


class IsClusterAdminTests(TestCase):
    def setUp(self):
        cache.clear()

    @override_settings(SCN_SERVICE_DID=SERVICE_DID)
    def test_true_for_a_current_admin(self):
        with patch.object(atproto, "find_record", return_value=record(entry(JACOB))):
            self.assertTrue(membership.is_cluster_admin(JACOB))
            self.assertFalse(membership.is_cluster_admin(OUTSIDER))

    # An unreachable roster must not hand out admin, and must not 500 a login.
    @override_settings(SCN_SERVICE_DID=SERVICE_DID)
    def test_false_when_the_roster_cannot_be_fetched(self):
        with patch.object(
            atproto, "find_record", side_effect=atproto.OAuthError("pds down")
        ):
            self.assertFalse(membership.is_cluster_admin(JACOB))

    # Unconfigured is a different failure from unreachable, and fetch_roster
    # says so — but the request path still just answers "no".
    @override_settings(SCN_SERVICE_DID="")
    def test_false_and_explicit_when_unconfigured(self):
        self.assertFalse(membership.is_cluster_admin(JACOB))
        with self.assertRaisesMessage(
            membership.RosterError, "SCN_SERVICE_DID is not configured"
        ):
            membership.fetch_roster()

    @override_settings(SCN_SERVICE_DID=SERVICE_DID)
    def test_false_for_an_empty_did_without_fetching(self):
        with patch.object(atproto, "find_record", side_effect=AssertionError):
            self.assertFalse(membership.is_cluster_admin(""))
            self.assertFalse(membership.is_cluster_admin(None))


class GetRecordTests(TestCase):
    """The unauthenticated public-record read the roster rides on."""

    DOC = {
        "id": SERVICE_DID,
        "service": [
            {
                "id": "#atproto_pds",
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": "https://pds.commonscomputer.com",
            }
        ],
    }

    def test_resolves_the_pds_and_returns_the_record_value(self):
        value = {"admins": [], "updatedAt": "2026-08-12T00:00:00Z"}
        from corliss.tests.test_client import FakeResp

        with patch.object(atproto, "fetch_did_document", return_value=self.DOC):
            with patch.object(
                atproto.requests, "get",
                return_value=FakeResp(json_data={"uri": "at://…", "value": value}),
            ) as get:
                got = atproto.get_record(
                    SERVICE_DID, membership.ROSTER_COLLECTION, "self"
                )

        self.assertEqual(got, value)
        url, kwargs = get.call_args[0][0], get.call_args[1]
        self.assertEqual(
            url, "https://pds.commonscomputer.com/xrpc/com.atproto.repo.getRecord"
        )
        self.assertEqual(
            kwargs["params"],
            {
                "repo": SERVICE_DID,
                "collection": membership.ROSTER_COLLECTION,
                "rkey": "self",
            },
        )

    # No auth header, no DPoP proof — that is the property that makes ELEVATE
    # free of the service-auth question.
    def test_sends_no_credentials(self):
        from corliss.tests.test_client import FakeResp

        with patch.object(atproto, "fetch_did_document", return_value=self.DOC):
            with patch.object(
                atproto.requests, "get",
                return_value=FakeResp(json_data={"value": {"admins": []}}),
            ) as get:
                atproto.get_record(SERVICE_DID, membership.ROSTER_COLLECTION, "self")
        self.assertNotIn("headers", get.call_args[1])

    def test_a_response_without_a_record_value_raises(self):
        from corliss.tests.test_client import FakeResp

        with patch.object(atproto, "fetch_did_document", return_value=self.DOC):
            with patch.object(
                atproto.requests, "get", return_value=FakeResp(json_data={})
            ):
                with self.assertRaises(atproto.OAuthError):
                    atproto.get_record(SERVICE_DID, "some.collection", "self")


class HandlesForTests(TestCase):
    """`handles_for` — display labels, and the ways a label can go missing.

    The rule these tests pin is that no failure here is fatal: an unknown or
    unreachable DID drops out of the map and the caller shows the DID, which is
    still true. What must not happen is a console that 500s because a directory
    was slow.
    """

    def setUp(self):
        cache.clear()
        self.addCleanup(cache.clear)

    def test_a_signed_in_member_resolves_from_their_user_row_without_network(self):
        from django.contrib.auth import get_user_model

        get_user_model().objects.create_user(username="alice.bsky.social", did=JACOB)

        with patch.object(atproto, "fetch_did_document") as fetch:
            got = membership.handles_for([JACOB])

        self.assertEqual(got, {JACOB: "alice.bsky.social"})
        fetch.assert_not_called()

    def test_an_unknown_did_resolves_from_its_did_document(self):
        doc = {"alsoKnownAs": ["at://scott.bsky.social"]}

        with patch.object(atproto, "fetch_did_document", return_value=doc):
            got = membership.handles_for([SCOTT])

        self.assertEqual(got, {SCOTT: "scott.bsky.social"})

    def test_a_resolved_handle_is_cached_rather_than_fetched_per_render(self):
        doc = {"alsoKnownAs": ["at://scott.bsky.social"]}

        with patch.object(atproto, "fetch_did_document", return_value=doc) as fetch:
            membership.handles_for([SCOTT])
            membership.handles_for([SCOTT])

        self.assertEqual(fetch.call_count, 1)

    def test_an_unreachable_directory_leaves_the_did_unresolved(self):
        with patch.object(
            atproto, "fetch_did_document", side_effect=atproto.OAuthError("down")
        ):
            got = membership.handles_for([SCOTT])

        self.assertEqual(got, {})

    def test_a_failure_is_remembered_too_so_the_timeout_is_not_paid_twice(self):
        # Without this every render of the console pays the full request
        # timeout again for a DID that is not going to resolve.
        with patch.object(
            atproto, "fetch_did_document", side_effect=atproto.OAuthError("down")
        ) as fetch:
            membership.handles_for([SCOTT])
            membership.handles_for([SCOTT])

        self.assertEqual(fetch.call_count, 1)

    def test_blank_and_duplicate_dids_are_asked_about_once(self):
        doc = {"alsoKnownAs": ["at://scott.bsky.social"]}

        with patch.object(atproto, "fetch_did_document", return_value=doc) as fetch:
            got = membership.handles_for([SCOTT, SCOTT, "", None])

        self.assertEqual(got, {SCOTT: "scott.bsky.social"})
        self.assertEqual(fetch.call_count, 1)
