"""Editing the admin roster: the guards, the record shape, and the two halves.

The load-bearing tests here are the two refusals. Emptying the roster ends
every approve and revoke with no way back except editing the service account's
repo by hand — the registry's `BOOTSTRAP_ADMIN_DID` escape only applies when
the record is *absent*, not when it exists and lists nobody. Removing the
service account is worse still: it is what performs these writes, so off the
roster it fails GATE, cannot sign in, and cannot be put back.

The other thing worth breaking on is that entries are stamped, never deleted.
`Roster.was_admin_at` answers for the grants a departed admin wrote while they
were current, and it can only do that if their term is still in the record.

Appointing is two writes against two systems and the second can fail on its
own. That is reported, never raised: the roster write already happened, and
telling the caller nothing happened when something did is the one outcome that
leaves an operator with no idea what state they are in.
"""

from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, override_settings

from corliss import atproto, membership
from corliss.models import AtprotoToken
from corliss.tests.roster_fixtures import (
    GENESIS,
    OTHER_ADMIN,
    SERVICE_DID,
    RosterWriteMixin,
)

User = get_user_model()

JACOB = "did:plc:hhyrsndukexwr6qucdngcf4r"
BORIS = "did:plc:2cxgdrgtsmrbqnjkwyplmp43"
# Never granted membership, so appointing them is refused.
STRANGER = "did:plc:ewvi7nxzyoun6zhxrhs64oiz"


@override_settings(SCN_SERVICE_DID=SERVICE_DID)
class AppointAdminTests(RosterWriteMixin, TestCase):
    def setUp(self):
        super().setUp()
        # Appointing requires membership, so the candidate holds a grant. The
        # refusal when they do not is its own test below.
        self.grant(BORIS)

    def test_it_refuses_someone_who_is_not_a_member(self):
        """Admins are members. Enforced here rather than only in the console, so
        the CLI and any later caller obey the same rule."""
        with self.assertRaisesMessage(membership.RosterError, "only a current member"):
            membership.appoint_admin(JACOB, STRANGER)
        self.write_record.assert_not_called()

    def test_it_creates_the_local_row_so_the_table_can_show_them(self):
        """The console reads admin status off `is_staff`, so a member with no
        local row would render as not-an-admin however correct the roster is."""
        User.objects.filter(did=BORIS).delete()

        membership.appoint_admin(JACOB, BORIS)

        self.assertTrue(User.objects.get(did=BORIS).is_staff)

    def test_it_appends_a_term_naming_who_appointed_them(self):
        membership.appoint_admin(JACOB, BORIS)

        entry = self._written_entry(BORIS)
        self.assertEqual(entry["did"], BORIS)
        self.assertEqual(entry["addedBy"], JACOB)
        self.assertIsNone(entry.get("removedAt"))

    def test_it_leaves_the_existing_entries_alone(self):
        membership.appoint_admin(JACOB, BORIS)

        self.assertEqual(
            self._current_dids(), [SERVICE_DID, OTHER_ADMIN, BORIS]
        )
        # Untouched, not rewritten with today's timestamp: the record is the
        # history of who held authority and when.
        self.assertEqual(self._written_entry(OTHER_ADMIN)["addedAt"], GENESIS)

    def test_a_re_added_admin_gets_a_second_term(self):
        """Never merged into the old one, so the record still says when each
        term began and ended — which is what `Roster.covers` reads."""
        self.roster_entries = [
            {"did": SERVICE_DID, "addedAt": GENESIS},
            {"did": OTHER_ADMIN, "addedAt": GENESIS},
            {"did": BORIS, "addedAt": GENESIS, "removedAt": "2026-02-01T00:00:00Z"},
        ]

        membership.appoint_admin(JACOB, BORIS)

        terms = [e for e in self.written[-1]["admins"] if e["did"] == BORIS]
        self.assertEqual(len(terms), 2)
        self.assertEqual(terms[0]["removedAt"], "2026-02-01T00:00:00Z")
        self.assertIsNone(terms[1].get("removedAt"))

    def test_it_refuses_someone_already_current(self):
        with self.assertRaisesMessage(membership.RosterError, "already a current"):
            membership.appoint_admin(JACOB, OTHER_ADMIN)
        self.write_record.assert_not_called()

    def test_it_refuses_a_value_that_is_not_a_did(self):
        """The console takes a typed handle or DID, so this is a real input."""
        with self.assertRaises(membership.RosterError):
            membership.appoint_admin(JACOB, "boris.bsky.social")
        self.write_record.assert_not_called()

    def test_it_grants_registry_space_access(self):
        """The half that decides whether they can actually approve anyone."""
        membership.appoint_admin(JACOB, BORIS)

        _token, did, access = self.set_space_access.call_args.args
        self.assertEqual((did, access), (BORIS, "write"))

    def test_a_failed_space_sync_is_reported_not_raised(self):
        self.set_space_access.side_effect = membership.RegistryError("boom")

        note = membership.appoint_admin(JACOB, BORIS)

        # The roster write stands, and the note says what is still missing.
        self.assertIsNotNone(self._written_entry(BORIS))
        self.assertIn("cannot approve anyone", note)
        self.assertIn("again", note)

    def test_it_writes_the_genesis_roster_when_none_exists(self):
        """A network nobody has bootstrapped. The service account seeds itself
        because it must be a current admin to pass GATE and sign back in."""
        self.roster_entries = None

        membership.appoint_admin(SERVICE_DID, BORIS)

        self.assertEqual(self._current_dids(), [SERVICE_DID, BORIS])

    def test_the_cached_roster_is_dropped_after_a_write(self):
        """Otherwise `/manage/` renders pre-write state for up to five minutes
        and the admin who just appointed someone thinks it failed."""
        membership.fetch_roster()
        self.assertIsNotNone(cache.get(membership._ROSTER_CACHE_KEY))

        membership.appoint_admin(JACOB, BORIS)

        self.assertIsNone(cache.get(membership._ROSTER_CACHE_KEY))


@override_settings(SCN_SERVICE_DID=SERVICE_DID)
class DismissAdminTests(RosterWriteMixin, TestCase):
    def test_it_stamps_the_term_rather_than_deleting_it(self):
        membership.dismiss_admin(JACOB, OTHER_ADMIN)

        entry = self._written_entry(OTHER_ADMIN)
        self.assertIsNotNone(entry["removedAt"])
        self.assertEqual(entry["removedBy"], JACOB)
        self.assertEqual(entry["addedAt"], GENESIS)

    def test_the_departed_admin_is_still_in_the_record(self):
        """`was_admin_at` answers for the grants they wrote while current, and
        it needs the term to do that. Removing an admin must never look like
        un-granting everyone they approved."""
        membership.dismiss_admin(JACOB, OTHER_ADMIN)

        dids = [e["did"] for e in self.written[-1]["admins"]]
        self.assertIn(OTHER_ADMIN, dids)
        self.assertNotIn(OTHER_ADMIN, self._current_dids())

    def test_it_refuses_the_last_admin(self):
        """An existing-but-empty roster fails closed everywhere, and the
        registry's bootstrap escape only covers an *absent* record — so this
        would end every approve and revoke with no way back."""
        self.roster_entries = [{"did": JACOB, "addedAt": GENESIS}]

        with self.assertRaisesMessage(membership.RosterError, "last admin"):
            membership.dismiss_admin(JACOB, JACOB)
        self.write_record.assert_not_called()

    def test_it_refuses_the_service_account(self):
        """It performs these writes. Off the roster it fails GATE, cannot sign
        in to be given anything back, and the only repair is editing the repo
        by hand."""
        with self.assertRaisesMessage(membership.RosterError, "service account"):
            membership.dismiss_admin(JACOB, SERVICE_DID)
        self.write_record.assert_not_called()

    def test_an_admin_may_remove_themselves(self):
        """Allowed on purpose — the console confirms rather than refuses."""
        self.roster_entries = [
            {"did": SERVICE_DID, "addedAt": GENESIS},
            {"did": JACOB, "addedAt": GENESIS},
        ]

        membership.dismiss_admin(JACOB, JACOB)

        self.assertEqual(self._current_dids(), [SERVICE_DID])

    def test_it_refuses_someone_who_is_not_a_current_admin(self):
        with self.assertRaisesMessage(membership.RosterError, "not a current"):
            membership.dismiss_admin(JACOB, BORIS)
        self.write_record.assert_not_called()

    def test_it_removes_registry_space_access(self):
        membership.dismiss_admin(JACOB, OTHER_ADMIN)

        _token, did, access = self.set_space_access.call_args.args
        self.assertEqual((did, access), (OTHER_ADMIN, "none"))


@override_settings(SCN_SERVICE_DID=SERVICE_DID)
class ServiceSessionTests(RosterWriteMixin, TestCase):
    """The one prerequisite, and saying which half of it is missing.

    Corliss's stored PDS tokens and HappyView's registered copy expire
    independently, and only re-authenticating repairs the second. Both look the
    same from the console unless the message distinguishes them.
    """

    def setUp(self):
        super().setUp()
        self.grant(BORIS)

    def test_no_session_at_all_names_the_fix(self):
        AtprotoToken.objects.all().delete()

        with self.assertRaisesMessage(membership.RosterError, "authenticate"):
            membership.appoint_admin(JACOB, BORIS)
        self.write_record.assert_not_called()

    def test_the_roster_write_does_not_need_a_registry_session(self):
        """It is a plain PDS call. Only the space-access half needs HappyView,
        so a half-dead session must still get the roster written."""
        self.set_space_access.side_effect = membership.RegistryError("no session")

        note = membership.appoint_admin(JACOB, BORIS)

        self.assertIsNotNone(self._written_entry(BORIS))
        self.assertTrue(note)

    def test_a_failed_roster_write_stops_before_the_second_half(self):
        """Ordered so the writes cannot half-happen in the direction that
        matters: no space access for someone who is not on the roster."""
        self.write_record.side_effect = atproto.OAuthError("pds down")

        with self.assertRaises(membership.RosterError):
            membership.appoint_admin(JACOB, BORIS)
        self.set_space_access.assert_not_called()

    def test_status_reports_a_missing_session(self):
        AtprotoToken.objects.all().delete()

        status = membership.service_session_status()

        self.assertTrue(status["configured"])
        self.assertFalse(status["present"])

    def test_status_reports_a_live_session(self):
        token = AtprotoToken.objects.get()
        token.registry_session_at = membership.timezone.now()
        token.save(update_fields=["registry_session_at"])

        status = membership.service_session_status()

        self.assertTrue(status["present"])
        self.assertTrue(status["can_write_registry"])
        self.assertFalse(status["stale"])

    def test_status_flags_an_old_session_without_refusing_it(self):
        """Advisory only. The PDS is the authority on whether a token works;
        this exists so a lapse is found on a quiet day."""
        token = AtprotoToken.objects.get()
        token.registry_session_at = membership.timezone.now() - membership.timedelta(
            days=membership.SERVICE_SESSION_STALE_DAYS + 1
        )
        token.save(update_fields=["registry_session_at"])

        self.assertTrue(membership.service_session_status()["stale"])
        # Still usable — nothing refuses on staleness.
        membership.appoint_admin(JACOB, BORIS)
        self.assertIsNotNone(self._written_entry(BORIS))

    @override_settings(SCN_SERVICE_DID="")
    def test_status_reports_an_unconfigured_deployment(self):
        self.assertFalse(membership.service_session_status()["configured"])

    def test_keep_alive_never_raises(self):
        """It rides along with reconciliation; a dead session must not fail the
        cache rebuild, which is the recovery path."""
        with patch.object(
            atproto, "refresh_session", side_effect=atproto.OAuthError("expired")
        ):
            note = membership.refresh_service_session()

        self.assertIn("authenticate", note)

    def test_keep_alive_refreshes_the_stored_session(self):
        with patch.object(atproto, "refresh_session") as refresh:
            note = membership.refresh_service_session()

        refresh.assert_called_once()
        self.assertIn("refreshed", note)
