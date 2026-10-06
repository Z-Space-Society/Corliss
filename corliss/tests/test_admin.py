"""The Django admin — its registrations, and the command that opens its door.

The load-bearing test here is that the membership cache is *read-only*. It is a
cached computation over the registry's events, so an edit made in the admin is
either reverted by the next push or, until then, a membership that no record
backs. Anything that re-opens add/change/delete on it should break these.

`MakeAdminCommandTests` covers the other half of the same subject: who gets in
here at all, and — just as much — what that does *not* grant them.
"""

import json
from io import StringIO
from unittest.mock import patch

from django.contrib import admin
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase, override_settings
from django.urls import reverse

from corliss import atproto, membership
from corliss.models import AtprotoToken, MembershipCache
from corliss.tests.roster_fixtures import (
    OTHER_ADMIN as OTHER,
    SERVICE_DID,
    RosterWriteMixin,
)

User = get_user_model()

DID = "did:plc:ewvi7nxzyoun6zhxrhs64oiz"
STRANGER = "did:plc:granted7nxzyoun6zhxrhs64x"


def _grant(did=DID, *, tier="level-2", active=True):
    return MembershipCache.objects.create(
        did=did,
        active=active,
        tier=tier,
        last_rkey=f"{did}:3lqxaaaaaaaaa",
        last_event_at="2026-01-01T00:00:00Z",
        author_did="did:plc:anadmin",
    )


class UserAdminTests(TestCase):
    """The member list, which is the one place DID, handle, name and email are
    all shown together."""

    def setUp(self):
        self.superuser = User.objects.create_superuser(
            username="root.bsky.social", did="did:plc:rootrootrootrootrootroot"
        )
        self.client.force_login(self.superuser)

    def test_the_list_shows_the_name(self):
        User.objects.create_user(
            username="alice.bsky.social", did=DID, display_name="Alice Example"
        )
        resp = self.client.get(reverse("admin:corliss_user_changelist"))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Alice Example")
        self.assertContains(resp, DID)

    def test_a_member_can_be_found_by_name(self):
        User.objects.create_user(
            username="alice.bsky.social", did=DID, display_name="Alice Example"
        )
        resp = self.client.get(
            reverse("admin:corliss_user_changelist"), {"q": "Alice Example"}
        )
        self.assertContains(resp, "alice.bsky.social")

    def test_the_change_form_does_not_offer_first_and_last_name(self):
        """They come free with AbstractUser and this app uses neither. Two
        empty boxes on the form invite an operator to fill in the pair nothing
        reads — which is why `fieldsets` is declared rather than appended to."""
        user = User.objects.create_user(username="alice.bsky.social", did=DID)
        resp = self.client.get(
            reverse("admin:corliss_user_change", args=[user.pk])
        )
        self.assertEqual(resp.status_code, 200)
        self.assertNotContains(resp, 'name="first_name"')
        self.assertNotContains(resp, 'name="last_name"')
        # The one name this app does keep is on the form, and editable.
        self.assertContains(resp, 'name="display_name"')

    def test_email_confirmed_is_shown_but_not_editable(self):
        """It means the PDS vouched for the address — not something an operator
        can decide here, and what `email_verified` in the id_token reads."""
        user = User.objects.create_user(
            username="alice.bsky.social", did=DID, email_confirmed=True
        )
        resp = self.client.get(
            reverse("admin:corliss_user_change", args=[user.pk])
        )
        self.assertContains(resp, "Email confirmed")
        self.assertNotContains(resp, 'name="email_confirmed"')

    def test_a_member_with_no_name_still_lists(self):
        """Blank is the normal state for someone with no profile record, and
        for every member until their next sign-in after this shipped."""
        User.objects.create_user(username="bob.bsky.social", did=STRANGER)
        resp = self.client.get(reverse("admin:corliss_user_changelist"))
        self.assertContains(resp, "bob.bsky.social")


class MembershipCacheAdminTests(TestCase):
    def setUp(self):
        self.superuser = User.objects.create_superuser(
            username="root.bsky.social", did="did:plc:rootrootrootrootrootroot"
        )
        self.client.force_login(self.superuser)

    def test_the_cache_is_listed(self):
        _grant(tier="level-5")
        resp = self.client.get(reverse("admin:corliss_membershipcache_changelist"))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, DID)
        self.assertContains(resp, "level-5")

    def test_a_row_shows_the_handle_of_a_member_who_has_signed_in(self):
        User.objects.create_user(username="alice.bsky.social", did=DID)
        _grant()
        resp = self.client.get(reverse("admin:corliss_membershipcache_changelist"))
        self.assertContains(resp, "alice.bsky.social")

    def test_a_member_who_has_never_signed_in_still_lists(self):
        """The INVITE case: granted before the account exists, so no handle."""
        _grant(STRANGER)
        resp = self.client.get(reverse("admin:corliss_membershipcache_changelist"))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, STRANGER)

    def test_nothing_can_be_added_changed_or_deleted_even_by_a_superuser(self):
        row = _grant()
        site_admin = admin.site._registry[MembershipCache]
        request = type("Req", (), {"user": self.superuser, "method": "GET"})()

        self.assertFalse(site_admin.has_add_permission(request))
        self.assertFalse(site_admin.has_change_permission(request, row))
        self.assertFalse(site_admin.has_delete_permission(request, row))

    def test_the_add_and_delete_urls_are_refused(self):
        row = _grant()
        add = self.client.get(reverse("admin:corliss_membershipcache_add"))
        delete = self.client.get(
            reverse("admin:corliss_membershipcache_delete", args=[row.pk])
        )
        self.assertEqual(add.status_code, 403)
        self.assertEqual(delete.status_code, 403)

    def test_the_detail_page_opens_but_saves_nothing(self):
        """Read-only admin still gets a view page — that is what it is for."""
        row = _grant()
        resp = self.client.get(
            reverse("admin:corliss_membershipcache_change", args=[row.pk])
        )
        self.assertEqual(resp.status_code, 200)
        self.assertNotContains(resp, 'name="_save"')


@override_settings(SCN_SERVICE_DID=SERVICE_DID)
class MakeAdminCommandTests(RosterWriteMixin, TestCase):
    """`manage.py make_admin` — the CLI face of "make someone an admin".

    It writes the registry roster, which is the authority, and mirrors that
    onto `is_staff`. The same two writes back the button on `/manage/`; both
    call `membership.appoint_admin`, so this and the console cannot drift into
    meaning different things.

    Admins are members, so the candidate holds a grant before any of this —
    the refusal when they do not is its own test.
    """

    def setUp(self):
        super().setUp()
        self.grant(DID)

    def _run(self, *args, **opts):
        out = StringIO()
        call_command("make_admin", *args, stdout=out, **opts)
        return out.getvalue()

    def test_it_adds_them_to_the_roster(self):
        self._run("alice.bsky.social", did=DID)

        entry = self._written_entry(DID)
        self.assertIsNotNone(entry)
        self.assertIsNone(entry.get("removedAt"))
        # Attributed to the account that performs the write: a shell command
        # cannot prove who typed it.
        self.assertEqual(entry["addedBy"], SERVICE_DID)

    def test_it_mirrors_onto_is_staff(self):
        User.objects.create_user(username="alice.bsky.social", did=DID)

        self._run("alice.bsky.social", did=DID)

        self.assertTrue(User.objects.get(did=DID).is_staff)

    def test_a_roster_failure_grants_no_django_access(self):
        """The roster is written first precisely so this cannot half-happen."""
        User.objects.create_user(username="alice.bsky.social", did=DID)
        self.write_record.side_effect = atproto.OAuthError("pds down")

        with self.assertRaises(CommandError):
            self._run("alice.bsky.social", did=DID)

        self.assertFalse(User.objects.get(did=DID).is_staff)

    def test_it_creates_the_local_row_when_they_have_never_signed_in(self):
        """The invitation case. The row is made here rather than waiting for a
        first sign-in, because the console reads admin status off `is_staff`
        and would otherwise show a real admin as not one."""
        self._run("alice.bsky.social", did=DID)

        self.assertIsNotNone(self._written_entry(DID))
        self.assertTrue(User.objects.get(did=DID).is_staff)

    def test_it_refuses_someone_who_is_not_a_member(self):
        """The same rule the console enforces, applied to the CLI so the two
        cannot mean different things."""
        MembershipCache.objects.filter(did=DID).delete()

        with self.assertRaisesMessage(CommandError, "only a current member"):
            self._run("alice.bsky.social", did=DID)

        self.write_record.assert_not_called()

    def test_remove_ends_the_term_without_deleting_it(self):
        User.objects.create_user(
            username="alice.bsky.social", did=DID, is_staff=True
        )
        self.roster_entries = [
            {"did": SERVICE_DID, "addedAt": "2026-01-01T00:00:00Z"},
            {"did": OTHER, "addedAt": "2026-01-01T00:00:00Z"},
            {"did": DID, "addedAt": "2026-01-01T00:00:00Z"},
        ]

        self._run("alice.bsky.social", did=DID, remove=True)

        entry = self._written_entry(DID)
        # Stamped, not dropped — `was_admin_at` needs the departed term to
        # answer for the grants they wrote while current.
        self.assertIsNotNone(entry["removedAt"])
        self.assertEqual(entry["removedBy"], SERVICE_DID)
        self.assertFalse(User.objects.get(did=DID).is_staff)

    def test_it_refuses_to_remove_the_last_admin(self):
        self.roster_entries = [{"did": DID, "addedAt": "2026-01-01T00:00:00Z"}]

        with self.assertRaises(CommandError):
            self._run("alice.bsky.social", did=DID, remove=True)

        self.write_record.assert_not_called()

    def test_it_says_what_to_do_when_there_is_no_service_session(self):
        """The one prerequisite, named rather than surfaced as a 401."""
        AtprotoToken.objects.all().delete()

        with self.assertRaisesMessage(CommandError, "authenticate"):
            self._run("alice.bsky.social", did=DID)

    def test_superuser_is_granted_only_when_asked_for(self):
        self._run("alice.bsky.social", did=DID)
        self.assertFalse(User.objects.filter(did=DID, is_superuser=True).exists())

        self.grant(STRANGER)
        self._run("bob.bsky.social", did=STRANGER, superuser=True)
        self.assertTrue(User.objects.get(did=STRANGER).is_superuser)

    def test_the_superuser_row_cannot_authenticate_with_a_password(self):
        """It only ever signs in through ATProto OAuth."""
        self._run("alice.bsky.social", did=DID, superuser=True)
        self.assertFalse(User.objects.get(did=DID).has_usable_password())

    def test_it_writes_no_membership_event(self):
        """Appointing needs a member and does not make one. The cache belongs to
        the registry's push, and a command that quietly wrote a grant would put
        a membership here that no record backs."""
        before = MembershipCache.objects.get(did=DID).last_rkey

        self._run("alice.bsky.social", did=DID)

        self.assertEqual(MembershipCache.objects.get(did=DID).last_rkey, before)


@override_settings(SCN_SERVICE_DID=SERVICE_DID)
class MakeAdminAdmitTests(RosterWriteMixin, TestCase):
    """`make_admin --admit` — admitting and appointing in one command.

    Opt-in on purpose. Without the flag the member-first refusal stands (see
    `MakeAdminCommandTests`), so "make them an admin" never quietly also means
    "let them in".
    """

    def setUp(self):
        super().setUp()
        approve = patch.object(
            membership.MembershipRegistry,
            "approve",
            side_effect=lambda token, did, tier: self.grant(did, tier=tier),
        )
        self.approve = approve.start()
        self.addCleanup(approve.stop)

    def _run(self, *args, **opts):
        out = StringIO()
        call_command("make_admin", *args, stdout=out, **opts)
        return out.getvalue()

    def test_it_admits_then_appoints(self):
        out = self._run("alice.bsky.social", did=DID, admit=True, tier="level-2")

        self.assertEqual(self.approve.call_args.args[1:], (DID, "level-2"))
        self.assertIsNotNone(self._written_entry(DID))
        self.assertIn("admitted as a member at level-2", out)
        # zai-ops reads this word to decide whether the run changed anything.
        self.assertIn("promoted", out)

    def test_an_existing_member_is_not_re_granted(self):
        self.grant(DID, tier="level-5")

        self._run("alice.bsky.social", did=DID, admit=True)

        self.approve.assert_not_called()
        self.assertEqual(MembershipCache.objects.get(did=DID).tier, "level-5")
        self.assertIsNotNone(self._written_entry(DID))

    def test_a_tier_the_network_does_not_issue_is_refused(self):
        self.approve.side_effect = membership.RegistryError("not a tier")

        with self.assertRaisesMessage(CommandError, "not a tier"):
            self._run("alice.bsky.social", did=DID, admit=True, tier="level-99")

        self.write_record.assert_not_called()

    def test_remove_never_admits(self):
        self.grant(DID)
        self.roster_entries = self.roster_entries + [
            {"did": DID, "addedAt": "2026-01-01T00:00:00Z"}
        ]

        self._run("alice.bsky.social", did=DID, remove=True, admit=True)

        self.approve.assert_not_called()


@override_settings(SCN_SERVICE_DID=SERVICE_DID)
class ListAdminsCommandTests(RosterWriteMixin, TestCase):
    """`manage.py list_admins` — the roster as JSON, for tooling."""

    def setUp(self):
        super().setUp()
        handles = patch.object(
            membership,
            "handles_for",
            side_effect=lambda dids: {SERVICE_DID: "sharedcomputer.network"},
        )
        handles.start()
        self.addCleanup(handles.stop)

    def _run(self):
        out = StringIO()
        call_command("list_admins", stdout=out)
        return json.loads(out.getvalue())

    def test_it_lists_the_current_admins(self):
        report = self._run()

        self.assertTrue(report["roster_exists"])
        self.assertEqual(
            {a["did"] for a in report["admins"]}, {SERVICE_DID, OTHER}
        )

    def test_a_departed_admin_is_left_out(self):
        self.roster_entries[1]["removedAt"] = "2026-02-01T00:00:00Z"

        self.assertEqual([a["did"] for a in self._run()["admins"]], [SERVICE_DID])

    def test_it_shows_a_handle_and_falls_back_to_the_did(self):
        by_did = {a["did"]: a for a in self._run()["admins"]}

        self.assertEqual(by_did[SERVICE_DID]["handle"], "sharedcomputer.network")
        self.assertEqual(by_did[OTHER]["handle"], OTHER)

    def test_it_reports_membership_and_the_local_mirror(self):
        """Both can lag the roster, so they are reported, not assumed."""
        User.objects.create_user(username="other.test", did=OTHER, is_staff=True)

        by_did = {a["did"]: a for a in self._run()["admins"]}

        self.assertTrue(by_did[OTHER]["member"])
        self.assertTrue(by_did[OTHER]["is_staff"])
        # The service account holds authority and no grant.
        self.assertFalse(by_did[SERVICE_DID]["member"])

    def test_it_reports_the_service_session(self):
        self.assertTrue(self._run()["service"]["can_write_registry"])

    def test_no_roster_record_is_an_answer_not_an_error(self):
        self.roster_entries = None

        report = self._run()

        self.assertFalse(report["roster_exists"])
        self.assertEqual(report["admins"], [])


@override_settings(SCN_SERVICE_DID=SERVICE_DID)
class SyncAdminsCommandTests(RosterWriteMixin, TestCase):
    """`manage.py sync_admins` — the `is_staff` mirror, re-derived for everyone."""

    def setUp(self):
        super().setUp()
        handles = patch.object(membership, "handles_for", side_effect=lambda dids: {})
        handles.start()
        self.addCleanup(handles.stop)

    def _run(self):
        out = StringIO()
        call_command("sync_admins", stdout=out)
        return out.getvalue()

    def _staff(self, did):
        return User.objects.get(did=did).is_staff

    def test_a_current_admin_gets_the_flag_and_a_row(self):
        """OTHER has never signed in: no row at all, and still an admin."""
        out = self._run()

        self.assertTrue(self._staff(OTHER))
        self.assertTrue(self._staff(SERVICE_DID))
        self.assertIn(f"{OTHER}: marked as an admin", out)

    def test_a_departed_admin_loses_the_flag(self):
        User.objects.create_user(username="other.test", did=OTHER, is_staff=True)
        self.roster_entries[1]["removedAt"] = "2026-02-01T00:00:00Z"

        out = self._run()

        self.assertFalse(self._staff(OTHER))
        self.assertIn(f"{OTHER}: no longer marked as an admin", out)

    def test_staff_who_were_never_on_the_roster_lose_the_flag(self):
        User.objects.create_user(username="stray.test", did=DID, is_staff=True)

        self._run()

        self.assertFalse(self._staff(DID))

    def test_superusers_are_left_alone(self):
        """Which is also what keeps the break-glass row out of this."""
        User.objects.create_user(
            username="admin", did="did:local:admin", is_staff=True, is_superuser=True
        )

        self._run()

        self.assertTrue(self._staff("did:local:admin"))

    def test_a_second_run_changes_nothing(self):
        self._run()

        self.assertIn("already matches the roster", self._run())

    def test_no_roster_record_means_the_service_account_alone(self):
        User.objects.create_user(username="other.test", did=OTHER, is_staff=True)
        self.roster_entries = None

        self._run()

        self.assertTrue(self._staff(SERVICE_DID))
        self.assertFalse(self._staff(OTHER))

    def test_an_unreadable_roster_changes_nothing(self):
        User.objects.create_user(username="other.test", did=OTHER, is_staff=True)
        self.find_record.side_effect = atproto.OAuthError("PDS unreachable")

        with self.assertRaises(CommandError):
            self._run()

        self.assertTrue(self._staff(OTHER))

    def test_it_does_not_touch_the_roster_or_space_access(self):
        self._run()

        self.assertEqual(self.written, [])
        self.set_space_access.assert_not_called()
