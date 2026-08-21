"""The Django admin — its registrations, and the command that opens its door.

The load-bearing test here is that the membership cache is *read-only*. It is a
cached computation over the registry's events, so an edit made in the admin is
either reverted by the next push or, until then, a membership that no record
backs. Anything that re-opens add/change/delete on it should break these.

`MakeAdminCommandTests` covers the other half of the same subject: who gets in
here at all, and — just as much — what that does *not* grant them.
"""

from io import StringIO
from unittest.mock import patch

from django.contrib import admin
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase
from django.urls import reverse

from corliss.models import MembershipCache

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


class MakeAdminCommandTests(TestCase):
    """`manage.py make_admin` — Django's admin, and nothing else.

    It used to set `is_superuser` under the name "admin", which is the one
    thing the deploy plan says not to do: that flag bypasses every permission
    check and opens the admin above, where Corliss's own OIDC client config and
    session tables live. Narrowing it costs nothing, because it is no longer
    the bootstrap path — cluster admin is a live read of the registry's roster,
    and a first ATProto login creates its own `User` row.
    """

    def _run(self, *args, **opts):
        out = StringIO()
        call_command("make_admin", *args, stdout=out, **opts)
        return out.getvalue()

    def test_it_creates_a_staff_user_who_is_not_a_superuser(self):
        self._run("alice.bsky.social", did=DID)

        user = User.objects.get(did=DID)
        self.assertTrue(user.is_staff)
        self.assertFalse(user.is_superuser)

    def test_the_created_row_cannot_authenticate_with_a_password(self):
        """This row only ever signs in through ATProto OAuth."""
        self._run("alice.bsky.social", did=DID)
        self.assertFalse(User.objects.get(did=DID).has_usable_password())

    def test_superuser_is_granted_only_when_asked_for(self):
        self._run("alice.bsky.social", did=DID, superuser=True)
        self.assertTrue(User.objects.get(did=DID).is_superuser)

    def test_it_promotes_an_existing_row_without_granting_superuser(self):
        """The row a first ATProto login left behind."""
        User.objects.create_user(username="alice.bsky.social", did=DID)

        self._run("alice.bsky.social", did=DID)

        user = User.objects.get(did=DID)
        self.assertTrue(user.is_staff)
        self.assertFalse(user.is_superuser)

    def test_it_never_withdraws_superuser_it_did_not_grant(self):
        """"Do not grant" is not "revoke". Silently demoting the account an
        operator is signed in with would be a worse surprise than the one this
        change is fixing."""
        User.objects.create_superuser(username="alice.bsky.social", did=DID)

        output = self._run("alice.bsky.social", did=DID)

        self.assertTrue(User.objects.get(did=DID).is_superuser)
        self.assertIn("is_superuser is set", output)

    def test_it_keys_on_the_did_not_the_handle(self):
        """A member who changed handle keeps one row — the same field
        `views._upsert_member` keys on."""
        User.objects.create_user(username="old.handle.test", did=DID)

        self._run("alice.bsky.social", did=DID)

        self.assertEqual(User.objects.filter(did=DID).count(), 1)
        self.assertEqual(User.objects.get(did=DID).username, "alice.bsky.social")

    def test_it_says_that_cluster_admin_is_somewhere_else(self):
        """The confusion the rename exists to prevent: running this to give
        someone cluster admin does nothing of the kind."""
        output = self._run("alice.bsky.social", did=DID)
        self.assertIn("roster", output)

    def test_it_grants_no_cluster_admin_and_no_membership(self):
        self._run("alice.bsky.social", did=DID, superuser=True)

        user = User.objects.get(did=DID)
        with patch("corliss.membership.is_cluster_admin", return_value=False):
            self.assertFalse(user.is_cluster_admin)
        self.assertFalse(MembershipCache.objects.filter(did=DID).exists())
