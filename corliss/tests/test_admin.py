"""The Django admin registrations.

The load-bearing test here is that the membership cache is *read-only*. It is a
cached computation over the registry's events, so an edit made in the admin is
either reverted by the next push or, until then, a membership that no record
backs. Anything that re-opens add/change/delete on it should break these.
"""

from django.contrib import admin
from django.contrib.auth import get_user_model
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
