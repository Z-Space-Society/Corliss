"""Workspaces: who can see one, who can change one, and who cannot.

Three things here are load-bearing and none of them is obvious from the diff:

- **The creator must land in `members`.** `created_by` grants nothing, and being
  in `members` is the entire permission, so a create that forgot the `.add()`
  would lock the maker out of the workspace they had just made, on the redirect.
- **A workspace you are not in answers 404, not 403.** Membership is the
  permission *and* the lookup, so an id you were never given is a page that does
  not exist. A 403 would make bare ids enumerable.
- **The last member cannot be removed.** An empty roster is a workspace nobody
  can ever open again: not the remover, not the creator, not a cluster admin.

Nothing here reaches the network: `NoRosterMixin` pins the roster read that the
nav performs on every page, and `may_enter` is answered from the cache.
"""

from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from corliss.models import MembershipCache, Workspace

User = get_user_model()

ALICE = "did:plc:ewvi7nxzyoun6zhxrhs64oiz"
BOB = "did:plc:hhyrsndukexwr6qucdngcf4r"
STRANGER = "did:plc:n4mzxx6z4ehnswc7znswtfr2"


def _grant(did, *, active=True):
    """A cache row as the registry's push would have left it."""
    return MembershipCache.objects.create(
        did=did,
        active=active,
        tier="level-2",
        last_rkey=f"{did}:3lqxaaaaaaaaa",
        last_event_at="2026-01-01T00:00:00Z",
        author_did=ALICE,
    )


def _member(handle, did, *, granted=True, **extra):
    """A member who has signed in here, with a grant unless told otherwise."""
    user = User.objects.create_user(username=handle, did=did, **extra)
    if granted:
        _grant(did)
    return user


class NoRosterMixin:
    """Pin ELEVATE to False. Same reason as `test_account.NoRosterMixin`: the
    nav on every page asks `user.is_cluster_admin`, a live roster read out of
    the service DID's repo that would otherwise reach the network."""

    def setUp(self):
        super().setUp()
        patcher = patch("corliss.membership.is_cluster_admin", return_value=False)
        patcher.start()
        self.addCleanup(patcher.stop)


class WorkspaceGateTests(NoRosterMixin, TestCase):
    """GATE covers all three pages: making a workspace is something the cluster
    gives you, so a signed-in non-member gets no further than the home page."""

    def test_anonymous_is_bounced_through_login(self):
        for name in ("workspaces", "workspace_new"):
            with self.subTest(view=name):
                resp = self.client.get(reverse(name))
                self.assertRedirects(
                    resp, reverse("login"), fetch_redirect_response=False
                )

    def test_signed_in_non_member_is_refused(self):
        """Refused to the home page, which is where the refusal is explained."""
        self.client.force_login(_member("nobody.test", STRANGER, granted=False))
        for name in ("workspaces", "workspace_new"):
            with self.subTest(view=name):
                resp = self.client.get(reverse(name))
                self.assertRedirects(
                    resp, reverse("home"), fetch_redirect_response=False
                )

    def test_revoked_member_is_refused(self):
        """The row survives for audit; it is not permission."""
        user = _member("gone.test", STRANGER, granted=False)
        _grant(STRANGER, active=False)
        self.client.force_login(user)
        resp = self.client.get(reverse("workspaces"))
        self.assertRedirects(resp, reverse("home"), fetch_redirect_response=False)


class WorkspaceCreateTests(NoRosterMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.alice = _member("alice.test", ALICE)
        self.client.force_login(self.alice)

    def test_creating_puts_the_creator_in_members(self):
        """Without this the maker is locked out on the very next request."""
        resp = self.client.post(
            reverse("workspace_new"),
            {"name": "Notes", "description": "Where the notes go."},
        )
        workspace = Workspace.objects.get(name="Notes")
        self.assertRedirects(
            resp, reverse("workspace_edit", kwargs={"pk": workspace.pk})
        )
        self.assertEqual(list(workspace.members.all()), [self.alice])
        self.assertEqual(workspace.created_by, self.alice)
        # Reserved for the notes editor, and blank until then. A required
        # column here would have made every create fail.
        self.assertEqual(workspace.automerge_root, "")

    def test_the_new_workspace_is_on_the_list(self):
        self.client.post(reverse("workspace_new"), {"name": "Notes"})
        resp = self.client.get(reverse("workspaces"))
        self.assertContains(resp, "Notes")

    def test_a_blank_name_is_refused_and_redisplays_the_form(self):
        resp = self.client.post(
            reverse("workspace_new"), {"name": "   ", "description": "kept"}
        )
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(Workspace.objects.exists())
        # What they typed comes back with the error, rather than being dropped.
        self.assertContains(resp, "kept")

    def test_the_empty_list_says_so(self):
        resp = self.client.get(reverse("workspaces"))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "not in a workspace yet")


class WorkspaceVisibilityTests(NoRosterMixin, TestCase):
    """Only yours, and a workspace you are not in does not exist."""

    def setUp(self):
        super().setUp()
        self.alice = _member("alice.test", ALICE)
        self.bob = _member("bob.test", BOB)

        self.hers = Workspace.objects.create(name="Alice's place", created_by=self.alice)
        self.hers.members.add(self.alice)
        self.his = Workspace.objects.create(name="Bob's place", created_by=self.bob)
        self.his.members.add(self.bob)

        self.client.force_login(self.alice)

    def test_the_list_shows_only_your_own(self):
        resp = self.client.get(reverse("workspaces"))
        self.assertContains(resp, "Alice&#x27;s place")
        self.assertNotContains(resp, "Bob&#x27;s place")

    def test_someone_elses_workspace_is_a_404(self):
        url = reverse("workspace_edit", kwargs={"pk": self.his.pk})
        self.assertEqual(self.client.get(url).status_code, 404)

    def test_posting_to_someone_elses_workspace_is_a_404(self):
        """The check is the lookup, so every action re-asks it. A member of one
        workspace cannot write another by knowing its id."""
        url = reverse("workspace_edit", kwargs={"pk": self.his.pk})
        for payload in (
            {"action": "save", "name": "Mine now"},
            {"action": "add_member", "handle": "alice.test"},
            {"action": "remove_member", "did": BOB},
        ):
            with self.subTest(action=payload["action"]):
                self.assertEqual(self.client.post(url, payload).status_code, 404)
        self.his.refresh_from_db()
        self.assertEqual(self.his.name, "Bob's place")
        self.assertEqual(list(self.his.members.all()), [self.bob])


class WorkspaceEditTests(NoRosterMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.alice = _member("alice.test", ALICE, display_name="Alice Example")
        self.bob = _member("bob.test", BOB)
        self.workspace = Workspace.objects.create(
            name="Notes", created_by=self.alice
        )
        self.workspace.members.add(self.alice)
        self.url = reverse("workspace_edit", kwargs={"pk": self.workspace.pk})
        self.client.force_login(self.alice)

    def test_renaming_saves(self):
        resp = self.client.post(
            self.url, {"action": "save", "name": "Shared notes", "description": "hi"}
        )
        self.assertRedirects(resp, self.url)
        self.workspace.refresh_from_db()
        self.assertEqual(self.workspace.name, "Shared notes")
        self.assertEqual(self.workspace.description, "hi")

    def test_a_blank_name_is_refused_and_changes_nothing(self):
        resp = self.client.post(self.url, {"action": "save", "name": ""})
        self.assertEqual(resp.status_code, 200)
        self.workspace.refresh_from_db()
        self.assertEqual(self.workspace.name, "Notes")

    def test_a_message_survives_exactly_one_hop(self):
        self.client.post(self.url, {"action": "add_member", "handle": "bob.test"})
        self.assertContains(self.client.get(self.url), "Added bob.test")
        self.assertNotContains(self.client.get(self.url), "Added bob.test")

    def test_a_save_leaves_no_message(self):
        """The heading it changed is the feedback. A notice over the new name
        would say what the page already says."""
        resp = self.client.post(
            self.url, {"action": "save", "name": "Shared notes"}, follow=True
        )
        self.assertNotContains(resp, "alert--notice")
        self.assertContains(resp, "Shared notes")

    def test_adding_by_handle(self):
        resp = self.client.post(
            self.url, {"action": "add_member", "handle": "bob.test"}
        )
        self.assertRedirects(resp, self.url)
        self.assertIn(self.bob, self.workspace.members.all())

    def test_adding_is_case_insensitive_and_takes_a_leading_at(self):
        self.client.post(self.url, {"action": "add_member", "handle": "@BOB.test"})
        self.assertIn(self.bob, self.workspace.members.all())

    def test_an_unknown_handle_adds_nobody(self):
        # `follow=True` rather than a second GET: the message rides one hop in
        # the session, and a bare `assertRedirects` would fetch the target and
        # spend it before the assertion could see it.
        resp = self.client.post(
            self.url, {"action": "add_member", "handle": "ghost.test"}, follow=True
        )
        self.assertRedirects(resp, self.url)
        self.assertEqual(self.workspace.members.count(), 1)
        self.assertContains(resp, "No member here goes by")

    def test_a_non_member_cannot_be_added(self):
        """The one place cluster membership and workspace membership touch. A
        datalist is a convenience; this is the check, and a hand-written POST
        arrives here having skipped the first."""
        _member("outsider.test", STRANGER, granted=False)
        resp = self.client.post(
            self.url, {"action": "add_member", "handle": "outsider.test"}, follow=True
        )
        self.assertRedirects(resp, self.url)
        self.assertEqual(self.workspace.members.count(), 1)
        self.assertContains(resp, "not a cluster member")

    def test_adding_someone_already_here_changes_nothing(self):
        self.client.post(self.url, {"action": "add_member", "handle": "alice.test"})
        self.assertEqual(self.workspace.members.count(), 1)

    def test_the_candidate_list_offers_members_who_are_not_here(self):
        resp = self.client.get(self.url)
        self.assertContains(resp, 'value="bob.test"')
        # Already in, so not on offer.
        self.assertNotContains(resp, 'value="alice.test"')

    def test_a_revoked_member_is_not_offered(self):
        """`active` is not optional: the row survives revocation for audit."""
        _member("gone.test", STRANGER, granted=False)
        _grant(STRANGER, active=False)
        self.assertNotContains(self.client.get(self.url), 'value="gone.test"')

    def test_removing_a_member(self):
        self.workspace.members.add(self.bob)
        resp = self.client.post(
            self.url, {"action": "remove_member", "did": BOB}
        )
        self.assertRedirects(resp, self.url)
        self.assertEqual(list(self.workspace.members.all()), [self.alice])

    def test_removing_someone_who_is_not_here_changes_nothing(self):
        resp = self.client.post(
            self.url, {"action": "remove_member", "did": BOB}
        )
        self.assertRedirects(resp, self.url)
        self.assertEqual(self.workspace.members.count(), 1)

    def test_the_page_reads_before_it_edits(self):
        """The description is text and the form is behind Edit. The panel is in
        the markup either way, so what is asserted is the read view being there
        rather than the form being absent."""
        self.workspace.description = "What it is for."
        self.workspace.save()
        resp = self.client.get(self.url)
        self.assertContains(resp, "What it is for.")
        self.assertContains(resp, 'href="#edit"')

    def test_a_refused_name_holds_the_edit_panel_open(self):
        """The fragment does not survive a POST, so without `is-open` the errors
        would render inside a panel CSS has already hidden."""
        resp = self.client.post(self.url, {"action": "save", "name": ""})
        self.assertContains(resp, "workspace-panel is-open")

    def test_the_sole_member_is_offered_no_way_out(self):
        """Disabled rather than absent, so the rule is readable. The view still
        refuses it: see the test below."""
        resp = self.client.get(self.url)
        self.assertContains(resp, "disabled")
        self.assertNotContains(resp, 'name="action" value="remove_member"')

    def test_the_handle_links_out_by_did(self):
        """By DID, not handle: a handle written into a link goes stale the
        moment the member changes theirs."""
        resp = self.client.get(self.url)
        self.assertContains(resp, f"https://bsky.app/profile/{ALICE}")
        self.assertNotContains(resp, "https://bsky.app/profile/alice.test")

    def test_the_leave_control_returns_once_there_are_two(self):
        self.workspace.members.add(self.bob)
        resp = self.client.get(self.url)
        self.assertContains(resp, 'name="action" value="remove_member"')

    def test_the_last_member_cannot_be_removed(self):
        """An empty roster is a workspace nobody can ever open again."""
        resp = self.client.post(
            self.url, {"action": "remove_member", "did": ALICE}, follow=True
        )
        self.assertRedirects(resp, self.url)
        self.assertEqual(list(self.workspace.members.all()), [self.alice])
        self.assertContains(resp, "needs someone in it")

    def test_leaving_lands_on_the_list_not_the_page_you_just_left(self):
        self.workspace.members.add(self.bob)
        resp = self.client.post(
            self.url, {"action": "remove_member", "did": ALICE}
        )
        self.assertRedirects(resp, reverse("workspaces"))
        self.assertEqual(list(self.workspace.members.all()), [self.bob])
        # And it really is gone: the page she just left is now a 404.
        self.assertEqual(self.client.get(self.url).status_code, 404)

    def test_an_added_member_can_edit_and_add(self):
        """Flat by design: no owner clause, so the person added holds exactly
        what the person who added them holds."""
        self.workspace.members.add(self.bob)
        self.client.force_login(self.bob)
        resp = self.client.post(
            self.url, {"action": "save", "name": "Bob renamed it"}
        )
        self.assertRedirects(resp, self.url)
        self.workspace.refresh_from_db()
        self.assertEqual(self.workspace.name, "Bob renamed it")
        # Including removing the person who made it.
        self.client.post(self.url, {"action": "remove_member", "did": ALICE})
        self.assertEqual(list(self.workspace.members.all()), [self.bob])
