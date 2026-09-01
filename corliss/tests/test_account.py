"""The account page: the member's own name and email, and who owns them.

Two things here are load-bearing and neither is visible in the diff:

- **A save must survive the next login.** `views._upsert_member` fills these
  two fields only when they are blank, and that rule exists for this page. The
  overwrite it replaced would have reverted every edit at the member's next
  sign-in — silently, because nobody watches their profile while logging in.
  The other side of it is covered in `test_views.py`; what is covered here is
  that a blank submission is a real answer and re-arms the fill.
- **Editing the email un-confirms it.** `email_confirmed` means "the PDS
  vouched for this address", and it is what `email_verified` in the `id_token`
  reads. An address the member typed here has no such backing.

Nothing here touches the network: the page reads and writes one row.
"""

from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

User = get_user_model()

DID = "did:plc:ewvi7nxzyoun6zhxrhs64oiz"


class NoRosterMixin:
    """Pin ELEVATE to False. Same reason as `test_views.NoRosterMixin`: the nav
    on every page asks `user.is_cluster_admin`, which is a live roster read out
    of the service DID's repo and would otherwise reach the network."""

    def setUp(self):
        super().setUp()
        patcher = patch("corliss.membership.is_cluster_admin", return_value=False)
        patcher.start()
        self.addCleanup(patcher.stop)


class AccountPageTests(NoRosterMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.user = User.objects.create_user(
            username="alice.bsky.social",
            did=DID,
            display_name="Alice Example",
            email="alice@pds.example",
            email_confirmed=True,
        )
        self.client.force_login(self.user)

    def test_it_renders_the_current_values(self):
        resp = self.client.get(reverse("account"))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Alice Example")
        self.assertContains(resp, "alice@pds.example")
        # The two facts this page cannot change are shown beside the two it can.
        self.assertContains(resp, DID)
        self.assertContains(resp, "alice.bsky.social")

    def test_signed_out_is_sent_to_login_and_comes_back(self):
        self.client.logout()
        resp = self.client.get(reverse("account"))
        self.assertRedirects(
            resp, reverse("login"), fetch_redirect_response=False
        )
        self.assertEqual(
            self.client.session["post_login_redirect"], reverse("account")
        )

    def test_a_non_member_may_still_edit_their_name(self):
        """Deliberately not member-gated: an applicant in the queue is exactly
        the person an admin is about to read a name for.

        This user holds no `MembershipCache` row, so they would fail
        `require_membership` — which this page deliberately does not call.
        """
        resp = self.client.post(
            reverse("account"),
            {"display_name": "Alice", "email": "alice@pds.example"},
        )
        self.assertRedirects(
            resp, reverse("account"), fetch_redirect_response=False
        )
        self.user.refresh_from_db()
        self.assertEqual(self.user.display_name, "Alice")

    def test_saving_a_name_redirects_and_reports(self):
        resp = self.client.post(
            reverse("account"),
            {"display_name": "  Alice A.  ", "email": "alice@pds.example"},
            follow=True,
        )
        self.user.refresh_from_db()
        self.assertEqual(self.user.display_name, "Alice A.")  # stripped
        self.assertContains(resp, "Saved.")

    def test_changing_the_email_clears_the_confirmation(self):
        self.client.post(
            reverse("account"),
            {"display_name": "Alice Example", "email": "me@elsewhere.example"},
        )
        self.user.refresh_from_db()
        self.assertEqual(self.user.email, "me@elsewhere.example")
        self.assertFalse(self.user.email_confirmed)

    def test_an_unchanged_email_keeps_its_confirmation(self):
        """Saving a name must not quietly un-verify an address nobody touched."""
        self.client.post(
            reverse("account"),
            {"display_name": "Alice", "email": "alice@pds.example"},
        )
        self.user.refresh_from_db()
        self.assertTrue(self.user.email_confirmed)

    def test_clearing_both_fields_is_allowed(self):
        """Blank is how a member undoes an edit — the next login refills it."""
        self.client.post(reverse("account"), {"display_name": "", "email": ""})
        self.user.refresh_from_db()
        self.assertEqual(self.user.display_name, "")
        self.assertEqual(self.user.email, "")
        self.assertFalse(self.user.email_confirmed)

    def test_an_invalid_email_saves_nothing_and_says_so(self):
        resp = self.client.post(
            reverse("account"),
            {"display_name": "Changed Too", "email": "not-an-address"},
        )
        self.assertEqual(resp.status_code, 200)  # re-rendered, not redirected
        self.assertContains(resp, "not an email address")
        self.user.refresh_from_db()
        self.assertEqual(self.user.email, "alice@pds.example")
        # The name went back too — one form, one save, all or nothing.
        self.assertEqual(self.user.display_name, "Alice Example")

    def test_an_invalid_email_re_renders_what_was_typed(self):
        """Not the stored values: the member is correcting a submission, not
        starting the form over."""
        resp = self.client.post(
            reverse("account"),
            {"display_name": "Changed Too", "email": "not-an-address"},
        )
        self.assertContains(resp, "Changed Too")
        self.assertContains(resp, "not-an-address")

    def test_it_cannot_be_pointed_at_another_member(self):
        """Nothing identifying a subject is read from the request. A DID in the
        POST is ignored, not honoured."""
        other = User.objects.create_user(
            username="bob.bsky.social",
            did="did:plc:2cxgdrgtsmrbqnjkwyplmp43",
            display_name="Bob",
        )
        self.client.post(
            reverse("account"),
            {
                "display_name": "Hijacked",
                "email": "alice@pds.example",
                "did": other.did,
                "user": other.pk,
            },
        )
        other.refresh_from_db()
        self.user.refresh_from_db()
        self.assertEqual(other.display_name, "Bob")
        self.assertEqual(self.user.display_name, "Hijacked")
