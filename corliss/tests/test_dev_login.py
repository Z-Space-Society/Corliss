"""The local-development auth bypass, and the guards that keep it local.

/auth/dev-login issues a session for any handle with no authentication at all,
so the tests that matter most here are the negative ones: it must be inert
unless DEBUG and DEV_LOGIN_ENABLED are *both* on, and a production config that
sets the flag must fail startup rather than serve it.
"""

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from corliss import views
from corliss.apps import check_dev_login_requires_debug
from corliss.models import MembershipCache
from corliss.views import POST_LOGIN_REDIRECT

User = get_user_model()

DEV_URLS = "corliss.tests.urls_dev_login"

# Both guards on: the only configuration in which the bypass may work.
ENABLED = override_settings(
    ROOT_URLCONF=DEV_URLS, DEBUG=True, DEV_LOGIN_ENABLED=True
)


@ENABLED
class DevLoginTests(TestCase):
    def test_post_creates_member_and_starts_session(self):
        resp = self.client.post(
            reverse("dev_login"), {"handle": "alice.bsky.social"}
        )
        self.assertRedirects(resp, reverse("home"))

        user = User.objects.get(did="did:dev:alice.bsky.social")
        self.assertEqual(user.username, "alice.bsky.social")
        self.assertFalse(user.email_confirmed)
        self.assertIsNotNone(user.last_seen)
        self.assertEqual(
            int(self.client.session["_auth_user_id"]), user.pk
        )

    def test_did_is_a_non_registered_method_so_it_cannot_collide(self):
        """Fake members must never occupy a real atproto DID."""
        self.client.post(reverse("dev_login"), {"handle": "alice.bsky.social"})
        did = User.objects.get(username="alice.bsky.social").did
        self.assertTrue(did.startswith("did:dev:"))
        self.assertFalse(did.startswith("did:plc:"))
        self.assertFalse(did.startswith("did:web:"))

    def test_repeat_login_reuses_the_same_member(self):
        for _ in range(2):
            self.client.post(
                reverse("dev_login"), {"handle": "alice.bsky.social"}
            )
        self.assertEqual(
            User.objects.filter(did="did:dev:alice.bsky.social").count(), 1
        )

    def test_blank_handle_re_renders_the_form(self):
        resp = self.client.post(reverse("dev_login"), {"handle": "   "})
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Enter a handle.")
        self.assertFalse(User.objects.exists())

    def test_leading_at_is_stripped(self):
        self.client.post(reverse("dev_login"), {"handle": "@alice.bsky.social"})
        self.assertTrue(
            User.objects.filter(did="did:dev:alice.bsky.social").exists()
        )

    def test_handle_case_folds_to_one_member(self):
        """Handles are case-insensitive; the DIDs derived from them are not.

        Two spellings must not become two members, of which only one matches
        DEV_ADMIN_DIDS. See the note in the README's dev sign-in section.
        """
        for handle in ("Alice.BSky.Social", "alice.bsky.social"):
            self.client.post(reverse("dev_login"), {"handle": handle})
        self.assertEqual(User.objects.count(), 1)
        self.assertTrue(
            User.objects.filter(did="did:dev:alice.bsky.social").exists()
        )

    def test_get_is_rejected(self):
        """POST-only: a bare link must not be able to sign anyone in."""
        resp = self.client.get(reverse("dev_login"))
        self.assertEqual(resp.status_code, 405)

    @override_settings(DEV_ADMIN_DIDS=["did:dev:alice.bsky.social"])
    def test_a_dev_admin_gets_django_superuser(self):
        """Otherwise `/admin/` opens as an index with no model permissions —
        `is_staff` alone grants none — and looking at a row locally means
        editing settings and then running `createsuperuser` by hand. A bypass
        that needs a second setup step is not doing its job."""
        self.client.post(reverse("dev_login"), {"handle": "alice.bsky.social"})
        user = User.objects.get(did="did:dev:alice.bsky.social")
        self.assertTrue(user.is_superuser)
        self.assertTrue(user.is_staff)

    def test_an_ordinary_dev_member_does_not(self):
        """The list is the whole grant — signing in is not."""
        self.client.post(reverse("dev_login"), {"handle": "bob.bsky.social"})
        self.assertFalse(
            User.objects.get(did="did:dev:bob.bsky.social").is_superuser
        )

    def test_dropping_a_did_from_the_list_clears_the_flag(self):
        """Mirrored, not merely set — the way `_heal_staff_flag` mirrors the
        roster — so removing yourself from the list takes effect rather than
        leaving a superuser behind that nothing will ever take back."""
        with override_settings(DEV_ADMIN_DIDS=["did:dev:alice.bsky.social"]):
            self.client.post(
                reverse("dev_login"), {"handle": "alice.bsky.social"}
            )
        self.assertTrue(
            User.objects.get(did="did:dev:alice.bsky.social").is_superuser
        )

        with override_settings(DEV_ADMIN_DIDS=[]):
            self.client.post(
                reverse("dev_login"), {"handle": "alice.bsky.social"}
            )
        self.assertFalse(
            User.objects.get(did="did:dev:alice.bsky.social").is_superuser
        )

    def test_resumes_a_pending_oidc_authorize(self):
        # The resume is gated on membership exactly as `callback`'s is — one
        # helper serves both — so a dev session has to be a member's to be
        # handed onward. Refusal is `test_gate.LoginResumeGateTests`.
        MembershipCache.objects.create(
            did="did:dev:alice.bsky.social",
            active=True,
            tier="level-2",
            last_rkey="did:dev:alice.bsky.social:3lqxaaaaaaaaa",
            last_event_at="2026-01-01T00:00:00Z",
            author_did="did:plc:anadmin",
        )
        session = self.client.session
        session[POST_LOGIN_REDIRECT] = "/oidc/authorize?client_id=open-webui"
        session.save()

        resp = self.client.post(
            reverse("dev_login"), {"handle": "alice.bsky.social"}
        )
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp["Location"], "/oidc/authorize?client_id=open-webui")

    def test_offsite_redirect_target_is_ignored(self):
        session = self.client.session
        session[POST_LOGIN_REDIRECT] = "//evil.example/steal"
        session.save()

        resp = self.client.post(
            reverse("dev_login"), {"handle": "alice.bsky.social"}
        )
        self.assertRedirects(resp, reverse("home"))

    def test_login_page_offers_the_dev_form(self):
        resp = self.client.get(reverse("login"))
        self.assertContains(resp, "Dev sign-in (no auth)")


class DevLoginRefusedTests(TestCase):
    """The route exists in this URLconf; the view must still refuse."""

    @override_settings(
        ROOT_URLCONF=DEV_URLS, DEBUG=True, DEV_LOGIN_ENABLED=False
    )
    def test_404_when_flag_is_off(self):
        resp = self.client.post(
            reverse("dev_login"), {"handle": "alice.bsky.social"}
        )
        self.assertEqual(resp.status_code, 404)
        self.assertFalse(User.objects.exists())

    @override_settings(
        ROOT_URLCONF=DEV_URLS, DEBUG=False, DEV_LOGIN_ENABLED=True
    )
    def test_404_when_debug_is_off_even_though_flag_is_on(self):
        resp = self.client.post(
            reverse("dev_login"), {"handle": "alice.bsky.social"}
        )
        self.assertEqual(resp.status_code, 404)
        self.assertFalse(User.objects.exists())

    @override_settings(
        ROOT_URLCONF=DEV_URLS, DEBUG=False, DEV_LOGIN_ENABLED=False
    )
    def test_login_page_hides_the_dev_form(self):
        resp = self.client.get(reverse("login"))
        self.assertNotContains(resp, "Dev sign-in (no auth)")

    @override_settings(
        DEBUG=False,
        DEV_LOGIN_ENABLED=False,
        DEV_ADMIN_DIDS=["did:dev:alice.bsky.social"],
    )
    def test_dev_superuser_re_checks_its_own_guards(self):
        """`_apply_dev_superuser` is only ever called from `dev_login`, which is
        not even routed outside DEBUG — so this asserts the re-check, the same
        belt-and-braces the view itself does. A helper that hands out
        `is_superuser` should not be one route registration away from doing it.
        """
        user = User.objects.create_user(
            username="alice.bsky.social", did="did:dev:alice.bsky.social"
        )
        views._apply_dev_superuser(user)
        user.refresh_from_db()
        self.assertFalse(user.is_superuser)


class DevLoginSystemCheckTests(TestCase):
    """A production env file carrying the flag must fail `manage.py check`.

    The check reads DEBUG_FROM_ENV rather than DEBUG precisely so that it stays
    quiet here — the test runner forces settings.DEBUG off, and keying on that
    would make the whole suite unrunnable on a machine with the flag set.
    """

    @override_settings(DEBUG_FROM_ENV=False, DEV_LOGIN_ENABLED=True)
    def test_errors_when_enabled_without_debug(self):
        errors = check_dev_login_requires_debug(None)
        self.assertEqual([e.id for e in errors], ["corliss.E001"])

    @override_settings(DEBUG_FROM_ENV=True, DEV_LOGIN_ENABLED=True)
    def test_silent_in_local_development(self):
        self.assertEqual(check_dev_login_requires_debug(None), [])

    @override_settings(DEBUG_FROM_ENV=False, DEV_LOGIN_ENABLED=False)
    def test_silent_in_a_normal_production_config(self):
        self.assertEqual(check_dev_login_requires_debug(None), [])

    @override_settings(DEBUG=False, DEBUG_FROM_ENV=True, DEV_LOGIN_ENABLED=True)
    def test_test_runner_forcing_debug_off_does_not_trip_the_check(self):
        """Regression: this configuration is every test run on a dev machine."""
        self.assertEqual(check_dev_login_requires_debug(None), [])
