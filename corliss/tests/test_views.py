from datetime import date, datetime
from unittest.mock import patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from corliss import atproto, litellm, views
from corliss.models import AtprotoToken, MembershipCache
from corliss.views import SESSION_PREFIX

User = get_user_model()

DID = "did:plc:ewvi7nxzyoun6zhxrhs64oiz"
# Someone other than the signed-in user, for the roster-edit tests below.
STRANGER = "did:plc:2cxgdrgtsmrbqnjkwyplmp43"


def _seed_pending(test_client, state, *, did=DID, handle="alice.bsky.social"):
    """Put a pending-flow record into the session, as `login` would have."""
    session = test_client.session
    session[SESSION_PREFIX + state] = {
        "code_verifier": "verifier",
        "dpop_pem": atproto.key_to_pem(atproto.generate_key()),
        "dpop_nonce": "nonce",
        "issuer": "https://auth.example",
        "token_endpoint": "https://auth.example/token",
        "did": did,
        "pds_url": "https://pds.example.com",
        "handle": handle,
    }
    session.save()


class LoginViewTests(TestCase):
    def test_login_get_renders_form(self):
        resp = self.client.get(reverse("login"))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "name=\"handle\"")


class FooterTests(TestCase):
    """base.html's footer, rendered on every page (login is the public one)."""

    def setUp(self):
        self.html = self.client.get(reverse("login")).content.decode()

    def test_build_stamp_links_the_repo_and_the_running_version(self):
        # Shape, never a literal version: asserting v0.2.0 here would break on
        # every release and on every developer's dirty tree.
        self.assertIn(settings.REPO_URL, self.html)
        self.assertIn(settings.VERSION, self.html)
        if settings.VERSION_URL:
            self.assertIn(settings.VERSION_URL, self.html)

    def test_site_name_links_its_own_origin(self):
        self.assertIn(f'href="{settings.PUBLIC_BASE_URL}"', self.html)

    def test_no_separator_glyph_between_the_site_name_and_z_space(self):
        self.assertIn("sharedcomputer.network</a> by ", self.html)

    @override_settings(
        VERSION="v0.9.9",
        VERSION_URL="https://github.com/Z-Space-Society/Corliss/releases/tag/v0.9.9",
    )
    def test_linkable_version_renders_as_an_anchor(self):
        # The state the cluster is always in (clean checkout, exactly on a tag),
        # forced here so it's covered whatever the developer's tree looks like.
        resp = self.client.get(reverse("login"))
        self.assertContains(resp, ">v0.9.9</a>")

    @override_settings(VERSION="v0.9.9-dirty", VERSION_URL=None)
    def test_unlinkable_version_renders_as_bare_text(self):
        resp = self.client.get(reverse("login"))
        self.assertContains(resp, "v0.9.9-dirty")
        self.assertNotContains(resp, ">v0.9.9-dirty</a>")

    @override_settings(VERSION="", VERSION_URL=None)
    def test_unresolved_version_omits_the_stamp_entirely(self):
        resp = self.client.get(reverse("login"))
        self.assertNotContains(resp, "footer__version")
        # The copyright line is untouched by the version's absence.
        self.assertContains(resp, "sharedcomputer.network")


MANAGE_URL = "https://manage.example.com"


def _at(text):
    """An aware UTC datetime from the registry's ISO-8601-with-Z format."""
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def _grant(did=DID, *, tier="level-2", active=True):
    """A membership grant as the registry's push would have left it."""
    MembershipCache.objects.create(
        did=did,
        active=active,
        tier=tier,
        last_rkey=f"{did}:3lqxaaaaaaaaa",
        last_event_at="2026-01-01T00:00:00Z",
        author_did="did:plc:anadmin",
    )


class NoRosterMixin:
    """Pin ELEVATE to False unless a test says otherwise.

    `user.is_cluster_admin` reads the roster out of the service DID's repo, so
    without this every test's answer would depend on the developer's
    SCN_SERVICE_DID — and reach the network to discover it is blank.
    """

    def setUp(self):
        super().setUp()
        patcher = patch("corliss.membership.is_cluster_admin", return_value=False)
        patcher.start()
        self.addCleanup(patcher.stop)


class HomeViewTests(NoRosterMixin, TestCase):
    """`/` — signed out, signed in without membership, signed in with it."""

    def setUp(self):
        super().setUp()
        self.user = User.objects.create_user(username="alice.bsky.social", did=DID)

    def test_anonymous_gets_the_page_not_a_redirect(self):
        # Was @login_required until the home page grew a signed-out state.
        resp = self.client.get(reverse("home"))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "The Shared Computer Network")

    def test_signed_out_home_does_not_restate_the_login_form(self):
        # The nav already links sign-in and login.html owns the form. A second
        # copy here is a second thing to keep in step.
        resp = self.client.get(reverse("home"))
        self.assertNotContains(resp, 'name="handle"')

    def test_non_member_is_told_so_and_offered_the_apply_button(self):
        # A real non-member has a PDS — it is resolved at login — and no
        # application yet. Both halves matter: the button is held back without
        # a PDS to write to, and replaced by the pending state once there is a
        # record to show.
        self.user.pds_url = "https://pds.example.com"
        self.user.save(update_fields=["pds_url"])
        self.client.force_login(self.user)
        with patch.object(atproto, "find_record", return_value=None):
            resp = self.client.get(reverse("home"))
        self.assertContains(resp, "not a member yet")
        self.assertContains(resp, "Apply for membership")

    def test_member_sees_no_apply_button(self):
        _grant()
        self.client.force_login(self.user)
        resp = self.client.get(reverse("home"))
        self.assertNotContains(resp, "Apply for membership")

    @override_settings(CHAT_URL="https://chat.example.com")
    def test_member_is_welcomed_and_pointed_at_both_ways_in(self):
        _grant()
        self.client.force_login(self.user)
        resp = self.client.get(reverse("home"))
        self.assertContains(resp, "Welcome to the cluster")
        self.assertContains(resp, "https://chat.example.com")
        self.assertContains(resp, reverse("api"))

    @override_settings(CHAT_URL="")
    def test_no_chat_url_drops_the_chat_block_but_keeps_the_api_one(self):
        # Same rule the nav follows: the page must not offer what is not
        # deployed. The API half is served by this app and always there.
        _grant()
        self.client.force_login(self.user)
        resp = self.client.get(reverse("home"))
        self.assertNotContains(resp, "Open chat")
        self.assertContains(resp, "Create an API key")

    def test_a_non_member_is_not_welcomed_in(self):
        self.client.force_login(self.user)
        resp = self.client.get(reverse("home"))
        self.assertNotContains(resp, "Welcome to the cluster")
        self.assertContains(resp, "not a member yet")

    def test_identity_is_not_restated_on_the_page(self):
        # Handle and DID live in the nav's account menu. The page carrying its
        # own copy is what the account card was.
        self.client.force_login(self.user)
        resp = self.client.get(reverse("home"))
        self.assertNotContains(resp, "account-card")


class NavMenuTests(NoRosterMixin, TestCase):
    """The nav's Manage menu, rendered by base.html on every page.

    Its two links answer to two different authorities on purpose: the console to
    the atproto roster, the Django admin to Django's own permissions.
    """

    def setUp(self):
        super().setUp()
        self.user = User.objects.create_user(username="alice.bsky.social", did=DID)

    def _as_cluster_admin(self):
        patcher = patch("corliss.membership.is_cluster_admin", return_value=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_anonymous_sees_no_manage_menu(self):
        resp = self.client.get(reverse("home"))
        self.assertNotContains(resp, ">Manage<")

    def test_plain_member_sees_no_manage_menu(self):
        _grant()
        self.client.force_login(self.user)
        resp = self.client.get(reverse("home"))
        self.assertNotContains(resp, ">Manage<")

    @override_settings(MANAGE_URL=MANAGE_URL)
    def test_cluster_admin_sees_the_console_but_not_the_django_admin(self):
        # The roster grants the console alone. Handing it the Django admin as
        # well would let a roster edit reach the session and OIDC client tables.
        self._as_cluster_admin()
        self.client.force_login(self.user)
        resp = self.client.get(reverse("home"))
        self.assertContains(resp, reverse("manage"))
        self.assertNotContains(resp, ">Django<")

    @override_settings(MANAGE_URL=MANAGE_URL)
    def test_the_manage_console_is_not_in_the_nav_even_when_configured(self):
        # A configured MANAGE_URL no longer buys a nav entry: /manage/ covers
        # what that console did, and two entries onto the same job only ask the
        # reader which one is current. The setting still feeds the fallback link
        # on /manage/, so it is the *nav* this asserts about, not the setting.
        self._as_cluster_admin()
        self.client.force_login(self.user)
        resp = self.client.get(reverse("home"))
        self.assertNotContains(resp, MANAGE_URL)
        self.assertNotContains(resp, "Manage Console")

    @override_settings(MANAGE_URL=MANAGE_URL)
    def test_console_link_survives_an_empty_membership_cache(self):
        # The recovery path. The roster is read from the service DID's repo and
        # never depends on this table, so an admin locked out here would be
        # locked out of the console that repopulates it.
        self.assertFalse(MembershipCache.objects.exists())
        self._as_cluster_admin()
        self.client.force_login(self.user)
        resp = self.client.get(reverse("home"))
        self.assertContains(resp, reverse("manage"))

    @override_settings(MANAGE_URL=MANAGE_URL)
    def test_superuser_sees_the_django_admin_without_being_on_the_roster(self):
        self.user.is_superuser = True
        self.user.save(update_fields=["is_superuser"])
        self.client.force_login(self.user)
        resp = self.client.get(reverse("home"))
        self.assertContains(resp, reverse("admin:index"))
        self.assertNotContains(resp, "Manage Console")

    @override_settings(MANAGE_URL="")
    def test_cluster_admin_with_no_manage_url_still_gets_the_corliss_console(self):
        # The menu-onto-nothing case this used to guard is now unreachable: the
        # Corliss console is served by this app, so a cluster admin always has
        # at least one entry and no setting can leave it pointing nowhere. The
        # protection that still matters is that the *unconfigured* link stays
        # absent rather than rendering an empty href.
        self._as_cluster_admin()
        self.client.force_login(self.user)
        resp = self.client.get(reverse("home"))
        self.assertContains(resp, reverse("manage"))
        self.assertNotContains(resp, "Manage Console")

    @override_settings(API_URL="https://api.example.com")
    def test_cluster_admin_sees_the_litellm_admin_link(self):
        self._as_cluster_admin()
        self.client.force_login(self.user)
        resp = self.client.get(reverse("home"))
        self.assertContains(resp, "https://api.example.com/ui/")
        self.assertContains(resp, ">LiteLLM<")

    @override_settings(API_URL="https://api.example.com/")
    def test_a_trailing_slash_on_api_url_does_not_double_up(self):
        # API_URL is operator-set, so it can arrive either way.
        self._as_cluster_admin()
        self.client.force_login(self.user)
        resp = self.client.get(reverse("home"))
        self.assertContains(resp, "https://api.example.com/ui/")
        self.assertNotContains(resp, "com//ui/")

    @override_settings(API_URL="https://api.example.com")
    def test_a_plain_member_never_sees_the_litellm_admin_link(self):
        # The proxy's admin UI is not a member surface, and the /api/ page they
        # do get is a different thing entirely.
        _grant()
        self.client.force_login(self.user)
        resp = self.client.get(reverse("home"))
        self.assertNotContains(resp, ">LiteLLM<")

    @override_settings(API_URL="")
    def test_no_api_url_drops_the_link_rather_than_pointing_at_slash_ui(self):
        self._as_cluster_admin()
        self.client.force_login(self.user)
        resp = self.client.get(reverse("home"))
        self.assertNotContains(resp, ">LiteLLM<")
        self.assertNotContains(resp, '"/ui/"')

    @override_settings(HAPPYVIEW_URL="https://view.example.com")
    def test_cluster_admin_sees_the_happyview_link(self):
        self._as_cluster_admin()
        self.client.force_login(self.user)
        resp = self.client.get(reverse("home"))
        self.assertContains(resp, "https://view.example.com")
        self.assertContains(resp, ">HappyView<")

    @override_settings(PROXMOX_URL="https://pve.example.lan:8006")
    def test_cluster_admin_sees_the_proxmox_link_when_there_is_one(self):
        self._as_cluster_admin()
        self.client.force_login(self.user)
        resp = self.client.get(reverse("home"))
        self.assertContains(resp, ">Proxmox<")

    @override_settings(PROXMOX_URL="", HAPPYVIEW_URL="")
    def test_unconfigured_service_consoles_are_absent_not_empty_hrefs(self):
        # Proxmox is blank on the cluster today — the host is LAN-only and not a
        # Caddy route — so this is the live case, not a hypothetical one.
        self._as_cluster_admin()
        self.client.force_login(self.user)
        resp = self.client.get(reverse("home"))
        self.assertNotContains(resp, ">Proxmox<")
        self.assertNotContains(resp, ">HappyView<")

    def test_cluster_admin_sees_systems(self):
        self._as_cluster_admin()
        self.client.force_login(self.user)
        resp = self.client.get(reverse("home"))
        self.assertContains(resp, reverse("systems"))

    def test_a_plain_member_sees_no_systems_link(self):
        _grant()
        self.client.force_login(self.user)
        resp = self.client.get(reverse("home"))
        self.assertNotContains(resp, reverse("systems"))


class SystemsViewTests(NoRosterMixin, TestCase):
    """`/systems/` — the stack, for cluster admins.

    A stub, so what is worth asserting is the gate and the honesty of the
    status column: it must not claim anything is up that nobody checked.
    """

    def setUp(self):
        super().setUp()
        self.user = User.objects.create_user(username="alice.bsky.social", did=DID)

    def _as_cluster_admin(self):
        patcher = patch("corliss.membership.is_cluster_admin", return_value=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_cluster_admin_sees_the_whole_stack(self):
        self._as_cluster_admin()
        self.client.force_login(self.user)
        resp = self.client.get(reverse("systems"))
        self.assertEqual(resp.status_code, 200)
        for service in ("Garage", "PostgreSQL", "Redis", "Caddy",
                        "HappyView", "LiteLLM", "Corliss", "Open WebUI"):
            self.assertContains(resp, service)

    def test_unchecked_services_say_unknown_rather_than_up(self):
        # The whole point of the stub. A page that guessed would be worse than
        # one that admits it has not looked.
        self._as_cluster_admin()
        self.client.force_login(self.user)
        resp = self.client.get(reverse("systems"))
        self.assertContains(resp, "Unknown")
        self.assertContains(resp, "wired up yet")

    def test_a_non_admin_gets_404_not_403(self):
        # A non-admin has no business learning the page exists — same posture
        # as /manage/.
        _grant()
        self.client.force_login(self.user)
        self.assertEqual(self.client.get(reverse("systems")).status_code, 404)

    def test_an_anonymous_visitor_is_bounced_through_login(self):
        resp = self.client.get(reverse("systems"))
        self.assertRedirects(resp, reverse("login"))


class ManageViewTests(NoRosterMixin, TestCase):
    """`/manage/` — the cluster console.

    The load-bearing test is the rebuild one: this page must open for an admin
    when the membership cache is empty, because the button that repopulates the
    cache lives on it. Gating it on anything stored in the database would make
    the recovery path depend on the thing being recovered.
    """

    def setUp(self):
        super().setUp()
        self.user = User.objects.create_user(username="alice.bsky.social", did=DID)
        # The console resolves the DIDs it shows to handles, which for anyone
        # who has never signed in here is a DID-document read. Pinned to a
        # failure so the tables fall back to DIDs rather than the suite
        # depending on plc.directory being up.
        cache.clear()
        self.addCleanup(cache.clear)
        patcher = patch.object(
            atproto, "fetch_did_document", side_effect=atproto.OAuthError("no net")
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        # The page reads the application queue on every render. Pinned empty by
        # default so the tests below stay about what they are about — and so
        # that the ones which configure a registry URL cannot reach for it.
        self._applications([])

    def _applications(self, applications, unreadable=0, truncated=False):
        from corliss import membership

        patcher = patch.object(
            membership.MembershipRegistry,
            "fetch_applications",
            return_value=membership.ApplicationList(
                applications, unreadable, truncated
            ),
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def _as_cluster_admin(self):
        patcher = patch("corliss.membership.is_cluster_admin", return_value=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _roster(self, *entries):
        from corliss import membership

        return patch.object(
            membership, "fetch_roster", return_value=membership.Roster(list(entries))
        )

    def test_anonymous_is_bounced_through_login_and_resumes_here(self):
        resp = self.client.get(reverse("manage"))
        self.assertRedirects(resp, reverse("login"))
        self.assertEqual(
            self.client.session["post_login_redirect"], reverse("manage")
        )

    def test_a_signed_in_non_admin_gets_a_404_not_a_403(self):
        # A non-admin has no business learning the page exists.
        _grant()
        self.client.force_login(self.user)
        self.assertEqual(self.client.get(reverse("manage")).status_code, 404)

    def test_an_admin_sees_the_member_roll(self):
        _grant(tier="level-5")
        self._as_cluster_admin()
        self.client.force_login(self.user)

        with self._roster():
            resp = self.client.get(reverse("manage"))

        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, DID)
        self.assertContains(resp, "level-5")

    def test_the_queue_says_who_has_asked_and_what_they_said(self):
        from corliss import membership

        self._applications(
            [membership.Application(
                "did:plc:applicant", _at("2026-08-17T13:44:05Z"), "HEYO"
            )]
        )
        self._as_cluster_admin()
        self.client.force_login(self.user)

        with self._roster():
            resp = self.client.get(reverse("manage"))

        self.assertContains(resp, "did:plc:applicant")
        self.assertContains(resp, "HEYO")
        self.assertContains(resp, "2026-08-17")
        self.assertContains(resp, "1 awaiting a decision")

    def test_applications_already_decided_are_left_out_but_counted(self):
        """The queue is the people nobody has answered, not everyone who ever
        asked. Listing the decided ones made this a second copy of the member
        table below it."""
        from corliss import membership

        _grant(did="did:plc:member")
        MembershipCache.objects.create(
            did="did:plc:exmember",
            active=False,
            tier="level-1",
            last_rkey="did:plc:exmember:3lqxaaaaaaaab",
            last_event_at="2026-09-01T00:00:00Z",
            author_did="did:plc:anadmin",
        )
        # Each decided application predates the event that decided it, which is
        # the ordinary order of things: you ask, then you are answered.
        # `_grant` stamps 2026-01-01; the revocation above stamps 2026-09-01.
        self._applications([
            membership.Application("did:plc:member", _at("2025-12-01T00:00:00Z")),
            membership.Application("did:plc:exmember", _at("2026-08-02T00:00:00Z")),
            membership.Application("did:plc:applicant", _at("2026-08-03T00:00:00Z")),
        ])
        self._as_cluster_admin()
        self.client.force_login(self.user)

        with self._roster():
            resp = self.client.get(reverse("manage"))

        # Scoped to the applications panel: both decided DIDs still appear
        # further down, in the member table, which is the whole point of not
        # repeating them here.
        html = " ".join(resp.content.decode().split())
        # Sliced between section headings and then picked by the heading's own
        # text, not by position: the sections have been reordered once already,
        # and an index would have kept passing while asserting about whichever
        # section happened to be second.
        queue = next(
            section
            for section in html.split('<h2 class="section-title"')
            if section.startswith(">Applications</h2>")
        )
        self.assertIn("did:plc:applicant", queue)
        # Both were answered before their application on file, so neither is
        # waiting — including the revoked one, whose decision was "no longer".
        self.assertNotIn("did:plc:member", queue)
        self.assertNotIn("did:plc:exmember", queue)
        # Counted, not silently dropped: the same posture as `unreadable`.
        self.assertIn("1 awaiting a decision", queue)
        self.assertIn("2 already-decided applications are on file", queue)

    def test_applying_again_after_a_decision_puts_them_back_in_the_queue(self):
        """The case a "has a cache row, therefore handled" rule would drop: a
        revoked member asking to come back writes a fresh record at the same
        rkey, and would otherwise be invisible forever."""
        from corliss import membership

        MembershipCache.objects.create(
            did="did:plc:exmember",
            active=False,
            tier="level-1",
            last_rkey="did:plc:exmember:3lqxaaaaaaaab",
            last_event_at="2026-02-01T00:00:00Z",
            author_did="did:plc:anadmin",
        )
        self._applications([
            membership.Application(
                "did:plc:exmember", _at("2026-08-02T00:00:00Z"), "let me back in"
            ),
        ])
        self._as_cluster_admin()
        self.client.force_login(self.user)

        with self._roster():
            resp = self.client.get(reverse("manage"))

        self.assertContains(resp, "did:plc:exmember")
        self.assertContains(resp, "let me back in")
        # Flagged rather than shown as an ordinary applicant: readmitting
        # someone is a different decision from admitting a stranger.
        self.assertContains(resp, "asked again")

    def test_the_applicant_links_to_their_profile_by_did_not_by_handle(self):
        """Deciding on a stranger means looking them up, so the handle is a
        link out to their profile.

        **Addressed by DID.** bsky.app takes either, but a handle is mutable and
        display-only everywhere else in this app; one that changed since the
        application was written would land on a 404 or on whoever holds it now.
        The handle is still what is *displayed* — that half is unchanged."""
        from corliss import membership

        self._applications([
            membership.Application("did:plc:applicant", _at("2026-08-01T00:00:00Z")),
        ])
        with patch.object(
            membership,
            "handles_for",
            return_value={"did:plc:applicant": "nandi.uk"},
        ):
            self._as_cluster_admin()
            self.client.force_login(self.user)

            with self._roster():
                resp = self.client.get(reverse("manage"))

        self.assertContains(resp, "https://bsky.app/profile/did:plc:applicant")
        self.assertNotContains(resp, "https://bsky.app/profile/nandi.uk")
        # Displayed by handle, as everywhere else.
        self.assertContains(resp, ">nandi.uk</a>")
        # A detour taken mid-decision: the queue should still be there after it.
        self.assertContains(resp, 'target="_blank" rel="noopener"')

    def test_an_empty_queue_with_history_does_not_claim_nobody_applied(self):
        from corliss import membership

        _grant(did="did:plc:member")  # stamps 2026-01-01
        self._applications([
            membership.Application("did:plc:member", _at("2025-12-01T00:00:00Z")),
        ])
        self._as_cluster_admin()
        self.client.force_login(self.user)

        with self._roster():
            resp = self.client.get(reverse("manage"))

        self.assertContains(resp, "Nothing is waiting")
        self.assertNotContains(resp, "Nobody has applied")

    def test_records_that_could_not_be_read_are_reported_as_a_count(self):
        from corliss import membership

        self._applications(
            [membership.Application("did:plc:applicant", _at("2026-08-01T00:00:00Z"))],
            unreadable=2,
        )
        self._as_cluster_admin()
        self.client.force_login(self.user)

        with self._roster():
            resp = self.client.get(reverse("manage"))

        # Whitespace-normalised: the sentence wraps in the template, and the
        # assertion is about what a reader sees, not where the newlines fell.
        html = " ".join(resp.content.decode().split())
        self.assertIn("2 records could not be read", html)

    def test_an_unreadable_queue_shows_a_failure_not_an_empty_one(self):
        """Same posture as the roster: "could not find out" is not "none"."""
        from corliss import membership

        self._as_cluster_admin()
        self.client.force_login(self.user)

        with self._roster():
            with patch.object(
                membership.MembershipRegistry,
                "fetch_applications",
                side_effect=membership.RegistryError("registry returned HTTP 500"),
            ):
                resp = self.client.get(reverse("manage"))

        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "could not be read")
        self.assertContains(resp, "registry returned HTTP 500")
        self.assertNotContains(resp, "Nobody has applied")

    def test_an_admin_reaches_it_with_an_empty_cache(self):
        """The rebuild case, and the reason this page is gated on the roster."""
        self.assertFalse(MembershipCache.objects.exists())
        self._as_cluster_admin()
        self.client.force_login(self.user)

        with self._roster():
            resp = self.client.get(reverse("manage"))

        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "cache is empty")

    def test_the_admin_column_marks_current_admins_only(self):
        """Admin is a column on the member table now, read from the local
        `is_staff` mirror. A departed admin's grants stay valid —
        `Roster.was_admin_at` reads that history — but they are not an admin
        today, and the column answers only today's question."""
        _grant()
        self.user.is_staff = True
        self.user.save(update_fields=["is_staff"])
        _grant(STRANGER)
        User.objects.create_user(username="bob.bsky.social", did=STRANGER)
        self._as_cluster_admin()
        self.client.force_login(self.user)

        with self._roster():
            resp = self.client.get(reverse("manage"))

        html = resp.content.decode()
        self.assertEqual(html.count(">Admin</span>"), 1)

    def test_only_active_members_are_listed(self):
        """A revoked person is history, and the registry is where history
        lives. Re-inviting the same handle readmits them, which is what
        readmission always was."""
        _grant()
        _grant(STRANGER, active=False)
        User.objects.create_user(username="bob.bsky.social", did=STRANGER)
        self._as_cluster_admin()
        self.client.force_login(self.user)

        with self._roster():
            resp = self.client.get(reverse("manage"))

        self.assertContains(resp, "alice.bsky.social")
        self.assertNotContains(resp, "bob.bsky.social")

    def test_members_are_shown_by_handle_with_the_did_on_the_title(self):
        """Handles are what a person reads; a DID is never text. Resolved from
        the `User` row for anyone who has signed in, so the common case costs
        no network at all.

        The member cell is a link into that member's panel, so the handle is the
        link's text and the DID is the link's title — the cell's, as it was, one
        element in. What must not appear is a DID in the table itself."""
        _grant()
        self._as_cluster_admin()
        self.client.force_login(self.user)

        with self._roster():
            resp = self.client.get(reverse("manage"))

        self.assertContains(resp, ">alice.bsky.social</a>")
        # Not dropped — it is the title on the cell that replaced it.
        self.assertContains(resp, f'title="{DID}"')

    def test_the_member_controls_are_in_a_panel_and_not_in_the_table(self):
        """A `Change` column sets the table's width from its widest control
        rather than from anything anybody reads, which is what made this table
        scroll sideways. The writes moved to a panel opened from the handle.

        The panel opens on `:target`, so it needs no script — this page holds
        the reconcile button and is how a broken deployment gets fixed."""
        _grant()
        self._as_cluster_admin()
        self.client.force_login(self.user)

        # The writes render only for an admin holding a registry session, which
        # is the point of this test: it is asserting *where* they are.
        with self._roster(), patch.object(views, "_can_decide", return_value=True):
            resp = self.client.get(reverse("manage"))

        self.assertNotContains(resp, "<th>Change</th>")
        self.assertNotContains(resp, "<th>Granted by</th>")
        # The handle is the way in, and what it opens holds the writes.
        self.assertContains(resp, 'href="#member-1"')
        self.assertContains(resp, 'id="member-1"')
        self.assertContains(resp, "Set Tier")
        self.assertContains(resp, "Revoke")
        # Closing is an ordinary link to the section above, not a script.
        self.assertContains(resp, 'id="members"')
        self.assertContains(resp, 'href="#members"')

    # Pinned rather than left to the ambient environment: this asserts the
    # UNCONFIGURED page, so a developer whose .env carries real registry
    # settings would otherwise watch it fail on a checkout they had not touched.
    @override_settings(
        MEMBERSHIP_REGISTRY_URL="",
        MEMBERSHIP_REGISTRY_CLIENT_KEY="",
        MEMBERSHIP_REGISTRY_TOKEN="",
    )
    def test_the_button_is_disabled_with_a_reason_when_unconfigured(self):
        self._as_cluster_admin()
        self.client.force_login(self.user)

        with self._roster():
            resp = self.client.get(reverse("manage"))

        self.assertContains(resp, "Not configured")
        self.assertNotContains(resp, "Reconcile memberships")

    @override_settings(
        MEMBERSHIP_REGISTRY_URL="https://registry.example",
        MEMBERSHIP_REGISTRY_CLIENT_KEY="hvc_key",
        MEMBERSHIP_REGISTRY_TOKEN="token",
    )
    def test_posting_runs_the_same_reconcile_the_command_runs(self):
        from corliss import membership

        self._as_cluster_admin()
        self.client.force_login(self.user)
        report = membership.ReconcileReport()
        report.applied.append(DID)

        with self._roster():
            with patch.object(
                membership.MembershipRegistry, "reconcile", return_value=report
            ) as run:
                resp = self.client.post(reverse("manage"))

        run.assert_called_once_with()
        self.assertContains(resp, "Complete")

    @override_settings(
        MEMBERSHIP_REGISTRY_URL="https://registry.example",
        MEMBERSHIP_REGISTRY_CLIENT_KEY="hvc_key",
        MEMBERSHIP_REGISTRY_TOKEN="token",
    )
    def test_the_console_never_previews(self):
        """The Preview button is gone, and a stray `dry_run` must not revive it.

        It sat beside the real action and mostly invited clicking the wrong one.
        Previewing still exists where it is asked for deliberately —
        `manage.py reconcile_membership --dry-run`, through this same entry
        point — so what must not happen is this page quietly running one because
        a form field said so.
        """
        from corliss import membership

        self._as_cluster_admin()
        self.client.force_login(self.user)

        with self._roster():
            with patch.object(
                membership.MembershipRegistry,
                "reconcile",
                return_value=membership.ReconcileReport(),
            ) as run:
                resp = self.client.post(reverse("manage"), {"dry_run": "1"})

        run.assert_called_once_with()
        self.assertNotContains(resp, "Preview")

    @override_settings(
        MEMBERSHIP_REGISTRY_URL="https://registry.example",
        MEMBERSHIP_REGISTRY_CLIENT_KEY="hvc_key",
        MEMBERSHIP_REGISTRY_TOKEN="token",
    )
    def test_an_incomplete_report_says_so_rather_than_reading_as_success(self):
        """The proof obligation, on screen: unresolved and orphans are blockers."""
        from corliss import membership

        self._as_cluster_admin()
        self.client.force_login(self.user)
        report = membership.ReconcileReport()
        report.unresolved.append(
            {"did": DID, "rkey": f"{DID}:3lqxaaaaaaaaa", "error": "grant has no 'tier'"}
        )

        with self._roster():
            with patch.object(
                membership.MembershipRegistry, "reconcile", return_value=report
            ):
                resp = self.client.post(reverse("manage"))

        self.assertContains(resp, "Incomplete")
        self.assertContains(resp, "no &#x27;tier&#x27;")

    @override_settings(
        MEMBERSHIP_REGISTRY_URL="https://registry.example",
        MEMBERSHIP_REGISTRY_CLIENT_KEY="hvc_key",
        MEMBERSHIP_REGISTRY_TOKEN="token",
    )
    def test_a_registry_failure_renders_as_a_failure_not_an_empty_report(self):
        from corliss import membership

        self._as_cluster_admin()
        self.client.force_login(self.user)

        with self._roster():
            with patch.object(
                membership.MembershipRegistry,
                "reconcile",
                side_effect=membership.RegistryError("could not reach the registry"),
            ):
                resp = self.client.post(reverse("manage"))

        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "could not run")
        self.assertContains(resp, "could not reach the registry")

    def test_an_unreadable_roster_shows_a_failure_not_an_empty_table(self):
        """"Could not find out" and "there are no admins" are different facts."""
        from corliss import membership

        self._as_cluster_admin()
        self.client.force_login(self.user)

        with patch.object(
            membership, "fetch_roster", side_effect=membership.RosterError("PDS down")
        ):
            resp = self.client.get(reverse("manage"))

        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "could not be read")
        self.assertContains(resp, "PDS down")
        # And says what the page is falling back to, rather than presenting the
        # mirror as though it were the roster.
        self.assertContains(resp, "may be stale")

    # --- Editing the roster from the console ------------------------------
    #
    # The handler is Post/Redirect/Get for a reason the approve path does not
    # have: a roster edit is a read-modify-write, so a re-posted form appends a
    # *second* entry for the same person rather than being absorbed by
    # latest-event-wins.

    def _post_roster(self, action, subject):
        from corliss import membership

        self._as_cluster_admin()
        self.client.force_login(self.user)
        patcher = patch.object(membership, "appoint_admin", return_value="")
        appoint = patcher.start()
        self.addCleanup(patcher.stop)
        patcher2 = patch.object(membership, "dismiss_admin", return_value="")
        dismiss = patcher2.start()
        self.addCleanup(patcher2.stop)
        resp = self.client.post(
            reverse("manage"), {"action": action, "subject": subject}
        )
        return resp, appoint, dismiss

    def test_making_an_admin_redirects_rather_than_rendering(self):
        resp, appoint, _ = self._post_roster("add_admin", STRANGER)

        self.assertRedirects(resp, reverse("manage"), fetch_redirect_response=False)
        appoint.assert_called_once_with(DID, STRANGER)

    def test_removing_an_admin_redirects_rather_than_rendering(self):
        resp, _, dismiss = self._post_roster("remove_admin", STRANGER)

        self.assertRedirects(resp, reverse("manage"), fetch_redirect_response=False)
        dismiss.assert_called_once_with(DID, STRANGER)

    def test_a_refusal_reaches_the_next_page_as_an_error(self):
        from corliss import membership

        self._as_cluster_admin()
        self.client.force_login(self.user)

        with patch.object(
            membership,
            "appoint_admin",
            side_effect=membership.RosterError("already a current admin"),
        ):
            self.client.post(
                reverse("manage"), {"action": "add_admin", "subject": STRANGER}
            )
            with self._roster():
                resp = self.client.get(reverse("manage"))

        self.assertContains(resp, "already a current admin")

    def test_a_partial_success_says_so_rather_than_claiming_success(self):
        """The roster write landed and the space-access half did not. Reporting
        only "done" would leave an admin who cannot approve anyone and an
        operator with no idea why."""
        from corliss import membership

        self._as_cluster_admin()
        self.client.force_login(self.user)

        with patch.object(
            membership,
            "appoint_admin",
            return_value="registry space access was not granted",
        ):
            self.client.post(
                reverse("manage"), {"action": "add_admin", "subject": STRANGER}
            )
            with self._roster():
                resp = self.client.get(reverse("manage"))

        self.assertContains(resp, "registry space access was not granted")

    def test_naming_nobody_is_refused_without_a_write(self):
        from corliss import membership

        self._as_cluster_admin()
        self.client.force_login(self.user)

        with patch.object(membership, "appoint_admin") as appoint:
            self.client.post(reverse("manage"), {"action": "add_admin", "subject": " "})

        appoint.assert_not_called()

    def test_a_non_admin_cannot_post_a_roster_edit(self):
        """The page 404s for them, and so must the action — a form is not the
        access control."""
        from corliss import membership

        self.client.force_login(self.user)

        with patch.object(membership, "appoint_admin") as appoint:
            resp = self.client.post(
                reverse("manage"), {"action": "add_admin", "subject": STRANGER}
            )

        self.assertEqual(resp.status_code, 404)
        appoint.assert_not_called()

    def test_a_handle_is_resolved_before_the_roster_is_touched(self):
        """Admins are named by handle in the console, and granting admin must
        not trust the third-party resolver to say which DID that is."""
        from corliss import membership

        self._as_cluster_admin()
        self.client.force_login(self.user)

        with patch.object(
            atproto, "resolve_handle_for_admin", return_value=STRANGER
        ) as resolve:
            with patch.object(membership, "appoint_admin", return_value="") as appoint:
                self.client.post(
                    reverse("manage"),
                    {"action": "add_admin", "subject": "boris.bsky.social"},
                )

        resolve.assert_called_once_with("boris.bsky.social")
        appoint.assert_called_once_with(DID, STRANGER)

    def test_an_unresolvable_handle_is_an_error_not_a_crash(self):
        from corliss import membership

        self._as_cluster_admin()
        self.client.force_login(self.user)

        with patch.object(
            atproto,
            "resolve_handle_for_admin",
            side_effect=atproto.OAuthError("no such handle"),
        ):
            with patch.object(membership, "appoint_admin") as appoint:
                self.client.post(
                    reverse("manage"),
                    {"action": "add_admin", "subject": "nope.invalid"},
                )
            with self._roster():
                resp = self.client.get(reverse("manage"))

        appoint.assert_not_called()
        self.assertContains(resp, "no such handle")

    @override_settings(SCN_SERVICE_DID="did:plc:n4mzxx6z4ehnswc7znswtfr2")
    def test_a_missing_service_session_is_visible_before_it_is_needed(self):
        """It is spent by nothing else, so a lapse would otherwise surface at
        the moment somebody tries to appoint an admin."""
        self._as_cluster_admin()
        self.client.force_login(self.user)

        with self._roster():
            resp = self.client.get(reverse("manage"))

        # The lock is offered, closed, and says what it is for. "Authenticate",
        # never "sign in" — the admin stays signed in as themselves throughout.
        self.assertContains(resp, "lock--closed")
        self.assertContains(resp, "Authenticate")
        self.assertNotContains(resp, "lock--open")

    @override_settings(SCN_SERVICE_DID="")
    def test_an_unconfigured_deployment_says_so_rather_than_looking_broken(self):
        """No `SCN_SERVICE_DID` is a deployment that never wired the registry
        up — a different fix from a lapsed session, so a different message.

        Overridden explicitly because the suite inherits the developer's own
        `.env`, where this is set."""
        self._as_cluster_admin()
        self.client.force_login(self.user)

        with self._roster():
            resp = self.client.get(reverse("manage"))

        # No service account configured means no lock at all: there is nothing
        # to authenticate, and a control that cannot work should not be offered.
        self.assertNotContains(resp, "lock--closed")
        self.assertNotContains(resp, "lock--open")


class AccountMenuTests(NoRosterMixin, TestCase):
    """The nav's account menu — identity and standing, on every page."""

    def setUp(self):
        super().setUp()
        self.user = User.objects.create_user(username="alice.bsky.social", did=DID)
        self.client.force_login(self.user)

    def test_shows_the_did_and_a_sign_out_link(self):
        resp = self.client.get(reverse("home"))
        self.assertContains(resp, DID)
        self.assertContains(resp, reverse("logout"))

    def test_membership_reads_none_without_a_grant(self):
        resp = self.client.get(reverse("home"))
        self.assertContains(resp, "Membership: <span")
        self.assertContains(resp, ">none<")

    def test_membership_reads_the_granted_tier(self):
        _grant(tier="level-1")
        resp = self.client.get(reverse("home"))
        self.assertContains(resp, ">level 1<")

    def test_revoked_member_reads_none_not_their_last_tier(self):
        # MembershipCache keeps `tier` after a revocation for audit. Showing it
        # would advertise an entitlement that has already ended.
        _grant(tier="level-1")
        MembershipCache.objects.filter(did=DID).update(active=False)
        resp = self.client.get(reverse("home"))
        self.assertContains(resp, ">none<")
        self.assertNotContains(resp, ">level 1<")


LITELLM_SETTINGS = {
    "LITELLM_URL": "http://10.1.1.112:4000",
    "LITELLM_PROVISIONER_KEY": "sk-provisioner",
    "LITELLM_MAX_KEYS_PER_MEMBER": 5,
}


def _key(token="abc123def456", alias="alice.bsky.social/laptop"):
    return litellm.ApiKey(
        token=token, masked="sk-...4f2a", alias=alias,
        spend=0, created_at="2026-08-01", blocked=False,
    )


def _model(name, mode="chat", context=131072):
    return litellm.Model(name=name, mode=mode, context=context)


class ApiViewTests(NoRosterMixin, TestCase):
    """`/api/` — the member's keys.

    Member-gated, so these sign in as one. The gate's own behaviour on this page
    — who is refused, and where they land — is `test_gate.ApiGateTests`, and the
    LiteLLM client's own rules are `test_litellm`. What is asserted here is the
    wiring between them: that the page asks about the right member, that a POST
    cannot outrun the gate, and that the secret is shown once.
    """

    def setUp(self):
        super().setUp()
        self.user = User.objects.create_user(username="alice.bsky.social", did=DID)
        _grant()
        self.client.force_login(self.user)

        # `/api/` asks LiteLLM three things and each test here is about at most
        # one of them. The catalogue is stubbed class-wide because it is the one
        # nothing below cares about: left unpatched it reaches for the real
        # proxy, which is a five-second connect timeout on a laptop and a live
        # call on anything that can route to the cluster. Tests that *are* about
        # models patch over this.
        models = patch.object(litellm.LiteLLM, "models", return_value=[])
        models.start()
        self.addCleanup(models.stop)

    @override_settings(API_URL="https://api.example.com")
    def test_endpoint_is_shown_when_configured(self):
        resp = self.client.get(reverse("api"))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "https://api.example.com")

    @override_settings(API_URL="")
    def test_unconfigured_endpoint_block_is_omitted(self):
        resp = self.client.get(reverse("api"))
        self.assertNotContains(resp, "endpoint")

    @override_settings(LITELLM_URL="", LITELLM_PROVISIONER_KEY="")
    def test_no_litellm_says_so_instead_of_erroring(self):
        # An unconfigured integration is inert and visible. Same posture as the
        # console's reconcile panel.
        resp = self.client.get(reverse("api"))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Not configured")

    @override_settings(**LITELLM_SETTINGS)
    def test_the_page_lists_the_signed_in_members_keys(self):
        with patch.object(litellm.LiteLLM, "keys_for", return_value=[_key()]) as keys_for:
            with patch.object(litellm.LiteLLM, "usage", return_value=([], None)):
                resp = self.client.get(reverse("api"))
        keys_for.assert_called_once_with(DID)
        self.assertContains(resp, "laptop")
        self.assertContains(resp, "sk-...4f2a")

    @override_settings(**LITELLM_SETTINGS)
    def test_a_form_posts_where_the_dead_button_used_to_sit(self):
        with patch.object(litellm.LiteLLM, "keys_for", return_value=[]):
            with patch.object(litellm.LiteLLM, "usage", return_value=([], None)):
                resp = self.client.get(reverse("api"))
        self.assertContains(resp, 'name="csrfmiddlewaretoken"')
        self.assertContains(resp, 'name="action" value="create"')
        self.assertContains(resp, "Create key")

    @override_settings(**LITELLM_SETTINGS)
    def test_creating_a_key_shows_the_secret_exactly_once(self):
        with patch.object(litellm.LiteLLM, "issue_key", return_value="sk-brand-new"):
            resp = self.client.post(reverse("api"), {"action": "create", "label": "laptop"})
        # Not followed: fetching the redirect target here would render the page
        # once before the assertions below, and rendering is what consumes the
        # secret. That is the behaviour under test, so it must not be spent by
        # the harness.
        self.assertRedirects(resp, reverse("api"), fetch_redirect_response=False)

        with patch.object(litellm.LiteLLM, "keys_for", return_value=[_key()]):
            with patch.object(litellm.LiteLLM, "usage", return_value=([], None)):
                first = self.client.get(reverse("api"))
                second = self.client.get(reverse("api"))
        self.assertContains(first, "sk-brand-new")
        self.assertContains(first, "Copy this now")
        # A secret that survives a refresh is a secret shown twice.
        self.assertNotContains(second, "sk-brand-new")

    @override_settings(**LITELLM_SETTINGS)
    def test_the_key_is_issued_for_the_session_did_and_the_cached_tier(self):
        # Neither comes from the request body. A member choosing their own DID
        # or tier is the whole failure the provisioner key makes possible.
        with patch.object(litellm.LiteLLM, "issue_key", return_value="sk-x") as issue:
            self.client.post(
                reverse("api"),
                {"action": "create", "label": "laptop",
                 "did": "did:plc:someoneelse", "tier": "level-9"},
            )
        did, label = issue.call_args.args
        self.assertEqual(did, DID)
        self.assertEqual(label, "laptop")
        self.assertEqual(issue.call_args.kwargs["tier"], "level-2")

    @override_settings(**LITELLM_SETTINGS)
    def test_a_refused_issue_renders_the_reason_and_mints_nothing(self):
        with patch.object(
            litellm.LiteLLM, "issue_key",
            side_effect=litellm.LiteLLMError("key limit reached"),
        ):
            self.client.post(reverse("api"), {"action": "create", "label": "laptop"})
        with patch.object(litellm.LiteLLM, "keys_for", return_value=[]):
            with patch.object(litellm.LiteLLM, "usage", return_value=([], None)):
                resp = self.client.get(reverse("api"))
        self.assertContains(resp, "key limit reached")

    @override_settings(**LITELLM_SETTINGS)
    def test_revoking_passes_the_token_through_with_the_session_did(self):
        with patch.object(litellm.LiteLLM, "revoke_key") as revoke:
            resp = self.client.post(
                reverse("api"), {"action": "revoke", "token": "abc123def456"}
            )
        revoke.assert_called_once_with(DID, "abc123def456")
        self.assertRedirects(resp, reverse("api"), fetch_redirect_response=False)

    @override_settings(**LITELLM_SETTINGS)
    def test_a_tierless_member_is_not_offered_the_form(self):
        # An unscoped key reaches every model, so this is the page half of the
        # refusal `litellm.issue_key` also makes on its own account.
        MembershipCache.objects.filter(did=DID).update(tier="")
        with patch.object(litellm.LiteLLM, "keys_for", return_value=[]):
            with patch.object(litellm.LiteLLM, "usage", return_value=([], None)):
                resp = self.client.get(reverse("api"))
        self.assertContains(resp, "No tier yet")
        self.assertNotContains(resp, 'value="create"')

    @override_settings(**LITELLM_SETTINGS)
    def test_a_member_at_the_cap_is_told_rather_than_offered_the_form(self):
        with patch.object(
            litellm.LiteLLM, "keys_for",
            return_value=[_key(token=f"tok{n}0000000") for n in range(5)],
        ):
            with patch.object(litellm.LiteLLM, "usage", return_value=([], None)):
                resp = self.client.get(reverse("api"))
        self.assertContains(resp, "Key limit reached")
        self.assertNotContains(resp, 'value="create"')

    @override_settings(**LITELLM_SETTINGS)
    def test_unreadable_usage_does_not_take_the_keys_panel_with_it(self):
        with patch.object(litellm.LiteLLM, "keys_for", return_value=[_key()]):
            with patch.object(
                litellm.LiteLLM, "usage",
                side_effect=litellm.LiteLLMError("usage is down"),
            ):
                resp = self.client.get(reverse("api"))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "laptop")
        self.assertContains(resp, "Usage is unavailable right now")

    @override_settings(**LITELLM_SETTINGS)
    def test_unreadable_keys_say_so_without_claiming_there_are_none(self):
        # "Could not list your keys" and "you have no keys" are different
        # facts, and rendering the empty state for the first is a lie.
        with patch.object(
            litellm.LiteLLM, "keys_for",
            side_effect=litellm.LiteLLMError("the API service could not be reached"),
        ):
            resp = self.client.get(reverse("api"))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "could not be listed")
        self.assertNotContains(resp, "No keys yet")

    @override_settings(**LITELLM_SETTINGS)
    def test_usage_is_asked_for_the_trailing_window(self):
        with patch.object(litellm.LiteLLM, "keys_for", return_value=[]):
            with patch.object(litellm.LiteLLM, "usage", return_value=([], None)) as usage:
                self.client.get(reverse("api"))
        did, start, end = usage.call_args.args
        self.assertEqual(did, DID)
        self.assertEqual(
            (date.fromisoformat(end) - date.fromisoformat(start)).days,
            views.USAGE_WINDOW_DAYS - 1,
        )

    # --- the quickstart and the model list ---------------------------------

    @override_settings(**LITELLM_SETTINGS)
    def test_models_are_listed_for_the_cached_tier(self):
        # The tier is not a parameter of the request, for the same reason
        # issuance isn't: it comes from the membership cache or nowhere.
        with patch.object(
            litellm.LiteLLM, "models", return_value=[_model("qwen3-coder")]
        ) as models:
            with patch.object(litellm.LiteLLM, "keys_for", return_value=[]):
                with patch.object(litellm.LiteLLM, "usage", return_value=([], None)):
                    resp = self.client.get(reverse("api"))
        models.assert_called_once_with("level-2")
        self.assertContains(resp, "qwen3-coder")

    @override_settings(**LITELLM_SETTINGS)
    def test_the_quickstart_names_a_model_the_member_can_actually_call(self):
        # A runnable paste or it is not worth putting on the page. The model in
        # the curl body is the first chat model the member's own tier reaches.
        with patch.object(
            litellm.LiteLLM,
            "models",
            return_value=[_model("nomic-embed-text", mode="embedding"),
                          _model("qwen3-coder")],
        ):
            with patch.object(litellm.LiteLLM, "keys_for", return_value=[]):
                with patch.object(litellm.LiteLLM, "usage", return_value=([], None)):
                    resp = self.client.get(reverse("api"))
        self.assertContains(resp, '"model": "qwen3-coder"')
        self.assertNotContains(resp, '"model": "nomic-embed-text"')

    @override_settings(**LITELLM_SETTINGS)
    def test_an_empty_catalogue_leaves_a_blank_to_fill_not_a_guess(self):
        # A plausible-looking model name would send someone debugging a 400
        # that was ours.
        with patch.object(litellm.LiteLLM, "keys_for", return_value=[]):
            with patch.object(litellm.LiteLLM, "usage", return_value=([], None)):
                resp = self.client.get(reverse("api"))
        self.assertContains(resp, views.EXAMPLE_MODEL_FALLBACK)

    @override_settings(**LITELLM_SETTINGS)
    def test_unreadable_models_do_not_take_the_keys_panel_with_them(self):
        with patch.object(
            litellm.LiteLLM, "models",
            side_effect=litellm.LiteLLMError("models are down"),
        ):
            with patch.object(litellm.LiteLLM, "keys_for", return_value=[_key()]):
                with patch.object(litellm.LiteLLM, "usage", return_value=([], None)):
                    resp = self.client.get(reverse("api"))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "laptop")
        self.assertContains(resp, "The model list is unavailable right now")

    @override_settings(**LITELLM_SETTINGS)
    def test_the_export_line_carries_the_real_key_once_and_then_a_placeholder(self):
        # The whole answer to "why can't I see my key again": the one render
        # that has it is the one where the block is a working paste.
        with patch.object(litellm.LiteLLM, "issue_key", return_value="sk-brand-new"):
            self.client.post(reverse("api"), {"action": "create", "label": "laptop"})

        with patch.object(litellm.LiteLLM, "keys_for", return_value=[_key()]):
            with patch.object(litellm.LiteLLM, "usage", return_value=([], None)):
                first = self.client.get(reverse("api"))
                second = self.client.get(reverse("api"))
        self.assertContains(first, "export SCN_API_KEY=<span data-key-slot>sk-brand-new")
        self.assertNotContains(second, "sk-brand-new")
        self.assertContains(second, "export SCN_API_KEY=<span data-key-slot>sk-")

    @override_settings(**LITELLM_SETTINGS)
    def test_the_key_filler_is_offered_only_when_there_is_no_fresh_key(self):
        # Right after creation the examples are already filled, so an input
        # inviting a paste would be asking for something already done.
        with patch.object(litellm.LiteLLM, "issue_key", return_value="sk-brand-new"):
            self.client.post(reverse("api"), {"action": "create", "label": "laptop"})
        with patch.object(litellm.LiteLLM, "keys_for", return_value=[_key()]):
            with patch.object(litellm.LiteLLM, "usage", return_value=([], None)):
                fresh = self.client.get(reverse("api"))
                later = self.client.get(reverse("api"))
        self.assertNotContains(fresh, "data-key-fill")
        self.assertContains(later, "data-key-fill")


class CallbackViewTests(TestCase):
    def test_unknown_state_is_rejected(self):
        resp = self.client.get(
            reverse("callback"), {"state": "bogus", "code": "x"}
        )
        self.assertEqual(resp.status_code, 400)

    def test_missing_state_is_rejected(self):
        resp = self.client.get(reverse("callback"), {"code": "x"})
        self.assertEqual(resp.status_code, 400)

    @patch("corliss.views.atproto.fetch_session_email")
    @patch("corliss.views.atproto.exchange_code")
    def test_successful_callback_creates_member_and_session(
        self, mock_exchange, mock_email
    ):
        mock_exchange.return_value = (
            {"sub": DID, "access_token": "AT", "refresh_token": "RT"},
            "n2",
        )
        mock_email.return_value = ("", False)
        _seed_pending(self.client, "state1")
        resp = self.client.get(
            reverse("callback"), {"state": "state1", "code": "code", "iss": "https://auth.example"}
        )
        self.assertRedirects(
            resp, reverse("home"), fetch_redirect_response=False
        )
        user = User.objects.get(did=DID)
        self.assertEqual(user.username, "alice.bsky.social")
        self.assertEqual(user.pds_url, "https://pds.example.com")
        self.assertIsNotNone(user.last_seen)
        # Authenticated Django session established.
        self.assertEqual(int(self.client.session["_auth_user_id"]), user.pk)
        # Tokens + DPoP key stored server-side.
        token = AtprotoToken.objects.get(user=user)
        self.assertEqual(token.refresh_token, "RT")
        self.assertTrue(token.dpop_private_pem)

    @patch("corliss.views.atproto.fetch_session_email")
    @patch("corliss.views.atproto.exchange_code")
    def test_callback_persists_email_from_pds(self, mock_exchange, mock_email):
        mock_exchange.return_value = (
            {"sub": DID, "access_token": "AT", "refresh_token": "RT"},
            "n2",
        )
        mock_email.return_value = ("alice@example.com", True)
        _seed_pending(self.client, "state_email")
        self.client.get(
            reverse("callback"),
            {"state": "state_email", "code": "code", "iss": "https://auth.example"},
        )
        user = User.objects.get(did=DID)
        self.assertEqual(user.email, "alice@example.com")
        self.assertTrue(user.email_confirmed)

    @patch("corliss.views.atproto.fetch_session_email")
    @patch("corliss.views.atproto.exchange_code")
    def test_existing_member_handle_is_refreshed(self, mock_exchange, mock_email):
        User.objects.create_user(username="old.handle", did=DID)
        mock_exchange.return_value = (
            {"sub": DID, "access_token": "AT", "refresh_token": "RT"},
            "n2",
        )
        mock_email.return_value = ("", False)
        _seed_pending(self.client, "state2", handle="new.handle")
        self.client.get(
            reverse("callback"), {"state": "state2", "code": "code", "iss": "https://auth.example"}
        )
        user = User.objects.get(did=DID)
        self.assertEqual(user.username, "new.handle")  # refreshed
        self.assertIsNotNone(user.last_seen)
        self.assertEqual(User.objects.filter(did=DID).count(), 1)  # no duplicate

    def test_issuer_mismatch_is_rejected(self):
        _seed_pending(self.client, "state_iss")
        resp = self.client.get(
            reverse("callback"),
            {"state": "state_iss", "code": "code", "iss": "https://evil.example"},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertFalse(User.objects.filter(did=DID).exists())

    @patch("corliss.views.atproto.exchange_code")
    def test_missing_sub_is_rejected(self, mock_exchange):
        # Token response without `sub` must not fall back to the resolved DID.
        mock_exchange.return_value = ({"access_token": "AT"}, "n2")
        _seed_pending(self.client, "state_nosub")
        resp = self.client.get(
            reverse("callback"),
            {"state": "state_nosub", "code": "code", "iss": "https://auth.example"},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertFalse(User.objects.filter(did=DID).exists())

    @patch("corliss.views.atproto.exchange_code")
    def test_did_mismatch_is_rejected(self, mock_exchange):
        mock_exchange.return_value = (
            {"sub": "did:plc:somebodyelse", "access_token": "AT"},
            "n2",
        )
        _seed_pending(self.client, "state3", did=DID)
        resp = self.client.get(
            reverse("callback"), {"state": "state3", "code": "code", "iss": "https://auth.example"}
        )
        self.assertEqual(resp.status_code, 400)
        self.assertFalse(User.objects.filter(did=DID).exists())


SERVICE_DID = "did:plc:n4mzxx6z4ehnswc7znswtfr2"


@override_settings(SCN_SERVICE_DID=SERVICE_DID)
class ServiceUnlockTests(NoRosterMixin, TestCase):
    """Authenticating the service account, from the console's side.

    **The regression this exists for is the `auth_login` that must not run.**
    The roster lives in the service account's repo and only that account can
    write it, so Corliss needs a session for it — but establishing one is an
    errand an admin runs while signed in as themselves. The first cut called
    `auth_login` on the way back and replaced their session with the service
    account's, which is unusable: you would appoint an admin and find yourself
    logged in as the network.

    It is also not a password field. HappyView verifies the tokens handed to
    `/oauth/sessions` against the DPoP key it provisioned, so an app password
    could never produce a session that calls `setSpaceAccess` — see
    `docs`/CLAUDE.md. The password is typed at the PDS and never reaches here.
    """

    def setUp(self):
        super().setUp()
        self.user = User.objects.create_user(username="alice.bsky.social", did=DID)

    def _as_cluster_admin(self):
        patcher = patch("corliss.membership.is_cluster_admin", return_value=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _complete(self, returned_did, *, state="svc1"):
        """Run the callback for a service-link flow that returned `did`."""
        _seed_pending(
            self.client, state, did=SERVICE_DID, handle="sharedcomputer.network"
        )
        session = self.client.session
        session[SESSION_PREFIX + state]["service_link"] = True
        session.save()
        with patch.object(
            atproto,
            "exchange_code",
            return_value=(
                {"sub": returned_did, "access_token": "AT", "refresh_token": "RT"},
                "n2",
            ),
        ):
            with patch.object(
                atproto, "fetch_session_email", return_value=("", False)
            ):
                return self.client.get(
                    reverse("callback"),
                    {
                        "state": state,
                        "code": "code",
                        "iss": "https://auth.example",
                    },
                )

    def test_a_non_admin_cannot_start_it(self):
        self.client.force_login(self.user)
        resp = self.client.post(reverse("manage_unlock"))
        self.assertEqual(resp.status_code, 404)

    def test_it_is_not_startable_by_a_link(self):
        """POST-only: it begins an authorization redirect, and a GET would let
        any page on the internet start one on an admin's behalf."""
        self._as_cluster_admin()
        self.client.force_login(self.user)
        resp = self.client.get(reverse("manage_unlock"))
        self.assertEqual(resp.status_code, 405)

    def test_completing_it_leaves_you_signed_in_as_yourself(self):
        """The whole point. Before this, authenticating the service account
        swapped the admin's own session for it."""
        self._as_cluster_admin()
        self.client.force_login(self.user)

        resp = self._complete(SERVICE_DID)

        self.assertRedirects(
            resp, reverse("manage"), fetch_redirect_response=False
        )
        self.assertEqual(self.client.session["_auth_user_id"], str(self.user.pk))

    def test_it_stores_the_session_against_the_service_account(self):
        self._as_cluster_admin()
        self.client.force_login(self.user)

        self._complete(SERVICE_DID)

        token = AtprotoToken.objects.get(user__did=SERVICE_DID)
        self.assertEqual(token.access_token, "AT")

    def test_authenticating_the_wrong_account_stores_nothing(self):
        """The flow is started by an admin, but which account comes back is
        decided at the PDS's own login screen — so "somebody else signed in"
        is a real outcome, not a hypothetical.

        Caught by `callback`'s existing DID-mismatch guard, which compares the
        token's `sub` against the DID the flow was started for and refuses
        outright. The `service_link` branch re-checks against the setting as
        well; that second check is unreachable while the two agree, and is kept
        because what it protects — a service session pointing at a repo nobody
        reads, and every roster write vanishing into it — is silent when it goes
        wrong.
        """
        self._as_cluster_admin()
        self.client.force_login(self.user)

        resp = self._complete(DID)

        self.assertEqual(resp.status_code, 400)
        self.assertFalse(
            AtprotoToken.objects.filter(user__did=SERVICE_DID).exists()
        )
        # And the admin is still themselves, not half-swapped into something.
        self.assertEqual(self.client.session["_auth_user_id"], str(self.user.pk))

    def test_an_ordinary_login_still_signs_you_in(self):
        """The branch must be reached only by the marker — a regression here
        would break every member's login, silently."""
        _seed_pending(self.client, "plain")
        with patch.object(
            atproto,
            "exchange_code",
            return_value=(
                {"sub": DID, "access_token": "AT", "refresh_token": "RT"},
                "n2",
            ),
        ):
            with patch.object(
                atproto, "fetch_session_email", return_value=("", False)
            ):
                self.client.get(
                    reverse("callback"),
                    {"state": "plain", "code": "c", "iss": "https://auth.example"},
                )

        self.assertIn("_auth_user_id", self.client.session)


@override_settings(SCN_SERVICE_DID=SERVICE_DID)
class InviteAndCascadeTests(NoRosterMixin, TestCase):
    """Inviting by handle, and revoking someone who is also an admin.

    Inviting exists so a member has a readable name from the moment they are
    granted. Before it, someone admitted before their first sign-in had nothing
    to render but a DID, which is not something to show a person.

    Revoking cascades because admins are members: leaving a revoked non-member
    holding roster authority would break the rule the console enforces at
    appointment. Admin goes first — that is the order whose half-done state is
    safe.
    """

    def setUp(self):
        super().setUp()
        self.user = User.objects.create_user(username="alice.bsky.social", did=DID)
        self.token = AtprotoToken.objects.create(
            user=self.user,
            pds_url="https://pds.example.com",
            issuer="https://auth.example",
            token_endpoint="https://auth.example/token",
            access_token="AT",
            dpop_private_pem=atproto.key_to_pem(atproto.generate_key()),
            registry_session_at=timezone.now(),
        )
        patcher = patch(
            "corliss.membership.is_cluster_admin", side_effect=lambda d: d == DID
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        handles = patch.object(atproto, "fetch_did_document",
                               side_effect=atproto.OAuthError("no net"))
        handles.start()
        self.addCleanup(handles.stop)
        apps = patch.object(
            views.membership.MembershipRegistry,
            "fetch_applications",
            return_value=views.membership.ApplicationList([], 0, False),
        )
        apps.start()
        self.addCleanup(apps.stop)
        self.client.force_login(self.user)

    def test_inviting_resolves_the_handle_and_records_it(self):
        with patch.object(
            atproto, "resolve_handle_for_admin", return_value=STRANGER
        ) as resolve:
            with patch.object(views.membership.MembershipRegistry, "approve"):
                self.client.post(
                    reverse("manage"),
                    {"action": "approve", "handle": "bmann.ca", "tier": "level-2"},
                )

        resolve.assert_called_once_with("bmann.ca")
        # Named, not numbered, from the moment they are admitted.
        self.assertEqual(User.objects.get(did=STRANGER).username, "bmann.ca")

    def test_an_unresolvable_handle_grants_nothing(self):
        with patch.object(
            atproto,
            "resolve_handle_for_admin",
            side_effect=atproto.OAuthError("no such handle"),
        ):
            with patch.object(
                views.membership.MembershipRegistry, "approve"
            ) as approve:
                self.client.post(
                    reverse("manage"),
                    {"action": "approve", "handle": "nope.invalid", "tier": "level-2"},
                )

        approve.assert_not_called()
        self.assertFalse(User.objects.filter(did=STRANGER).exists())

    def test_revoking_a_plain_member_does_not_touch_the_roster(self):
        with patch.object(views.membership, "dismiss_admin") as dismiss:
            with patch.object(views.membership.MembershipRegistry, "revoke"):
                self.client.post(
                    reverse("manage"), {"action": "revoke", "did": STRANGER}
                )

        dismiss.assert_not_called()

    def test_revoking_an_admin_ends_their_authority_first(self):
        calls = []
        with patch.object(
            views.membership,
            "is_cluster_admin",
            side_effect=lambda d: d in (DID, STRANGER),
        ):
            with patch.object(
                views.membership,
                "dismiss_admin",
                side_effect=lambda a, s: calls.append("admin") or "",
            ):
                with patch.object(
                    views.membership.MembershipRegistry,
                    "revoke",
                    side_effect=lambda *a, **k: calls.append("member"),
                ):
                    self.client.post(
                        reverse("manage"), {"action": "revoke", "did": STRANGER}
                    )

        self.assertEqual(calls, ["admin", "member"])

    def test_a_failed_admin_removal_stops_the_revocation(self):
        """The safe direction. The reverse would leave a non-member still
        holding registry write access — the thing the revoke was for."""
        with patch.object(
            views.membership,
            "is_cluster_admin",
            side_effect=lambda d: d in (DID, STRANGER),
        ):
            with patch.object(
                views.membership,
                "dismiss_admin",
                side_effect=views.membership.RosterError("locked"),
            ):
                with patch.object(
                    views.membership.MembershipRegistry, "revoke"
                ) as revoke:
                    self.client.post(
                        reverse("manage"), {"action": "revoke", "did": STRANGER}
                    )

        revoke.assert_not_called()
        self.assertIn("locked", self.client.session[views.MANAGE_ERROR_SESSION_KEY])
