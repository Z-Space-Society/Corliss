from datetime import date, datetime
from unittest.mock import patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse

from corliss import atproto, litellm, views
from corliss.models import AtprotoToken, MembershipCache
from corliss.views import SESSION_PREFIX

User = get_user_model()

DID = "did:plc:ewvi7nxzyoun6zhxrhs64oiz"


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


def _grant(did=DID, *, tier="level-2"):
    """A membership grant as the registry's push would have left it."""
    MembershipCache.objects.create(
        did=did,
        active=True,
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
        self.client.force_login(self.user)
        resp = self.client.get(reverse("home"))
        self.assertContains(resp, "not a member yet")
        self.assertContains(resp, "Apply for membership")

    def test_member_sees_no_apply_button(self):
        _grant()
        self.client.force_login(self.user)
        resp = self.client.get(reverse("home"))
        self.assertNotContains(resp, "Apply for membership")

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
        self.assertContains(resp, MANAGE_URL)
        self.assertNotContains(resp, "Django admin")

    @override_settings(MANAGE_URL=MANAGE_URL)
    def test_console_link_survives_an_empty_membership_cache(self):
        # The recovery path. The roster is read from the service DID's repo and
        # never depends on this table, so an admin locked out here would be
        # locked out of the console that repopulates it.
        self.assertFalse(MembershipCache.objects.exists())
        self._as_cluster_admin()
        self.client.force_login(self.user)
        resp = self.client.get(reverse("home"))
        self.assertContains(resp, MANAGE_URL)

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
        self.assertContains(resp, "LiteLLM Admin")

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
        self.assertNotContains(resp, "LiteLLM Admin")

    @override_settings(API_URL="")
    def test_no_api_url_drops_the_link_rather_than_pointing_at_slash_ui(self):
        self._as_cluster_admin()
        self.client.force_login(self.user)
        resp = self.client.get(reverse("home"))
        self.assertNotContains(resp, "LiteLLM Admin")
        self.assertNotContains(resp, '"/ui/"')

    @override_settings(HAPPYVIEW_URL="https://view.example.com")
    def test_cluster_admin_sees_the_happyview_link(self):
        self._as_cluster_admin()
        self.client.force_login(self.user)
        resp = self.client.get(reverse("home"))
        self.assertContains(resp, "https://view.example.com")
        self.assertContains(resp, "HappyView Admin")

    @override_settings(PROXMOX_URL="https://pve.example.lan:8006")
    def test_cluster_admin_sees_the_proxmox_link_when_there_is_one(self):
        self._as_cluster_admin()
        self.client.force_login(self.user)
        resp = self.client.get(reverse("home"))
        self.assertContains(resp, "Proxmox Admin")

    @override_settings(PROXMOX_URL="", HAPPYVIEW_URL="")
    def test_unconfigured_service_consoles_are_absent_not_empty_hrefs(self):
        # Proxmox is blank on the cluster today — the host is LAN-only and not a
        # Caddy route — so this is the live case, not a hypothetical one.
        self._as_cluster_admin()
        self.client.force_login(self.user)
        resp = self.client.get(reverse("home"))
        self.assertNotContains(resp, "Proxmox Admin")
        self.assertNotContains(resp, "HappyView Admin")

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

    def test_an_admin_reaches_it_with_an_empty_cache(self):
        """The rebuild case, and the reason this page is gated on the roster."""
        self.assertFalse(MembershipCache.objects.exists())
        self._as_cluster_admin()
        self.client.force_login(self.user)

        with self._roster():
            resp = self.client.get(reverse("manage"))

        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "cache is empty")

    def test_only_admins_holding_the_role_now_are_listed(self):
        """The table answers "who can decide membership today".

        A departed admin's grants stay valid — `Roster.was_admin_at` is what
        reads that history — but they are not who an operator is looking for
        here, and a column of ended terms buries the people who are.
        """
        from corliss import membership

        current = membership.AdminEntry(
            "did:plc:currentadmin", _at("2026-01-01T00:00:00Z")
        )
        departed = membership.AdminEntry(
            "did:plc:formeradmin",
            _at("2026-01-01T00:00:00Z"),
            _at("2026-06-01T00:00:00Z"),
        )
        self._as_cluster_admin()
        self.client.force_login(self.user)

        with self._roster(current, departed):
            resp = self.client.get(reverse("manage"))

        self.assertContains(resp, "did:plc:currentadmin")
        self.assertNotContains(resp, "did:plc:formeradmin")

    def test_a_readmitted_admin_appears_once_at_their_current_term(self):
        from corliss import membership

        first = membership.AdminEntry(
            "did:plc:returner",
            _at("2026-01-01T00:00:00Z"),
            _at("2026-03-01T00:00:00Z"),
        )
        again = membership.AdminEntry("did:plc:returner", _at("2026-07-01T00:00:00Z"))
        self._as_cluster_admin()
        self.client.force_login(self.user)

        with self._roster(first, again):
            resp = self.client.get(reverse("manage"))

        # One row, not one per term — the cell's title carries the DID once.
        html = resp.content.decode()
        self.assertEqual(html.count('title="did:plc:returner"'), 1)
        self.assertContains(resp, "2026-07-01")
        self.assertNotContains(resp, "2026-01-01 00:00")

    def test_members_and_admins_are_shown_by_handle_where_one_is_known(self):
        """Handles are what a person reads; the DID stays on the cell's title.

        Resolved from the `User` row for anyone who has signed in, so the
        common case costs no network at all.
        """
        from corliss import membership

        _grant()
        User.objects.create_user(
            username="admin.bsky.social", did="did:plc:currentadmin"
        )
        self._as_cluster_admin()
        self.client.force_login(self.user)

        with self._roster(
            membership.AdminEntry("did:plc:currentadmin", _at("2026-01-01T00:00:00Z"))
        ):
            resp = self.client.get(reverse("manage"))

        self.assertContains(resp, ">alice.bsky.social</td>")
        self.assertContains(resp, ">admin.bsky.social</td>")
        # The DID is not dropped — it is the title on the cell that replaced it.
        self.assertContains(resp, f'title="{DID}"')

    def test_a_did_that_resolves_to_no_handle_renders_as_the_did(self):
        """A failed lookup is not an error: the DID is still the true answer."""
        from corliss import membership

        self._as_cluster_admin()
        self.client.force_login(self.user)

        with self._roster(
            membership.AdminEntry("did:plc:currentadmin", _at("2026-01-01T00:00:00Z"))
        ):
            resp = self.client.get(reverse("manage"))

        self.assertContains(resp, ">did:plc:currentadmin</td>")

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
