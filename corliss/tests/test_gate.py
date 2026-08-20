"""GATE: signing in is not the same as being let in.

The load-bearing test here is `authorize` refusing a session that predates the
gate. Everything else can be right and that one wrong, and the result is a gate
with a hole in it — every member who signed in before GATE shipped keeps
walking into Open WebUI, because nothing on the way there asks again.

Two more that look like housekeeping and are not:

- **`/admin/login/` stays reachable.** The break-glass admin is not on the
  roster and will never have a cache row, so a gate that covers Django's own
  login locks out the account that exists for when nothing else works.
- **`/manage/` stays reachable with an empty cache.** It holds the button that
  refills the cache; gating it on the cache makes recovery depend on the thing
  being recovered.
"""

from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlparse

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from corliss import atproto, membership
from corliss.models import MembershipCache, OidcAuthCode
from corliss.views import POST_LOGIN_REDIRECT, SESSION_PREFIX

User = get_user_model()

MEMBER = "did:plc:ewvi7nxzyoun6zhxrhs64oiz"
ADMIN = "did:plc:hhyrsndukexwr6qucdngcf4r"
STRANGER = "did:plc:n4mzxx6z4ehnswc7znswtfr2"

CLIENT_ID = "open-webui"
REDIRECT_URI = "https://chat.example.test/oauth/oidc/callback"


def _grant(did=MEMBER, *, tier="level-2", active=True):
    """A cache row as the registry's push would have left it."""
    return MembershipCache.objects.create(
        did=did,
        active=active,
        tier=tier,
        last_rkey=f"{did}:3lqxaaaaaaaaa",
        last_event_at="2026-01-01T00:00:00Z",
        author_did=ADMIN,
    )


class NoRosterMixin:
    """Pin ELEVATE to False unless a test says otherwise.

    Same reason as `test_views.NoRosterMixin`: the roster is a live read out of
    the service DID's repo, so without this every answer depends on the
    developer's SCN_SERVICE_DID and reaches the network to find out.
    """

    def setUp(self):
        super().setUp()
        self._roster_patcher = patch(
            "corliss.membership.is_cluster_admin", return_value=False
        )
        self._roster_patcher.start()
        self.addCleanup(self._roster_patcher.stop)

    def as_roster_admin(self, *dids):
        """Put these DIDs on the roster, and nobody else."""
        self._roster_patcher.stop()
        patcher = patch(
            "corliss.membership.is_cluster_admin",
            side_effect=lambda did: did in dids,
        )
        patcher.start()
        self.addCleanup(patcher.stop)


class MayEnterTests(NoRosterMixin, TestCase):
    """`membership.may_enter` — the question, by person state.

    State numbers are from the Cluster Access state map: cache row × roster.
    """

    def test_active_grant_passes(self):
        """State 1 — a member."""
        _grant()
        self.assertTrue(membership.may_enter(MEMBER))

    def test_revoked_member_is_refused(self):
        """State 6 — the row survives for audit; it is not permission."""
        _grant(active=False)
        self.assertFalse(membership.may_enter(MEMBER))

    def test_unknown_did_is_refused(self):
        """State 5 — fails closed. No row is a no, never a default-allow."""
        self.assertFalse(membership.may_enter(STRANGER))

    def test_roster_admin_with_no_cache_row_passes(self):
        """State 3 — the clause that makes closing the gate survivable.

        This is what every rebuilt cluster looks like: an empty cache, and an
        admin who has to get in to press Reconcile.
        """
        self.as_roster_admin(ADMIN)
        self.assertFalse(MembershipCache.objects.filter(did=ADMIN).exists())
        self.assertTrue(membership.may_enter(ADMIN))

    def test_roster_admin_with_a_revoked_row_passes(self):
        """State 4 — revoked as a member, still holding the roster seat."""
        _grant(ADMIN, active=False)
        self.as_roster_admin(ADMIN)
        self.assertTrue(membership.may_enter(ADMIN))

    def test_departed_admin_keeps_the_membership_they_were_granted(self):
        """State 8 — losing the roster seat is not losing the grant."""
        _grant(ADMIN)
        self.assertFalse(membership.is_cluster_admin(ADMIN))
        self.assertTrue(membership.may_enter(ADMIN))

    def test_empty_did_is_refused(self):
        self.assertFalse(membership.may_enter(""))
        self.assertFalse(membership.may_enter(None))


class GateNeverReconcilesTests(NoRosterMixin, TestCase):
    """The invariant: reconcile stays out of the login path.

    A cache miss is an answer, not a cue to go asking the registry. An inline
    fetch would put a network call to HappyView — and its failure modes — in
    front of every sign-in, and would make the gate's answer depend on a service
    that is deliberately not on this path.
    """

    def test_a_cache_miss_does_not_reach_the_registry(self):
        with patch.object(
            membership.MembershipRegistry, "fetch_events"
        ) as fetch_events:
            self.assertFalse(membership.may_enter(STRANGER))
        fetch_events.assert_not_called()

    @override_settings(
        OIDC_CLIENT_ID=CLIENT_ID, OIDC_REDIRECT_URIS=[REDIRECT_URI]
    )
    def test_a_refused_authorize_does_not_reach_the_registry(self):
        user = User.objects.create_user(username="stranger", did=STRANGER)
        self.client.force_login(user)
        with patch.object(
            membership.MembershipRegistry, "fetch_events"
        ) as fetch_events:
            self.client.get(reverse("authorize"), _authorize_params())
        fetch_events.assert_not_called()


def _authorize_params(**overrides):
    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": "openid profile",
        "state": "rp-state",
        "nonce": "rp-nonce",
    }
    params.update(overrides)
    return params


@override_settings(OIDC_CLIENT_ID=CLIENT_ID, OIDC_REDIRECT_URIS=[REDIRECT_URI])
class AuthorizeGateTests(NoRosterMixin, TestCase):
    """`/oidc/authorize` — the handoff into Open WebUI, and GATE's real surface.

    Every other gated surface is a courtesy; this one is the enforcement. It is
    reached on each exchange with the relying party, which is what lets it
    refuse a session minted before the gate existed.
    """

    def setUp(self):
        super().setUp()
        self.user = User.objects.create_user(
            username="alice.bsky.social", did=MEMBER
        )

    def test_a_member_gets_a_code(self):
        _grant()
        self.client.force_login(self.user)
        resp = self.client.get(reverse("authorize"), _authorize_params())
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(resp.url.startswith(REDIRECT_URI))
        qs = parse_qs(urlparse(resp.url).query)
        self.assertTrue(OidcAuthCode.objects.filter(code=qs["code"][0]).exists())

    def test_a_non_member_with_a_valid_session_is_refused(self):
        """**The load-bearing test.**

        A session established before GATE existed is indistinguishable from one
        established a moment ago — it is a valid Django session for a real
        atproto identity. Gating only login would let every one of them through
        forever, because login is not on this path.

        That no code was minted is the actual assertion. A redirect the caller
        ignores proves nothing if an authorization code was issued anyway.
        """
        self.client.force_login(self.user)  # signed in, never granted
        resp = self.client.get(reverse("authorize"), _authorize_params())
        self.assertRedirects(resp, reverse("home"))
        self.assertEqual(OidcAuthCode.objects.count(), 0)

    def test_a_member_revoked_after_signing_in_is_refused(self):
        """The same hole from the other side: the session outlives the grant.

        Revocation reaches the cache by push, and nothing tells the browser. If
        this endpoint did not ask on every exchange, a revoked member would keep
        their access until they happened to sign out.
        """
        row = _grant()
        self.client.force_login(self.user)
        self.assertEqual(
            self.client.get(reverse("authorize"), _authorize_params()).status_code,
            302,
        )
        OidcAuthCode.objects.all().delete()

        MembershipCache.objects.filter(pk=row.pk).update(active=False)
        resp = self.client.get(reverse("authorize"), _authorize_params())
        self.assertRedirects(resp, reverse("home"))
        self.assertEqual(OidcAuthCode.objects.count(), 0)

    def test_a_roster_admin_with_no_grant_gets_a_code(self):
        """State 3 reaching the chat app. They get in; the tier is a separate
        question, answered in `test_provider`."""
        admin = User.objects.create_user(username="admin.bsky.social", did=ADMIN)
        self.as_roster_admin(ADMIN)
        self.client.force_login(admin)
        resp = self.client.get(reverse("authorize"), _authorize_params())
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(resp.url.startswith(REDIRECT_URI))

    def test_an_anonymous_visitor_is_still_bounced_through_login(self):
        """GATE must not turn the login bounce into a refusal — a signed-out
        member has done nothing wrong yet."""
        resp = self.client.get(reverse("authorize"), _authorize_params())
        self.assertEqual(resp.status_code, 302)
        self.assertIn(reverse("login"), resp.url)
        self.assertIn(
            reverse("authorize"), self.client.session[POST_LOGIN_REDIRECT]
        )


RESUME_TARGET = "/oidc/authorize?client_id=open-webui"


class LoginResumeGateTests(NoRosterMixin, TestCase):
    """The resume after login — gated, while the login itself is not.

    A non-member must still be able to sign in: the home page's apply state
    needs a session to exist at all, and it is where APPLY will live. What they
    must not get is a ride onward into the relying party they arrived from.

    Driven through `callback` rather than the helper directly, because the claim
    is about a completed login, and a synthesized request would not prove that
    the session was established before the check ran.
    """

    def _complete_login(self, resume_to=RESUME_TARGET):
        session = self.client.session
        session[POST_LOGIN_REDIRECT] = resume_to
        session[SESSION_PREFIX + "state1"] = {
            "code_verifier": "verifier",
            "dpop_pem": atproto.key_to_pem(atproto.generate_key()),
            "dpop_nonce": "nonce",
            "issuer": "https://auth.example",
            "token_endpoint": "https://auth.example/token",
            "did": MEMBER,
            "pds_url": "https://pds.example.com",
            "handle": "alice.bsky.social",
        }
        session.save()

        with patch.object(
            atproto,
            "exchange_code",
            return_value=({"sub": MEMBER, "access_token": "AT"}, "n2"),
        ), patch.object(atproto, "fetch_session_email", return_value=("", False)):
            return self.client.get(
                reverse("callback"),
                {"state": "state1", "code": "code", "iss": "https://auth.example"},
            )

    def test_a_member_is_resumed_into_the_authorize_they_came_from(self):
        _grant()
        resp = self._complete_login()
        self.assertEqual(resp["Location"], RESUME_TARGET)

    def test_a_non_member_lands_on_home_with_a_session_intact(self):
        resp = self._complete_login()
        self.assertEqual(resp["Location"], reverse("home"))
        # The login itself succeeded — refusing the resume must not refuse the
        # session, or there is no way to reach the page that explains why.
        self.assertIn("_auth_user_id", self.client.session)
        self.assertTrue(User.objects.filter(did=MEMBER).exists())


class HomeIsWhereRefusalsLandTests(NoRosterMixin, TestCase):
    """`/` is never gated — it is the page every refusal redirects *to*.

    Its signed-in-but-not-a-member state is the gate's user-facing form, and the
    only place membership can be asked for. Gating it would leave the
    explanation with nowhere to live and the refused with nowhere to go.
    """

    def setUp(self):
        super().setUp()
        self.user = User.objects.create_user(
            username="alice.bsky.social", did=MEMBER
        )

    def test_a_non_member_gets_the_page_and_the_way_to_ask(self):
        # `pds_url` is what a real login resolves and what the apply form needs
        # somewhere to write to; `find_record` is stubbed to "no application
        # yet" so this stays a page test rather than a network one.
        self.user.pds_url = "https://pds.example.com"
        self.user.save(update_fields=["pds_url"])
        self.client.force_login(self.user)
        with patch.object(atproto, "find_record", return_value=None):
            resp = self.client.get(reverse("home"))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "not a member yet")
        self.assertContains(resp, "Apply for membership")

    def test_a_member_gets_their_standing(self):
        # The claim is which of the two states this page renders, not the exact
        # words: a member gets the welcome, and specifically NOT the refusal
        # that every gated surface redirects here to show.
        _grant()
        self.client.force_login(self.user)
        resp = self.client.get(reverse("home"))
        self.assertContains(resp, "Welcome to the cluster")
        self.assertNotContains(resp, "not a member yet")

    def test_a_signed_out_visitor_still_gets_the_intro(self):
        resp = self.client.get(reverse("home"))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "The Shared Computer Network")


LITELLM_SETTINGS = {
    "LITELLM_URL": "http://10.1.1.112:4000",
    "LITELLM_PROVISIONER_KEY": "sk-provisioner",
}


class ApiGateTests(NoRosterMixin, TestCase):
    """`/api/` — the member's keys, and who is refused them.

    The POST cases are the ones that matter now the page has teeth. GET being
    gated only costs a refused reader; POST being gated is what stands between
    a non-member and a working credential minted with the provisioner key.
    """

    def setUp(self):
        super().setUp()
        self.user = User.objects.create_user(
            username="alice.bsky.social", did=MEMBER
        )

    @override_settings(API_URL="https://api.example.com")
    def test_a_member_sees_it(self):
        _grant()
        self.client.force_login(self.user)
        resp = self.client.get(reverse("api"))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "https://api.example.com")

    def test_a_non_member_is_refused(self):
        self.client.force_login(self.user)
        self.assertRedirects(self.client.get(reverse("api")), reverse("home"))

    def test_an_anonymous_visitor_is_bounced_through_login(self):
        resp = self.client.get(reverse("api"))
        self.assertRedirects(resp, reverse("login"))
        self.assertEqual(self.client.session[POST_LOGIN_REDIRECT], reverse("api"))

    @override_settings(**LITELLM_SETTINGS)
    def test_a_non_member_posting_never_reaches_litellm(self):
        # The refusal has to happen before the provisioner key is touched, not
        # inside the call. Patched at the transport so ANY request would show.
        self.client.force_login(self.user)
        with patch("corliss.litellm.requests.request") as request:
            resp = self.client.post(
                reverse("api"), {"action": "create", "label": "laptop"}
            )
        self.assertRedirects(resp, reverse("home"))
        request.assert_not_called()

    @override_settings(**LITELLM_SETTINGS)
    def test_a_revoked_member_posting_never_reaches_litellm(self):
        _grant(active=False)
        self.client.force_login(self.user)
        with patch("corliss.litellm.requests.request") as request:
            resp = self.client.post(
                reverse("api"), {"action": "revoke", "token": "abc123def456"}
            )
        self.assertRedirects(resp, reverse("home"))
        request.assert_not_called()

    @override_settings(**LITELLM_SETTINGS)
    def test_an_anonymous_post_never_reaches_litellm(self):
        with patch("corliss.litellm.requests.request") as request:
            resp = self.client.post(
                reverse("api"), {"action": "create", "label": "laptop"}
            )
        self.assertRedirects(resp, reverse("login"))
        request.assert_not_called()

    @override_settings(**LITELLM_SETTINGS)
    def test_a_roster_admin_with_no_grant_gets_the_page_but_no_key(self):
        """The split GATE exists for, at the surface that hands out
        entitlements.

        An admin must be able to reach a Corliss whose cache is empty — that is
        the recovery path. They must not receive a key, because a key with no
        tier reaches every model and the registry granted them nothing.
        """
        admin = User.objects.create_user(username="admin.bsky.social", did=ADMIN)
        self.as_roster_admin(ADMIN)
        self.client.force_login(admin)

        empty = Mock(status_code=200, content=b"{}", text="{}")
        empty.json.return_value = {"keys": [], "results": [], "metadata": {}}
        with patch("corliss.litellm.requests.request", return_value=empty) as request:
            page = self.client.get(reverse("api"))
            posted = self.client.post(
                reverse("api"), {"action": "create", "label": "laptop"}
            )

        self.assertEqual(page.status_code, 200)
        self.assertContains(page, "No tier yet")
        self.assertNotContains(page, 'value="create"')
        # The POST is not refused by GATE — they passed it — so it reaches the
        # view and is stopped by the tier check, having minted nothing.
        self.assertRedirects(posted, reverse("api"), fetch_redirect_response=False)
        for call in request.call_args_list:
            self.assertNotIn("/key/generate", call.args[1])


class GateDoesNotCoverTheRecoveryDoorsTests(NoRosterMixin, TestCase):
    """The two surfaces GATE must never reach.

    Both exist for the case where membership is exactly what is broken, so both
    would be useless if they asked about it. This is why GATE is a per-view
    helper rather than middleware: middleware covers everything by default, and
    these two would have to be remembered as exemptions.
    """

    def test_the_break_glass_admin_can_still_log_in_to_django(self):
        """`did:local:admin` is not on the roster and will never have a cache
        row. It is the way in when atproto or OIDC is broken."""
        admin = User.objects.create_user(
            username="admin", did="did:local:admin", is_staff=True, is_superuser=True
        )
        admin.set_password("break-glass-pw")
        admin.save()

        self.assertEqual(self.client.get("/admin/login/").status_code, 200)
        self.assertFalse(membership.may_enter("did:local:admin"))

        resp = self.client.post(
            "/admin/login/",
            {"username": "admin", "password": "break-glass-pw", "next": "/admin/"},
        )
        self.assertRedirects(resp, "/admin/", fetch_redirect_response=False)
        self.assertEqual(self.client.get("/admin/").status_code, 200)

    def test_manage_opens_for_an_admin_with_an_empty_cache(self):
        """The recovery path, asserted from GATE's side.

        `test_views.ManageViewTests` covers this as the console's own contract;
        here the claim is narrower and about this change — GATE did not creep
        onto the page that holds the reconcile button.
        """
        admin = User.objects.create_user(username="admin.bsky.social", did=ADMIN)
        self.as_roster_admin(ADMIN)
        self.client.force_login(admin)
        self.assertFalse(MembershipCache.objects.exists())

        with patch.object(
            membership, "fetch_roster", return_value=membership.Roster([])
        ):
            resp = self.client.get(reverse("manage"))

        self.assertEqual(resp.status_code, 200)
