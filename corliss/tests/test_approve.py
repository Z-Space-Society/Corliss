"""Approving and revoking — the only writes Corliss makes to the registry.

Owed since v0.8.2, which shipped with **every approve failing** `401 DPoP proof
htu mismatch`: the proof named the internal address while the registry rebuilds
the request URI from the public `Host` Corliss presents. That is the HTTP 421
"Unknown host" bug of v0.4.1 one layer up, and it reached production because
this path had no test and no probe. `ProofTests` is the regression, and it is
the reason this file exists.

The rest is shaped by what a write costs if it is wrong. A read that fails is
visible on the next render; a write appends a permanent record to the space,
authored by a named admin, and nothing here can take it back. So the tests
divide by who is refusing:

- **Corliss refuses first** for a tier this network does not issue, for an
  admin whose session cannot write, and for a POST that names nobody — all
  before any network call, asserted by the call never being made.
- **The registry refuses last**, and its words are what an operator needs, so a
  Lua `error()` must arrive intact rather than as "something went wrong".
- **Nothing here touches `MembershipCache`.** The registry's push is the only
  thing allowed to move it, and a click that quietly wrote a cache row would
  make the console disagree with the space it is supposed to mirror.

`requests.post` is mocked at the boundary rather than `post_json_with_dpop`, so
the real proof gets built and can be read back out of the request. Mocking the
helper would have let the v0.8.2 bug through this file untouched.
"""

import json
from unittest.mock import patch

import jwt
import requests
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from corliss import atproto, membership
from corliss.models import AtprotoToken, MembershipCache
from corliss.views import MANAGE_ERROR_SESSION_KEY, MANAGE_NOTICE_SESSION_KEY

User = get_user_model()

URL = "http://10.1.1.100:3000"  # where the request actually goes
HOST = "view.sharedcomputer.network"  # what the registry knows itself by
CLIENT_KEY = "hvc_testkey"

ADMIN = "did:plc:hhyrsndukexwr6qucdngcf4r"
MEMBER = "did:plc:ewvi7nxzyoun6zhxrhs64oiz"

APPROVE = membership.APPROVE_MEMBER_NSID
REVOKE = membership.REVOKE_MEMBER_NSID
SET_SPACE_ACCESS = membership.SET_SPACE_ACCESS_NSID


class FakeResponse:
    def __init__(self, body, status_code=200, headers=None):
        self._body = body
        self.status_code = status_code
        self.headers = headers or {}
        self.text = body if isinstance(body, str) else json.dumps(body)

    def json(self):
        if isinstance(self._body, str):
            raise ValueError("not json")
        return self._body


def registry(url=URL, client_key=CLIENT_KEY, token="reconcile-token", host=HOST):
    return membership.MembershipRegistry(url, client_key, token, host)


def proof_from(call):
    """The DPoP proof's claims, out of the request the mock recorded.

    Read unverified: the signature is checked by the registry, and what these
    tests are about is what the proof *claims*.
    """
    return jwt.decode(
        call.kwargs["headers"]["DPoP"], options={"verify_signature": False}
    )


class TokenMixin:
    """An admin whose login picked up a registry session, as `views.login`
    leaves them: the tokens are the member's own, and the DPoP key is the one
    the registry provisioned."""

    def setUp(self):
        super().setUp()
        self.user = User.objects.create_user(username="admin.bsky.social", did=ADMIN)
        self.token = AtprotoToken.objects.create(
            user=self.user,
            pds_url="https://pds.example.com",
            issuer="https://auth.example",
            token_endpoint="https://auth.example/token",
            access_token="admin-access-token",
            dpop_private_pem=atproto.key_to_pem(atproto.generate_key()),
            registry_session_at=timezone.now(),
        )


class ProofTests(TokenMixin, TestCase):
    """The v0.8.3 regression: signed for the public name, sent to the private
    address."""

    def test_the_proof_names_the_public_host_not_the_address_dialled(self):
        """The whole bug. The registry reconstructs the request URI from the
        `Host` header it was given, so a proof signed for `10.1.1.100:3000`
        earns a 401 no matter how correct everything else is."""
        with patch.object(
            requests, "post", return_value=FakeResponse({"ok": True})
        ) as post:
            registry().approve(self.token, MEMBER, "level-2")

        self.assertEqual(post.call_args.args[0], f"{URL}/xrpc/{APPROVE}")
        self.assertEqual(
            proof_from(post.call_args)["htu"], f"https://{HOST}/xrpc/{APPROVE}"
        )

    def test_with_no_host_override_the_proof_names_the_url_itself(self):
        """A deployment pointed straight at the public origin has one name for
        the registry, and the two halves must not drift apart."""
        with patch.object(
            requests, "post", return_value=FakeResponse({"ok": True})
        ) as post:
            registry(url="https://view.example", host="").approve(
                self.token, MEMBER, "level-2"
            )

        self.assertEqual(
            proof_from(post.call_args)["htu"], f"https://view.example/xrpc/{APPROVE}"
        )

    def test_the_proof_binds_the_method_and_the_access_token(self):
        """`ath` is what makes this a proof of possession rather than a
        signature anyone holding the token could have replayed elsewhere."""
        with patch.object(
            requests, "post", return_value=FakeResponse({"ok": True})
        ) as post:
            registry().approve(self.token, MEMBER, "level-2")

        claims = proof_from(post.call_args)
        self.assertEqual(claims["htm"], "POST")
        self.assertIn("ath", claims)
        self.assertEqual(
            post.call_args.kwargs["headers"]["Authorization"],
            "DPoP admin-access-token",
        )

    def test_the_host_and_client_key_ride_along_with_the_proof(self):
        """`Host` is what makes the internal address reachable at all — without
        it the registry answers 421 before any routing happens."""
        with patch.object(
            requests, "post", return_value=FakeResponse({"ok": True})
        ) as post:
            registry().approve(self.token, MEMBER, "level-2")

        headers = post.call_args.kwargs["headers"]
        self.assertEqual(headers["Host"], HOST)
        self.assertEqual(headers["x-client-key"], CLIENT_KEY)

    def test_a_nonce_the_registry_issues_is_remembered(self):
        """So the next write skips the round trip. The retry itself belongs to
        `atproto`; what is asserted here is that the answer is persisted."""
        replies = [
            FakeResponse(
                {"error": "use_dpop_nonce"}, 401, {"DPoP-Nonce": "server-nonce"}
            ),
            FakeResponse({"ok": True}, 200, {"DPoP-Nonce": "server-nonce"}),
        ]
        with patch.object(requests, "post", side_effect=replies) as post:
            registry().approve(self.token, MEMBER, "level-2")

        self.assertEqual(post.call_count, 2)
        self.assertEqual(proof_from(post.call_args)["nonce"], "server-nonce")
        self.token.refresh_from_db()
        self.assertEqual(self.token.dpop_nonce, "server-nonce")

    def test_set_space_access_signs_for_the_public_host_too(self):
        """The newest write inherits the same trap. It goes through the same
        `_procedure`, so this asserts the property has not been special-cased
        away rather than re-testing the helper."""
        with patch.object(
            requests, "post", return_value=FakeResponse({"ok": True, "member": True})
        ) as post:
            registry().set_space_access(self.token, MEMBER, "write")

        self.assertEqual(post.call_args.args[0], f"{URL}/xrpc/{SET_SPACE_ACCESS}")
        self.assertEqual(
            proof_from(post.call_args)["htu"],
            f"https://{HOST}/xrpc/{SET_SPACE_ACCESS}",
        )


class SetSpaceAccessTests(TokenMixin, TestCase):
    """Granting a new admin the space membership that makes their approvals
    real — the second half of a roster edit.

    Unlike approve and revoke, this one is called with the **service account's**
    session, never the acting admin's: the space runtime accepts member changes
    only from the space authority. The asymmetry is the registry's, not a choice
    made here, and it is why this is a separate wrapper rather than another
    caller of the same one.
    """

    def test_it_sends_the_did_and_the_access_level(self):
        with patch.object(
            requests, "post", return_value=FakeResponse({"ok": True, "member": True})
        ) as post:
            registry().set_space_access(self.token, MEMBER, "write")

        self.assertEqual(
            post.call_args.kwargs["json"], {"did": MEMBER, "access": "write"}
        )

    def test_removing_access_sends_none(self):
        with patch.object(
            requests, "post", return_value=FakeResponse({"ok": True, "member": False})
        ) as post:
            registry().set_space_access(self.token, MEMBER, "none")

        self.assertEqual(post.call_args.kwargs["json"]["access"], "none")

    def test_an_access_level_the_lua_would_reject_never_leaves_here(self):
        """The Lua refuses it as well, but as an HTTP 500 carrying a Lua
        string — the same reason the tier check is duplicated in `approve`."""
        with patch.object(requests, "post") as post:
            with self.assertRaises(membership.RegistryError):
                registry().set_space_access(self.token, MEMBER, "readonly")

        post.assert_not_called()


class ApproveTests(TokenMixin, TestCase):
    def test_it_calls_approve_member_with_the_did_and_tier(self):
        with patch.object(
            requests, "post", return_value=FakeResponse({"ok": True})
        ) as post:
            registry().approve(self.token, MEMBER, "level-2")

        self.assertEqual(post.call_args.args[0], f"{URL}/xrpc/{APPROVE}")
        self.assertEqual(
            post.call_args.kwargs["json"], {"did": MEMBER, "tier": "level-2"}
        )

    def test_a_tier_this_network_does_not_issue_never_reaches_the_registry(self):
        """Refused here as well as in the Lua. A tierless or unknown grant is a
        fail-open bug, not a harmless default: a consumer that turns it into an
        empty group claim makes Open WebUI remove nothing, so the member
        silently keeps the tier they had."""
        for tier in ["", None, "level-99", "gold", "LEVEL-2", "0"]:
            with self.subTest(tier=tier):
                with patch.object(requests, "post") as post:
                    with self.assertRaises(membership.RegistryError) as caught:
                        registry().approve(self.token, MEMBER, tier)
                self.assertIn("not a tier this network issues", str(caught.exception))
                post.assert_not_called()

    def test_every_tier_the_console_offers_is_one_the_registry_will_take(self):
        """The dropdown's vocabulary and this check read the same tuple; a test
        that let them diverge would let the console offer a tier that always
        fails."""
        with patch.object(
            requests, "post", return_value=FakeResponse({"ok": True})
        ) as post:
            for tier in membership.TIERS:
                registry().approve(self.token, MEMBER, tier)

        self.assertEqual(post.call_count, len(membership.TIERS))
        self.assertIn(membership.DEFAULT_TIER, membership.TIERS)

    def test_re_approving_is_how_a_tier_changes(self):
        """No `change_tier` call exists and none should: the space is
        append-only, so a tier change is a fresh grant and latest-event-wins
        resolves it. Approving twice is harmless for the same reason, which
        matters because the push that clears the queue row is asynchronous."""
        with patch.object(
            requests, "post", return_value=FakeResponse({"ok": True})
        ) as post:
            registry().approve(self.token, MEMBER, "level-2")
            registry().approve(self.token, MEMBER, "level-5")

        self.assertEqual(
            [call.kwargs["json"]["tier"] for call in post.call_args_list],
            ["level-2", "level-5"],
        )
        self.assertTrue(
            all(call.args[0].endswith(APPROVE) for call in post.call_args_list)
        )

    def test_the_grant_is_not_written_into_the_cache_here(self):
        """The registry's push to `/membership/events` is the only thing
        allowed to move `MembershipCache`. A write here would make the console
        claim a membership the space might not have accepted."""
        with patch.object(requests, "post", return_value=FakeResponse({"ok": True})):
            registry().approve(self.token, MEMBER, "level-2")

        self.assertFalse(MembershipCache.objects.exists())


class RevokeTests(TokenMixin, TestCase):
    def test_a_revocation_with_no_reason_sends_only_the_did(self):
        """`reason` is optional in the lexicon, and a blank string is not a
        reason — sending one would put empty text on a permanent record."""
        with patch.object(
            requests, "post", return_value=FakeResponse({"ok": True})
        ) as post:
            registry().revoke(self.token, MEMBER)

        self.assertEqual(post.call_args.args[0], f"{URL}/xrpc/{REVOKE}")
        self.assertEqual(post.call_args.kwargs["json"], {"did": MEMBER})

    def test_a_blank_or_whitespace_reason_is_dropped_not_sent(self):
        for reason in ["", "   ", "\n"]:
            with self.subTest(reason=repr(reason)):
                with patch.object(
                    requests, "post", return_value=FakeResponse({"ok": True})
                ) as post:
                    registry().revoke(self.token, MEMBER, reason)
                self.assertNotIn("reason", post.call_args.kwargs["json"])

    def test_a_reason_is_trimmed_and_capped_to_what_the_lexicon_allows(self):
        """Capped here rather than discovered as a 400 from the registry after
        the admin has typed three hundred characters."""
        with patch.object(
            requests, "post", return_value=FakeResponse({"ok": True})
        ) as post:
            registry().revoke(self.token, MEMBER, "  spammed the space  ")
            registry().revoke(self.token, MEMBER, "x" * 400)

        self.assertEqual(
            post.call_args_list[0].kwargs["json"]["reason"], "spammed the space"
        )
        self.assertEqual(
            len(post.call_args_list[1].kwargs["json"]["reason"]),
            membership.REASON_MAX_CHARS,
        )

    def test_revoking_appends_a_record_and_deletes_nothing(self):
        """A revocation is a new event, never a deletion — the grant it answers
        stays in the space as the history of what was decided when."""
        with patch.object(
            requests, "post", return_value=FakeResponse({"ok": True})
        ) as post:
            with patch.object(requests, "delete") as delete:
                registry().revoke(self.token, MEMBER, "left the network")

        self.assertTrue(post.call_args.args[0].endswith(REVOKE))
        delete.assert_not_called()


class WriteConfigurationTests(TokenMixin, TestCase):
    """What a write needs that a read does not, and how it says so."""

    def test_writes_need_the_client_key_even_though_reads_do_not(self):
        """A query dispatches with no client key at all — `is_configured` says
        so deliberately, because requiring one would tie recovery to the
        console being configured. A procedure is the other case, and the fix is
        a deployment step, so it names the setting."""
        with patch.object(requests, "post") as post:
            with self.assertRaises(membership.RegistryError) as caught:
                registry(client_key="").approve(self.token, MEMBER, "level-2")

        self.assertIn("MEMBERSHIP_REGISTRY_CLIENT_KEY", str(caught.exception))
        post.assert_not_called()

    def test_an_unconfigured_url_names_the_setting_to_fix(self):
        with patch.object(requests, "post") as post:
            with self.assertRaises(membership.RegistryError) as caught:
                registry(url="").approve(self.token, MEMBER, "level-2")

        self.assertIn("MEMBERSHIP_REGISTRY_URL", str(caught.exception))
        post.assert_not_called()

    def test_a_lua_refusal_arrives_with_its_own_words(self):
        """The half an admin who has just been removed from the roster needs to
        read. A Lua `error()` comes back as a 500 carrying the script's text."""
        refusal = FakeResponse("forbidden: caller is not a current admin", 500)
        with patch.object(requests, "post", return_value=refusal):
            with self.assertRaises(membership.RegistryError) as caught:
                registry().approve(self.token, MEMBER, "level-2")

        self.assertIn("500", str(caught.exception))
        self.assertIn("caller is not a current admin", str(caught.exception))

    def test_an_unreachable_registry_raises_rather_than_reading_as_success(self):
        with patch.object(
            requests, "post", side_effect=requests.ConnectionError("no route")
        ):
            with self.assertRaises(membership.RegistryError) as caught:
                registry().approve(self.token, MEMBER, "level-2")

        self.assertIn("could not reach the registry", str(caught.exception))

    def test_a_success_that_is_not_json_is_not_read_as_a_grant(self):
        with patch.object(requests, "post", return_value=FakeResponse("<html>", 200)):
            with self.assertRaises(membership.RegistryError):
                registry().approve(self.token, MEMBER, "level-2")


class CanDecideTests(TokenMixin, TestCase):
    """Whether the console offers a live button or a disabled one with a
    reason. False is the ordinary answer for almost everyone, and none of the
    ways of getting there is an error."""

    def test_an_admin_with_a_registry_session_can_decide(self):
        from corliss import views

        self.assertTrue(views._can_decide(self.user))

    def test_a_login_that_predates_this_feature_cannot(self):
        from corliss import views

        self.token.registry_session_at = None
        self.token.save(update_fields=["registry_session_at"])
        self.assertFalse(views._can_decide(self.user))

    def test_an_account_with_no_atproto_token_cannot(self):
        """Every `dev_login` account, and the break-glass Django admin."""
        from corliss import views

        other = User.objects.create_user(username="dev", did="did:local:dev")
        self.assertFalse(views._can_decide(other))


class DecideMembershipViewTests(TokenMixin, TestCase):
    """`/manage/` POST — the click, from the browser's side.

    The registry object is mocked here rather than the transport: what these
    tests are about is which decision reaches it, and whether the admin is told
    what happened. `ApproveTests` above owns the wire.
    """

    def setUp(self):
        super().setUp()
        # Only the acting admin, not everyone. A blanket True would make the
        # *subject* of a revoke look like an admin too, and revoking an admin
        # cascades into ending their roster authority first — a different code
        # path from the one these tests are about.
        patcher = patch(
            "corliss.membership.is_cluster_admin", side_effect=lambda did: did == ADMIN
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        # Display only, and a network call for anyone who has never signed in
        # here. Pinned so these tests do not depend on plc.directory.
        handles = patch.object(
            membership, "handles_for", return_value={MEMBER: "bob.bsky.social"}
        )
        handles.start()
        self.addCleanup(handles.stop)
        self.client.force_login(self.user)

    def post(self, **data):
        return self.client.post(reverse("manage"), data)

    def test_approving_redirects_and_says_who_got_what(self):
        """Post/Redirect/Get, unlike reconcile: a refresh that re-posted would
        append a second grant. Harmless by design, but an audit log should
        record decisions, not browser reloads."""
        with patch.object(membership.MembershipRegistry, "approve") as approve:
            resp = self.post(action="approve", did=MEMBER, tier="level-2")

        self.assertRedirects(resp, reverse("manage"), fetch_redirect_response=False)
        approve.assert_called_once()
        self.assertEqual(approve.call_args.args[1:], (MEMBER, "level-2"))
        self.assertEqual(
            self.client.session[MANAGE_NOTICE_SESSION_KEY],
            "bob.bsky.social is a member at level-2.",
        )

    def test_revoking_passes_the_reason_through(self):
        with patch.object(membership.MembershipRegistry, "revoke") as revoke:
            resp = self.post(action="revoke", did=MEMBER, reason="left the network")

        self.assertRedirects(resp, reverse("manage"), fetch_redirect_response=False)
        self.assertEqual(revoke.call_args.args[1:], (MEMBER, "left the network"))
        self.assertIn("revoked", self.client.session[MANAGE_NOTICE_SESSION_KEY])

    def test_declining_writes_a_revocation_that_says_it_was_a_decline(self):
        """Answering "no" to an application. With no grant before it, a
        revocation is already exactly what "not a member" resolves to under
        latest-event-wins — so there is no new record type and nothing to
        deploy at the registry.

        The reason is what keeps the log honest: the record would otherwise
        read as a revocation of a membership that never existed, which an
        auditor can infer from the absence of a grant but should not have to.
        """
        with patch.object(membership.MembershipRegistry, "revoke") as revoke:
            resp = self.post(action="decline", did=MEMBER)

        self.assertRedirects(resp, reverse("manage"), fetch_redirect_response=False)
        self.assertEqual(revoke.call_args.args[1:], (MEMBER, "Application declined."))
        notice = self.client.session[MANAGE_NOTICE_SESSION_KEY]
        self.assertIn("application is declined", notice)
        # They are not shut out: a fresh application post-dates this and comes
        # back to the queue flagged "asked again".
        self.assertIn("can apply again", notice)

    def test_declining_refuses_to_end_a_live_membership(self):
        """The queue can hold a current member — someone who applied again
        after being admitted keeps their row, flagged "asked again". On that
        row Decline would otherwise revoke a sitting member, and cascade
        through `dismiss_admin` if they were an admin. That is a large and
        silent thing for a control that says "decline"; revoking a member is a
        decision taken on their own row, where the confirmation says so."""
        MembershipCache.objects.create(
            did=MEMBER,
            active=True,
            tier="level-2",
            last_rkey=f"{MEMBER}:3lqxaaaaaaaaa",
            last_event_at=timezone.now(),
            author_did=ADMIN,
        )

        with patch.object(membership.MembershipRegistry, "revoke") as revoke:
            resp = self.post(action="decline", did=MEMBER)

        self.assertRedirects(resp, reverse("manage"), fetch_redirect_response=False)
        revoke.assert_not_called()
        error = self.client.session[MANAGE_ERROR_SESSION_KEY]
        self.assertIn("already a member", error)
        # Says what to do instead, rather than only refusing.
        self.assertIn("Revoke them from the members table", error)

    def test_a_declined_applicant_is_not_dismissed_as_an_admin(self):
        """The guard above is what makes this true, and it is worth asserting
        on its own: the revoke path cascades into ending roster authority, and
        a decline must never reach that."""
        with patch.object(membership, "dismiss_admin") as dismiss:
            with patch.object(membership.MembershipRegistry, "revoke"):
                self.post(action="decline", did=ADMIN)

        dismiss.assert_not_called()

    def test_the_admins_own_session_is_what_authors_the_write(self):
        """There is deliberately no Corliss credential that could do this. The
        token handed to the registry is this admin's own row."""
        with patch.object(membership.MembershipRegistry, "approve") as approve:
            self.post(action="approve", did=MEMBER, tier="level-0")

        self.assertEqual(approve.call_args.args[0].pk, self.token.pk)

    def test_a_session_that_cannot_write_is_told_how_to_get_one(self):
        """Not a traceback and not a silent no-op: the fix is signing out and
        in again, so the message says that."""
        self.token.registry_session_at = None
        self.token.save(update_fields=["registry_session_at"])

        with patch.object(membership.MembershipRegistry, "approve") as approve:
            resp = self.post(action="approve", did=MEMBER, tier="level-2")

        self.assertRedirects(resp, reverse("manage"), fetch_redirect_response=False)
        approve.assert_not_called()
        self.assertIn(
            "Sign out and in again", self.client.session[MANAGE_ERROR_SESSION_KEY]
        )

    def test_a_post_that_names_nobody_decides_nothing(self):
        for did in ["", "   "]:
            with self.subTest(did=repr(did)):
                with patch.object(membership.MembershipRegistry, "approve") as approve:
                    resp = self.post(action="approve", did=did, tier="level-2")
                self.assertRedirects(
                    resp, reverse("manage"), fetch_redirect_response=False
                )
                approve.assert_not_called()
                self.assertEqual(
                    self.client.session[MANAGE_ERROR_SESSION_KEY],
                    "No member was named.",
                )

    def test_a_refusal_from_the_registry_is_shown_in_its_own_words(self):
        """The fail-visible posture that made the 421 and the query/procedure
        bugs ten-minute fixes: the console carries the registry's error text
        rather than reporting a generic failure."""
        with patch.object(
            membership.MembershipRegistry,
            "approve",
            side_effect=membership.RegistryError(
                "registry returned HTTP 500: forbidden: caller is not a current admin"
            ),
        ):
            resp = self.post(action="approve", did=MEMBER, tier="level-2")

        self.assertRedirects(resp, reverse("manage"), fetch_redirect_response=False)
        self.assertIn(
            "caller is not a current admin",
            self.client.session[MANAGE_ERROR_SESSION_KEY],
        )
        self.assertNotIn(MANAGE_NOTICE_SESSION_KEY, self.client.session)

    def test_a_failed_decision_leaves_the_cache_alone(self):
        with patch.object(
            membership.MembershipRegistry,
            "approve",
            side_effect=membership.RegistryError("boom"),
        ):
            self.post(action="approve", did=MEMBER, tier="level-2")

        self.assertFalse(MembershipCache.objects.exists())

    def test_a_successful_decision_also_leaves_the_cache_alone(self):
        """The push is what moves it, so the tables on the next render may lag
        this click by a round trip. That is the design, not a bug to patch over
        by writing the row here."""
        with patch.object(membership.MembershipRegistry, "approve"):
            self.post(action="approve", did=MEMBER, tier="level-2")

        self.assertFalse(MembershipCache.objects.exists())

    def test_a_non_admin_cannot_decide_anything(self):
        """The `is_cluster_admin` check is a courtesy — the Lua re-reads the
        roster and refuses a caller who is not on it — but removing the near
        check would hand membership to whoever could reach this view."""
        with patch("corliss.membership.is_cluster_admin", return_value=False):
            with patch.object(membership.MembershipRegistry, "approve") as approve:
                resp = self.post(action="approve", did=MEMBER, tier="level-2")

        self.assertEqual(resp.status_code, 404)
        approve.assert_not_called()

