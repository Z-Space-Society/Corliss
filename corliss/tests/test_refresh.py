"""Refresh tokens for public clients: rotation, reuse, and the membership check.

The refresh grant is the only moment Corliss is asked again about a member who
is connected through Claude or Obsidian, so it is where "stops when you are not
a member" is enforced. The tests that matter most here are the two under
`MembershipTests` and the reuse cases, where the wrong answer either keeps a
removed member connected or signs an honest one out on a bad connection.
"""

from datetime import timedelta
from unittest.mock import patch

import jwt
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone

from corliss import membership, oidc
from corliss.models import (
    MembershipCache,
    OidcClientDocument,
    OidcRefreshToken,
)
from corliss.tests.test_backchannel import _event
from corliss.tests.test_public_clients import (
    CLAUDE,
    DID,
    MCP,
    OWUI,
    PLUGIN,
    SYNC,
    PublicFlowCase,
)


class RefreshCase(PublicFlowCase):
    def sign_in(self, **overrides):
        """A completed sign-in: the token response the client first receives."""
        resp = self.exchange(self.code_for(**overrides))
        self.assertEqual(resp.status_code, 200, resp.content)
        return resp.json()

    def refresh(self, token, **overrides):
        data = {
            "grant_type": "refresh_token",
            "refresh_token": token,
            "client_id": PLUGIN,
        }
        data.update(overrides)
        return self.client.post(
            reverse("token"), {k: v for k, v in data.items() if v is not None}
        )

    def row(self, token):
        return OidcRefreshToken.objects.get(
            token_hash=OidcRefreshToken.hash_token(token)
        )

    def assertRefused(self, resp, error="invalid_grant"):
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.json()["error"], error)


class IssuanceTests(RefreshCase):
    def test_sign_in_returns_a_refresh_token_and_stores_only_its_hash(self):
        body = self.sign_in()
        token = body["refresh_token"]
        row = self.row(token)
        self.assertEqual(row.user, self.user)
        self.assertEqual(row.client_id, PLUGIN)
        self.assertEqual(row.resource, SYNC)
        self.assertFalse(OidcRefreshToken.objects.filter(token_hash=token).exists())

    def test_it_does_not_depend_on_the_offline_access_scope(self):
        """Claude may send no scope at all. Without a refresh token it would
        sign the member in again every fifteen minutes."""
        body = self.sign_in(scope=None)
        self.assertEqual(body["scope"], "")
        self.assertIn("refresh_token", body)

    def test_it_follows_the_grants_the_client_declared(self):
        self.assertTrue(oidc.issues_refresh_tokens(PLUGIN))
        self.assertFalse(oidc.issues_refresh_tokens(CLAUDE))

        now = timezone.now()
        document = {
            "client_id": CLAUDE,
            "client_name": "Claude",
            "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
        }
        row = OidcClientDocument.objects.create(
            client_id=CLAUDE, document=document, fetched_at=now, expires_at=now
        )
        self.assertFalse(oidc.issues_refresh_tokens(CLAUDE))

        row.document = {**document, "grant_types": ["authorization_code", "refresh_token"]}
        row.save()
        self.assertTrue(oidc.issues_refresh_tokens(CLAUDE))

    def test_a_remembered_failed_fetch_is_not_a_client(self):
        now = timezone.now()
        OidcClientDocument.objects.create(
            client_id=CLAUDE, last_error="timed out", fetched_at=now, expires_at=now
        )
        self.assertIsNone(oidc.known_client(CLAUDE))


class RotationTests(RefreshCase):
    def test_a_refresh_returns_a_new_pair_for_the_same_resource(self):
        first = self.sign_in()["refresh_token"]
        resp = self.refresh(first)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp["Cache-Control"], "no-store")
        body = resp.json()
        self.assertNotEqual(body["refresh_token"], first)
        self.assertEqual(body["expires_in"], 900)
        self.assertNotIn("id_token", body)

        claims = jwt.decode(body["access_token"], options={"verify_signature": False})
        self.assertEqual(claims["aud"], SYNC)
        self.assertEqual(claims["sub"], DID)
        self.assertEqual(claims["client_id"], PLUGIN)
        header = jwt.get_unverified_header(body["access_token"])
        self.assertEqual(header["typ"], "at+jwt")

        old, new = self.row(first), self.row(body["refresh_token"])
        self.assertIsNotNone(old.used_at)
        self.assertEqual(new.parent, old)
        self.assertEqual(new.family, old.family)
        self.assertEqual(new.resource, SYNC)

    def test_a_chain_of_refreshes_keeps_working(self):
        token = self.sign_in()["refresh_token"]
        for _ in range(3):
            token = self.refresh(token).json()["refresh_token"]
        self.assertEqual(OidcRefreshToken.objects.count(), 4)

    def test_each_rotation_starts_a_new_thirty_days(self):
        first = self.sign_in()["refresh_token"]
        soon = timezone.now() + timedelta(days=2)
        OidcRefreshToken.objects.update(expires_at=soon)
        second = self.refresh(first).json()["refresh_token"]
        self.assertGreater(
            self.row(second).expires_at, timezone.now() + timedelta(days=29)
        )

    def test_an_expired_token_is_refused_and_its_family_left_alone(self):
        token = self.sign_in()["refresh_token"]
        OidcRefreshToken.objects.update(
            expires_at=timezone.now() - timedelta(seconds=1)
        )
        self.assertRefused(self.refresh(token))
        self.assertTrue(OidcRefreshToken.objects.exists())

    def test_an_unknown_or_missing_token_is_refused(self):
        self.sign_in()
        self.assertRefused(self.refresh("not-a-token"))
        self.assertRefused(self.refresh(None))

    def test_another_client_cannot_use_it_and_does_not_spend_it(self):
        token = self.sign_in()["refresh_token"]
        self.assertRefused(self.refresh(token, client_id=CLAUDE))
        self.assertEqual(self.refresh(token).status_code, 200)

    def test_resource_is_optional_but_must_match(self):
        token = self.sign_in()["refresh_token"]
        self.assertRefused(self.refresh(token, resource=MCP), "invalid_target")
        self.assertRefused(
            self.refresh(token, resource="https://elsewhere.test"), "invalid_target"
        )
        self.assertEqual(self.refresh(token, resource=SYNC + "/").status_code, 200)

    def test_a_token_only_ever_mints_for_its_own_resource(self):
        token = self.sign_in()["refresh_token"]
        body = self.refresh(token).json()
        claims = jwt.decode(body["access_token"], options={"verify_signature": False})
        self.assertEqual(claims["aud"], SYNC)

    def test_scope_can_narrow_and_never_widen(self):
        token = self.sign_in(scope="openid offline_access")["refresh_token"]

        wider = self.refresh(token, scope="openid offline_access email").json()
        self.assertEqual(wider["scope"], "openid offline_access")

        narrower = self.refresh(wider["refresh_token"], scope="openid").json()
        self.assertEqual(narrower["scope"], "openid")

        # Narrowing one access token does not shrink the grant.
        after = self.refresh(narrower["refresh_token"]).json()
        self.assertEqual(after["scope"], "openid offline_access")

    def test_open_webui_is_not_offered_the_grant(self):
        token = self.sign_in()["refresh_token"]
        resp = self.refresh(token, client_id=OWUI, client_secret="owui-secret")
        self.assertRefused(resp, "unsupported_grant_type")


class ReuseTests(RefreshCase):
    """A token presented twice. Inside the grace window with nothing issued
    from it yet used, that is a client that never saw its answer. Anything
    else is two holders, and the family ends."""

    def _age(self, token, seconds):
        OidcRefreshToken.objects.filter(pk=self.row(token).pk).update(
            used_at=timezone.now() - timedelta(seconds=seconds)
        )

    def test_a_retry_inside_the_window_gets_its_own_pair(self):
        first = self.sign_in()["refresh_token"]
        lost = self.refresh(first).json()["refresh_token"]
        retry = self.refresh(first)
        self.assertEqual(retry.status_code, 200)
        kept = retry.json()["refresh_token"]

        self.assertIsNotNone(self.row(lost).superseded_at)
        self.assertIsNone(self.row(kept).superseded_at)
        self.assertEqual(self.refresh(kept).status_code, 200)

    def test_the_window_is_measured_from_the_first_use(self):
        first = self.sign_in()["refresh_token"]
        self.refresh(first)
        used_at = self.row(first).used_at
        self.refresh(first)
        self.assertEqual(self.row(first).used_at, used_at)

    def test_the_superseded_token_ends_the_family(self):
        first = self.sign_in()["refresh_token"]
        lost = self.refresh(first).json()["refresh_token"]
        kept = self.refresh(first).json()["refresh_token"]

        self.assertRefused(self.refresh(lost))
        self.assertFalse(OidcRefreshToken.objects.exists())
        self.assertRefused(self.refresh(kept))

    def test_a_replay_after_the_window_ends_the_family(self):
        first = self.sign_in()["refresh_token"]
        second = self.refresh(first).json()["refresh_token"]
        self._age(first, 61)

        self.assertRefused(self.refresh(first))
        self.assertFalse(OidcRefreshToken.objects.exists())
        self.assertRefused(self.refresh(second))

    def test_a_replay_after_its_successor_was_used_ends_the_family(self):
        """Still inside the window, but the answer was plainly received."""
        first = self.sign_in()["refresh_token"]
        second = self.refresh(first).json()["refresh_token"]
        third = self.refresh(second).json()["refresh_token"]

        self.assertRefused(self.refresh(first))
        self.assertFalse(OidcRefreshToken.objects.exists())
        self.assertRefused(self.refresh(third))

    def test_ending_one_family_leaves_the_members_other_connection(self):
        """Sync and MCP are separate authorizations with separate families."""
        sync = self.sign_in()["refresh_token"]
        mcp = self.sign_in(resource=MCP)["refresh_token"]
        self.refresh(sync)
        self._age(sync, 61)
        self.assertRefused(self.refresh(sync))
        self.assertEqual(self.refresh(mcp).status_code, 200)

    def test_two_requests_with_one_token_both_succeed_and_one_result_is_superseded(self):
        """What the row lock makes of a concurrent pair: served in turn, the
        second as a retry of the first."""
        first = self.sign_in()["refresh_token"]
        a = self.refresh(first).json()["refresh_token"]
        b = self.refresh(first).json()["refresh_token"]
        live = [t for t in (a, b) if self.row(t).superseded_at is None]
        self.assertEqual(live, [b])


class MembershipTests(RefreshCase):
    def _revocation(self):
        return membership.parse(_event(DID, "revoke", tid="3lqxbbbbbbbbb"))

    @override_settings(OIDC_BACKCHANNEL_LOGOUT_URI="")
    def test_a_revoked_member_cannot_refresh_and_their_tokens_are_deleted(self):
        token = self.sign_in()["refresh_token"]
        self.sign_in(resource=MCP)
        with patch("corliss.litellm.on_membership_revoked"):
            self.assertTrue(membership.apply_event(self._revocation()))

        self.assertFalse(OidcRefreshToken.objects.exists())
        self.assertRefused(self.refresh(token))

    def test_the_membership_check_alone_is_enough(self):
        """The delete on revocation is a tidy-up. With it skipped, the token
        is still in the table and still mints nothing."""
        token = self.sign_in()["refresh_token"]
        MembershipCache.objects.filter(did=DID).update(active=False)
        self.assertTrue(OidcRefreshToken.objects.exists())

        self.assertRefused(self.refresh(token))
        self.assertFalse(OidcRefreshToken.objects.exists())

    def test_a_member_with_no_cache_row_cannot_refresh(self):
        """A cache miss is a no, never a lookup."""
        token = self.sign_in()["refresh_token"]
        MembershipCache.objects.all().delete()
        self.assertRefused(self.refresh(token))

    def test_a_roster_admin_with_no_grant_can_refresh(self):
        token = self.sign_in()["refresh_token"]
        MembershipCache.objects.all().delete()
        with patch("corliss.membership.is_cluster_admin", return_value=True):
            self.assertEqual(self.refresh(token).status_code, 200)

    def test_signing_out_of_corliss_leaves_refresh_tokens_alone(self):
        """A browser session and an app on another device are not connected."""
        token = self.sign_in()["refresh_token"]
        self.client.get(reverse("logout"))
        self.assertEqual(self.refresh(token).status_code, 200)

    def test_a_grant_event_deletes_nothing(self):
        token = self.sign_in()["refresh_token"]
        grant = membership.parse(_event(DID, "grant", tid="3lqxbbbbbbbbb"))
        with patch("corliss.litellm.on_membership_granted"):
            membership.apply_event(grant)
        self.assertEqual(self.refresh(token).status_code, 200)
