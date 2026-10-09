from datetime import timedelta

from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.test import TestCase
from django.utils import timezone

from corliss.models import (
    OidcAuthCode,
    OidcClientDocument,
    OidcConsent,
    OidcRefreshToken,
)

User = get_user_model()

DID = "did:plc:ewvi7nxzyoun6zhxrhs64oiz"


class UserModelTests(TestCase):
    def test_create_user_with_did(self):
        """A member is created keyed by DID, with the handle in username."""
        user = User.objects.create_user(
            username="alice.bsky.social",
            did=DID,
            pds_url="https://pds.example.com",
        )
        self.assertEqual(user.did, DID)
        self.assertEqual(user.username, "alice.bsky.social")
        self.assertEqual(user.pds_url, "https://pds.example.com")
        self.assertIsNone(user.last_seen)

    def test_did_is_unique(self):
        """Two members cannot share a DID — it's the primary identity."""
        User.objects.create_user(username="alice.bsky.social", did=DID)
        with transaction.atomic():
            with self.assertRaises(IntegrityError):
                User.objects.create_user(username="alice2.bsky.social", did=DID)

    def test_handle_lives_in_username_and_is_mutable(self):
        """The handle (username) can change while the DID stays fixed."""
        user = User.objects.create_user(username="old.handle", did=DID)
        user.username = "new.handle"
        user.save(update_fields=["username"])
        user.refresh_from_db()
        self.assertEqual(user.username, "new.handle")
        self.assertEqual(user.did, DID)

    def test_touch_last_seen(self):
        """touch_last_seen stamps activity."""
        user = User.objects.create_user(username="alice.bsky.social", did=DID)
        self.assertIsNone(user.last_seen)
        user.touch_last_seen()
        user.refresh_from_db()
        self.assertIsNotNone(user.last_seen)

    def test_str_prefers_handle_then_did(self):
        user = User.objects.create_user(username="alice.bsky.social", did=DID)
        self.assertEqual(str(user), "alice.bsky.social")

    def test_email_confirmed_defaults_false(self):
        """Email is best-effort PDS data; unconfirmed until the PDS says so."""
        user = User.objects.create_user(username="alice.bsky.social", did=DID)
        self.assertEqual(user.email, "")
        self.assertFalse(user.email_confirmed)

    def test_email_and_confirmation_can_be_set(self):
        user = User.objects.create_user(
            username="alice.bsky.social",
            did=DID,
            email="alice@example.com",
            email_confirmed=True,
        )
        self.assertEqual(user.email, "alice@example.com")
        self.assertTrue(user.email_confirmed)


CLIENT = "https://claude.ai/oauth/claude-code-client-metadata"
SYNC = "https://sync.example.test"
MCP = "https://mcp.example.test"
TTL = timedelta(days=30)


class OidcAuthCodeModelTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice.bsky.social", did=DID)

    def _code(self, value, *, expires_in):
        return OidcAuthCode.objects.create(
            code=value,
            user=self.user,
            client_id=CLIENT,
            redirect_uri="obsidian://scn-obsidian",
            expires_at=timezone.now() + timedelta(seconds=expires_in),
        )

    def test_a_custom_scheme_redirect_and_a_url_client_id_are_stored_as_given(self):
        code = self._code("c1", expires_in=600)
        code.refresh_from_db()
        self.assertEqual(code.redirect_uri, "obsidian://scn-obsidian")
        self.assertEqual(code.client_id, CLIENT)

    def test_the_new_columns_default_blank(self):
        """A code issued before they existed, or to Open WebUI, has neither."""
        code = self._code("c1", expires_in=600)
        self.assertEqual(code.code_challenge, "")
        self.assertEqual(code.resource, "")

    def test_purge_expired_keeps_live_codes(self):
        self._code("old", expires_in=-1)
        self._code("live", expires_in=600)
        OidcAuthCode.purge_expired()
        self.assertEqual(
            list(OidcAuthCode.objects.values_list("code", flat=True)), ["live"]
        )


class OidcRefreshTokenModelTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice.bsky.social", did=DID)

    def _issue(self, **overrides):
        kwargs = {
            "user": self.user,
            "client_id": CLIENT,
            "resource": SYNC,
            "scope": "offline_access",
            "ttl": TTL,
        }
        kwargs.update(overrides)
        return OidcRefreshToken.issue(**kwargs)

    def test_only_the_hash_is_stored(self):
        raw, row = self._issue()
        self.assertNotEqual(row.token_hash, raw)
        self.assertEqual(len(row.token_hash), 64)
        self.assertEqual(row.token_hash, OidcRefreshToken.hash_token(raw))

    def test_lookup_finds_the_row_by_the_raw_token(self):
        raw, row = self._issue()
        self.assertEqual(OidcRefreshToken.lookup(raw), row)
        self.assertIsNone(OidcRefreshToken.lookup("not-a-token"))
        self.assertIsNone(OidcRefreshToken.lookup(""))

    def test_a_successor_joins_its_parents_family(self):
        _, first = self._issue()
        _, second = self._issue(parent=first)
        _, unrelated = self._issue()
        self.assertEqual(second.family, first.family)
        self.assertEqual(second.parent, first)
        self.assertNotEqual(unrelated.family, first.family)

    def test_revoke_family_leaves_other_families_alone(self):
        _, first = self._issue()
        self._issue(parent=first)
        _, other = self._issue(resource=MCP)
        self.assertEqual(first.revoke_family(), 2)
        self.assertEqual(list(OidcRefreshToken.objects.all()), [other])

    def test_revoke_for_did_removes_every_token_the_member_holds(self):
        other_user = User.objects.create_user(
            username="bob.bsky.social", did="did:plc:bobbobbobbobbobbobbobbob"
        )
        self._issue()
        self._issue(resource=MCP)
        _, theirs = self._issue(user=other_user)
        self.assertEqual(OidcRefreshToken.revoke_for_did(DID), 2)
        self.assertEqual(list(OidcRefreshToken.objects.all()), [theirs])

    def test_expiry(self):
        _, live = self._issue()
        _, dead = self._issue(ttl=timedelta(seconds=-1))
        self.assertFalse(live.is_expired)
        self.assertTrue(dead.is_expired)

    def test_issuing_purges_expired_tokens_and_long_used_ones(self):
        _, expired = self._issue(ttl=timedelta(seconds=-1))
        _, long_used = self._issue()
        _, just_used = self._issue()
        now = timezone.now()
        OidcRefreshToken.objects.filter(pk=long_used.pk).update(
            used_at=now - timedelta(days=2)
        )
        OidcRefreshToken.objects.filter(pk=just_used.pk).update(used_at=now)

        _, fresh = self._issue()

        self.assertEqual(
            set(OidcRefreshToken.objects.values_list("pk", flat=True)),
            {just_used.pk, fresh.pk},
        )


class OidcConsentModelTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice.bsky.social", did=DID)

    def test_consent_is_per_client_and_per_resource(self):
        OidcConsent.record(self.user, client_id=CLIENT, resource=SYNC)
        self.assertTrue(OidcConsent.given(self.user, client_id=CLIENT, resource=SYNC))
        self.assertFalse(OidcConsent.given(self.user, client_id=CLIENT, resource=MCP))
        self.assertFalse(
            OidcConsent.given(self.user, client_id=CLIENT + "x", resource=SYNC)
        )

    def test_recording_twice_keeps_one_row(self):
        OidcConsent.record(self.user, client_id=CLIENT, resource=SYNC)
        OidcConsent.record(self.user, client_id=CLIENT, resource=SYNC)
        self.assertEqual(OidcConsent.objects.count(), 1)


class OidcClientDocumentModelTests(TestCase):
    def test_freshness_follows_expires_at(self):
        now = timezone.now()
        fresh = OidcClientDocument.objects.create(
            client_id=CLIENT, fetched_at=now, expires_at=now + timedelta(hours=1)
        )
        stale = OidcClientDocument.objects.create(
            client_id=CLIENT + "2", fetched_at=now, expires_at=now - timedelta(seconds=1)
        )
        self.assertTrue(fresh.is_fresh)
        self.assertFalse(stale.is_fresh)

    def test_client_id_is_unique(self):
        now = timezone.now()
        OidcClientDocument.objects.create(
            client_id=CLIENT, fetched_at=now, expires_at=now
        )
        with transaction.atomic():
            with self.assertRaises(IntegrityError):
                OidcClientDocument.objects.create(
                    client_id=CLIENT, fetched_at=now, expires_at=now
                )
