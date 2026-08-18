"""Back-channel logout: ending a relying party's session, not waiting it out.

The load-bearing tests here are the two that decide whether revocation means
anything in practice:

- **A revoke reaching a live member notifies the relying party.** That is the
  whole point — it turns "revoked, and still chatting for up to four hours"
  into "revoked, and signed out in seconds".
- **A revoke reaching a member with no live row does NOT.** That is reconcile
  replaying old events into an empty cache on a rebuilt cluster. Notifying
  there would put a burst of outbound POSTs on the recovery path, to end
  sessions that ended long ago.

Two more that look like housekeeping and are not:

- **Delivery failure changes nothing for the caller.** Sign-out still signs
  out, the membership push still reports what it applied. A chat server being
  unreachable must not break a working thing to report a broken one.
- **A logout token carries no `nonce`.** The spec forbids it and relying
  parties reject it, so a stray nonce would fail every delivery — silently
  turning immediate revocation back into the four-hour window.
"""

import tempfile
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import jwt
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from corliss import membership, oidc, signing
from corliss.models import MembershipCache, OidcSession

User = get_user_model()

DID = "did:plc:ewvi7nxzyoun6zhxrhs64oiz"
ADMIN_DID = "did:plc:hhyrsndukexwr6qucdngcf4r"
CLIENT_ID = "open-webui"
CLIENT_SECRET = "test-secret"
REDIRECT_URI = "https://chat.example.test/oauth/oidc/callback"
LOGOUT_URI = "http://10.1.1.121:8080/oauth/backchannel-logout"

ISSUER = "https://auth.zai.test"


def _write_keys(d: Path):
    """A throwaway ES256 + RS256 pair, the same idiom as `test_provider`."""
    ec_path, rsa_path = d / "ec.pem", d / "rsa.pem"
    ec_path.write_bytes(
        ec.generate_private_key(ec.SECP256R1()).private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    rsa_path.write_bytes(
        rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return ec_path, rsa_path


def _event(did, kind, *, tid="3lqxaaaaaaaaa", tier="level-2", author=ADMIN_DID):
    """A push envelope, exactly as the registry's Lua sends it."""
    record = (
        {"status": "active", "grantedAt": "2026-01-01T00:00:00Z", "tier": tier}
        if kind == "grant"
        else {"status": "revoked", "revokedAt": "2026-01-02T00:00:00Z"}
    )
    return {
        "event": kind,
        "did": did,
        "rkey": f"{did}:{tid}",
        "authorDid": author,
        "record": record,
    }


def _ok():
    """A relying party that accepts the token."""
    response = requests.Response()
    response.status_code = 200
    return response


class KeysMixin:
    """Real signing keys, since the point is that an RP can verify the token."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._tmp = tempfile.TemporaryDirectory()
        cls.ec_path, cls.rsa_path = _write_keys(Path(cls._tmp.name))

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()
        super().tearDownClass()

    def setUp(self):
        super().setUp()
        signing._load_private_key.cache_clear()
        self._ov = override_settings(
            ATPROTO_EC_PRIVATE_KEY_PATH=str(self.ec_path),
            OIDC_RSA_PRIVATE_KEY_PATH=str(self.rsa_path),
        )
        self._ov.enable()
        self.addCleanup(self._ov.disable)
        self.addCleanup(signing._load_private_key.cache_clear)
        self.user = User.objects.create_user(
            username="alice.bsky.social", did=DID, pds_url="https://pds.example.com"
        )


@override_settings(
    PUBLIC_BASE_URL=ISSUER,
    OIDC_CLIENT_ID=CLIENT_ID,
    OIDC_BACKCHANNEL_LOGOUT_URI=LOGOUT_URI,
)
class LogoutTokenTests(KeysMixin, TestCase):
    """The token itself — what a relying party will actually check."""

    def test_verifies_against_the_published_jwks(self):
        # Verify exactly as the RP does: fetch JWKS, pick the RSA key, decode
        # with the audience and issuer it has configured.
        token = oidc.mint_logout_token(self.user, client_id=CLIENT_ID, sid="s1")
        rsa_jwk = next(k for k in signing.jwks()["keys"] if k["kty"] == "RSA")
        claims = jwt.decode(
            token,
            key=jwt.PyJWK.from_dict(rsa_jwk).key,
            algorithms=["RS256"],
            audience=CLIENT_ID,
            issuer=ISSUER,
        )
        self.assertEqual(claims["sub"], DID)
        self.assertEqual(claims["aud"], CLIENT_ID)
        self.assertEqual(claims["sid"], "s1")
        self.assertIn("iat", claims)
        self.assertIn("jti", claims)

    def test_carries_the_backchannel_logout_event(self):
        # The RP rejects a token without exactly this key — it is what
        # distinguishes a logout token from any other JWT we sign.
        token = oidc.mint_logout_token(self.user, client_id=CLIENT_ID)
        claims = jwt.decode(token, options={"verify_signature": False})
        self.assertEqual(
            claims["events"],
            {"http://schemas.openid.net/event/backchannel-logout": {}},
        )

    def test_carries_no_nonce(self):
        # Forbidden by spec and rejected outright by Open WebUI. A nonce here
        # would fail every delivery, quietly restoring the old window.
        token = oidc.mint_logout_token(self.user, client_id=CLIENT_ID, sid="s1")
        claims = jwt.decode(token, options={"verify_signature": False})
        self.assertNotIn("nonce", claims)

    def test_signed_with_the_same_key_as_the_id_token(self):
        # Not incidental: it is why an RP that can validate an id_token can
        # validate this with no extra configuration.
        logout_kid = jwt.get_unverified_header(
            oidc.mint_logout_token(self.user, client_id=CLIENT_ID)
        )["kid"]
        id_kid = jwt.get_unverified_header(
            oidc.mint_id_token(self.user, client_id=CLIENT_ID)
        )["kid"]
        self.assertEqual(logout_kid, id_kid)
        self.assertEqual(logout_kid, signing.oidc_kid())

    def test_discovery_advertises_backchannel_logout(self):
        doc = self.client.get(reverse("openid_configuration")).json()
        self.assertIs(doc["backchannel_logout_supported"], True)
        self.assertIs(doc["backchannel_logout_session_supported"], True)


@override_settings(
    PUBLIC_BASE_URL=ISSUER,
    OIDC_CLIENT_ID=CLIENT_ID,
    OIDC_BACKCHANNEL_LOGOUT_URI=LOGOUT_URI,
)
class NotifyLogoutTests(KeysMixin, TestCase):
    """Delivery: who gets told, and what happens when telling them fails."""

    def setUp(self):
        super().setUp()
        self.session = oidc.record_session(self.user, client_id=CLIENT_ID)

    def test_posts_a_form_encoded_logout_token(self):
        with patch("corliss.oidc.requests.post", return_value=_ok()) as post:
            self.assertEqual(oidc.notify_logout(self.user), 1)

        (uri,), kwargs = post.call_args
        self.assertEqual(uri, LOGOUT_URI)
        # Form-encoded `logout_token` is the transport the spec defines and the
        # only one relying parties implement — `data=`, never `json=`.
        self.assertIn("logout_token", kwargs["data"])
        self.assertNotIn("json", kwargs)
        self.assertEqual(
            kwargs["timeout"], oidc.LOGOUT_TOKEN_TIMEOUT_SECONDS
        )
        claims = jwt.decode(
            kwargs["data"]["logout_token"], options={"verify_signature": False}
        )
        self.assertEqual(claims["sub"], DID)
        self.assertEqual(claims["sid"], self.session.sid)

    def test_accepted_delivery_drops_the_session_row(self):
        with patch("corliss.oidc.requests.post", return_value=_ok()):
            oidc.notify_logout(self.user)
        self.assertFalse(OidcSession.objects.filter(user=self.user).exists())

    def test_failed_delivery_keeps_the_session_row(self):
        # Kept on purpose: the session may still be live over there, so the
        # next trigger should try again rather than forget it existed.
        with patch(
            "corliss.oidc.requests.post",
            side_effect=requests.ConnectionError("refused"),
        ):
            self.assertEqual(oidc.notify_logout(self.user), 0)
        self.assertTrue(OidcSession.objects.filter(user=self.user).exists())

    def test_rejected_token_is_not_treated_as_success(self):
        response = requests.Response()
        response.status_code = 400
        response._content = b'{"error":"invalid_request"}'
        with patch("corliss.oidc.requests.post", return_value=response):
            self.assertEqual(oidc.notify_logout(self.user), 0)
        self.assertTrue(OidcSession.objects.filter(user=self.user).exists())

    @override_settings(OIDC_BACKCHANNEL_LOGOUT_URI="")
    def test_unconfigured_is_inert_and_touches_no_network(self):
        with patch("corliss.oidc.requests.post") as post:
            self.assertEqual(oidc.notify_logout(self.user), 0)
        post.assert_not_called()
        # The row survives: nothing was told, so nothing was ended.
        self.assertTrue(OidcSession.objects.filter(user=self.user).exists())

    def test_member_with_no_relying_party_session_notifies_nobody(self):
        OidcSession.objects.all().delete()
        with patch("corliss.oidc.requests.post") as post:
            self.assertEqual(oidc.notify_logout(self.user), 0)
        post.assert_not_called()

    def test_did_with_no_user_row_is_a_silent_no_op(self):
        # MembershipCache is DID-keyed with no FK to User precisely so a grant
        # can exist for someone who has never logged in. Such a DID holds no
        # relying-party session, so this is normal, not an error.
        with patch("corliss.oidc.requests.post") as post:
            self.assertEqual(
                oidc.notify_logout_for_did("did:plc:neverloggedin00000000000"), 0
            )
        post.assert_not_called()


@override_settings(
    PUBLIC_BASE_URL=ISSUER,
    OIDC_CLIENT_ID=CLIENT_ID,
    OIDC_CLIENT_SECRET=CLIENT_SECRET,
    OIDC_REDIRECT_URIS=[REDIRECT_URI],
    OIDC_BACKCHANNEL_LOGOUT_URI=LOGOUT_URI,
)
class SessionRecordingTests(KeysMixin, TestCase):
    """`OidcSession` is created where a session actually begins: redemption."""

    def setUp(self):
        super().setUp()
        MembershipCache.objects.create(
            did=DID,
            active=True,
            tier="level-2",
            last_rkey=f"{DID}:3lqxaaaaaaaaa",
            last_event_at="2026-01-01T00:00:00Z",
            author_did=ADMIN_DID,
        )

    def _redeem(self):
        """Drive a full authorize → token exchange and return the id_token."""
        self.client.force_login(self.user)
        resp = self.client.get(
            reverse("authorize"),
            {
                "client_id": CLIENT_ID,
                "redirect_uri": REDIRECT_URI,
                "response_type": "code",
                "scope": "openid",
            },
        )
        code = parse_qs(urlparse(resp["Location"]).query)["code"][0]
        token_resp = self.client.post(
            reverse("token"),
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
            },
        )
        self.assertEqual(token_resp.status_code, 200)
        return token_resp.json()["id_token"]

    def test_redemption_records_the_session_and_the_id_token_carries_its_sid(self):
        id_token = self._redeem()
        session = OidcSession.objects.get(user=self.user, client_id=CLIENT_ID)
        claims = jwt.decode(id_token, options={"verify_signature": False})
        self.assertEqual(claims["sid"], session.sid)

    def test_a_second_exchange_rotates_sid_without_adding_a_row(self):
        # One row per (member, relying party) — see OidcSession. Repeated
        # sign-ins must not grow the table.
        self._redeem()
        first = OidcSession.objects.get(user=self.user, client_id=CLIENT_ID)
        self._redeem()
        self.assertEqual(OidcSession.objects.filter(user=self.user).count(), 1)
        second = OidcSession.objects.get(user=self.user, client_id=CLIENT_ID)
        self.assertEqual(first.pk, second.pk)
        self.assertNotEqual(first.sid, second.sid)


@override_settings(
    PUBLIC_BASE_URL=ISSUER,
    OIDC_CLIENT_ID=CLIENT_ID,
    OIDC_BACKCHANNEL_LOGOUT_URI=LOGOUT_URI,
)
class LogoutViewTests(KeysMixin, TestCase):
    """Signing out of Corliss now signs you out of chat."""

    def setUp(self):
        super().setUp()
        oidc.record_session(self.user, client_id=CLIENT_ID)
        self.client.force_login(self.user)

    def test_logout_notifies_the_relying_party(self):
        with patch("corliss.oidc.requests.post", return_value=_ok()) as post:
            resp = self.client.get(reverse("logout"))
        post.assert_called_once()
        self.assertRedirects(resp, reverse("login"), fetch_redirect_response=False)
        # And the local session really did end.
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_unreachable_relying_party_still_signs_you_out(self):
        # The failure mode that must not break a working thing: a chat server
        # that is down cannot be allowed to trap someone in a session.
        with patch(
            "corliss.oidc.requests.post",
            side_effect=requests.ConnectionError("refused"),
        ):
            resp = self.client.get(reverse("logout"))
        self.assertRedirects(resp, reverse("login"), fetch_redirect_response=False)
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_anonymous_logout_notifies_nobody(self):
        self.client.logout()
        with patch("corliss.oidc.requests.post") as post:
            self.client.get(reverse("logout"))
        post.assert_not_called()


@override_settings(
    PUBLIC_BASE_URL=ISSUER,
    OIDC_CLIENT_ID=CLIENT_ID,
    OIDC_BACKCHANNEL_LOGOUT_URI=LOGOUT_URI,
)
class RevocationTriggerTests(KeysMixin, TestCase):
    """The trigger that is the whole point: revoked means signed out, now.

    These drive `membership.apply_event` directly, which is the single place
    both the registry push and `reconcile` pass through — so what holds here
    holds for both routes into the cache.
    """

    def setUp(self):
        super().setUp()
        oidc.record_session(self.user, client_id=CLIENT_ID)

    def _apply(self, event):
        """Apply an event and return the mocked `requests.post`.

        `captureOnCommitCallbacks` because the notification is deferred to
        commit — an outbound POST has no business running inside the atomic
        block that writes the cache row.
        """
        with patch("corliss.oidc.requests.post", return_value=_ok()) as post:
            with self.captureOnCommitCallbacks(execute=True):
                self.applied = membership.apply_event(membership.parse(event))
        return post

    def test_revoking_a_live_member_ends_their_chat_session(self):
        self._apply(_event(DID, "grant"))
        post = self._apply(_event(DID, "revoke", tid="3lqxbbbbbbbbb"))
        post.assert_called_once()
        claims = jwt.decode(
            post.call_args.kwargs["data"]["logout_token"],
            options={"verify_signature": False},
        )
        self.assertEqual(claims["sub"], DID)

    def test_granting_notifies_nobody(self):
        post = self._apply(_event(DID, "grant"))
        post.assert_not_called()

    def test_revoke_with_no_prior_row_notifies_nobody(self):
        # The rebuild case: reconcile replaying a long-past revocation into an
        # empty cache. The recovery path must not emit a burst of POSTs to end
        # sessions that ended long ago.
        post = self._apply(_event(DID, "revoke"))
        self.assertTrue(self.applied)
        post.assert_not_called()

    def test_revoking_an_already_revoked_member_notifies_nobody(self):
        self._apply(_event(DID, "grant"))
        self._apply(_event(DID, "revoke", tid="3lqxbbbbbbbbb"))
        post = self._apply(_event(DID, "revoke", tid="3lqxccccccccc"))
        post.assert_not_called()

    def test_a_replayed_revoke_notifies_nobody(self):
        self._apply(_event(DID, "grant", tid="3lqxbbbbbbbbb"))
        self._apply(_event(DID, "revoke", tid="3lqxccccccccc"))
        # Same rkey again — a normal best-effort-push retry.
        post = self._apply(_event(DID, "revoke", tid="3lqxccccccccc"))
        self.assertFalse(self.applied)
        post.assert_not_called()

    def test_delivery_failure_does_not_fail_the_push(self):
        # The membership event is the fact; the notification is best-effort.
        # The registry's Lua treats a non-2xx as a failure worth logging, so a
        # chat server being down must not turn a good push into a bad one.
        self._apply(_event(DID, "grant"))
        with patch(
            "corliss.oidc.requests.post",
            side_effect=requests.ConnectionError("refused"),
        ):
            with self.captureOnCommitCallbacks(execute=True):
                applied = membership.apply_event(
                    membership.parse(_event(DID, "revoke", tid="3lqxbbbbbbbbb"))
                )
        self.assertTrue(applied)
        self.assertFalse(
            MembershipCache.objects.get(did=DID).active, "the revocation still landed"
        )


@override_settings(
    PUBLIC_BASE_URL=ISSUER,
    OIDC_CLIENT_ID=CLIENT_ID,
    OIDC_BACKCHANNEL_LOGOUT_URI=LOGOUT_URI,
)
class ReconcileTriggerTests(KeysMixin, TestCase):
    """Reconcile deactivating someone signs them out; a dry run does not."""

    def setUp(self):
        super().setUp()
        oidc.record_session(self.user, client_id=CLIENT_ID)
        self.roster = membership.Roster.from_record(
            {"admins": [{"did": ADMIN_DID, "addedAt": "2020-01-01T00:00:00Z"}]}
        )
        # A live membership for the reconcile run to end.
        with self.captureOnCommitCallbacks(execute=True):
            membership.apply_event(membership.parse(_event(DID, "grant")))

    def test_reconcile_deactivating_a_member_ends_their_chat_session(self):
        events = [_event(DID, "revoke", tid="3lqxbbbbbbbbb")]
        with patch("corliss.oidc.requests.post", return_value=_ok()) as post:
            with self.captureOnCommitCallbacks(execute=True):
                report = membership.reconcile(events, self.roster)
        self.assertEqual(report.applied, [DID])
        post.assert_called_once()

    def test_dry_run_notifies_nobody(self):
        # A preview must not sign anyone out to show an operator what a run
        # *would* do. Guaranteed by dry runs going through `_would_change`
        # rather than `apply_event` — the only place that notifies.
        events = [_event(DID, "revoke", tid="3lqxbbbbbbbbb")]
        with patch("corliss.oidc.requests.post") as post:
            with self.captureOnCommitCallbacks(execute=True):
                report = membership.reconcile(events, self.roster, dry_run=True)
        self.assertEqual(report.applied, [DID])
        post.assert_not_called()
        self.assertTrue(
            MembershipCache.objects.get(did=DID).active, "dry run wrote nothing"
        )
