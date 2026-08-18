"""OIDC *provider* core: discovery document, auth-code issuance, id_token
minting, and ending the sessions those tokens started.

This is the half of Corliss that re-exposes a logged-in member to relying
parties. The `id_token` is RS256 (broad OIDC-client compatibility), signed with
the OIDC key from `corliss.signing` and verifiable via the JWKS endpoint.
Claims: `sub` = DID, `handle`, and `email`/`email_verified` when the member's
PDS supplied one (see `corliss.atproto.fetch_session_email`).

**Back-channel logout lives here too, including the outbound HTTP.** That is a
deliberate repeat of the shape `corliss.membership` already uses for
`MembershipRegistry`: issuing a token and revoking it are two halves of one
relationship with the relying party, and splitting the transport into its own
module would put half of that relationship in each of two files. See
"Back-channel logout" at the bottom.
"""

import logging
import secrets
import time
from datetime import timedelta

import requests
from django.conf import settings
from django.urls import reverse
from django.utils import timezone

from corliss import signing
from corliss.models import OidcAuthCode, OidcSession, User

log = logging.getLogger(__name__)

CODE_TTL_SECONDS = 600
ID_TOKEN_TTL_SECONDS = 3600


def base_url() -> str:
    return settings.PUBLIC_BASE_URL.rstrip("/")


def discovery_document() -> dict:
    return {
        "issuer": base_url(),
        "authorization_endpoint": base_url() + reverse("authorize"),
        "token_endpoint": base_url() + reverse("token"),
        "jwks_uri": base_url() + reverse("jwks"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_post",
            "client_secret_basic",
        ],
        # Advertised for the next relying party, not for the current one: Open
        # WebUI reads only `issuer` and `jwks_uri` out of this document when it
        # validates a logout token, and learns that we do back-channel logout
        # by being told one. A conforming RP discovers it here instead.
        "backchannel_logout_supported": True,
        "backchannel_logout_session_supported": True,
        "claims_supported": [
            "sub",
            "handle",
            "preferred_username",
            "email",
            "email_verified",
            "iss",
            "aud",
            "exp",
            "iat",
            "nonce",
        ],
    }


def issue_code(user, *, client_id, redirect_uri, nonce="", scope="") -> str:
    code = secrets.token_urlsafe(48)
    OidcAuthCode.objects.create(
        code=code,
        user=user,
        client_id=client_id,
        redirect_uri=redirect_uri,
        nonce=nonce,
        scope=scope,
        expires_at=timezone.now() + timedelta(seconds=CODE_TTL_SECONDS),
    )
    return code


def record_session(user, *, client_id) -> OidcSession:
    """Note that `client_id` now holds a session for `user`, and return it.

    Called at token *redemption* rather than at `authorize`. An authorization
    code is only a promise — it can expire unredeemed, and the RP has no
    session until it exchanges one. Redemption is the moment a session actually
    begins on the other side, so it is the moment worth recording.

    `update_or_create` on the (user, client_id) pair, rotating `sid`: one row
    per member per relying party, by construction. See `OidcSession` for why
    that is the right grain rather than one row per login.
    """
    session, _ = OidcSession.objects.update_or_create(
        user=user,
        client_id=client_id,
        defaults={"sid": secrets.token_urlsafe(24)},
    )
    return session


def mint_id_token(user, *, client_id, nonce="", sid="") -> str:
    now = int(time.time())
    payload = {
        "iss": base_url(),
        "sub": user.did,  # DID is the stable subject identifier
        "aud": client_id,
        "iat": now,
        "exp": now + ID_TOKEN_TTL_SECONDS,
        "auth_time": now,
        "handle": user.username,
        "preferred_username": user.username,
    }
    # Best-effort claim: only present when the member's PDS supplied an email
    # (fetch_session_email at login). Absent, not empty-string, when unknown.
    if user.email:
        payload["email"] = user.email
        payload["email_verified"] = user.email_confirmed
    if nonce:
        payload["nonce"] = nonce  # OIDC requires echoing the RP's nonce
    if sid:
        # Ties this token to the OidcSession a later logout_token will name.
        payload["sid"] = sid
    return signing.sign_rs256(payload)


# --- Back-channel logout ----------------------------------------------------
#
# Ending a session Corliss started, rather than waiting for it to expire.
#
# The problem this solves is the one place GATE cannot reach. `require_membership`
# runs at /oidc/authorize, which the relying party visits only when it has no
# valid session of its own — so once Open WebUI mints its own token, Corliss is
# not asked again until that token expires. Revoke a member and they keep
# chatting; sign out of Corliss and chat does not notice. The RP's token
# lifetime *is* the revocation window.
#
# OIDC Back-Channel Logout 1.0 closes it from this side: mint a short JWT that
# says "this subject's session is over", POST it to the RP, and the RP drops
# the session itself. Minting is nearly free — `signing.sign_rs256` already
# does exactly this shape for the id_token, and the RP already trusts our JWKS
# because that is how it validated the id_token in the first place.
#
# Three properties this code exists to hold, each with a plausible wrong answer:
#
# - **It must never raise into its caller.** Every trigger is something that
#   has already happened and cannot be undone: a member signed out, or the
#   registry recorded a revocation. Failing the sign-out or the membership push
#   because a chat server was unreachable would break a working thing to report
#   a broken one. Delivery is best-effort and loud in the log.
# - **It must not be the thing revocation depends on.** It makes revocation
#   immediate; it does not make it *correct*. What still bounds a revoked
#   member when this fails is the RP's own token lifetime, which is why that
#   value is kept short deliberately rather than relaxed now that this exists.
# - **It must stay quiet on the recovery path.** See `membership.apply_event`.

# The RP is on the other side of one hop on the internal bridge, and one of the
# two callers is a human's sign-out request. A slow endpoint must not hold that
# request open, and a hung one must not hold it forever.
LOGOUT_TOKEN_TIMEOUT_SECONDS = 5

# The event that makes a logout token a logout token. The RP checks for exactly
# this key and rejects the token without it.
BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"


def mint_logout_token(user, *, client_id, sid="") -> str:
    """A signed `logout_token` for one member at one relying party.

    Same key, same algorithm and the same JWKS as the `id_token`, so an RP that
    can validate one can validate the other with no extra configuration.

    Deliberately carries **no `nonce`**. The spec forbids it — a logout token
    is not an authentication response, and accepting one with a nonce would let
    an id_token be replayed as a logout — and relying parties reject it
    outright, so a stray nonce here would fail every delivery.
    """
    now = int(time.time())
    payload = {
        "iss": base_url(),
        "sub": user.did,
        "aud": client_id,
        "iat": now,
        # Single-use identifier, so an RP can refuse a replayed logout token.
        "jti": secrets.token_urlsafe(16),
        "events": {BACKCHANNEL_LOGOUT_EVENT: {}},
    }
    if sid:
        payload["sid"] = sid
    return signing.sign_rs256(payload)


def _deliver_logout_token(uri, token) -> bool:
    """POST one logout token. True if the RP accepted it.

    Form-encoded with a single `logout_token` field — the transport the spec
    defines and the only one relying parties implement.
    """
    try:
        response = requests.post(
            uri,
            data={"logout_token": token},
            timeout=LOGOUT_TOKEN_TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:
        # The endpoint was unreachable, refused or too slow. Nothing to retry
        # against here: the caller has already committed the event that
        # triggered this, and the RP's token lifetime is the fallback bound.
        log.warning("back-channel logout: POST to %s failed: %s", uri, exc)
        return False

    if response.status_code >= 400:
        # A 4xx is the more alarming half — it usually means the token was
        # rejected (clock skew, an `aud` that does not match the RP's client_id,
        # a JWKS the RP could not fetch), which is a misconfiguration that will
        # fail every time rather than a transient outage. Log the body: relying
        # parties put the reason there.
        log.warning(
            "back-channel logout: %s returned %s: %s",
            uri,
            response.status_code,
            response.text[:200],
        )
        return False

    return True


def logout_uri_for(client_id):
    """The back-channel logout endpoint for a relying party, or None.

    One registered client today, mirroring `settings.OIDC_CLIENT_ID` — the same
    single-RP shape `views.authorize` validates against. A second RP turns this
    into a mapping and nothing else in this module has to change.
    """
    if client_id != settings.OIDC_CLIENT_ID:
        return None
    return settings.OIDC_BACKCHANNEL_LOGOUT_URI or None


def notify_logout(user) -> int:
    """Tell every relying party holding a session for `user` that it is over.

    Returns how many were successfully notified. **Never raises** — see the
    section comment above.

    A row is deleted once its RP accepts the token, and kept when delivery
    fails. Keeping it is the useful direction: the session really may still be
    live over there, so the next trigger tries again, and an operator reading
    the table sees a session Corliss believes it failed to end.
    """
    notified = 0
    # Materialised up front because the loop deletes rows out from under itself.
    for session in list(user.oidc_sessions.all()):
        uri = logout_uri_for(session.client_id)
        if not uri:
            # Unconfigured, or a client that never registered an endpoint.
            # Inert by design: the gate still holds and the RP's own token
            # lifetime still bounds the session, exactly as before this existed.
            continue

        try:
            token = mint_logout_token(
                user, client_id=session.client_id, sid=session.sid
            )
        except Exception:
            # Signing failing means a missing or unreadable OIDC key, which is
            # a deployment fault worth a full traceback — but not one worth
            # failing a sign-out or a membership push over.
            log.exception(
                "back-channel logout: could not mint a token for %s at %s",
                user.did,
                session.client_id,
            )
            continue

        if _deliver_logout_token(uri, token):
            session.delete()
            notified += 1

    if notified:
        log.info(
            "back-channel logout: ended %s relying-party session(s) for %s",
            notified,
            user.did,
        )
    return notified


def notify_logout_for_did(did) -> int:
    """`notify_logout`, for callers holding a DID rather than a `User`.

    The membership half works in DIDs — `MembershipCache` is DID-keyed with no
    foreign key to `User`, precisely so a grant can exist for someone who has
    never logged in. A DID with no `User` row has by definition never completed
    a token exchange and so holds no relying-party session, which makes "no
    such user" a normal, silent outcome here rather than an error.
    """
    user = User.objects.filter(did=did).first()
    if user is None:
        return 0
    return notify_logout(user)
