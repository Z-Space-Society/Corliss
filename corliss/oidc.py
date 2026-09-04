"""OIDC *provider* core: discovery document, auth-code issuance, id_token
minting, and ending the sessions those tokens started.

This is the half of Corliss that re-exposes a logged-in member to relying
parties. The `id_token` is RS256 (broad OIDC-client compatibility), signed with
the OIDC key from `corliss.signing` and verifiable via the JWKS endpoint.
Claims: `sub` = DID, `handle`, and — when the member has one — `name` and
`email`/`email_verified`. Both of those are seeded from the member's PDS at
login and editable at `/account/`, so neither is guaranteed; each is omitted
rather than sent empty.

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
            "name",
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
    # Best-effort claims, and **absent rather than empty-string** when unknown.
    # That distinction is the whole reason these are conditional: a relying
    # party reading `name` as a display name will happily render "" over the
    # username it would otherwise have fallen back to, so an empty claim is
    # worse than no claim.
    #
    # `name` is what an RP shows a person; `preferred_username` above stays the
    # handle, which is what it keys the account on. Two different questions.
    if user.display_name:
        payload["name"] = user.display_name
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
# The problem this solves is the one place GATE cannot reach. `membership_denial`
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


def registered_logout_endpoints():
    """Every relying party we would tell about a logout: `(client_id, uri)`.

    One registered client today, mirroring `settings.OIDC_CLIENT_ID` — the same
    single-RP shape `views.authorize` validates against. A second RP turns this
    into a mapping and nothing else in this module has to change.

    Empty when unconfigured, which is inert by design: the gate still holds and
    the RP's own token lifetime still bounds the session, exactly as before any
    of this existed.
    """
    if not settings.OIDC_BACKCHANNEL_LOGOUT_URI:
        return []
    return [(settings.OIDC_CLIENT_ID, settings.OIDC_BACKCHANNEL_LOGOUT_URI)]


def notify_logout(user) -> int:
    """Tell every registered relying party that this member's session is over.

    Returns how many accepted the token. **Never raises** — see the section
    comment above.

    **Notification is driven by the registered relying parties, not by our
    `OidcSession` rows**, and that distinction is the whole reason this works
    on a session we have no record of. Corliss only starts recording sessions
    the moment this feature ships, so gating delivery on a row means every
    session that already existed is unreachable — sign-out and revocation
    silently do nothing for exactly the people who were already signed in. That
    is the same shape as the hole GATE had to close at `/oidc/authorize`, where
    enforcing only at login would have let every pre-existing session walk
    through forever, and it deserved the same answer: act on the thing that is
    always true (the RP is registered, and we know the member's `sub`) rather
    than on a record that only exists going forward.

    So the row is an optimisation and an audit trail, never a precondition. It
    supplies `sid` when we have one, and the RP's own lookup by `sub` does the
    work when we don't. Telling an RP about a member who never signed in there
    costs one internal round trip and gets a 200 with an empty body, which is
    much cheaper than the failure the alternative produces.

    A row is deleted once its RP accepts the token, and kept when delivery
    fails. Keeping it is the useful direction: the session really may still be
    live over there, so the next trigger tries again, and an operator reading
    the table sees a session Corliss believes it failed to end.
    """
    notified = 0
    sessions = {s.client_id: s for s in user.oidc_sessions.all()}

    for client_id, uri in registered_logout_endpoints():
        session = sessions.get(client_id)
        try:
            token = mint_logout_token(
                user,
                client_id=client_id,
                # Absent when we never witnessed the exchange. Legal — the spec
                # requires sub OR sid, and the RP resolves the member by sub.
                sid=session.sid if session else "",
            )
        except Exception:
            # Signing failing means a missing or unreadable OIDC key, which is
            # a deployment fault worth a full traceback — but not one worth
            # failing a sign-out or a membership push over.
            log.exception(
                "back-channel logout: could not mint a token for %s at %s",
                user.did,
                client_id,
            )
            continue

        if _deliver_logout_token(uri, token):
            if session is not None:
                session.delete()
            notified += 1

    if notified:
        log.info(
            "back-channel logout: notified %s relying part%s for %s",
            notified,
            "y" if notified == 1 else "ies",
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
