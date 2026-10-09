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

import base64
import hashlib
import hmac
import json
import logging
import re
import secrets
import time
from dataclasses import dataclass
from datetime import timedelta
from urllib.parse import urlsplit

import requests
from django.conf import settings
from django.urls import reverse
from django.utils import timezone

from corliss import signing
from corliss.models import OidcAuthCode, OidcClientDocument, OidcSession, User

log = logging.getLogger(__name__)

CODE_TTL_SECONDS = 600
ID_TOKEN_TTL_SECONDS = 3600
# Short, because nothing revokes an access token once it is issued. This is
# the whole of how long a removed member keeps access to a resource, and the
# relay closes a sync connection at `exp`.
ACCESS_TOKEN_TTL_SECONDS = 900
# Thirty days from each use, not from sign-in: a client in regular use never
# expires and an abandoned one does.
REFRESH_TOKEN_TTL = timedelta(days=30)
# How long after a refresh the same token is accepted once more, for a client
# that never received the answer. See `OidcRefreshToken.is_lost_response_retry`.
REFRESH_REUSE_GRACE = timedelta(seconds=60)


def base_url() -> str:
    return settings.PUBLIC_BASE_URL.rstrip("/")


# --- Clients ----------------------------------------------------------------
#
# Two kinds. The confidential one is Open WebUI, described by settings exactly
# as it always was. A public client has no secret and no row here: its
# `client_id` is the URL of a metadata document that says what it is.

CONFIDENTIAL = "confidential"
PUBLIC = "public"


class ClientError(Exception):
    """A `client_id` Corliss will not serve. Carries the OAuth error code."""

    def __init__(self, error, description):
        super().__init__(description)
        self.error = error
        self.description = description


@dataclass(frozen=True)
class Client:
    client_id: str
    kind: str
    redirect_uris: tuple
    name: str
    # The host of the `client_id` URL, which is what the consent screen names
    # the app by. Blank for the confidential client, which has no URL.
    host: str = ""
    grant_types: tuple = ("authorization_code",)

    @property
    def is_public(self) -> bool:
        return self.kind == PUBLIC


def plugin_client_id() -> str:
    """The `client_id` of the scn-obsidian plugin: the URL of its document.

    **The path is part of the client's identity**, the same way the atproto
    `client_id` is. Change it and every install is a new client: its refresh
    tokens stop working and each member signs in again.
    """
    return base_url() + reverse("plugin_client_metadata")


def plugin_client_metadata() -> dict:
    """The metadata document for the scn-obsidian plugin, which Corliss hosts.

    The one document allowed a custom-scheme redirect, because Corliss wrote
    it. `client_name` is what the member installed: the plugin is listed in
    Obsidian as SCN Sync.
    """
    return {
        "client_id": plugin_client_id(),
        "client_name": "SCN Sync",
        "client_uri": base_url(),
        "redirect_uris": ["obsidian://scn-obsidian"],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    }


def _client_from_document(document) -> Client:
    return Client(
        client_id=document["client_id"],
        kind=PUBLIC,
        redirect_uris=tuple(document["redirect_uris"]),
        name=document.get("client_name", ""),
        host=urlsplit(document["client_id"]).hostname or "",
        grant_types=tuple(document.get("grant_types") or ["authorization_code"]),
    )


def resolve_client(client_id) -> Client:
    """The client a `client_id` names, or `ClientError`.

    Corliss's own document is read from the function that builds it and never
    fetched over HTTP: with two gunicorn workers a request to our own origin
    can wait on itself.
    """
    if client_id and client_id == settings.OIDC_CLIENT_ID:
        return Client(
            client_id=client_id,
            kind=CONFIDENTIAL,
            redirect_uris=tuple(settings.OIDC_REDIRECT_URIS),
            name=client_id,
        )
    if client_id and client_id == plugin_client_id():
        return _client_from_document(plugin_client_metadata())
    raise ClientError("unauthorized_client", "unknown client_id")


def known_client(client_id):
    """The public client a `client_id` names, **without fetching anything**.

    For the token endpoint, which must answer inside a client's deadline and
    so never makes an outbound request for a document. Corliss's own document
    comes from the function that builds it, anyone else's from the row
    `authorize` cached when the member signed in. None when there is neither.
    """
    if client_id and client_id == plugin_client_id():
        return _client_from_document(plugin_client_metadata())
    row = OidcClientDocument.objects.filter(client_id=client_id).first()
    if row is not None and row.document:
        return _client_from_document(row.document)
    return None


def issues_refresh_tokens(client_id) -> bool:
    """Whether this client is given a refresh token with its access token.

    Decided by the `refresh_token` grant in the client's own document, and
    deliberately **not** by the `offline_access` scope. The relay advertises
    no scopes and Claude Code's document declares none, so a client may never
    ask for it, and one with no refresh token signs its member in again every
    fifteen minutes. Membership is re-checked on every refresh, which is the
    control that matters; the scope would add nothing to it.
    """
    client = known_client(client_id)
    return client is not None and "refresh_token" in client.grant_types


# --- Resources --------------------------------------------------------------
#
# The services an access token can be issued for. Each is named by its public
# URL, and that URL is the token's `aud`, spelled exactly as configured: the
# relay compares it character for character.

RESOURCE_KINDS = ("sync", "mcp")


@dataclass(frozen=True)
class Resource:
    url: str
    kind: str
    label: str


def parse_resources(raw):
    """Read `OIDC_RESOURCES` into `(resources, problems)`.

    Any problem yields no resources at all. A deployment whose value is
    half right would otherwise issue tokens for one service and silently
    refuse the other, which is harder to notice than refusing both.
    """
    if not raw:
        return [], []
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError as exc:
            return [], [f"not valid JSON: {exc}"]
    if not isinstance(raw, list):
        return [], ["must be a JSON list of objects"]

    resources, problems = [], []
    for index, entry in enumerate(raw):
        where = f"entry {index + 1}"
        if not isinstance(entry, dict):
            problems.append(f"{where} is not an object")
            continue
        url, kind, label = entry.get("url"), entry.get("kind"), entry.get("label")
        parts = urlsplit(url) if isinstance(url, str) else None
        if not parts or parts.scheme not in ("http", "https") or not parts.hostname:
            problems.append(f"{where}: url must be an http(s) URL")
        if kind not in RESOURCE_KINDS:
            problems.append(f"{where}: kind must be one of {', '.join(RESOURCE_KINDS)}")
        elif any(r.kind == kind for r in resources):
            problems.append(f"{where}: a second {kind} resource")
        if not isinstance(label, str) or not label.strip():
            problems.append(f"{where}: label must be a non-empty string")
        if not problems:
            resources.append(Resource(url=url, kind=kind, label=label.strip()))

    return ([], problems) if problems else (resources, [])


def resources():
    """The configured resources. Empty when unset or invalid, which refuses
    every public client: an unconfigured deployment issues nothing."""
    return parse_resources(settings.OIDC_RESOURCES)[0]


def _normalise_resource(url) -> str:
    """A resource URL in the form two spellings of it are compared in.

    Lowercases the scheme and host and drops the slash from a path that is
    nothing else, so `https://MCP.example.com/` and `https://mcp.example.com`
    are one resource. Nothing more: a path's own trailing slash is kept.
    """
    parts = urlsplit(url)
    path = "" if parts.path == "/" else parts.path
    return parts._replace(
        scheme=parts.scheme.lower(), netloc=parts.netloc.lower(), path=path
    ).geturl()


def match_resource(requested):
    """The configured resource a client's `resource` parameter names, or None.

    The caller issues `aud` from the returned `url`, which is the configured
    spelling and never the client's. A client that sends a trailing slash
    still receives a token the relay accepts.
    """
    if not requested or not isinstance(requested, str):
        return None
    wanted = _normalise_resource(requested)
    for resource in resources():
        if _normalise_resource(resource.url) == wanted:
            return resource
    return None


# --- Request checks for public clients --------------------------------------

SCOPES = ("openid", "profile", "email", "offline_access")


def narrow_scope(granted, requested) -> str:
    """The scope for an access token issued on refresh.

    A client may ask for less than it was granted and never for more. With no
    request it gets what it was granted.
    """
    if not requested:
        return granted
    wanted = requested.split()
    return " ".join(value for value in granted.split() if value in wanted)


def grant_scope(requested) -> str:
    """The scope granted for a requested one: unknown values are dropped.

    An empty result is valid. The relay's protected resource metadata
    advertises no scopes, so an MCP client may ask for none at all.
    """
    granted = []
    for value in (requested or "").split():
        if value in SCOPES and value not in granted:
            granted.append(value)
    return " ".join(granted)


_LOOPBACK_HOSTS = ("localhost", "127.0.0.1", "::1")


def _loopback_parts(uri):
    """What a loopback redirect is compared on, or None if it is not one.

    Everything but the port. A native app listens on whatever port the
    system hands it, so the port is the one part it cannot declare ahead.
    """
    try:
        parts = urlsplit(uri)
        parts.port  # raises on a port that is not a number
    except ValueError:
        return None
    if parts.scheme != "http" or parts.hostname not in _LOOPBACK_HOSTS:
        return None
    if parts.username is not None or parts.fragment:
        return None
    return (parts.hostname, parts.path, parts.query)


def redirect_uri_matches(requested, registered) -> bool:
    """Whether a requested redirect URI is one the client declared.

    Exact string comparison for everything except loopback: an `https` URI,
    and a custom scheme such as `obsidian://scn-obsidian`, must appear in the
    list character for character. An `http` URI is accepted only on a
    loopback host, compared with the port ignored on both sides.

    `localhost` and `127.0.0.1` are different hosts here and do not match
    each other. A client that uses both declares both.
    """
    if not requested or not isinstance(requested, str):
        return False
    scheme = urlsplit(requested).scheme.lower()
    if not scheme:
        return False
    if scheme != "http":
        return requested in registered
    wanted = _loopback_parts(requested)
    if wanted is None:
        return False
    return any(_loopback_parts(entry) == wanted for entry in registered)


def is_loopback_redirect(uri) -> bool:
    return _loopback_parts(uri) is not None


# An S256 challenge is the base64url of a SHA-256 digest: 43 characters.
_CODE_CHALLENGE = re.compile(r"[A-Za-z0-9_-]{43}")
# RFC 7636: 43 to 128 characters from the unreserved set.
_CODE_VERIFIER = re.compile(r"[A-Za-z0-9._~-]{43,128}")


def valid_code_challenge(challenge) -> bool:
    return bool(challenge) and _CODE_CHALLENGE.fullmatch(challenge) is not None


def pkce_verifies(verifier, challenge) -> bool:
    """Whether `verifier` is the secret behind a stored S256 `challenge`."""
    if not verifier or not challenge or not _CODE_VERIFIER.fullmatch(verifier):
        return False
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return hmac.compare_digest(computed, challenge)


def discovery_document() -> dict:
    return {
        "issuer": base_url(),
        "authorization_endpoint": base_url() + reverse("authorize"),
        "token_endpoint": base_url() + reverse("token"),
        "jwks_uri": base_url() + reverse("jwks"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_post",
            "client_secret_basic",
            "none",
        ],
        # The three fields an MCP client reads before it will start. Without
        # the first it refuses to proceed. Claude uses a metadata document as
        # its `client_id` only when it sees both the second and `none` above,
        # and otherwise looks for a registration endpoint, which does not
        # exist here.
        "code_challenge_methods_supported": ["S256"],
        "client_id_metadata_document_supported": True,
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


def issue_code(
    user,
    *,
    client_id,
    redirect_uri,
    nonce="",
    scope="",
    code_challenge="",
    resource="",
) -> str:
    # The only cleanup codes get. There is no scheduled job, and one that is
    # issued is the natural moment to drop the ones nobody redeemed.
    OidcAuthCode.purge_expired()
    code = secrets.token_urlsafe(48)
    OidcAuthCode.objects.create(
        code=code,
        user=user,
        client_id=client_id,
        redirect_uri=redirect_uri,
        nonce=nonce,
        scope=scope,
        code_challenge=code_challenge,
        resource=resource,
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


def mint_access_token(user, *, client_id, resource, scope="") -> str:
    """An access token for one resource, as scn-sync-relay verifies it.

    **This shape is a contract with the relay**, and a change here is a change
    to its verifier. Three parts have a plausible wrong answer:

    - `typ` is `at+jwt`. It is what stops an `id_token`, signed by the same
      key, from being accepted as an access token.
    - `aud` is one string, the resource URL as configured. The relay refuses
      a list, and refuses a URL that differs by a trailing slash.
    - No handle, name or email. The plugin sends this token in a websocket
      URL, so it carries nothing about the person beyond the DID.
    """
    now = int(time.time())
    payload = {
        "iss": base_url(),
        "sub": user.did,
        "aud": resource,
        "iat": now,
        "exp": now + ACCESS_TOKEN_TTL_SECONDS,
        "jti": secrets.token_urlsafe(16),
        "scope": scope,
        "client_id": client_id,
    }
    return signing.sign_rs256(payload, headers={"typ": "at+jwt"})


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
