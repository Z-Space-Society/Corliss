"""ATProto OAuth *client*: config, DPoP, identity resolution, PAR, tokens, and
acting on a member's behalf against their own PDS.

Two halves. The first logs a member in: handle → DID → PDS discovery → PAR +
PKCE + DPoP + `private_key_jwt` → tokens. The second, at the bottom of the file,
spends those tokens — refreshing them when the PDS says they are stale, and
writing records into the member's own repo. Implemented directly on `requests` +
`PyJWT` (see requirements.txt for why): atproto's DID/PDS specifics and its
mandated ES256 keys make a transparent, unit-testable implementation easier to
reason about than wrapping a generic OAuth client.

Every network step is a small, separately testable function so the flow can be
unit tested with mocked HTTP. The DPoP dance (a 401 with `use_dpop_nonce` + a
`DPoP-Nonce` header, retried once) is handled in `_post_with_dpop`.

**Everything above "Acting as a member" is pure** — no database, no models, no
request. That is what lets the whole OAuth flow be tested with nothing but
mocked HTTP, and it is worth keeping. The stateful section imports
`AtprotoToken` inside its functions rather than at module top for the same
reason `models.User.is_cluster_admin` imports `membership` locally.
"""

import hashlib
import secrets
import time
import uuid
from datetime import timedelta
from urllib.parse import urlencode

import dns.resolver
import jwt
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from django.conf import settings
from django.urls import reverse
from django.utils import timezone

from corliss import signing

CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
TIMEOUT = 10

# Single source of truth for the scope: requested at PAR time and declared in
# client_metadata() below. The PDS authorization server checks a PAR request's
# scope against what the client publicly declares at its client_id URL —
# request a scope here that isn't ALSO listed in client_metadata()'s "scope"
# and PAR fails with invalid_scope, even though nothing here raises.
#
# transition:email is what unlocks fetch_session_email.
#
# The `repo:` term is the **granular** atproto permission scope, and it is
# deliberately narrow: write access to one collection in the member's repo, and
# nothing else. The alternative — `transition:generic`, which this used to
# request — is defined as "write (create/update/delete) any repository record
# type", i.e. standing permission for Corliss to write anything at all into
# every member's repo, in exchange for the one record it actually needs. The
# member-registry SPA has asked for exactly this granular form in production
# against stock Bluesky PDS software, which is what the applications now in the
# registry index were written with.
#
# `action=delete` is requested although nothing deletes yet: withdrawing an
# application will, and a scope added later would mean a second consent round
# for everyone.
#
# If some PDS turns out not to implement granular scopes, the fallback is to put
# `transition:generic` back — it is a one-line change, and PAR fails loudly with
# invalid_scope rather than failing quietly at write time.
SCOPE = (
    "atproto transition:email "
    "repo:network.sharedcomputer.membership.request"
    "?action=create&action=update&action=delete"
)

# The admin roster record, which lives in the service account's own repo. Only
# that account is ever asked for this, in `views._scope_for` — the roster is a
# single record in a single repo, so requesting it of a member would be asking
# permission to write something that would never be read.
#
# Kept as a *superset* of SCOPE rather than a separate term because the PDS
# checks a PAR request's scope against the whole string this client publishes:
# both values must appear in `client_metadata()`, and a request may narrow but
# never exceed what is declared there.
ROSTER_COLLECTION_SCOPE = (
    "repo:network.sharedcomputer.admin.list?action=create&action=update"
)
SERVICE_SCOPE = f"{SCOPE} {ROSTER_COLLECTION_SCOPE}"


class OAuthError(Exception):
    """Any failure resolving identity or talking to the PDS/auth server."""


class NoSession(OAuthError):
    """This member has no stored PDS session at all, so there is nothing to
    spend and nothing to refresh.

    Distinct from an expired one because the remedy differs and the page has to
    say something different: an expired session means "sign in again", while
    this means the account never had one — a `did:dev:` user from `dev_login`,
    or a token row that was never written.
    """


def _xrpc_error(resp) -> str | None:
    """The `error` string out of an XRPC/OAuth error body, or None.

    XRPC puts the machine-readable reason in the body, not the status line —
    `RecordNotFound`, `use_dpop_nonce` and `invalid_token` all arrive as a 400
    or a 401 — so every caller that must branch on *why* reads it from here.
    Never raises: a body that isn't JSON is simply an error we cannot name.
    """
    try:
        body = resp.json()
    except ValueError:
        return None
    return body.get("error") if isinstance(body, dict) else None


# --- Derived client URLs + published metadata ------------------------------
# Everything anchors on `settings.PUBLIC_BASE_URL` so local and cluster runs
# differ only by that one value. The `client_id` *is* the URL of the client-
# metadata document (an atproto requirement), and must be public HTTPS in
# production.


def base_url() -> str:
    return settings.PUBLIC_BASE_URL.rstrip("/")


def client_id() -> str:
    # atproto identifies the client by the URL that serves its metadata.
    return base_url() + reverse("client_metadata")


def redirect_uri() -> str:
    return base_url() + reverse("callback")


def jwks_uri() -> str:
    return base_url() + reverse("jwks")


def client_metadata() -> dict:
    """ATProto OAuth client metadata (served at the `client_id` URL).

    Confidential web client: `private_key_jwt` auth with an ES256 key and
    DPoP-bound access tokens, per the atproto OAuth profile.
    """
    return {
        "client_id": client_id(),
        "client_name": "Corliss",
        "client_uri": base_url(),
        "application_type": "web",
        "dpop_bound_access_tokens": True,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "redirect_uris": [redirect_uri()],
        # The **maximum** this client may ask for, not what any one login asks.
        # A PAR request may narrow it and almost always does: only the service
        # account is sent the roster term (see `views._scope_for`), and every
        # member's request is `SCOPE` alone. Declaring the union here is what
        # makes that narrowing legal — request a term absent from this string
        # and PAR fails with invalid_scope.
        "scope": SERVICE_SCOPE,
        "token_endpoint_auth_method": "private_key_jwt",
        "token_endpoint_auth_signing_alg": "ES256",
        "jwks_uri": jwks_uri(),
    }


# --- DPoP (RFC 9449) -------------------------------------------------------
# atproto binds OAuth tokens to a **per-session** EC key. We generate one per
# login, persist it server-side (the tokens are bound to it), and use it to
# sign a fresh DPoP proof for every request to the PDS / authorization server.


def generate_key() -> ec.EllipticCurvePrivateKey:
    """A fresh ephemeral DPoP key (EC P-256, as atproto requires)."""
    return ec.generate_private_key(ec.SECP256R1())


def key_to_pem(key: ec.EllipticCurvePrivateKey) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def key_from_pem(pem: str) -> ec.EllipticCurvePrivateKey:
    return serialization.load_pem_private_key(pem.encode(), password=None)


def make_proof(
    key: ec.EllipticCurvePrivateKey,
    htm: str,
    htu: str,
    *,
    nonce: str | None = None,
    access_token: str | None = None,
) -> str:
    """Build a signed DPoP proof JWT for an `htm` request to `htu`.

    Includes the server-issued `nonce` when present, and the access-token hash
    (`ath`) when proving possession on a resource request.
    """
    payload = {
        "jti": uuid.uuid4().hex,
        "htm": htm,
        "htu": htu,
        "iat": int(time.time()),
    }
    if nonce:
        payload["nonce"] = nonce
    if access_token:
        payload["ath"] = signing.b64url(
            hashlib.sha256(access_token.encode()).digest()
        )
    return jwt.encode(
        payload,
        key,
        algorithm="ES256",
        headers={"typ": "dpop+jwt", "jwk": signing.ec_public_jwk(key.public_key())},
    )


# --- Identity resolution --------------------------------------------------

def _resolve_via_well_known(handle: str) -> str | None:
    """The HTTPS well-known method: GET https://{handle}/.well-known/atproto-did."""
    try:
        r = requests.get(
            f"https://{handle}/.well-known/atproto-did", timeout=TIMEOUT
        )
        if r.ok and r.text.strip().startswith("did:"):
            return r.text.strip()
    except requests.RequestException:
        pass
    return None


def _resolve_via_dns_txt(handle: str) -> str | None:
    """The DNS TXT method: a `_atproto.{handle}` TXT record of `did=did:...`."""
    try:
        answers = dns.resolver.resolve(f"_atproto.{handle}", "TXT", lifetime=TIMEOUT)
    except dns.exception.DNSException:
        return None
    for rdata in answers:
        txt = b"".join(rdata.strings).decode("utf-8", "replace")
        if txt.startswith("did="):
            return txt[len("did="):]
    return None


def resolve_handle_to_did(handle: str) -> str:
    """Resolve a handle to a DID (or pass a DID straight through).

    Tries the HTTPS well-known method first, then the public resolver XRPC.
    """
    handle = handle.strip().lstrip("@")
    if handle.startswith("did:"):
        return handle
    did = _resolve_via_well_known(handle)
    if did:
        return did
    try:
        r = requests.get(
            "https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle",
            params={"handle": handle},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        return r.json()["did"]
    except (requests.RequestException, KeyError) as exc:
        raise OAuthError(f"could not resolve handle {handle!r}") from exc


def resolve_handle_for_admin(handle: str) -> str:
    """Resolve a handle to a DID for admin-granting: only the two atproto-spec
    methods (DNS TXT, then HTTPS well-known) — deliberately no fallback to the
    third-party public resolver, since granting admin shouldn't trust it."""
    handle = handle.strip().lstrip("@")
    did = _resolve_via_dns_txt(handle) or _resolve_via_well_known(handle)
    if not did:
        raise OAuthError(
            f"could not resolve handle {handle!r} via DNS TXT or well-known"
        )
    return did


def fetch_did_document(did: str) -> dict:
    if did.startswith("did:plc:"):
        url = f"https://plc.directory/{did}"
    elif did.startswith("did:web:"):
        domain = did[len("did:web:"):]
        url = f"https://{domain}/.well-known/did.json"
    else:
        raise OAuthError(f"unsupported DID method: {did!r}")
    try:
        r = requests.get(url, timeout=TIMEOUT)
        r.raise_for_status()
        return r.json()
    except requests.RequestException as exc:
        raise OAuthError(f"could not fetch DID document for {did}") from exc


def pds_endpoint_from_doc(doc: dict) -> str:
    for svc in doc.get("service", []):
        if (
            svc.get("id") in ("#atproto_pds", f"{doc.get('id', '')}#atproto_pds")
            or svc.get("type") == "AtprotoPersonalDataServer"
        ):
            endpoint = svc.get("serviceEndpoint")
            if not endpoint:
                raise OAuthError("PDS service entry has no serviceEndpoint")
            return endpoint.rstrip("/")
    raise OAuthError("no atproto PDS endpoint in DID document")


def handle_from_doc(doc: dict) -> str | None:
    for aka in doc.get("alsoKnownAs", []):
        if aka.startswith("at://"):
            return aka[len("at://"):]
    return None


def find_record(did: str, collection: str, rkey: str) -> dict | None:
    """Fetch a public record from a repo, or `None` if it isn't there.

    `com.atproto.repo.getRecord` is unauthenticated, so this reaches any public
    record in anyone's repo knowing only the DID — which is what makes reading
    the SCN admin roster free of the service-auth question that shapes the rest
    of this integration. Contrast `fetch_session_email`, the authenticated
    sibling that needs a live access token and a DPoP proof.

    Resolves the DID to its PDS on every call rather than caching: callers that
    read repeatedly should cache the *parsed result* (see
    `corliss.membership.fetch_roster`), not the endpoint, since a DID document
    can legitimately move a repo to a different PDS.

    **"Absent" and "unreachable" are different answers and this is the only
    place that can tell them apart.** A PDS reports a missing record as HTTP 400
    with `{"error": "RecordNotFound"}` — an ordinary status code carrying the
    distinction in its body — so a caller working from the status alone cannot
    separate "this member has not applied" from "their PDS is down". Everything
    else still raises.
    """
    doc = fetch_did_document(did)
    pds_url = pds_endpoint_from_doc(doc)
    try:
        r = requests.get(
            f"{pds_url}/xrpc/com.atproto.repo.getRecord",
            params={"repo": did, "collection": collection, "rkey": rkey},
            timeout=TIMEOUT,
        )
        if not r.ok:
            if _xrpc_error(r) == "RecordNotFound":
                return None
            r.raise_for_status()
        value = r.json().get("value")
    except requests.RequestException as exc:
        raise OAuthError(
            f"could not fetch {collection}/{rkey} from {did}"
        ) from exc
    except ValueError as exc:
        raise OAuthError(f"{pds_url} returned non-JSON for {collection}/{rkey}") from exc

    if not isinstance(value, dict):
        raise OAuthError(f"{collection}/{rkey} in {did} has no record value")
    return value


def get_record(did: str, collection: str, rkey: str) -> dict:
    """`find_record`, for callers to whom a missing record is a failure.

    The roster reads through here: an unreadable roster must never be mistaken
    for an empty one, so "not there" and "not reachable" collapse into the same
    raise. Callers that need the distinction — an applicant's own pending state,
    where absence is the normal answer — call `find_record`.
    """
    value = find_record(did, collection, rkey)
    if value is None:
        raise OAuthError(f"{collection}/{rkey} not found in {did}")
    return value


# --- Authorization-server discovery ---------------------------------------

def discover_auth_server(pds_url: str) -> dict:
    """Resolve the PDS to its authorization-server metadata document."""
    try:
        pr = requests.get(
            f"{pds_url}/.well-known/oauth-protected-resource", timeout=TIMEOUT
        )
        pr.raise_for_status()
        issuer = pr.json()["authorization_servers"][0].rstrip("/")
    except (requests.RequestException, KeyError, IndexError) as exc:
        raise OAuthError(f"PDS {pds_url} exposed no authorization server") from exc
    try:
        meta = requests.get(
            f"{issuer}/.well-known/oauth-authorization-server", timeout=TIMEOUT
        )
        meta.raise_for_status()
        return meta.json()
    except requests.RequestException as exc:
        raise OAuthError(f"could not fetch auth-server metadata at {issuer}") from exc


# --- PKCE + client assertion ----------------------------------------------

def pkce_pair() -> tuple[str, str]:
    """Return (code_verifier, code_challenge) for the S256 method."""
    verifier = secrets.token_urlsafe(64)
    challenge = signing.b64url(hashlib.sha256(verifier.encode()).digest())
    return verifier, challenge


def build_client_assertion(issuer: str) -> str:
    """A `private_key_jwt` proving the client to the auth server (ES256)."""
    now = int(time.time())
    payload = {
        "iss": client_id(),
        "sub": client_id(),
        "aud": issuer,
        "jti": uuid.uuid4().hex,
        "iat": now,
        "exp": now + 300,
    }
    return signing.sign_es256(payload)


# --- DPoP-bound POST with one-shot nonce retry ----------------------------

def _post_with_dpop(url, data, dpop_key, nonce=None):
    def _send(use_nonce):
        proof = make_proof(dpop_key, "POST", url, nonce=use_nonce)
        return requests.post(
            url, data=data, headers={"DPoP": proof}, timeout=TIMEOUT
        )

    return _retry_once_for_nonce(_send, nonce)


def _retry_once_for_nonce(send, nonce):
    """Send, and if the server asked for its own nonce, send once more with it.

    The one-shot half of RFC 9449 that every DPoP call here needs and that none
    of them should be spelling out for themselves: a server that has not yet
    issued a nonce answers the first request with `use_dpop_nonce` and the
    nonce in a header, and the same request succeeds when replayed with it.
    Returns `(response, nonce_to_remember)` — the latest nonce the server
    offered, so the caller can persist it and skip this round trip next time.
    """
    resp = send(nonce)
    if resp.status_code in (400, 401):
        server_nonce = resp.headers.get("DPoP-Nonce")
        if server_nonce and _xrpc_error(resp) == "use_dpop_nonce":
            resp = send(server_nonce)
            return resp, resp.headers.get("DPoP-Nonce", server_nonce)
    return resp, resp.headers.get("DPoP-Nonce", nonce)


def _get_with_dpop(url, access_token, dpop_key, nonce=None):
    """GET a DPoP-bound resource (e.g. the PDS's `getSession`) with one-shot
    nonce retry, mirroring `_post_with_dpop`."""

    def _send(use_nonce):
        proof = make_proof(
            dpop_key, "GET", url, nonce=use_nonce, access_token=access_token
        )
        return requests.get(
            url,
            headers={"DPoP": proof, "Authorization": f"DPoP {access_token}"},
            timeout=TIMEOUT,
        )

    return _retry_once_for_nonce(_send, nonce)


def post_json_with_dpop(
    url, payload, access_token, dpop_key, nonce=None, *, headers=None,
    htu=None, timeout=TIMEOUT,
):
    """POST JSON to a DPoP-bound XRPC procedure, with one-shot nonce retry.

    A third sibling rather than a flag on `_post_with_dpop`, because the two
    differ in both directions that matter: the token endpoint takes
    form-encoded data and authenticates the *client* (`private_key_jwt` in the
    body), while a resource call takes JSON and authenticates the *member* —
    an `Authorization: DPoP` header plus the access-token hash bound into the
    proof as `ath`. Collapsing them would mean a function whose every line is
    conditional on which caller it has.

    `headers` is merged in underneath the two this function owns, for callers
    whose destination wants more than the DPoP pair — the registry needs its
    client key and an explicit `Host`. It cannot override the proof or the
    authorization, which are the whole point of the call.

    `htu` overrides what the proof *claims* the request URI is, while the
    request still goes to `url`. They are the same thing for a PDS and are not
    for the registry, which Corliss reaches at an internal address while
    presenting the public `Host` — the server reconstructs the URI from that
    header and compares it to the proof, so signing the address we dialled earns
    a 401 `DPoP proof htu mismatch`. Only ever the public name for the same
    private address; a caller that could point this anywhere would be signing
    proofs for a server it is not talking to.

    Public, unlike its siblings, because `membership.MembershipRegistry` calls
    it: writing to the registry is a DPoP-authenticated POST like any other, and
    a second copy of the nonce dance living over there is exactly the drift this
    module exists to prevent.
    """

    def _send(use_nonce):
        proof = make_proof(
            dpop_key,
            "POST",
            htu or url,
            nonce=use_nonce,
            access_token=access_token,
        )
        return requests.post(
            url,
            json=payload,
            headers={
                **(headers or {}),
                "DPoP": proof,
                "Authorization": f"DPoP {access_token}",
            },
            timeout=timeout,
        )

    return _retry_once_for_nonce(_send, nonce)


# --- Email sourcing (transition:email) -------------------------------------

def fetch_session_email(pds_url, access_token, *, dpop_key, nonce=None):
    """Read `email`/`emailConfirmed` from the member's PDS via `getSession`.

    Email is optional data — the member may have declined the scope, or the
    PDS may not expose it. This never raises; a failure or missing field
    simply yields `("", False)` so login isn't blocked on it.
    """
    url = f"{pds_url}/xrpc/com.atproto.server.getSession"
    try:
        resp, _ = _get_with_dpop(url, access_token, dpop_key, nonce=nonce)
        if not resp.ok:
            return "", False
        data = resp.json()
    except (requests.RequestException, ValueError):
        return "", False
    return data.get("email") or "", bool(data.get("emailConfirmed"))


# --- PAR + token exchange -------------------------------------------------

def pushed_authorization_request(
    meta, *, dpop_key, state, code_challenge, login_hint, scope=None
):
    """Push the authorization request; return (request_uri, dpop_nonce).

    `scope` defaults to `SCOPE`, which is what every member's login sends. The
    caller passes a value only to *narrow or extend within* what
    `client_metadata()` publishes — today one case, the service account picking
    up `SERVICE_SCOPE` so it can write the roster record. An unpublished term
    fails here with `invalid_scope` rather than silently at write time.
    """
    data = {
        "client_id": client_id(),
        "response_type": "code",
        "redirect_uri": redirect_uri(),
        "scope": scope or SCOPE,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "login_hint": login_hint,
        "client_assertion_type": CLIENT_ASSERTION_TYPE,
        "client_assertion": build_client_assertion(meta["issuer"]),
    }
    resp, nonce = _post_with_dpop(
        meta["pushed_authorization_request_endpoint"], data, dpop_key
    )
    if not resp.ok:
        raise OAuthError(f"PAR failed ({resp.status_code}): {resp.text[:200]}")
    try:
        request_uri = resp.json()["request_uri"]
    except (ValueError, KeyError) as exc:
        raise OAuthError("PAR response missing request_uri") from exc
    return request_uri, nonce


def authorization_url(meta, request_uri: str) -> str:
    qs = urlencode({"client_id": client_id(), "request_uri": request_uri})
    return f"{meta['authorization_endpoint']}?{qs}"


def exchange_code(meta, *, code, code_verifier, dpop_key, nonce=None):
    """Exchange the auth code for DPoP-bound tokens; return (token, nonce)."""
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri(),
        "code_verifier": code_verifier,
        "client_id": client_id(),
        "client_assertion_type": CLIENT_ASSERTION_TYPE,
        "client_assertion": build_client_assertion(meta["issuer"]),
    }
    resp, new_nonce = _post_with_dpop(
        meta["token_endpoint"], data, dpop_key, nonce=nonce
    )
    if not resp.ok:
        raise OAuthError(
            f"token exchange failed ({resp.status_code}): {resp.text[:200]}"
        )
    return resp.json(), new_nonce


def refresh_tokens(meta, *, refresh_token, dpop_key, nonce=None):
    """Trade a refresh token for a fresh access token; return (token, nonce).

    The same exchange as `exchange_code` with a different grant, and the same
    two proofs: `private_key_jwt` for the client, and a DPoP proof signed with
    the **session** key the tokens are bound to. Passing a fresh key here would
    fail — the binding is what a refresh preserves.

    The response's `refresh_token` REPLACES the one passed in. atproto refresh
    tokens are single-use, so a caller that stores the response but keeps the
    old refresh token has quietly ended the session at the next refresh.
    """
    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client_id(),
        "client_assertion_type": CLIENT_ASSERTION_TYPE,
        "client_assertion": build_client_assertion(meta["issuer"]),
    }
    resp, new_nonce = _post_with_dpop(
        meta["token_endpoint"], data, dpop_key, nonce=nonce
    )
    if not resp.ok:
        raise OAuthError(
            f"token refresh failed ({resp.status_code}): {resp.text[:200]}"
        )
    return resp.json(), new_nonce


# --- Writing to a member's repo -------------------------------------------


def put_record(
    pds_url,
    *,
    repo,
    collection,
    rkey,
    record,
    access_token,
    dpop_key,
    nonce=None,
):
    """`com.atproto.repo.putRecord` into `repo`, as the member. Upserts.

    Returns `(response, nonce)` rather than raising on a non-2xx, because the
    caller has to read the error before deciding: a 401 `invalid_token` is
    recoverable by refreshing, and everything else is not. `write_record` is
    where that decision lives.

    The PDS enforces that `repo` is the authenticated member's own — this is
    not the place that could write into someone else's, and there isn't one.
    """
    return post_json_with_dpop(
        f"{pds_url}/xrpc/com.atproto.repo.putRecord",
        {
            "repo": repo,
            "collection": collection,
            "rkey": rkey,
            "record": record,
        },
        access_token,
        dpop_key,
        nonce=nonce,
    )


# --- Acting as a member ----------------------------------------------------
#
# Below here the module touches the database: this is the part that spends a
# member's stored tokens rather than obtaining them. `AtprotoToken` is imported
# inside the functions, not at module top, so everything above stays testable
# with nothing but mocked HTTP.


def write_record(user, collection, rkey, record):
    """Write a record into the member's own repo, refreshing if the PDS says to.

    **One retry, for one reason.** The PDS answers a stale access token with 401
    `invalid_token`; that is the only failure this recovers from, and it does so
    once. Any other failure is returned to the caller as an `OAuthError` — a
    write that fails twice for the same reason will fail a third time, and the
    member is better served by an error they can act on than by a page that
    hangs while we try again.

    Corliss's Django session outlives a PDS access token by a wide margin, so
    this path is not an edge case: a member who signed in this morning and
    applies this afternoon takes it every time.

    Persists whatever the round trip produced — the server's latest DPoP nonce,
    and on a refresh the new access token, the **rotated** refresh token and the
    expiry. Nothing new is stored: every one of those fields already exists on
    `AtprotoToken` and `expires_at` was simply never being set.
    """
    from corliss.models import AtprotoToken

    try:
        token = user.atproto_token
    except AtprotoToken.DoesNotExist:
        raise NoSession(
            f"{user.did} has no stored PDS session"
        ) from None

    if not token.access_token:
        raise NoSession(f"{user.did} has no access token")

    dpop_key = key_from_pem(token.dpop_private_pem)

    def attempt():
        resp, nonce = put_record(
            token.pds_url,
            repo=user.did,
            collection=collection,
            rkey=rkey,
            record=record,
            access_token=token.access_token,
            dpop_key=dpop_key,
            nonce=token.dpop_nonce or None,
        )
        if nonce and nonce != token.dpop_nonce:
            token.dpop_nonce = nonce
            token.save(update_fields=["dpop_nonce", "updated_at"])
        return resp

    try:
        resp = attempt()
        if resp.status_code == 401 and _xrpc_error(resp) == "invalid_token":
            _refresh(token, dpop_key)
            resp = attempt()
    except requests.RequestException as exc:
        raise OAuthError(f"could not reach {token.pds_url}") from exc

    if not resp.ok:
        raise OAuthError(
            f"writing {collection}/{rkey} failed "
            f"({resp.status_code}): {resp.text[:200]}"
        )
    try:
        return resp.json()
    except ValueError:
        # A 2xx with an unreadable body still wrote the record. Say so rather
        # than turning a success into a failure the member would retry.
        return {}


def refresh_session(token):
    """Refresh a stored session on purpose, rather than on being told to.

    The public door onto `_refresh` for the one caller that has to act *before*
    a failure: `membership.refresh_service_session`, keeping the service
    account's session alive between roster edits that happen monthly. Everywhere
    else refreshes reactively, on the PDS answering `invalid_token`, which is
    the better default — the note in `_refresh` about not pre-empting a clock we
    do not own still stands for every other path.
    """
    return _refresh(token, key_from_pem(token.dpop_private_pem))


def _refresh(token, dpop_key):
    """Refresh `token` in place and persist the result. Raises `OAuthError`.

    Kept private and separate from `write_record` only so the retry above reads
    as one line. There is deliberately no proactive "is it expired yet" check
    anywhere: the PDS is the authority on that, `expires_at` is advisory, and a
    clock we do not own is not worth pre-empting.
    """
    if not token.refresh_token:
        raise NoSession(
            "session has no refresh token; sign in again"
        )

    data, nonce = refresh_tokens(
        {"issuer": token.issuer, "token_endpoint": token.token_endpoint},
        refresh_token=token.refresh_token,
        dpop_key=dpop_key,
        nonce=token.dpop_nonce or None,
    )

    # Checked BEFORE anything is persisted. Storing an empty access token and
    # then raising would leave the member with a session that cannot be used and
    # cannot be refreshed either — the stored one still works until its own
    # expiry, so a nonsense response must not be allowed to overwrite it.
    access_token = data.get("access_token") or ""
    if not access_token:
        raise OAuthError("refresh returned no access token")

    token.access_token = access_token
    # Single-use: keep the old one only if the server declined to rotate.
    token.refresh_token = data.get("refresh_token") or token.refresh_token
    token.dpop_nonce = nonce or ""
    expires_in = data.get("expires_in")
    if isinstance(expires_in, int):
        token.expires_at = timezone.now() + timedelta(seconds=expires_in)
    token.save(
        update_fields=[
            "access_token",
            "refresh_token",
            "dpop_nonce",
            "expires_at",
            "updated_at",
        ]
    )
