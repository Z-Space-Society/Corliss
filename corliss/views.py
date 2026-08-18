"""All of Corliss's HTTP endpoints — the ATProto client half and the OIDC
provider half, in the order a member meets them.

ATProto client (people):
- `client_metadata`: serves the client metadata at the `client_id` URL.
- `login`: handle form → resolve → discover → PAR → redirect to the PDS.
- `callback`: validate `state` → DPoP-bound token exchange → upsert the member,
  store tokens server-side, establish the Django session.
- `home`: the root page — an intro when signed out, your standing when in.
- `api`: placeholder for direct API access; nothing on it is wired up yet.
- `manage`: the cluster console — members, admins, and reconciliation. Gated on
  the atproto roster, not on any Django flag, so it survives a rebuild.
- `logout`: ends this device's Corliss session. Local-session-only for now (no
  upstream ATProto/OIDC RP-initiated logout) — a relying party like Open WebUI
  ending its own session doesn't end this one, so a member who wants a real
  logout has to hit this too.
- `dev_login`: LOCAL DEVELOPMENT ONLY. Mints a session for any handle with no
  authentication whatsoever, so the rest of the app is workable without the
  public-HTTPS `client_id` a real atproto login demands. Off by default and
  refused outside DEBUG — see settings.DEV_LOGIN_ENABLED.

OIDC provider (machines):
- `jwks`: published public keys.
- `openid_configuration`: discovery document.
- `authorize`: the RP sends the member here; if signed in we issue an auth code
  and redirect back, otherwise we bounce through atproto login and resume.
- `token`: the RP redeems the code (with its client secret) for an `id_token`.

Registry (machines):
- `membership_push`: the SCN registry POSTs each grant/revocation here so
  Corliss can cache who is a member. See `corliss.membership`.
"""

import base64
import hmac
import json
import secrets
from urllib.parse import urlencode

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth import login as auth_login
from django.contrib.auth import logout as auth_logout
from django.http import Http404, HttpResponseBadRequest, JsonResponse
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from corliss import atproto, membership, oidc, signing
from corliss.models import AtprotoToken, MembershipCache, OidcAuthCode

User = get_user_model()

SESSION_PREFIX = "corliss:oauth:"

# Key in the Django session for "where to resume after atproto login".
POST_LOGIN_REDIRECT = "post_login_redirect"


# --- ATProto OAuth client endpoints ----------------------------------------


def client_metadata(request):
    """Serve the ATProto OAuth client metadata at the `client_id` URL."""
    return JsonResponse(atproto.client_metadata())


def login(request):
    if request.method != "POST":
        return render(request, "login.html")

    handle = request.POST.get("handle", "").strip()
    if not handle:
        return render(request, "login.html", {"error": "Enter a handle."})

    try:
        did = atproto.resolve_handle_to_did(handle)
        doc = atproto.fetch_did_document(did)
        pds_url = atproto.pds_endpoint_from_doc(doc)
        meta = atproto.discover_auth_server(pds_url)
        dpop_key = atproto.generate_key()
        verifier, challenge = atproto.pkce_pair()
        state = secrets.token_urlsafe(32)
        request_uri, nonce = atproto.pushed_authorization_request(
            meta,
            dpop_key=dpop_key,
            state=state,
            code_challenge=challenge,
            login_hint=handle,
        )
    except atproto.OAuthError as exc:
        return render(request, "login.html", {"error": str(exc)})

    # Pending-flow state lives in the server-side Django session, keyed by the
    # opaque `state` we just minted (validated on callback — CSRF defense).
    request.session[SESSION_PREFIX + state] = {
        "code_verifier": verifier,
        "dpop_pem": atproto.key_to_pem(dpop_key),
        "dpop_nonce": nonce,
        "issuer": meta["issuer"],
        "token_endpoint": meta["token_endpoint"],
        "did": did,
        "pds_url": pds_url,
        "handle": handle,
    }
    return redirect(atproto.authorization_url(meta, request_uri))


def callback(request):
    state = request.GET.get("state")
    pending = (
        request.session.pop(SESSION_PREFIX + state, None) if state else None
    )
    # Unknown/expired/missing state → reject (CSRF / replay protection).
    if not state or pending is None:
        return HttpResponseBadRequest("Invalid or expired authorization state.")

    if request.GET.get("error"):
        return render(
            request,
            "login.html",
            {"error": f"Authorization denied: {request.GET.get('error')}"},
        )

    # RFC 9207 mix-up defense: the authorization response must carry the exact
    # issuer we started the flow with, else a code could be redeemed against a
    # different authorization server.
    if request.GET.get("iss") != pending["issuer"]:
        return HttpResponseBadRequest("Issuer mismatch in authorization response.")

    code = request.GET.get("code")
    if not code:
        return HttpResponseBadRequest("Missing authorization code.")

    dpop_key = atproto.key_from_pem(pending["dpop_pem"])
    meta = {
        "issuer": pending["issuer"],
        "token_endpoint": pending["token_endpoint"],
    }
    try:
        token_data, nonce = atproto.exchange_code(
            meta,
            code=code,
            code_verifier=pending["code_verifier"],
            dpop_key=dpop_key,
            nonce=pending["dpop_nonce"],
        )
    except atproto.OAuthError as exc:
        return render(request, "login.html", {"error": str(exc)})

    # The token's `sub` is the PDS-authenticated DID — authoritative and
    # required. Never fall back to the unverified pre-resolved DID.
    did = token_data.get("sub")
    if not did or did != pending["did"]:
        return HttpResponseBadRequest("DID mismatch in token response.")

    # Best-effort: read email straight from the member's PDS (requires the
    # transition:email grant). Never blocks login — see fetch_session_email.
    email, email_confirmed = atproto.fetch_session_email(
        pending["pds_url"],
        token_data.get("access_token", ""),
        dpop_key=dpop_key,
        nonce=nonce,
    )

    user = _upsert_member(
        did=did,
        handle=pending["handle"],
        pds_url=pending["pds_url"],
        email=email,
        email_confirmed=email_confirmed,
    )
    _store_tokens(user, token_data, dpop_key, nonce, pending)

    auth_login(
        request, user, backend="django.contrib.auth.backends.ModelBackend"
    )
    user.touch_last_seen()

    # Resume an in-progress OIDC authorize (the RP) if one bounced us here.
    # Only honour a safe same-site path (single leading slash, no scheme/host).
    next_url = request.session.pop(POST_LOGIN_REDIRECT, None)
    if next_url and next_url.startswith("/") and not next_url.startswith("//"):
        return redirect(next_url)
    return redirect("home")


@require_http_methods(["POST"])
def dev_login(request):
    """LOCAL DEVELOPMENT ONLY — sign in as anyone, verifying nothing.

    A real atproto login can't complete over loopback (the authorization server
    fetches our client-metadata.json over public HTTPS), so this exists to make
    the rest of the app — the OIDC half, the templates, the admin, relying-party
    wiring — workable without a tunnel. It skips the entire handshake: no DID
    resolution, no PDS discovery, no PAR, no DPoP, no token exchange.

    Consequently it proves nothing about the atproto client. Use a tunnel for
    that (README, "Real atproto login locally").

    Gated on DEBUG *and* DEV_LOGIN_ENABLED here as well as at the URLconf, and
    corliss.apps.check_dev_login_requires_debug fails startup if the flag is set
    without DEBUG. See the DEV_LOGIN_ENABLED note in settings.py.
    """
    if not (settings.DEBUG and settings.DEV_LOGIN_ENABLED):
        raise Http404("dev login is not enabled")

    handle = request.POST.get("handle", "").strip().lstrip("@")
    if not handle:
        return render(request, "login.html", {"error": "Enter a handle."})

    # `did:dev:` is not a registered DID method, so these rows can never collide
    # with a real atproto DID and are obvious as fakes in the admin and the DB.
    # Deriving it from the handle keeps repeat logins landing on the same member.
    user = _upsert_member(
        did=f"did:dev:{handle}",
        handle=handle,
        pds_url="",
        email=f"{handle}@dev.invalid",
        email_confirmed=False,
    )
    auth_login(
        request, user, backend="django.contrib.auth.backends.ModelBackend"
    )
    user.touch_last_seen()

    # Resume an in-progress OIDC authorize, exactly as `callback` does, so the
    # relying-party flow is testable end to end without atproto.
    next_url = request.session.pop(POST_LOGIN_REDIRECT, None)
    if next_url and next_url.startswith("/") and not next_url.startswith("//"):
        return redirect(next_url)
    return redirect("home")


def home(request):
    """The home page: signed out, or signed in with or without membership.

    Deliberately not `@login_required` — a signed-out visitor gets the intro
    here rather than being bounced to the login form.

    Membership is resolved here rather than in the template because it is a
    real lookup against the cache table. Admin is not: it hangs off the user as
    `user.is_cluster_admin` because the nav asks it on every page, not just this
    one.
    """
    did = request.user.did if request.user.is_authenticated else None
    return render(
        request,
        "home.html",
        {"is_member": bool(did) and membership.is_active_member(did)},
    )


def api(request):
    """Placeholder for direct API access — copy and a dead "create key" button.

    Nothing here is wired up yet. It exists so the nav entry, the endpoint, and
    the shape of the key flow are settled before any of it is built.
    """
    return render(request, "api.html")


@require_http_methods(["GET", "POST"])
def manage(request):
    """The cluster console: who is a member, who is an admin, and reconcile.

    Gated on `is_cluster_admin` — a live read of the public roster — and
    deliberately **not** on `is_superuser`. That distinction is what keeps this
    page reachable on a cluster rebuilt from nothing: the roster needs no
    database and no cache, so an admin can arrive here with `MembershipCache`
    empty and every member locked out. The recovery action therefore lives
    behind the one door that does not depend on the thing being recovered.

    POST runs reconciliation, through the same `MembershipRegistry.reconcile`
    the management command calls. One code path, so a click and a scheduled run
    can never mean different things.
    """
    if not request.user.is_authenticated:
        request.session[POST_LOGIN_REDIRECT] = request.get_full_path()
        return redirect("login")
    if not request.user.is_cluster_admin:
        # 404 rather than 403: a non-admin has no business learning that this
        # page exists, and the nav never offers it to them.
        raise Http404

    registry = membership.MembershipRegistry.from_settings()
    report, reconcile_error = None, None

    if request.method == "POST":
        try:
            report = registry.reconcile(dry_run="dry_run" in request.POST)
        except (membership.RegistryError, membership.ReconcileError) as exc:
            # "The answer would not be trustworthy" — distinct from a report
            # that ran and came back bad, which renders as the report.
            reconcile_error = str(exc)

    try:
        # Who holds admin *now*, one row each. A DID that was removed and later
        # re-added has several terms on the roster; the console answers "who can
        # decide membership today", so it shows the term in force and drops the
        # rest. The history is not lost — it is in the record, and
        # `Roster.was_admin_at` is what reads it when authority is being
        # judged at some past moment.
        entries, roster_error = membership.fetch_roster().entries, None
        current = {}
        for entry in entries:
            if entry.is_current and (
                entry.did not in current
                or entry.added_at > current[entry.did].added_at
            ):
                current[entry.did] = entry
        admins = sorted(current.values(), key=lambda e: e.added_at)
    except membership.RosterError as exc:
        # An unreadable roster is not "no admins". Rendering an empty table
        # would read as a fact; this reads as the failure it is.
        admins, roster_error = [], str(exc)

    # Active first, so the roll a reader is checking against the registry is at
    # the top and revoked history sinks below it.
    members = list(MembershipCache.objects.order_by("-active", "did"))

    # One resolution pass over every DID on the page — members, whoever granted
    # them, and the admins — so the lookups are shared rather than repeated per
    # table. Display only: see `membership.handles_for`.
    handles = membership.handles_for(
        [m.did for m in members]
        + [m.author_did for m in members]
        + [a.did for a in admins]
    )
    for member in members:
        member.handle = handles.get(member.did, member.did)
        member.author_handle = handles.get(member.author_did, member.author_did)
    # Dicts rather than the `AdminEntry` objects: the entry is a value read
    # from the record and has no room (or business) holding a display label.
    admins = [
        {
            "did": a.did,
            "handle": handles.get(a.did, a.did),
            "added_at": a.added_at,
        }
        for a in admins
    ]

    return render(
        request,
        "manage.html",
        {
            "members": members,
            "admins": admins,
            "roster_error": roster_error,
            "registry_configured": registry.is_configured,
            "report": report,
            "reconcile_error": reconcile_error,
        },
    )


def logout(request):
    """End this device's Corliss session. GET-friendly (no CSRF risk beyond
    forcing a re-login) since it's meant to be hit directly for now."""
    auth_logout(request)
    return redirect("login")


def _upsert_member(*, did, handle, pds_url, email="", email_confirmed=False):
    """Create the member on first login; refresh their PDS-sourced fields
    (handle, pds_url, email) on every login thereafter."""
    user, created = User.objects.get_or_create(
        did=did,
        defaults={
            "username": handle,
            "pds_url": pds_url,
            "email": email,
            "email_confirmed": email_confirmed,
        },
    )
    if not created:
        user.username = handle
        user.pds_url = pds_url
        user.email = email
        user.email_confirmed = email_confirmed
        user.save(
            update_fields=["username", "pds_url", "email", "email_confirmed"]
        )
    return user


def _store_tokens(user, token_data, dpop_key, nonce, pending):
    AtprotoToken.objects.update_or_create(
        user=user,
        defaults={
            "pds_url": pending["pds_url"],
            "issuer": pending["issuer"],
            "token_endpoint": pending["token_endpoint"],
            "access_token": token_data.get("access_token", ""),
            "refresh_token": token_data.get("refresh_token", ""),
            "dpop_private_pem": atproto.key_to_pem(dpop_key),
            "dpop_nonce": nonce or "",
        },
    )


# --- OIDC provider endpoints -----------------------------------------------


def jwks(request):
    """Publish the public halves of the signing keys (ES256 + RS256)."""
    return JsonResponse(signing.jwks())


def openid_configuration(request):
    return JsonResponse(oidc.discovery_document())


def _error(error, description, status=400):
    return JsonResponse(
        {"error": error, "error_description": description}, status=status
    )


@require_http_methods(["GET"])
def authorize(request):
    client_id = request.GET.get("client_id")
    redirect_uri = request.GET.get("redirect_uri")
    response_type = request.GET.get("response_type")
    scope = request.GET.get("scope", "")
    state = request.GET.get("state", "")
    nonce = request.GET.get("nonce", "")

    # Validate the relying party before doing anything else.
    if client_id != settings.OIDC_CLIENT_ID:
        return _error("unauthorized_client", "unknown client_id")
    if redirect_uri not in settings.OIDC_REDIRECT_URIS:
        return _error("invalid_request", "redirect_uri not registered")
    if response_type != "code":
        return _error("unsupported_response_type", "only 'code' is supported")
    if "openid" not in scope.split():
        return _error("invalid_scope", "missing 'openid' scope")

    # Member must be signed in (atproto). If not, bounce through login and resume.
    if not request.user.is_authenticated:
        request.session[POST_LOGIN_REDIRECT] = request.get_full_path()
        return redirect("login")

    code = oidc.issue_code(
        request.user,
        client_id=client_id,
        redirect_uri=redirect_uri,
        nonce=nonce,
        scope=scope,
    )
    params = {"code": code}
    if state:
        params["state"] = state
    return redirect(f"{redirect_uri}?{urlencode(params)}")


# --- Registry (membership push) --------------------------------------------


@csrf_exempt  # machine-to-machine from the registry, authenticated by bearer token
@require_http_methods(["POST"])
def membership_push(request):
    """Receive a grant or revocation from the SCN registry.

    Authenticated by a shared bearer token. That is proportionate here and
    nowhere else in this app: the token authorises exactly one verb — "assert
    a membership event" — against a cache. It reads nothing and acts on no
    one's behalf, so a leak costs a wrong cache until reconciliation, not a
    standing capability.

    Responses are shaped for the caller, which is Lua that logs any non-2xx and
    otherwise moves on. So a replayed or out-of-order event returns 200 with
    `applied: false` — it is a normal consequence of a best-effort push, not a
    failure worth waking anyone over.
    """
    # An unset token must refuse everything. Comparing against "" would accept
    # a request that also sends "", so the endpoint would be wide open on any
    # deployment that simply had not configured it yet.
    expected = settings.MEMBERSHIP_PUSH_TOKEN
    if not expected:
        return JsonResponse(
            {"error": "membership push is not configured"}, status=503
        )

    auth = request.META.get("HTTP_AUTHORIZATION", "")
    presented = auth[7:] if auth.startswith("Bearer ") else ""
    if not hmac.compare_digest(presented, expected):
        return JsonResponse({"error": "invalid token"}, status=401)

    try:
        payload = json.loads(request.body)
    except (ValueError, UnicodeDecodeError):
        return JsonResponse({"error": "body is not valid JSON"}, status=400)

    try:
        parsed = membership.parse(payload)
    except membership.PushError as exc:
        # The message is the useful half — it lands in HappyView's script log,
        # which is where a rejected push is actually visible to an operator.
        return JsonResponse({"error": str(exc)}, status=400)

    applied = membership.apply_event(parsed)
    return JsonResponse({"ok": True, "applied": applied})


# --- OIDC provider: token endpoint ------------------------------------------


def _client_credentials(request):
    """Read client_id/secret from POST body or HTTP Basic (the two RP methods)."""
    cid = request.POST.get("client_id")
    secret = request.POST.get("client_secret")
    auth = request.META.get("HTTP_AUTHORIZATION", "")
    if not cid and auth.startswith("Basic "):
        try:
            decoded = base64.b64decode(auth[6:]).decode()
            cid, secret = decoded.split(":", 1)
        except (ValueError, UnicodeDecodeError):
            return None, None
    return cid, secret


@csrf_exempt  # token endpoint is machine-to-machine, authenticated by client secret
@require_http_methods(["POST"])
def token(request):
    cid, secret = _client_credentials(request)
    # Constant-time comparison so the token endpoint doesn't leak the secret.
    cid_ok = hmac.compare_digest(cid or "", settings.OIDC_CLIENT_ID)
    secret_ok = hmac.compare_digest(secret or "", settings.OIDC_CLIENT_SECRET)
    if not (cid_ok and secret_ok):
        return _error("invalid_client", "client authentication failed", status=401)

    if request.POST.get("grant_type") != "authorization_code":
        return _error("unsupported_grant_type", "only authorization_code")

    code_value = request.POST.get("code", "")
    redirect_uri = request.POST.get("redirect_uri", "")

    try:
        code = OidcAuthCode.objects.select_related("user").get(code=code_value)
    except OidcAuthCode.DoesNotExist:
        return _error("invalid_grant", "unknown code")

    if not code.is_valid():
        return _error("invalid_grant", "code expired or already used")
    if code.client_id != cid or code.redirect_uri != redirect_uri:
        return _error("invalid_grant", "code/client/redirect mismatch")

    # Single-use, race-safe: only the request that flips used False→True wins,
    # so concurrent redemptions of the same code can't both mint a token.
    claimed = OidcAuthCode.objects.filter(code=code_value, used=False).update(
        used=True
    )
    if not claimed:
        return _error("invalid_grant", "code already used")

    id_token = oidc.mint_id_token(code.user, client_id=cid, nonce=code.nonce)
    return JsonResponse(
        {
            "access_token": id_token,  # we don't issue a separate RP access token
            "token_type": "Bearer",
            "expires_in": oidc.ID_TOKEN_TTL_SECONDS,
            "id_token": id_token,
        }
    )
