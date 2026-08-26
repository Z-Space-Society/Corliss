"""All of Corliss's HTTP endpoints — the ATProto client half and the OIDC
provider half, in the order a member meets them.

ATProto client (people):
- `client_metadata`: serves the client metadata at the `client_id` URL.
- `login`: handle form → resolve → discover → PAR → redirect to the PDS.
- `callback`: validate `state` → DPoP-bound token exchange → upsert the member,
  store tokens server-side, establish the Django session.
- `home`: the root page — an intro when signed out, your standing when in. The
  one page GATE never covers: it is where refused members land.
- `apply`: writes a membership application into the member's *own* PDS, which
  is the only thing a signed-in non-member can do here. It confers nothing:
  the record asks, and only an admin's grant answers. See
  `corliss.membership`'s "Applying" section.
- `api`: the member's own API keys — issue, list, revoke, and usage, read live
  from LiteLLM. Member-gated, and issuing needs a real grant on top of that:
  GATE lets a roster admin onto the page, not to a key. See `corliss.litellm`.
- `manage`: the cluster console — applications, members, admins, and
  reconciliation. Gated on the atproto roster, not on any Django flag, so it
  survives a rebuild. Read-only about applications: approving one is a write to
  the registry space, which needs the approving admin's own HappyView session.
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
- `authorize`: the RP sends the member here; if signed in *and* a member we
  issue an auth code and redirect back, otherwise we bounce through atproto
  login and resume, or refuse. GATE's most important surface — see below.
- `token`: the RP redeems the code (with its client secret) for an `id_token`.

Registry (machines):
- `membership_push`: the SCN registry POSTs each grant/revocation here so
  Corliss can cache who is a member. See `corliss.membership`.
"""

import base64
import hmac
import json
import logging
import secrets
from datetime import timedelta
from urllib.parse import urlencode

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth import login as auth_login
from django.contrib.auth import logout as auth_logout
from django.db.models import OuterRef, Subquery
from django.http import Http404, HttpResponseBadRequest, JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from corliss import atproto, litellm, membership, oidc, signing
from corliss.models import AtprotoToken, MembershipCache, OidcAuthCode

User = get_user_model()

log = logging.getLogger(__name__)

SESSION_PREFIX = "corliss:oauth:"

# Key in the Django session for "where to resume after atproto login".
POST_LOGIN_REDIRECT = "post_login_redirect"

# Where a freshly minted API key waits between the POST that made it and the
# GET that shows it exactly once. See `api` for why it goes through the session
# rather than being rendered straight off the POST.
NEW_KEY_SESSION_KEY = "corliss:new_api_key"

# Where a refusal from LiteLLM waits for the same hop, so the redirect that
# follows a failed POST can explain itself.
API_ERROR_SESSION_KEY = "corliss:api_error"

# The same one-hop handoff for a failed membership application.
APPLY_ERROR_SESSION_KEY = "corliss:apply_error"

# And for the console's own writes, which redirect after posting: what happened
# has to survive exactly one hop to be read on the page that follows.
MANAGE_NOTICE_SESSION_KEY = "corliss:manage_notice"
MANAGE_ERROR_SESSION_KEY = "corliss:manage_error"

# How far back /api/ reports usage. A month is what fits on the page and what
# a member is actually asking when they look ("am I using a lot?").
USAGE_WINDOW_DAYS = 30

# Stands in for a model name in /api/'s examples when the catalogue could not be
# read. Obviously a blank to fill rather than something that looks like it might
# work — a plausible-but-wrong model name would send someone debugging their
# curl invocation over a 400 that was ours.
EXAMPLE_MODEL_FALLBACK = "MODEL-NAME"


# --- GATE: is this person allowed in? --------------------------------------
#
# Signing in is not the same as being let in. Anyone with an atproto handle can
# complete a login here; membership is granted by an admin through the registry
# and answered by `membership.may_enter`. This is where that answer is enforced.
#
# Deliberately a helper each surface opts into, and **not middleware**.
# Middleware covers every path by default, and two paths must never be covered:
#
# - **`/admin/login/`** is the break-glass door. `ensure_admin` creates a local
#   admin (`did:local:admin`) that is not on the roster and will never have a
#   cache row, so a gate across Django's own login locks out the one account
#   that is supposed to work when atproto or OIDC is broken.
# - **`/manage/`** is gated on `is_cluster_admin` — a live roster read, no
#   database — precisely so it opens when the cache is empty. It holds the
#   reconcile button that refills the cache; gating it on the cache would make
#   recovery depend on the thing being recovered.
#
# Opting in keeps both of those true by construction, rather than by remembering
# to write an exemption for them.


def require_membership(request):
    """GATE at an HTTP surface: None to proceed, or where to send them instead.

    Refusal is a redirect to the home page rather than a 403, because that page
    already holds the state this describes — "you're signed in, but not a member
    yet", with the way to ask — and that state *is* the gate's user-facing form.
    A bare 403 would say less and duplicate more.

    Fails closed on an anonymous request. Callers bounce those through login
    first, since they have a `next` worth preserving; answering "no" rather than
    reaching for `AnonymousUser.did` means a surface that forgets to cannot fail
    open.
    """
    user = request.user
    if user.is_authenticated and membership.may_enter(user.did):
        return None
    return redirect("home")


def _resume_after_login(request):
    """Where to land once a login completes: back into the flow that sent us
    here, or home.

    **GATE applies to the resume, not to the login.** A non-member still gets
    their session — they need one to apply, and the home page has a state for
    them — but not a ride onward into the relying party they arrived from.
    Resuming would hand them to `authorize`, which refuses them anyway; the only
    difference is whether they read why on our page or watch Open WebUI render a
    generic failure.

    Only a safe same-site path is honoured (single leading slash, no scheme or
    host), so a poisoned session value cannot become an open redirect.
    """
    next_url = request.session.pop(POST_LOGIN_REDIRECT, None)
    if not next_url or not next_url.startswith("/") or next_url.startswith("//"):
        return redirect("home")
    denial = require_membership(request)
    if denial is not None:
        return denial
    return redirect(next_url)


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
        dpop_key, registry = _dpop_key_for(did)
        verifier, challenge = atproto.pkce_pair()
        state = secrets.token_urlsafe(32)
        request_uri, nonce = atproto.pushed_authorization_request(
            meta,
            dpop_key=dpop_key,
            state=state,
            code_challenge=challenge,
            login_hint=handle,
            scope=_scope_for(did),
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
        # Present only for an admin whose key came from the registry, and named
        # apart from `code_verifier` because the two PKCE pairs in flight here
        # are for different servers and confusing them would be silent.
        **registry,
    }
    return redirect(atproto.authorization_url(meta, request_uri))


@require_http_methods(["POST"])
def manage_unlock(request):
    """Authenticate the service account, without disturbing your own session.

    The roster lives in the service account's repo and only that account can
    write it, so Corliss needs a session for it — and the only way to get one is
    the atproto handshake, because HappyView verifies the tokens it is handed
    against the DPoP key it provisioned (an app password produces a Bearer token
    that fails that check, and so could never call `setSpaceAccess`).

    What this is *not* is a sign-in. You stay signed in as yourself for the whole
    round trip; the password is typed at your PDS, never here. See `callback`'s
    `service_link` branch, where the absence of `auth_login` is the entire
    mechanism.

    POST-only: it starts an authorization redirect, which is a state change, and
    a GET would let any page on the internet start one by linking to it.
    """
    if not request.user.is_authenticated:
        request.session[POST_LOGIN_REDIRECT] = reverse("manage")
        return redirect("login")
    if not request.user.is_cluster_admin:
        raise Http404

    service_did = settings.SCN_SERVICE_DID
    if not service_did:
        request.session[MANAGE_ERROR_SESSION_KEY] = (
            "SCN_SERVICE_DID is not set, so there is no service account to "
            "authenticate."
        )
        return redirect("manage")

    try:
        doc = atproto.fetch_did_document(service_did)
        # The handle is the login hint the PDS shows on its consent screen, and
        # it is what every message about this says out loud — a DID would be
        # unreadable in exactly the place someone needs to recognise an account.
        handle = atproto.handle_from_doc(doc) or service_did
        pds_url = atproto.pds_endpoint_from_doc(doc)
        meta = atproto.discover_auth_server(pds_url)
        dpop_key, registry = _dpop_key_for(service_did)
        verifier, challenge = atproto.pkce_pair()
        state = secrets.token_urlsafe(32)
        request_uri, nonce = atproto.pushed_authorization_request(
            meta,
            dpop_key=dpop_key,
            state=state,
            code_challenge=challenge,
            login_hint=handle,
            scope=_scope_for(service_did),
        )
    except atproto.OAuthError as exc:
        request.session[MANAGE_ERROR_SESSION_KEY] = (
            f"Could not reach the service account's PDS: {exc}"
        )
        return redirect("manage")

    request.session[SESSION_PREFIX + state] = {
        "code_verifier": verifier,
        "dpop_pem": atproto.key_to_pem(dpop_key),
        "dpop_nonce": nonce,
        "issuer": meta["issuer"],
        "token_endpoint": meta["token_endpoint"],
        "did": service_did,
        "pds_url": pds_url,
        "handle": handle,
        # The marker `callback` branches on. Everything else about this flow is
        # an ordinary login.
        "service_link": True,
        **registry,
    }
    return redirect(atproto.authorization_url(meta, request_uri))


def _scope_for(did):
    """The atproto scope this login should request.

    One account gets more than everyone else: the service account, whose repo
    holds the admin roster record. It is the only repo that record is ever read
    from, so asking any member for permission to write it would be asking for
    access to something nobody would look at.

    Decided from the *unverified* DID the handle resolved to, which is safe for
    the same reason `_dpop_key_for` is: the worst a spoofed handle achieves is a
    consent screen naming a scope its owner then declines, and the PDS would
    refuse the write regardless — `putRecord` only ever touches the
    authenticated account's own repo.
    """
    if did and did == settings.SCN_SERVICE_DID:
        return atproto.SERVICE_SCOPE
    return atproto.SCOPE


def _dpop_key_for(did):
    """The DPoP key this login should use, and the pending state that goes with
    it: the registry's, for a current admin, or a fresh ephemeral one.

    **Why the key has to be decided here, before PAR.** The registry provisions
    the DPoP key that an admin's session will be bound to, and it expects the
    atproto handshake to have been run with it. A key chosen after the token
    exchange is too late — the tokens are already bound to something the
    registry has never seen and cannot prove possession of. So an admin's login
    is a different login from the first network call onwards, and this is where
    that forks.

    **Deciding on an unverified DID is safe, and it is the opposite of the rule
    `callback` follows.** That function refuses to key on anything but the DID
    the token response asserts, because that decides *who someone is*. This
    decides only which key to generate. Guess wrong and the cost is a registry
    session nobody can use: the Lua re-reads the roster on every write, so a
    non-admin who talked their way into a provisioned key still gets
    "forbidden: caller is not a current admin".

    **A registry that cannot be reached is not a failed login.** It means no
    approvals until it is back, which is the documented consequence of the
    registry being down; turning it into "nobody can sign in" would be a much
    larger outage than the one actually happening. So this falls back, logs, and
    says nothing to the person signing in — they are not the one who can fix it.
    """
    if not membership.is_cluster_admin(did):
        return atproto.generate_key(), {}

    registry = membership.MembershipRegistry.from_settings()
    verifier, challenge = atproto.pkce_pair()
    try:
        provision_id, key = membership.provision_registry_key(
            registry, pkce_challenge=challenge
        )
    except membership.RegistryError as exc:
        log.warning("registry key provision failed for %s: %s", did, exc)
        return atproto.generate_key(), {}

    return key, {
        "registry_provision_id": provision_id,
        "registry_pkce_verifier": verifier,
    }


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
    _register_registry_session(user, token_data, pending)

    if pending.get("service_link"):
        # **The whole point of this branch is the `auth_login` that is not
        # here.** Authenticating the service account is an errand an admin runs
        # while signed in as themselves; replacing their session with the
        # service account's is what made the first cut of this unusable.
        #
        # Checked again against the setting rather than trusted from the pending
        # state: the flow is started by a signed-in admin, but the account that
        # comes back is chosen at the PDS's own login screen, so completing it as
        # somebody else would otherwise install the wrong service session and
        # every roster write would silently go to the wrong repo.
        if did != settings.SCN_SERVICE_DID:
            request.session[MANAGE_ERROR_SESSION_KEY] = (
                f"That authenticated {pending['handle']}, which is not the "
                f"service account. Admin controls are still locked."
            )
        else:
            request.session[MANAGE_NOTICE_SESSION_KEY] = (
                "Admin controls are unlocked."
            )
        return redirect("manage")

    auth_login(
        request, user, backend="django.contrib.auth.backends.ModelBackend"
    )
    user.touch_last_seen()

    # Resume an in-progress OIDC authorize (the RP) if one bounced us here —
    # subject to GATE, which is why this is not a bare redirect.
    return _resume_after_login(request)


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

    # Lowercased because handles are case-insensitive but DIDs are not: without
    # it `Jacob.example` and `jacob.example` mint two `did:dev:` DIDs, so one
    # person gets two member rows and only one spelling matches DEV_ADMIN_DIDS.
    # A real login can't drift this way — resolution returns one canonical DID.
    handle = request.POST.get("handle", "").strip().lstrip("@").lower()
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

    # Resume an in-progress OIDC authorize, exactly as `callback` does — same
    # helper, so the relying-party flow is testable end to end without atproto
    # and a dev session meets the same gate a real one does.
    return _resume_after_login(request)


def home(request):
    """The home page: signed out, or signed in with or without membership.

    Deliberately not `@login_required` — a signed-out visitor gets the intro
    here rather than being bounced to the login form.

    **This page is where GATE surfaces, and never where it redirects.** The
    signed-in-but-not-a-member state below is the gate's user-facing form: it is
    the only place that explains a refusal and offers the way out, which is why
    every gated surface refuses *to here*. Gating this page too would leave the
    explanation with nowhere to live.

    `is_member` is the grant, not GATE — a roster admin with no grant is not a
    member, and saying otherwise here would advertise an entitlement the
    registry never issued. See `membership.may_enter` for why those are two
    questions.

    Membership is resolved here rather than in the template because it is a
    real lookup against the cache table. Admin is not: it hangs off the user as
    `user.is_cluster_admin` because the nav asks it on every page, not just this
    one.

    For a non-member the page also carries their **application** state, which is
    three-valued and rendered as three different things: they have applied, they
    have not, or their PDS could not be asked. The third is not folded into the
    second — offering the button to someone who already has a record invites a
    second one over the first — so an unreachable PDS says so and offers a
    retry. `user.has_pending_application`, which the nav uses, is the flattened
    two-valued version; this page needs the honest one.
    """
    did = request.user.did if request.user.is_authenticated else None
    is_member = bool(did) and membership.is_active_member(did)

    # Where this account's repo lives, blank when we have never resolved one —
    # which is exactly the `dev_login` case, since those accounts complete no
    # handshake. No PDS means nothing to write an application to and nothing to
    # read one back from, so the page says that rather than offering a button
    # whose only possible outcome is an error.
    has_pds = bool(did) and bool(request.user.pds_url)

    application, application_unknown, applied_at = None, False, None
    if did and not is_member and has_pds:
        try:
            application = membership.my_application(did)
        except membership.ApplicationError:
            application_unknown = True
        if application is not None:
            # Parsed here so the template can use `|date`. A record whose
            # `createdAt` is unreadable still counts as an application — the
            # page just omits the date, the way the console renders an em-dash.
            applied_at = membership.application_created_at(application)

    return render(
        request,
        "home.html",
        {
            "is_member": is_member,
            "application": application,
            "applied_at": applied_at,
            "application_unknown": application_unknown,
            # Popped, not read: a failed apply explains itself exactly once,
            # and a refresh should not replay it. Same one-hop handoff as
            # `api`'s NEW_KEY_SESSION_KEY.
            "apply_error": request.session.pop(APPLY_ERROR_SESSION_KEY, None),
            "has_pds": has_pds,
        },
    )


@require_http_methods(["POST"])
def apply(request):
    """Write the signed-in member's membership application to their own PDS.

    POST only, and Post/Redirect/Get back to `home`: the state this creates is
    rendered there, and a refresh must not write a second time. The failure
    message rides one hop in the session for the same reason `api` parks a
    LiteLLM refusal there.

    **Refuses an existing member.** Not because it would break anything — the
    record is inert and a member who wrote one would simply have a redundant
    record — but because the page never offers it to them, so a POST that gets
    here is not something a member did on purpose.

    Nothing here writes to `MembershipCache`, and nothing here decides
    membership. An application asks; a grant answers.
    """
    if not request.user.is_authenticated:
        request.session[POST_LOGIN_REDIRECT] = reverse("home")
        return redirect("login")

    if membership.is_active_member(request.user.did):
        return redirect("home")

    try:
        membership.submit_application(
            request.user, request.POST.get("note", "")
        )
    except membership.ApplicationError as exc:
        request.session[APPLY_ERROR_SESSION_KEY] = str(exc)

    return redirect("home")


@require_http_methods(["GET", "POST"])
def api(request):
    """The member's own API keys: issue one, see them, revoke one, see usage.

    **GATE lets a roster admin in here without a grant; issuing does not.**
    `require_membership` answers "may this person be in Corliss", and the
    entitlement question is a different one — an admin with no grant receives
    nothing they were never given. So the tier comes from the cache row and an
    inactive or absent row means the form is not offered and a POST is refused,
    with `litellm.issue_key` refusing a blank tier again on its own account.

    **Post/Redirect/Get, with the secret parked in the session for one hop.**
    Rendering the new key straight off the POST would mint a second one on
    refresh, which the per-member cap makes immediately visible. The cost is
    that the plaintext sits in the server-side session store between the two
    requests — smaller than what `AtprotoToken` already keeps, and it is popped
    on the next render whether or not anyone reads it.

    Nothing about keys is stored by Corliss. LiteLLM is asked afresh on every
    render, so a key revoked from the CLI is gone from this page too.
    """
    if not request.user.is_authenticated:
        request.session[POST_LOGIN_REDIRECT] = request.get_full_path()
        return redirect("login")
    denial = require_membership(request)
    if denial is not None:
        return denial

    client = litellm.LiteLLM.from_settings()
    row = membership.membership_for(request.user)
    tier = row.tier if row is not None and row.active else ""

    if request.method == "POST":
        return _api_action(request, client, tier)

    # Popped, not read: a secret that survives one refresh is a secret shown
    # twice, and the page promises otherwise.
    new_key = request.session.pop(NEW_KEY_SESSION_KEY, None)
    key_error = request.session.pop(API_ERROR_SESSION_KEY, None)

    keys, keys_error = [], None
    if client.is_configured:
        try:
            keys = client.keys_for(request.user.did)
        except litellm.LiteLLMError as exc:
            # Carries LiteLLM's own words. The fail-visible posture is what
            # turned the last two integration defects into ten-minute fixes.
            keys_error = str(exc)

    models, models_error = [], None
    if client.is_configured and not keys_error:
        try:
            models = client.models(tier)
        except litellm.LiteLLMError as exc:
            # Non-fatal, for the reason usage is below: the quickstart falls
            # back to a placeholder model name and the table says so. A proxy
            # that cannot list its models can still be holding working keys.
            models_error = str(exc)

    usage_rows, usage_totals, usage_error = [], None, None
    if client.is_configured and not keys_error:
        try:
            # One `now()`, not two: taken either side of midnight they would
            # ask for a window a day wider than the page claims.
            today = timezone.now().date()
            usage_rows, usage_totals = client.usage(
                request.user.did,
                (today - timedelta(days=USAGE_WINDOW_DAYS - 1)).isoformat(),
                today.isoformat(),
            )
        except litellm.LiteLLMError as exc:
            # Non-fatal on purpose: usage is the least important thing on this
            # page and must never take the keys panel down with it.
            usage_error = str(exc)

    return render(
        request,
        "api.html",
        {
            "litellm_configured": client.is_configured,
            "tier": tier,
            "keys": keys,
            "keys_error": keys_error,
            "key_error": key_error,
            "new_key": new_key,
            "max_keys": client.max_keys,
            "at_limit": len(keys) >= client.max_keys,
            "models": models,
            "models_error": models_error,
            # Nothing on the cluster declares `max_input_tokens` today, and a
            # column of nothing but em-dashes reads as broken rather than as
            # "unknown". Shown when at least one model has an answer, so the
            # table gains the column the moment an operator sets one.
            "show_context": any(model.context for model in models),
            # What the quickstart puts in the `"model"` field. A real name from
            # the member's own tier makes the block a paste that runs; the
            # placeholder only shows when there is nothing true to say.
            "example_model": next(
                (model.name for model in models if model.is_chat),
                EXAMPLE_MODEL_FALLBACK,
            ),
            "usage_rows": usage_rows,
            "usage_totals": usage_totals,
            "usage_error": usage_error,
            "usage_days": USAGE_WINDOW_DAYS,
        },
    )


def _api_action(request, client, tier):
    """Issue or revoke one key, then redirect back to `/api/`.

    Errors go into the session rather than being rendered here, for the same
    reason the new key does: the response to a POST is a redirect, so anything
    the next page needs has to survive one hop.
    """
    if not client.is_configured:
        raise Http404

    did = request.user.did
    try:
        if request.POST.get("action") == "revoke":
            client.revoke_key(did, request.POST.get("token", ""))
        else:
            # The handle is display only — it goes into the key's alias so a
            # LiteLLM admin can attribute it. Ownership is the DID, always.
            handle = membership.handles_for([did]).get(did, "")
            request.session[NEW_KEY_SESSION_KEY] = client.issue_key(
                did,
                request.POST.get("label", ""),
                handle=handle,
                tier=tier,
            )
    except litellm.LiteLLMError as exc:
        request.session[API_ERROR_SESSION_KEY] = str(exc)

    return redirect("api")


# --- The stack, for /systems/ ------------------------------------------------
#
# A description of what this cluster is made of, grouped the way zai-ops groups
# its CTIDs: core infra is the data foundations (storage with no logic of its
# own), platform is services other services consume, apps are what members
# actually use. Held here rather than read from anywhere because nothing in
# Corliss knows the shape of the cluster — this is the one place that claims to.
#
# **Status is not checked yet.** Every entry reports "unknown" except the two
# this request can answer for free: Corliss is serving the page, and Postgres
# answered the query that rendered it. Anything else needs a probe per service,
# which is the next piece of work and deliberately not this one. An entry that
# guessed would be worse than one that admits it does not know.
STACK = [
    ("Core", [
        ("Garage", "object store — backup target for the control node"),
        ("PostgreSQL", "the cluster's database: Corliss, LiteLLM, Open WebUI, HappyView"),
        ("Redis", "session revocation store, so signing out reaches chat in seconds"),
    ]),
    ("Platform", [
        ("Caddy", "the edge — the only LAN-facing container, terminates TLS"),
        ("HappyView", "the membership registry: applications, grants, admin roster"),
        ("LiteLLM", "the API gateway in front of the models"),
    ]),
    ("Applications", [
        ("Corliss", "login, membership, OIDC, and members' API keys"),
        ("Open WebUI", "the chat app"),
        ("Manage Console", "the registry's admin surface, served as static files"),
    ]),
]


@require_http_methods(["GET"])
def systems(request):
    """What the cluster is made of, and (eventually) whether it is up.

    A stub, deliberately: it renders the stack and marks almost everything
    "unknown" rather than inventing a status. Two entries are honest without a
    probe — this app is serving the response, and Postgres answered the query
    behind `request.user` — and the rest need a check per service, which is the
    next piece of work rather than this one.

    Admin-gated the same way `manage` is, and 404 rather than 403 for the same
    reason: a non-admin has no business learning the page exists.
    """
    if not request.user.is_authenticated:
        request.session[POST_LOGIN_REDIRECT] = request.get_full_path()
        return redirect("login")
    if not request.user.is_cluster_admin:
        raise Http404

    live = {"Corliss", "PostgreSQL"}
    groups = [
        {
            "name": name,
            "services": [
                {
                    "name": service,
                    "purpose": purpose,
                    "state": "up" if service in live else "unknown",
                }
                for service, purpose in services
            ],
        }
        for name, services in STACK
    ]
    return render(request, "systems.html", {"groups": groups})


@require_http_methods(["GET", "POST"])
def manage(request):
    """The cluster console: who has asked, who is a member, who is an admin,
    and reconcile.

    Gated on `is_cluster_admin` — a live read of the public roster — and
    deliberately **not** on `is_superuser`. That distinction is what keeps this
    page reachable on a cluster rebuilt from nothing: the roster needs no
    database and no cache, so an admin can arrive here with `MembershipCache`
    empty and every member locked out. The recovery action therefore lives
    behind the one door that does not depend on the thing being recovered.

    POST runs reconciliation, through the same `MembershipRegistry.reconcile`
    the management command calls. One code path, so a click and a scheduled run
    can never mean different things.

    Three sources on one page, and the differences between them are the point:
    applications are read live from the registry's index and confer nothing;
    members are this deployment's cache and can be wrong; admins are a live
    read of a public record and cannot go stale. See `_applications`.
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
        action = request.POST.get("action", "reconcile")
        if action in ("approve", "revoke", "decline"):
            # Post/Redirect/Get, unlike reconcile below: these append a record
            # to the registry, and a refresh that re-posted would append a
            # second one. Harmless by design — latest-event-wins — but an
            # audit log should record decisions, not browser reloads.
            return _decide_membership(request, registry, action)
        if action in ("add_admin", "remove_admin"):
            # PRG for the same reason, and one more: the roster is a
            # read-modify-write, so a re-post would append a second entry for
            # the same person rather than being absorbed by latest-event-wins.
            return _edit_roster(request, action)
        try:
            # No dry-run switch here any more: the button is the recovery
            # action, and a preview beside it mostly invited clicking the wrong
            # one. `manage.py reconcile_membership --dry-run` still previews,
            # through this same entry point, for the case that wants it.
            report = registry.reconcile()
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

    # **Active memberships only.** A revoked member is history, and the registry
    # is where history lives — a table of people who are not members, with a
    # column to say so, was two facts fighting for one row. Readmitting is the
    # invite field: it takes any handle and writes a fresh grant, which is what
    # readmission always was.
    #
    # `is_staff` is annotated from the `User` row by DID rather than resolved
    # from the roster per render. It is a mirror, kept true at every login by
    # `_heal_staff_flag` and written alongside the roster by `appoint_admin`, and
    # reading it here costs one join instead of a network read.
    members = list(
        MembershipCache.objects.filter(active=True)
        .annotate(
            is_admin=Subquery(
                User.objects.filter(did=OuterRef("did")).values("is_staff")[:1]
            )
        )
        .order_by("did")
    )

    # Applications are matched against every member, not only the active ones —
    # an application from somebody previously revoked has still been decided
    # once, and the queue should not offer it as though it were new.
    applications = _applications(
        registry, list(MembershipCache.objects.all())
    )

    # One resolution pass over every DID on the page — applicants, members,
    # whoever granted them, and the admins — so the lookups are shared rather
    # than repeated per table. Display only: see `membership.handles_for`.
    handles = membership.handles_for(
        [row["did"] for row in applications["rows"]]
        + [m.did for m in members]
        + [m.author_did for m in members]
        + [a.did for a in admins]
    )
    for row in applications["rows"]:
        row["handle"] = handles.get(row["did"], row["did"])
    for member in members:
        member.handle = handles.get(member.did, member.did)
        member.author_handle = handles.get(member.author_did, member.author_did)
    # When each current admin's term began, keyed by DID, so the members table
    # can say "Admin since" without a second roster pass. The service account is
    # in here and simply never matches a member row — it holds no grant, which
    # is why it does not appear on this page at all.
    admin_since = {a.did: a.added_at for a in admins}
    for member in members:
        member.admin_since = admin_since.get(member.did)

    return render(
        request,
        "manage.html",
        {
            "applications": applications,
            "members": members,
            "roster_error": roster_error,
            "registry_configured": registry.is_configured,
            "report": report,
            "reconcile_error": reconcile_error,
            # Whether this admin's session can author a registry write, and the
            # vocabulary the controls offer. `tiers` comes from the module that
            # validates it, so the dropdown cannot drift from what the Lua will
            # accept — and there is no blank option anywhere, because a grant
            # with no tier is a fail-open bug rather than a harmless default.
            "can_decide": _can_decide(request.user),
            # Roster edits spend this, and nothing else does — so a lapse is
            # invisible until somebody tries to appoint an admin. Shown here so
            # it is found before then.
            "service_session": membership.service_session_status(),
            "tiers": membership.TIERS,
            "default_tier": membership.DEFAULT_TIER,
            "manage_notice": request.session.pop(
                MANAGE_NOTICE_SESSION_KEY, None
            ),
            "manage_error": request.session.pop(MANAGE_ERROR_SESSION_KEY, None),
        },
    )


def _can_decide(user):
    """Does this admin hold a registry session, and so a way to approve?

    False for anyone who signed in before this shipped, for anyone whose login
    happened while the registry was unreachable, and for every `dev_login`
    account — none of which is an error, and all of which the console has to say
    rather than discover at the click.
    """
    token = AtprotoToken.objects.filter(user=user).first()
    return token is not None and token.can_write_registry


# What a declined application's revocation records as its reason, so the log
# can tell the two apart. See `_decide_membership`.
DECLINE_REASON = "Application declined."


def _decide_membership(request, registry, action):
    """Approve, revoke, or decline, authored by the signed-in admin. Redirects
    to `/manage/`.

    **Declining is a revocation, and that is not a workaround.** The registry
    holds grants and revocations and derives membership as latest-event-wins,
    so "not a member" is exactly what a revocation with no grant before it
    resolves to — the Lua asks only that the caller is a current admin and that
    the DID is well formed, and `apply_event` already handles a revoke landing
    on no cache row, because that is what reconciling a rebuilt cluster does for
    everyone ever revoked. Nothing new is written to the registry for this.

    What the shape costs is that the log reads "revoked" for someone who was
    never granted, which an auditor can infer but should not have to. So a
    decline stamps `DECLINE_REASON` on the record: the event says what it was.

    **The authority here is the registry's, not this function's.** The Lua
    re-reads the admin roster on every write and refuses a caller who is not on
    it, and the runtime stamps the caller's DID as the record's author — which
    is what makes a grant real. The `is_cluster_admin` check that got the admin
    onto this page is a courtesy, so a stale roster shows a refusal here rather
    than a 500 from the registry. Neither check makes the other redundant, and
    removing the far one would hand membership to whoever could reach this view.

    Everything about the decision travels as the admin's own session: their
    access token and the DPoP key the registry provisioned at login. There is no
    Corliss credential that could do this, deliberately.

    Nothing here touches `MembershipCache`. The registry's Lua pushes the event
    back to `/membership/events` after the space write, and that push is the
    only thing allowed to move the cache — so the tables on the next render may
    lag this click by a round trip.
    """
    did = request.POST.get("did", "").strip()
    handle_hint = request.POST.get("handle", "").strip().lstrip("@")

    # Inviting: the console names someone by handle who has never applied, so
    # there is no DID on the page to post back. Resolved with the strict
    # two-method form — admitting someone should not trust the third-party
    # resolver — and the row is created here so the member has a readable name
    # from the moment they are granted rather than from their first sign-in.
    if not did and handle_hint:
        try:
            did = atproto.resolve_handle_for_admin(handle_hint)
        except atproto.OAuthError as exc:
            request.session[MANAGE_ERROR_SESSION_KEY] = str(exc)
            return redirect("manage")

    if not did:
        request.session[MANAGE_ERROR_SESSION_KEY] = "No member was named."
        return redirect("manage")

    token = AtprotoToken.objects.filter(user=request.user).first()
    if token is None or not token.can_write_registry:
        request.session[MANAGE_ERROR_SESSION_KEY] = (
            "This session cannot write to the registry. Sign out and in again "
            "to pick one up."
        )
        return redirect("manage")

    handle = handle_hint or membership.handles_for([did]).get(did, did)

    # **Decline answers an application; it never ends a live membership.** The
    # queue can hold a current member — someone who applied again after being
    # admitted keeps their row, flagged "asked again" — and on that row the
    # button would otherwise revoke a sitting member, cascading through
    # `dismiss_admin` if they were an admin. That is a large and silent thing
    # for a control that says "decline". Revoking a member is a decision taken
    # on their own row, where the confirmation says so.
    if action == "decline":
        if MembershipCache.objects.filter(did=did, active=True).exists():
            request.session[MANAGE_ERROR_SESSION_KEY] = (
                f"{handle} is already a member, so there is no application to "
                "decline. Revoke them from the members table instead."
            )
            return redirect("manage")

    try:
        if action == "approve":
            tier = request.POST.get("tier", "")
            registry.approve(token, did, tier)
            membership.ensure_user(did, handle_hint or None)
            request.session[MANAGE_NOTICE_SESSION_KEY] = (
                f"{handle} is a member at {tier}."
            )
        elif action == "decline":
            # No admin cascade: the guard above has already established there
            # is no live membership here, so there is nothing to end. The
            # reason is what keeps this legible in the log — a bare revocation
            # for a DID that was never granted is the same record either way.
            registry.revoke(token, did, DECLINE_REASON)
            request.session[MANAGE_NOTICE_SESSION_KEY] = (
                f"{handle}'s application is declined. They can apply again."
            )
        else:
            # **Admin first, then membership.** They cascade because an admin
            # who is not a member would break the rule the console enforces at
            # appointment — and this order is the one whose half-done state is
            # safe: a member who is not an admin, rather than a non-member who
            # still holds authority over the registry.
            note = ""
            if membership.is_cluster_admin(did):
                note = membership.dismiss_admin(request.user.did, did)
            registry.revoke(token, did, request.POST.get("reason", ""))
            request.session[MANAGE_NOTICE_SESSION_KEY] = (
                f"{handle}'s membership is revoked. {note}".strip()
                if note
                else f"{handle}'s membership is revoked."
            )
    except (membership.RegistryError, membership.RosterError) as exc:
        # `RosterError` reaches here only from the cascade above — a revoke that
        # could not first end their admin authority. Refusing the whole thing is
        # correct: revoking the membership anyway would leave them holding the
        # registry write access this was supposed to take away.
        log.warning("membership %s of %s failed: %s", action, did, exc)
        request.session[MANAGE_ERROR_SESSION_KEY] = str(exc)

    return redirect("manage")


def _edit_roster(request, action):
    """Add or remove a cluster admin, on behalf of the signed-in admin.

    **The actor is authorized here, but the edit is not made as them.** The
    roster lives in the service account's repo and atproto has no cross-repo
    write, so Corliss verifies the caller is a current admin and then spends the
    service account's own session — recording who asked in the entry. See
    `membership.appoint_admin`.

    Deliberately *not* gated on `can_write_registry`, unlike approve and revoke:
    that flag is about holding a HappyView session, and the roster is a PDS
    record. An admin whose registry session failed to provision can still edit
    the roster; only the space-access half of the change needs the registry, and
    that half is reported rather than raised.

    Accepts a handle or a DID, because the person adding an admin is reading a
    handle. Resolution is the strict two-method form — never the third-party
    resolver, since granting admin should not trust it.
    """
    subject = request.POST.get("subject", "").strip().lstrip("@")
    if not subject:
        request.session[MANAGE_ERROR_SESSION_KEY] = "No one was named."
        return redirect("manage")

    if subject.startswith("did:"):
        did = subject
    else:
        try:
            did = atproto.resolve_handle_for_admin(subject)
        except atproto.OAuthError as exc:
            request.session[MANAGE_ERROR_SESSION_KEY] = str(exc)
            return redirect("manage")

    # Re-asked at action time rather than trusted from the page render: the
    # roster is live, and the admin who loaded this page may have been removed
    # while it sat open.
    if not membership.is_cluster_admin(request.user.did):
        raise Http404

    handle = membership.handles_for([did]).get(did, did)
    try:
        if action == "add_admin":
            note = membership.appoint_admin(request.user.did, did)
            message = f"{handle} is a cluster admin."
        else:
            note = membership.dismiss_admin(request.user.did, did)
            message = (
                f"{handle} is no longer a cluster admin. Members they approved "
                f"stay members."
            )
        # A partial success says so in full rather than being flattened into
        # either "done" or "failed" — the operator has one more step to run.
        request.session[MANAGE_NOTICE_SESSION_KEY] = (
            f"{message} {note}".strip() if note else message
        )
    except (membership.RosterError, membership.RegistryError) as exc:
        log.warning("roster %s of %s failed: %s", action, did, exc)
        request.session[MANAGE_ERROR_SESSION_KEY] = str(exc)

    return redirect("manage")


def _applications(registry, members):
    """The application queue for `/manage/`: **only the ones still waiting.**

    An application record is permanent — the applicant writes it once and it
    stays exactly as written whether they were approved, refused, or never
    looked at, because it knows nothing about what happened to it. So the index
    returns every application ever made, and listing all of them made this panel
    a second copy of the member table below it, with the actual queue — the
    people nobody has answered — buried inside it. A to-do list that includes
    everything already done is not a to-do list.

    **Whether an application has been answered is a question for
    `MembershipCache`, and it is answered here by time, not by presence.** A DID
    having a cache row means somebody decided *once*; it does not mean the
    record on file now has been decided. A revoked member who applies again
    writes a fresh record — rkey `self`, so it replaces the old one with a new
    `createdAt` — and a rule of "has a cache row, therefore handled" would drop
    exactly the person who is asking to come back. So a row is still waiting
    when there is no membership event for that DID at all, **or** when the
    application post-dates the last one.

    The cost is that an application whose `createdAt` could not be parsed is
    treated as decided when the DID has a cache row, since it cannot be shown to
    post-date anything. It is counted in `decided` rather than dropped — nothing
    here vanishes without a number attached, which is the same reason
    `unreadable` exists.

    The comparison is between two clocks nobody here owns — the applicant's
    client wrote `createdAt`, the registry wrote `grantedAt`/`revokedAt`, and
    the latter is only second-resolution — so an approval issued moments after
    an application could in principle read as earlier than it. **No grace margin
    is applied deliberately.** Skew that close would leave a decided member
    sitting in the queue flagged "asked again", which is visible, explains
    itself, and clears the next time anyone decides anything about them; a
    margin would instead hide a genuine re-application made inside it. This
    panel's whole posture is that being seen twice beats not being seen.

    Returns a context dict rather than a list, because three facts about the
    *read* have to reach the template alongside the rows: how many applications
    were already decided, how many records could not be parsed, and whether the
    list was cut short. All three would otherwise show up as rows that simply
    are not there.

    A failed read renders as a failure. Never as an empty queue — same posture
    as the roster above, and for the same reason: "nobody has applied" and "we
    could not find out" are different facts and the page must not conflate
    them.

    `members` is already loaded for the table below, so the cross-reference
    costs no extra query and there is no second opinion about who is a member.
    """
    try:
        listing = registry.fetch_applications()
    except membership.RegistryError as exc:
        return {
            "rows": [],
            "decided": 0,
            "unreadable": 0,
            "truncated": False,
            "error": str(exc),
        }

    cached = {m.did: m for m in members}
    rows, decided = [], 0
    for application in listing:
        row = cached.get(application.did)
        # Asked again since whatever was last decided about them. Worth saying
        # on the row: "come back after a revocation" is a different decision
        # from "let this stranger in", and the queue should not flatten them.
        reapplied = (
            row is not None
            and application.created_at is not None
            and application.created_at > row.last_event_at
        )
        if row is not None and not reapplied:
            decided += 1
            continue
        rows.append(
            {
                "did": application.did,
                "created_at": application.created_at,
                "note": application.note,
                "reapplied": reapplied,
            }
        )

    # No sort: the registry returns newest first and that is the order kept.
    return {
        "rows": rows,
        "decided": decided,
        "unreadable": listing.unreadable,
        "truncated": listing.truncated,
        "error": None,
    }


def logout(request):
    """End this member's Corliss session, and the relying parties' sessions too.

    GET-friendly (no CSRF risk beyond forcing a re-login) since it's meant to
    be hit directly for now.

    The back-channel notification goes out *before* `auth_logout`, because that
    call is what makes `request.user` anonymous — afterwards there is no member
    left to look up. It cannot fail this view: `notify_logout` swallows its own
    errors, so an unreachable relying party costs a log line, not a sign-out.

    This ends the member's session at the relying party on **every** device,
    not just this browser — see `OidcSession` for why that is what the RP will
    do with the token regardless of how finely Corliss tracks sessions.
    """
    if request.user.is_authenticated:
        oidc.notify_logout(request.user)
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
            "is_staff": membership.is_cluster_admin(did),
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
        _heal_staff_flag(user)
    return user


def _heal_staff_flag(user):
    """Re-derive `is_staff` from the roster, which is the authority.

    `membership.appoint_admin` writes both halves together, so this normally
    finds nothing to do. It exists for when they come apart: the roster write
    succeeded and the local flag update did not, an admin was removed while
    signed in, or the row predates the two being one operation. Doing it at
    login means the local mirror is never more than one sign-in stale.

    **Superusers are skipped in both directions.** Django's admin needs
    `is_staff` as well as `is_superuser`, so clearing it here would lock out an
    account somebody deliberately escalated — a surprise worse than a stale
    flag. `--superuser` is opt-in and stays opt-out of this.

    Never touches the break-glass row: `did:local:admin` signs in through
    `/admin/login/` and never reaches this path.
    """
    if user.is_superuser:
        return
    should_be = membership.is_cluster_admin(user.did)
    if user.is_staff != should_be:
        user.is_staff = should_be
        user.save(update_fields=["is_staff"])


def _store_tokens(user, token_data, dpop_key, nonce, pending):
    # `expires_at` is recorded but never consulted: the PDS is the authority on
    # whether a token is still good, and `atproto.write_record` refreshes on
    # being told `invalid_token` rather than on a clock we do not own. It is
    # here so an operator looking at the row can see how old the session is.
    expires_in = token_data.get("expires_in")
    expires_at = (
        timezone.now() + timedelta(seconds=expires_in)
        if isinstance(expires_in, int)
        else None
    )
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
            "expires_at": expires_at,
        },
    )


def _register_registry_session(user, token_data, pending):
    """Hand an admin's freshly-exchanged tokens to the registry as a session.

    The second half of `_dpop_key_for`, and it runs only when that one
    provisioned a key — so for everyone else this is a dictionary lookup that
    misses and returns.

    Failure is swallowed for the same reason it is there: the person signing in
    cannot fix a registry outage, and refusing their login over it would turn
    "no approvals right now" into "no access at all". They arrive with
    `registry_session_at` unset, the console offers its buttons disabled with
    the reason, and signing in again once the registry is back is the fix.
    """
    provision_id = pending.get("registry_provision_id")
    if not provision_id:
        return

    registry = membership.MembershipRegistry.from_settings()
    try:
        membership.register_registry_session(
            registry,
            provision_id=provision_id,
            pkce_verifier=pending.get("registry_pkce_verifier", ""),
            did=user.did,
            token_data=token_data,
            pds_url=pending["pds_url"],
            issuer=pending["issuer"],
            scopes=atproto.SCOPE,
        )
    except membership.RegistryError as exc:
        log.warning("registry session registration failed for %s: %s", user.did, exc)
        return

    AtprotoToken.objects.filter(user=user).update(
        registry_session_at=timezone.now()
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

    # GATE, and this is the surface that makes it mean anything. This endpoint
    # is the handoff into Open WebUI and it is reached on *every* exchange, so
    # it is the only place that can refuse a session established before the gate
    # existed, or one whose owner has been revoked since they signed in. Gating
    # login alone is a gate with a hole in it: the session is already minted and
    # nothing on the way here asks again.
    #
    # A refused member is sent to our own home page rather than back to the RP
    # with `error=access_denied`. The spec-shaped answer would be correct and
    # useless — Open WebUI renders its own generic failure and the person is
    # left in the chat app with no idea why and nowhere to go, while the page
    # that explains it is one redirect away.
    denial = require_membership(request)
    if denial is not None:
        return denial

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

    # Record the session BEFORE minting, so the id_token can carry the `sid`
    # that a later logout_token will name. Redemption — not `authorize` — is
    # where this belongs: a code can expire unredeemed, and the RP has no
    # session until it trades one in. This row is how logout and revocation
    # know there is anybody to tell (see corliss.oidc.notify_logout).
    session = oidc.record_session(code.user, client_id=cid)
    id_token = oidc.mint_id_token(
        code.user, client_id=cid, nonce=code.nonce, sid=session.sid
    )
    return JsonResponse(
        {
            "access_token": id_token,  # we don't issue a separate RP access token
            "token_type": "Bearer",
            "expires_in": oidc.ID_TOKEN_TTL_SECONDS,
            "id_token": id_token,
        }
    )
