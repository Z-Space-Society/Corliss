"""All of Corliss's HTTP endpoints — the ATProto client half and the OIDC
provider half, in the order a member meets them.

ATProto client (people):
- `client_metadata`: serves the client metadata at the `client_id` URL.
- `login`: handle form → resolve → discover → PAR → redirect to the PDS.
- `callback`: validate `state` → DPoP-bound token exchange → upsert the member,
  store tokens server-side, establish the Django session.
- `home`: the root page — an intro when signed out, your standing when in. The
  one page GATE never covers: it is where refused members land.
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
import secrets
from datetime import timedelta
from urllib.parse import urlencode

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth import login as auth_login
from django.contrib.auth import logout as auth_logout
from django.http import Http404, HttpResponseBadRequest, JsonResponse
from django.shortcuts import redirect, render
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from corliss import atproto, litellm, membership, oidc, signing
from corliss.models import AtprotoToken, MembershipCache, OidcAuthCode

User = get_user_model()

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
    """
    did = request.user.did if request.user.is_authenticated else None
    return render(
        request,
        "home.html",
        {"is_member": bool(did) and membership.is_active_member(did)},
    )


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

    # Active first, so the roll a reader is checking against the registry is at
    # the top and revoked history sinks below it.
    members = list(MembershipCache.objects.order_by("-active", "did"))

    applications = _applications(registry, members)

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
            "applications": applications,
            "members": members,
            "admins": admins,
            "roster_error": roster_error,
            "registry_configured": registry.is_configured,
            "report": report,
            "reconcile_error": reconcile_error,
        },
    )


# States an application can be in, as far as this cluster can tell. The
# question "has this been dealt with" is answered by the cache and never by the
# application record, which knows nothing about what happened to it — the
# applicant writes it and it stays exactly as written whether they were
# approved, refused, or never looked at.
APPLICATION_PENDING = "pending"
APPLICATION_MEMBER = "member"
APPLICATION_REVOKED = "revoked"

# Pending first: the queue is a to-do list, and the rows needing a decision are
# the reason to open the page. Within a state, newest first — the order the
# registry already returns them in.
_APPLICATION_ORDER = {
    APPLICATION_PENDING: 0,
    APPLICATION_MEMBER: 1,
    APPLICATION_REVOKED: 1,
}


def _applications(registry, members):
    """The application queue for `/manage/`, cross-referenced with the cache.

    Returns a context dict rather than a list, because two facts about the
    *read* have to reach the template alongside the rows: how many records
    could not be parsed, and whether the list was cut short. Both would
    otherwise show up as rows that simply are not there.

    A failed read renders as a failure. Never as an empty queue — same posture
    as the roster above, and for the same reason: "nobody has applied" and "we
    could not find out" are different facts and the page must not conflate
    them.

    The state of each application comes from `MembershipCache`, which is
    already loaded for the table below — no extra query, and no second opinion
    about who is a member.
    """
    try:
        listing = registry.fetch_applications()
    except membership.RegistryError as exc:
        return {
            "rows": [],
            "pending": 0,
            "unreadable": 0,
            "truncated": False,
            "error": str(exc),
        }

    cached = {m.did: m for m in members}
    rows = []
    for application in listing:
        row = cached.get(application.did)
        if row is None:
            state = APPLICATION_PENDING
        elif row.active:
            state = APPLICATION_MEMBER
        else:
            state = APPLICATION_REVOKED
        rows.append(
            {
                "did": application.did,
                "created_at": application.created_at,
                "note": application.note,
                "state": state,
            }
        )

    rows.sort(key=lambda r: _APPLICATION_ORDER[r["state"]])
    return {
        "rows": rows,
        "pending": sum(1 for r in rows if r["state"] == APPLICATION_PENDING),
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
