"""Whether the cluster is up, as `/systems/` reports it.

Every other outbound module here owns one relationship — `membership.py` the
registry, `litellm.py` the gateway, `oidc.py` the back-channel. This one owns a
relationship with the *cluster*, which is why it is a module rather than a
probe smeared across the three: nothing else in Corliss has any business
knowing that Garage exists.

**Corliss can reach all of this, and that is the whole reason the page can stop
guessing.** It runs in its own CT on `vmbr1`, the same bridge as every service
below, so each probe is one hop to a neighbour. The addresses are therefore
INTERNAL without exception — server-side Python cannot fetch our own public
origin (Cloudflare's Browser Integrity Check answers `error code: 1010`), and
`API_URL`/`CHAT_URL`/`MANAGE_URL` are hrefs for a browser, never probe targets.

**Three states, and the third one is load-bearing.** `up` and `down` are
measurements. `unknown` is the honest answer when there is nothing to measure
with — a blank setting, or a probe that raised something we did not anticipate.
A missing address must never read `down`: that would report an outage in a
service nobody asked about. The page's predecessor rendered `unknown` for
everything precisely because an entry that guessed is worse than one that
admits it does not know, and that principle survives the probes being real.

**Two claims here are narrower than they look**, and both are deliberate:

- The sync relay's `/health` reports liveness only and never touches Postgres,
  so `up` means the process is serving, not that its storage works. Asking it
  to check the database would let a Postgres blip restart the relay out from
  under live sync connections, which is why upstream declines to.
- Garage's admin API binds to `127.0.0.1:3903` and is unreachable from here, so
  the probe talks to its S3 port instead. An unauthenticated `GET /` on an S3
  endpoint answers an XML error, so *any* HTTP status is proof it is serving —
  a 403 from Garage is a working Garage.

**No probe may raise, and none may block a page render for long.** They fan out
across a thread pool with a short timeout so the wall clock is one timeout
rather than eight, and the result is cached so a dead service does not cost
that timeout on every load.
"""

import logging
import socket
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

import requests
from django.conf import settings
from django.core.cache import cache
from django.db import Error as DatabaseError
from django.db import connection

log = logging.getLogger(__name__)


# The three states, as the template's CSS modifiers spell them.
UP = "up"
DOWN = "down"
UNKNOWN = "unknown"

_LABELS = {UP: "Up", DOWN: "Down", UNKNOWN: "Unknown"}

# Short, because this sits on a human waiting for a page. Shorter than
# LITELLM_TIMEOUT (5s), which is a member's key issuance and worth waiting for;
# a status dot is not. A service on the same bridge that has not answered in two
# seconds is not healthy in any sense this page should call "up".
HEALTH_TIMEOUT = 2

_CACHE_KEY = "corliss:health"

# An all-clear can sit for the full window: nothing is changing and re-asking
# eight services on every refresh buys nothing. A result with anything not-up is
# held for a third of that, because the reason somebody is reloading THIS page
# is to watch a service come back, and a stale red dot is the one staleness that
# actually costs them something.
#
# Note this is LocMemCache — Corliss configures no CACHES block — so the cache is
# per gunicorn worker rather than shared. That is fine and not worth fixing: it
# means each worker probes once per window, which is a handful of requests a
# minute against services that answer in milliseconds. Do not add Redis for it.
HEALTH_CACHE_TTL = 30
HEALTH_DEGRADED_TTL = 10


class Probe:
    """One service on the page: what it is, and how to ask whether it is up.

    `check` returns a state and takes no arguments — it reads whatever setting
    it needs itself, so an unconfigured service is that probe's own business
    rather than a special case in the runner.
    """

    __slots__ = ("name", "purpose", "check", "note")

    def __init__(self, name, purpose, check, note=""):
        self.name = name
        self.purpose = purpose
        self.check = check
        self.note = note


# --- transport ---------------------------------------------------------------


def _origin(url):
    """`scheme://host:port` of a URL, dropping any path it carries.

    Two settings reached below are addresses of a service rather than of an
    endpoint — `OIDC_BACKCHANNEL_LOGOUT_URI` names a specific path, and the
    registry URL has historically been written both ways — so the health path
    is appended to the origin instead of assumed to be all there is.
    """
    if not url:
        return ""
    parts = urlsplit(url)
    if not parts.scheme or not parts.netloc:
        log.warning("health: %r is not a usable URL", url)
        return ""
    return f"{parts.scheme}://{parts.netloc}"


def _http(name, url, *, host=None, any_status=False):
    """GET `url` and report whether something served it.

    Transport failure and HTTP status are checked separately, the same split
    `litellm._call` makes and for the same reason: they are different failures
    and collapsing them loses which one happened.

    Redirects are never followed. HappyView answers `/` with a 302 and that IS
    the healthy response; following it would probe wherever it points instead,
    and time the page out on a redirect chain.
    """
    if not url:
        return UNKNOWN

    try:
        response = requests.get(
            url,
            headers={"Host": host} if host else None,
            timeout=HEALTH_TIMEOUT,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        log.warning("health: %s unreachable: %s", name, exc)
        return DOWN

    if not any_status and response.status_code >= 400:
        log.warning("health: %s answered HTTP %s", name, response.status_code)
        return DOWN
    return UP


def _host_port(url, default_port):
    """The host and port of a URL, for a probe that does not speak HTTP."""
    parts = urlsplit(url)
    if not parts.hostname:
        log.warning("health: %r has no host to dial", url)
        return None, None
    return parts.hostname, parts.port or default_port


# --- the probes --------------------------------------------------------------


def _corliss():
    """Free: this process built the response the answer is rendered into."""
    return UP


def _postgres():
    """`SELECT 1`, rather than inferring it from the page having rendered.

    A dead Postgres means the session lookup behind `request.user` failed and
    nobody ever reached this page, so in practice this reads `up` whenever it is
    read at all — which is exactly why the old page felt entitled to assume it.
    The assumption was still the wrong shape: every other row here is measured,
    and one row that is deduced would be the row nobody could trust. It costs a
    round trip to the neighbour that already answered one.

    Runs on the request's own thread, not in the pool below. Django's
    connections are thread-local, so a probe in a worker thread would open a
    second connection and leak it when the thread ends.
    """
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
    except DatabaseError as exc:
        log.warning("health: postgres query failed: %s", exc)
        return DOWN
    return UP


def _redis():
    """`PING` over a raw socket, because `-NOAUTH` is a perfectly good answer.

    Redis on the cluster sets `requirepass`, so an unauthenticated PING is
    refused — and the refusal is the measurement. `-NOAUTH Authentication
    required.` can only come from a Redis that is up, listening and speaking its
    own protocol, which is everything this page claims when it says "Up".

    This is why there is no redis dependency in `pyproject.toml` and must not
    become one: a client library would buy a real credential's worth of
    complexity to learn something eleven bytes on a socket already prove. It is
    also why `REDIS_URL` here is a probe target and nothing else — Corliss holds
    no Redis client and its cache is LocMemCache. Do not wire one to this
    setting without saying so out loud.
    """
    if not settings.REDIS_URL:
        return UNKNOWN

    host, port = _host_port(settings.REDIS_URL, 6379)
    if not host:
        return UNKNOWN

    try:
        with socket.create_connection((host, port), timeout=HEALTH_TIMEOUT) as sock:
            sock.settimeout(HEALTH_TIMEOUT)
            sock.sendall(b"PING\r\n")
            reply = sock.recv(64)
    except OSError as exc:
        log.warning("health: redis unreachable: %s", exc)
        return DOWN

    if reply.startswith(b"+PONG") or reply.startswith(b"-NOAUTH"):
        return UP
    log.warning("health: redis answered %r", reply[:64])
    return DOWN


def _garage():
    """Any HTTP status from the S3 port — see the module docstring."""
    origin = _origin(settings.GARAGE_S3_URL)
    return _http("garage", origin + "/" if origin else "", any_status=True)


def _caddy():
    """Caddy's own `:80` health site, which exists whether or not TLS is on."""
    return _http("caddy", settings.CADDY_HEALTH_URL)


def _happyview():
    """`GET /`, with the `Host` header the edge would normally have supplied.

    **The header is not what makes this work, and the first version of this
    comment said it was.** The registry's HTTP 421 "Unknown host" is real, but it
    belongs to the XRPC routes, where HappyView rebuilds the request URI from
    `Host`. `/` is served by a default handler that redirects whatever it is
    asked as: measured against the cluster on 2026-08-31, this answers 303 both
    with the header and without it.

    The header is sent anyway, for a weaker but sufficient reason: it is how
    Corliss reaches HappyView on every other call, and a probe that dials a
    service differently from the code it is vouching for is measuring something
    else. It costs nothing, and `MEMBERSHIP_REGISTRY_HOST` already holds the
    value, so nothing new is configured to send it.

    A probe carrying the token to an XRPC route would exercise the routing that
    real calls depend on, and is deliberately not done: a liveness check has no
    business holding a credential, and this is the same `GET /` the happyview
    role's own smoke test uses.
    """
    origin = _origin(settings.MEMBERSHIP_REGISTRY_URL)
    return _http(
        "happyview",
        origin + "/" if origin else "",
        host=settings.MEMBERSHIP_REGISTRY_HOST or None,
    )


def _litellm():
    """`/health/liveliness` — unauthenticated, and the gateway's own answer.

    Not `/health`, which on LiteLLM walks every configured model and would turn
    one unreachable inference node into a red dot for the gateway in front of it.
    """
    origin = _origin(settings.LITELLM_URL)
    return _http("litellm", origin + "/health/liveliness" if origin else "")


def _sync_relay():
    """`/health` — liveness only, narrower than it reads. See the docstring."""
    origin = _origin(settings.SYNC_RELAY_URL)
    return _http("sync-relay", origin + "/health" if origin else "")


def _open_webui():
    """`/health`, at the internal address back-channel logout already names.

    Derived from `OIDC_BACKCHANNEL_LOGOUT_URI` rather than given a setting of
    its own: that value is already the internal origin of the same service, and
    a second setting for the same host is a second thing to get wrong.
    """
    origin = _origin(settings.OIDC_BACKCHANNEL_LOGOUT_URI)
    return _http("open-webui", origin + "/health" if origin else "")


# --- the stack ----------------------------------------------------------------
#
# What this cluster is made of, grouped the way zai-ops groups its CTIDs: core
# is the data foundations (storage with no logic of its own), platform is what
# other services consume, applications are what members actually use. Held here
# rather than read from anywhere because nothing else in Corliss knows the shape
# of the cluster — this is the one place that claims to, and now the one place
# that checks.
#
# Ordering inside a group is the dependency order, roughly: the thing others sit
# on comes first.
#
# **Every entry here is a running service with an address.** The list carried a
# "Manage Console" row until v0.9.3, describing static files that had already
# been deleted along with the `manage_console` role — its own console at
# `/manage/` replaced it, and zai-ops blanks `MANAGE_URL` for the same reason.
# A page whose whole claim is that it does not guess has no business listing
# something that is not there, so a row belongs here only if something can be
# asked whether it is up.
STACK = [
    ("Core", [
        Probe("Garage", "object store — backup target for the control node", _garage),
        Probe("PostgreSQL",
              "the cluster's database: Corliss, LiteLLM, Open WebUI, HappyView",
              _postgres),
        Probe("Redis", "session revocation store, so signing out reaches chat in seconds",
              _redis),
    ]),
    ("Platform", [
        Probe("Caddy", "the edge — the only LAN-facing container, terminates TLS", _caddy),
        Probe("HappyView", "the membership registry: applications, grants, admin roster",
              _happyview),
        Probe("LiteLLM", "the API gateway in front of the models", _litellm),
        Probe("Sync relay", "the Automerge sync server behind collaborative spaces",
              _sync_relay, note="liveness only — does not check its storage"),
    ]),
    ("Applications", [
        Probe("Corliss", "login, membership, OIDC, and members' API keys", _corliss),
        Probe("Open WebUI", "the chat app", _open_webui),
    ]),
]

# Probed on the request's own thread rather than in the pool, for the reason in
# each one's docstring: one needs the thread-local database connection, and the
# other does no I/O at all.
_INLINE = {_postgres, _corliss}


# --- running them -------------------------------------------------------------


def _safely(probe):
    """Run one probe. A probe that raises is a broken probe, not a broken service.

    Hence `unknown` rather than `down`: reporting an outage because our own code
    hit a case it did not expect would be the page telling a lie about somebody
    else. The traceback goes to the log, where it is ours to fix.
    """
    try:
        return probe.check()
    except Exception:  # noqa: BLE001 — a status page must survive its own bugs
        log.exception("health: the probe for %s raised", probe.name)
        return UNKNOWN


def _measure():
    """Every probe, run once. The network-bound ones concurrently."""
    remote = [p for group in STACK for p in group[1] if p.check not in _INLINE]

    states = {}
    for group in STACK:
        for probe in group[1]:
            if probe.check in _INLINE:
                states[probe.name] = _safely(probe)

    if remote:
        with ThreadPoolExecutor(max_workers=len(remote)) as pool:
            for probe, state in zip(remote, pool.map(_safely, remote)):
                states[probe.name] = state

    return [
        {
            "name": name,
            "services": [
                {
                    "name": probe.name,
                    "purpose": probe.purpose,
                    "note": probe.note,
                    "state": states[probe.name],
                    "label": _LABELS[states[probe.name]],
                }
                for probe in probes
            ],
        }
        for name, probes in STACK
    ]


def check_all(*, refresh=False):
    """The whole stack with a measured state, ready to render. Never raises.

    Returns the same shape the template has always been handed — groups of
    services — so the view stays a gate and a render.
    """
    if not refresh:
        cached = cache.get(_CACHE_KEY)
        if cached is not None:
            return cached

    groups = _measure()
    all_up = all(
        service["state"] == UP
        for group in groups
        for service in group["services"]
    )
    cache.set(_CACHE_KEY, groups, HEALTH_CACHE_TTL if all_up else HEALTH_DEGRADED_TTL)
    return groups
