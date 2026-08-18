"""
Django settings for Corliss.

Env-driven (12-factor): every deployment-specific value is read from the
environment so the same code runs locally and on the cluster with no edits.
A local `.env` (git-ignored) supplies values in development; `.env.example`
documents the full set with placeholders. No secrets live in this file.
"""

from pathlib import Path

import environ

from corliss import version

BASE_DIR = Path(__file__).resolve().parent.parent

env = environ.Env(
    DEBUG=(bool, False),
)

# Read a local .env if present (development convenience; never committed).
_env_file = BASE_DIR / ".env"
if _env_file.exists():
    environ.Env.read_env(_env_file)

# --- Core -----------------------------------------------------------------

# SECRET_KEY has an insecure default ONLY so `manage.py` runs out of the box in
# development; any real run sets it from the environment.
SECRET_KEY = env("SECRET_KEY", default="dev-insecure-key-do-not-use-in-prod")

# The DEBUG this environment actually asked for, and the runtime DEBUG, which
# are not always the same value: Django's test runner forces `settings.DEBUG`
# off for the duration of a test run. Runtime gates (is this route live?) want
# the mutable one; deploy-time system checks (did the operator misconfigure
# this?) want DEBUG_FROM_ENV, or they fire during `manage.py test` on any
# machine with a development flag set and block the suite.
DEBUG_FROM_ENV = env("DEBUG")
DEBUG = DEBUG_FROM_ENV
ALLOWED_HOSTS = env.list("ALLOWED_HOSTS", default=["localhost", "127.0.0.1"])

# Origins Django trusts for unsafe (POST) requests' CSRF Origin check. Needed
# when served behind an HTTPS proxy/tunnel (e.g. cloudflared in dev): the browser
# sends an `https://` Origin while the app sees the forwarded request as `http`,
# so the tunnel host must be declared trusted explicitly.
CSRF_TRUSTED_ORIGINS = env.list("CSRF_TRUSTED_ORIGINS", default=[])

# The public HTTPS origin this app is served from. It anchors the OAuth
# `client_id`, the OIDC issuer, and the redirect/JWKS URLs. In local dev it can
# be a tunnel or the localhost development convention (see README).
PUBLIC_BASE_URL = env("PUBLIC_BASE_URL", default="http://localhost:8000")

# --- Build identity -------------------------------------------------------
# Which build is this? Resolved from the checkout itself (see corliss.version),
# and pointedly NOT read from the environment like everything else in this file:
# this is not a deployment choice but a fact about the code that is running, and
# an env var could only ever make the footer lie about it.
VERSION = version.resolve(BASE_DIR)
VERSION_URL = version.url_for(VERSION)
REPO_URL = version.REPO_URL

# --- Signing keys ---------------------------------------------------------
# Paths to PEM private keys, loaded lazily by corliss.signing. atproto mandates
# ES256 (P-256) for DPoP + client assertion; the OIDC id_token uses RS256 for
# broad OIDC-client compatibility. Two keys, one JWKS. Never committed.
ATPROTO_EC_PRIVATE_KEY_PATH = env("ATPROTO_EC_PRIVATE_KEY_PATH", default="")
OIDC_RSA_PRIVATE_KEY_PATH = env("OIDC_RSA_PRIVATE_KEY_PATH", default="")

# --- OIDC provider --------------------------------------------------------
# The single relying party we issue id_tokens to (Open WebUI). Secret is read
# from the environment; only a placeholder appears in .env.example.
OIDC_CLIENT_ID = env("OIDC_CLIENT_ID", default="open-webui")
OIDC_CLIENT_SECRET = env("OIDC_CLIENT_SECRET", default="")
OIDC_REDIRECT_URIS = env.list("OIDC_REDIRECT_URIS", default=[])

# --- UI ---------------------------------------------------------------------
# Public origin of the cluster's chat app (Open WebUI). Blank hides the nav's
# "Chat" link entirely — e.g. local dev with no Open WebUI configured.
CHAT_URL = env("CHAT_URL", default="")

# Public origin of the cluster's API service (api.<domain>, served from heron).
# Shown on /api/ as the endpoint to point a client at. Blank leaves that page's
# endpoint block out — the page itself still explains what is coming.
API_URL = env("API_URL", default="")

# Public origin of the Manage Console, linked from the home page's admin block.
# Blank hides that one link (the Django admin link beside it always renders) —
# the console is deployed separately, so a Corliss without one is a real state.
MANAGE_URL = env("MANAGE_URL", default="")

# --- Registry membership push ----------------------------------------------
# Shared bearer token the SCN registry presents when POSTing a grant or
# revocation to /membership/events. Blank disables the endpoint outright (503)
# rather than leaving it comparing against an empty string, which would accept
# a request that also sent nothing.
MEMBERSHIP_PUSH_TOKEN = env("MEMBERSHIP_PUSH_TOKEN", default="")

# --- Registry admin roster --------------------------------------------------
# The SCN service DID, whose repo holds the public admin roster record. Corliss
# reads it directly from that repo — no credential, no HappyView, no cache in
# our database — which is what lets ELEVATE work on a Corliss with an empty
# database. Blank makes every admin check answer "no" rather than guess.
SCN_SERVICE_DID = env("SCN_SERVICE_DID", default="")

# --- Registry reconciliation -------------------------------------------------
# Reading membership back OUT of the registry, which the push cannot do: a
# Corliss rebuilt from nothing has witnessed no pushes, and the events it missed
# already happened. These three point at the `syncMembers` service door — a
# read-only endpoint authenticated by a shared token rather than by a signed-in
# admin, because the run that matters most happens at boot with nobody present.
#
# URL or TOKEN blank disables reconciliation with a visible "not configured"
# state rather than a traceback. The token is read-only by construction on the
# registry side; if it ever gains a write path it becomes equivalent to admin
# authority over membership.
#
# CLIENT_KEY is **optional** — sent when set. Verified against production
# 2026-08-18: HappyView dispatches to a Lua script with no session and no client
# key, so it adds nothing the token does not carry. Requiring it would tie the
# recovery path to the *console's* origin-bound key having been configured,
# which is the one dependency reconciliation must not have.
MEMBERSHIP_REGISTRY_URL = env("MEMBERSHIP_REGISTRY_URL", default="")
MEMBERSHIP_REGISTRY_TOKEN = env("MEMBERSHIP_REGISTRY_TOKEN", default="")
MEMBERSHIP_REGISTRY_CLIENT_KEY = env("MEMBERSHIP_REGISTRY_CLIENT_KEY", default="")

# --- Local development escape hatch ------------------------------------------
# A real atproto login can't complete over loopback: the authorization server
# fetches our client-metadata.json server-side over public HTTPS, so `client_id`
# must be publicly reachable (see the README's "Local dev without atproto").
#
# DEV_LOGIN_ENABLED exposes /auth/dev-login, which mints a full session for any
# handle typed into it WITHOUT authenticating anything. It is a complete
# authentication bypass and must never be on in production.
#
# Three independent guards, because this is an auth service:
#   1. it defaults to off, so enabling it is always explicit;
#   2. the route is only registered when this AND DEBUG are true, and the view
#      re-checks both and 404s otherwise (corliss.views.dev_login);
#   3. corliss.apps raises a system-check ERROR when it is set without DEBUG, so
#      a production config carrying it fails `manage.py check` — and therefore
#      the deploy's migrate/collectstatic — instead of quietly serving an open
#      door.
DEV_LOGIN_ENABLED = env.bool("DEV_LOGIN_ENABLED", default=False)

# The same escape hatch for ELEVATE. The admin roster is a record in the SCN
# service DID's repo, so until that record exists there is no way to be an admin
# locally and the admin surface cannot be looked at at all.
#
# DIDs listed here answer "yes" to `membership.is_cluster_admin` — and to nothing
# else. It grants no membership and writes no Django flag, exactly as the real
# roster doesn't. Guarded like DEV_LOGIN_ENABLED: read only under DEBUG (see
# `is_cluster_admin`) and flagged by a system check when set without it, so it
# cannot ride into production in a .env.
DEV_ADMIN_DIDS = env.list("DEV_ADMIN_DIDS", default=[])

# --- Applications ---------------------------------------------------------

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # Corliss is a single app: four models, one URL table, the atproto client
    # and OIDC provider as plain modules beside them. A future subsystem earns
    # its own app only by being genuinely standalone.
    "corliss",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "corliss.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        # Templates live in corliss/templates/ and are found by APP_DIRS.
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "corliss.context_processors.ui",
            ],
        },
    },
]

WSGI_APPLICATION = "corliss.wsgi.application"

# --- Database -------------------------------------------------------------
# Postgres is the target store, reached via a single connection URL so local
# and deployed runs differ only by env value.
DATABASES = {
    "default": env.db_url(
        "DATABASE_URL",
        default="postgres://localhost:5432/corliss",
    ),
}

# --- Auth -----------------------------------------------------------------
# The DID-keyed custom user model. Set BEFORE the first migration — switching
# AUTH_USER_MODEL after migrations exist is painful.
AUTH_USER_MODEL = "corliss.User"

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
]

LOGIN_URL = "login"

# --- i18n / static --------------------------------------------------------

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
# Source assets (base.css, vendored fonts) live in corliss/static/ and are
# found by the app-directories finder; STATIC_ROOT is the collectstatic output
# whitenoise serves from — gitignored, built at deploy time.
STATIC_ROOT = BASE_DIR / "staticfiles"
STORAGES = {
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage",
    },
}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# --- Session / cookie hardening -------------------------------------------
# Member sessions are server-side Django sessions (not browser-held JWTs).
SESSION_COOKIE_HTTPONLY = True
# Secure cookies are enforced whenever we're not in DEBUG (i.e. behind TLS).
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG

# Caddy terminates TLS and forwards plain HTTP internally (vmbr1); without this,
# Django sees every request as http and request.is_secure() is always False,
# breaking the SESSION_COOKIE_SECURE/CSRF_COOKIE_SECURE enforcement above.
# Caddy sets/overwrites X-Forwarded-Proto itself (not client-controllable
# through the proxy), so trusting it here doesn't reopen that spoofing hole.
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# 0 (off) by default so local dev/tunnels are unaffected; set a real value
# (e.g. 31536000) once TLS is confirmed stable in production (Fable review F7).
SECURE_HSTS_SECONDS = env.int("SECURE_HSTS_SECONDS", default=0)
