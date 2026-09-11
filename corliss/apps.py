from django.apps import AppConfig
from django.conf import settings
from django.core.checks import Error, register


def check_dev_login_requires_debug(app_configs, **kwargs):
    """Refuse to run with the auth bypass enabled outside DEBUG.

    DEV_LOGIN_ENABLED serves /auth/dev-login, which hands out a session for any
    handle with no authentication at all. The route is already gated on DEBUG
    twice over (urls.py registration, and the view itself), so this check exists
    for the case those cannot catch: a production env file that carries
    DEV_LOGIN_ENABLED=true by copy-paste. Django runs system checks ahead of
    almost every management command, so this turns that mistake into a failed
    `migrate`/`collectstatic` — i.e. a failed deploy — rather than a silent
    misconfiguration nobody notices until it's exploited.

    Keyed on DEBUG_FROM_ENV, not DEBUG: the test runner forces settings.DEBUG
    off, so keying on DEBUG would make `manage.py test` fail on any machine with
    the flag legitimately set. What we mean to catch is the operator's intent,
    which is what the env file records.
    """
    if settings.DEV_LOGIN_ENABLED and not settings.DEBUG_FROM_ENV:
        return [
            Error(
                "DEV_LOGIN_ENABLED is set while DEBUG is off.",
                hint=(
                    "/auth/dev-login is a complete authentication bypass: it "
                    "issues a session for any handle without verifying "
                    "anything. It is for local development only. Unset "
                    "DEV_LOGIN_ENABLED in this environment."
                ),
                id="corliss.E001",
            )
        ]
    return []


def check_dev_admins_require_debug(app_configs, **kwargs):
    """Refuse to run with hard-coded admins outside DEBUG.

    DEV_ADMIN_DIDS makes `is_cluster_admin` answer yes without consulting the
    roster. That is fine locally, where no roster record exists yet; in
    production it is a standing grant of admin that no roster edit can revoke.
    Keyed on DEBUG_FROM_ENV for the same reason as the check above.
    """
    if settings.DEV_ADMIN_DIDS and not settings.DEBUG_FROM_ENV:
        return [
            Error(
                "DEV_ADMIN_DIDS is set while DEBUG is off.",
                hint=(
                    "These DIDs are treated as cluster admins without appearing "
                    "on the roster, so removing them from the roster would not "
                    "revoke them. It is for local development only. Unset "
                    "DEV_ADMIN_DIDS in this environment."
                ),
                id="corliss.E002",
            )
        ]
    return []


def check_explicit_theme_exists(app_configs, **kwargs):
    """Refuse to run with a THEME that names no folder.

    A theme derived from PUBLIC_BASE_URL's host may have no folder, and that is
    every deployment wearing the default look. A THEME set by hand is a request
    for one particular look, so a missing folder there is a typo that would
    otherwise serve the default without a word. Keyed on THEME_FROM_ENV for
    exactly that distinction.
    """
    if settings.THEME_FROM_ENV and not settings.THEME_DIR.is_dir():
        return [
            Error(
                f"THEME is set to {settings.THEME_FROM_ENV!r}, but "
                f"{settings.THEME_DIR} does not exist.",
                hint=(
                    "THEME names a folder under themes/. Fix the name, or unset "
                    "THEME to use the one matching PUBLIC_BASE_URL's host."
                ),
                id="corliss.E003",
            )
        ]
    return []


class CorlissConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "corliss"

    def ready(self):
        register(check_dev_login_requires_debug)
        register(check_dev_admins_require_debug)
        register(check_explicit_theme_exists)
