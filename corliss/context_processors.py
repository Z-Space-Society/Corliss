"""Template context available on every page (base.html's nav + footer need this)."""

from django.conf import settings


def ui(request):
    return {
        "CHAT_URL": settings.CHAT_URL,
        # The footer's build stamp: which version is running, and where to read
        # it. APP_VERSION is "" when it can't be resolved and APP_VERSION_URL is
        # None on a dirty tree, so the template branches on both — see
        # corliss.version for why each of those cases is a deliberate outcome.
        "APP_VERSION": settings.VERSION,
        "APP_VERSION_URL": settings.VERSION_URL,
        "REPO_URL": settings.REPO_URL,
        # The footer links the site's own name back at its canonical origin.
        "PUBLIC_BASE_URL": settings.PUBLIC_BASE_URL,
        # Drives the login page's local-dev sign-in box. Mirrors the same
        # DEBUG-and-flag condition the URLconf registers the route under, so the
        # form is never rendered pointing at a 404 — or, worse, shown anywhere
        # it could be mistaken for a real sign-in option.
        "DEV_LOGIN_ENABLED": settings.DEBUG and settings.DEV_LOGIN_ENABLED,
    }
