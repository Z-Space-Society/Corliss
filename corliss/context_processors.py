"""Template context available on every page (base.html's nav needs this)."""

from django.conf import settings


def ui(request):
    return {
        "CHAT_URL": settings.CHAT_URL,
        # Drives the login page's local-dev sign-in box. Mirrors the same
        # DEBUG-and-flag condition the URLconf registers the route under, so the
        # form is never rendered pointing at a 404 — or, worse, shown anywhere
        # it could be mistaken for a real sign-in option.
        "DEV_LOGIN_ENABLED": settings.DEBUG and settings.DEV_LOGIN_ENABLED,
    }
