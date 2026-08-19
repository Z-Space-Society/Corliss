"""Template context available on every page (base.html's nav + footer need this)."""

from django.conf import settings


def ui(request):
    return {
        "CHAT_URL": settings.CHAT_URL,
        # The endpoint /api/ tells people to point their client at.
        "API_URL": settings.API_URL,
        # The nav's Manage menu links here, for cluster admins only and only
        # when configured — see base.html.
        "MANAGE_URL": settings.MANAGE_URL,
        # LiteLLM's own admin UI, derived from API_URL rather than configured
        # separately: it is served from the same origin as the API itself, so a
        # second setting could only ever disagree with the first — and this way
        # a `zai-set-domain` moves it along with everything else. Blank when
        # API_URL is, which drops the link rather than pointing it at "/ui/".
        # HappyView and Proxmox are plain hrefs for the Manage menu; each is
        # blank when there is nowhere to point it, which drops the link.
        "HAPPYVIEW_URL": settings.HAPPYVIEW_URL,
        "PROXMOX_URL": settings.PROXMOX_URL,
        "API_ADMIN_URL": (
            settings.API_URL.rstrip("/") + "/ui/" if settings.API_URL else ""
        ),
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
