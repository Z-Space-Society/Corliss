"""Every route Corliss serves.

One flat table, no app namespaces: the project *is* the app, so a bare
`reverse("login")` / `{% url 'home' %}` is unambiguous.

Two path families, deliberately shaped:
- the human/atproto-client surface under `/auth/` — login, logout, the OAuth
  callback, and the client-metadata document whose URL *is* the atproto
  `client_id`. Namespacing it keeps the root free for the home page and
  whatever else this app grows.
- the OIDC provider surface at the root, because the discovery document must
  sit at `issuer + /.well-known/openid-configuration` and the issuer is the
  bare origin.
- membership under `/membership/`, which is neither of those and holds both
  ends of the same subject: `events`, which the SCN registry POSTs to when a
  grant or revocation happens, and `apply`, which a signed-in non-member posts
  to in order to ask. One is machines telling Corliss who is a member; the
  other is a person asking to become one, and they share a prefix because they
  share a noun, not a caller.
"""

from django.conf import settings
from django.contrib import admin
from django.urls import path

from corliss import views

urlpatterns = [
    path("admin/", admin.site.urls),
    # ATProto OAuth client (people)
    path(
        "auth/client-metadata.json",
        views.client_metadata,
        name="client_metadata",
    ),
    path("auth/login", views.login, name="login"),
    path("auth/logout", views.logout, name="logout"),
    path("auth/oauth/callback", views.callback, name="callback"),
    # OIDC provider (machines)
    path(".well-known/jwks.json", views.jwks, name="jwks"),
    path(
        ".well-known/openid-configuration",
        views.openid_configuration,
        name="openid_configuration",
    ),
    path("oidc/authorize", views.authorize, name="authorize"),
    path("oidc/token", views.token, name="token"),
    # Registry (the SCN membership push)
    path(
        "membership/events",
        views.membership_push,
        name="membership_push",
    ),
    # The member's own end of the same subject: asking to join. Writes to the
    # applicant's PDS, never to the registry.
    path("membership/apply", views.apply, name="apply"),
    # The public explanation, in three pages. Ungated; see `views.about`.
    path("about/", views.about, name="about"),
    path("about/system/", views.about_system, name="about_system"),
    path("about/team/", views.about_team, name="about_team"),
    # The member's own name and email. Signed-in rather than member-gated —
    # see `views.account`.
    path("account/", views.account, name="account"),
    path("api/", views.api, name="api"),
    # The cluster console. Gated on the atproto admin roster, not on a Django
    # flag — see `views.manage`.
    path("manage/", views.manage, name="manage"),
    # Authenticates the *service account* so roster writes can be made. Comes
    # back through the ordinary `callback` route, which is why there is no second
    # redirect URI here — a new one would mint a different atproto client and
    # re-consent every member.
    path("manage/unlock", views.manage_unlock, name="manage_unlock"),
    # The stack and its health, for cluster admins. Probes in `corliss.health`.
    path("systems/", views.systems, name="systems"),
    path("", views.home, name="home"),
]

# Local-development auth bypass, registered only when explicitly enabled AND in
# DEBUG. In every other configuration the route simply does not exist, so there
# is nothing to probe for. See settings.DEV_LOGIN_ENABLED for the full rationale
# and the startup check that backs this up.
if settings.DEBUG and settings.DEV_LOGIN_ENABLED:
    urlpatterns += [
        path("auth/dev-login", views.dev_login, name="dev_login"),
    ]
