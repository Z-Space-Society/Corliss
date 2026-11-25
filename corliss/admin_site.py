"""Django's admin, answering to the roster.

There is one kind of admin: a current place on the atproto roster. A roster
admin signs in with their handle like everyone else and can do everything,
Django's admin included, because their row carries `is_staff` and
`is_superuser` as copies of the roster (`membership._set_admin_flags`).

Two things here keep that safe.

- **The admin re-asks the roster on every request.** The flags are a copy,
  refreshed at sign-in, so trusting them alone would leave an admin dismissed
  outside the console holding Django's admin until they next signed in.
  `has_permission` asks `membership.is_cluster_admin`, a cached roster read
  that fails closed, for every roster-governed row. The local accounts
  (`membership.LOCAL_DID_PREFIXES`) have no roster entry and are judged on
  their flags, which is what lets the break-glass account in when the roster
  is unreadable.

- **The password form is only served on the tunnel host.** `/admin/login/` is
  the break-glass account's door, reached through an SSH tunnel at
  `127.0.0.1`. Everywhere else, a signed-out visitor is sent to handle sign-in
  and back, and a signed-in one who is not an admin gets a 404, the same answer
  `views.admin_required` gives. GET and POST alike: the form being hidden is
  not enough if a POST still checks a password.

Wired in by `apps.CorlissAdminConfig.default_site`, so every `admin.register`
in `corliss.admin` lands here without naming it.
"""

from urllib.parse import urlencode

from django.contrib import admin
from django.http import Http404
from django.shortcuts import redirect
from django.urls import reverse

# The hosts the tunnel arrives on. `ALLOWED_HOSTS` already admits them for the
# smoke test, and the edge never forwards a request carrying them: Caddy routes
# by hostname, and neither matches a site it serves.
TUNNEL_HOSTS = frozenset({"127.0.0.1", "localhost"})


def on_tunnel_host(request):
    host = request.get_host().rsplit(":", 1)[0]
    return host in TUNNEL_HOSTS


class CorlissAdminSite(admin.AdminSite):
    def has_permission(self, request):
        user = request.user
        if not (user.is_active and user.is_staff):
            return False

        from corliss import membership

        if not membership.is_roster_governed(user.did):
            return True
        return membership.is_cluster_admin(user.did)

    def login(self, request, extra_context=None):
        if on_tunnel_host(request):
            return super().login(request, extra_context)
        if request.user.is_authenticated:
            if self.has_permission(request):
                # `next` is user input; an admin already in goes to the index
                # rather than anywhere a link told them to.
                return redirect("admin:index")
            raise Http404
        target = request.GET.get("next") or reverse("admin:index")
        return redirect(f"{reverse('login')}?{urlencode({'next': target})}")
