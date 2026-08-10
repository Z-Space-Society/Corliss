"""Test URLconf that always registers the dev-login route.

corliss.urls only registers `auth/dev-login` when DEBUG and DEV_LOGIN_ENABLED
are both true *at import time*, and Django's test runner forces DEBUG off — so
`override_settings` alone can never make the real URLconf serve that route.
Tests that need to exercise the view point ROOT_URLCONF here instead, which
keeps them independent of whatever the developer's own .env happens to say.

The view's own DEBUG/flag guard is unaffected by this, which is precisely what
makes it worth testing: see DevLoginRefusedTests.
"""

from django.urls import path

from corliss import views
from corliss.urls import urlpatterns as _base

urlpatterns = [
    p for p in _base if getattr(p, "name", None) != "dev_login"
] + [path("auth/dev-login", views.dev_login, name="dev_login")]
