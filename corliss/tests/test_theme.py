"""Themes: a folder under themes/ whose files shadow the app's by path.

See themes/README.md. These point TEMPLATES at a fixture theme rather than at a
real one, so editing the staging theme can never break the suite.
"""

import copy
import re
from pathlib import Path
from unittest.mock import patch

from django.conf import settings
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse

from corliss.apps import check_explicit_theme_exists

FIXTURE = Path(__file__).parent / "theme_fixture"


def _templates_with(dirs):
    templates = copy.deepcopy(settings.TEMPLATES)
    templates[0]["DIRS"] = dirs
    return templates


class NoRosterMixin:
    """Pin ELEVATE to False, as test_views does, so the nav reads no roster."""

    def setUp(self):
        super().setUp()
        patcher = patch("corliss.membership.is_cluster_admin", return_value=False)
        patcher.start()
        self.addCleanup(patcher.stop)


@override_settings(TEMPLATES=_templates_with([FIXTURE / "templates"]))
class ThemedTemplateTests(NoRosterMixin, TestCase):
    """The fixture theme holds about.html and _site_title.html, and nothing else."""

    def test_a_page_the_theme_has_is_the_themes(self):
        resp = self.client.get(reverse("about"))
        self.assertContains(resp, "Fixture theme about page.")
        self.assertNotContains(resp, "The Shared Computer Network is a collective")

    def test_a_page_the_theme_lacks_falls_back_to_the_app(self):
        # The whole promise of the mechanism: a theme holds only what it changes.
        resp = self.client.get(reverse("about_system"))
        self.assertContains(resp, "<h1>The System</h1>")
        self.assertNotContains(resp, "Fixture theme")

    def test_a_partial_the_theme_has_renames_every_page(self):
        html = self.client.get(reverse("about_system")).content.decode()
        self.assertRegex(html, r"<title>The System · Fixture\s*</title>")

    def test_a_partial_the_theme_lacks_is_the_apps(self):
        self.assertContains(self.client.get(reverse("about")), "nav__brand-mark")


# No theme, forced rather than assumed: a developer trying a theme locally has
# THEME in .env, and without this the suite would assert against their theme.
@override_settings(TEMPLATES=_templates_with([]))
class UnthemedTemplateTests(NoRosterMixin, TestCase):
    def test_the_default_title_names_the_site(self):
        html = self.client.get(reverse("home")).content.decode()
        self.assertRegex(html, r"<title>Home · SCN\s*</title>")

    def test_theme_css_is_linked_after_base_css(self):
        # Order is what lets a theme's tokens win, so assert it, not presence.
        html = self.client.get(reverse("home")).content.decode()
        base = re.search(r"css/base\.[^\"']*\.css", html)
        theme = re.search(r"css/theme\.[^\"']*\.css", html)
        self.assertIsNotNone(base)
        self.assertIsNotNone(theme)
        self.assertLess(base.start(), theme.start())


class ThemeCheckTests(SimpleTestCase):
    """corliss.E003 separates a typo from an unthemed deployment."""

    @override_settings(
        THEME_FROM_ENV="no-such-theme",
        THEME_DIR=settings.BASE_DIR / "themes" / "no-such-theme",
    )
    def test_a_hand_set_theme_with_no_folder_is_an_error(self):
        errors = check_explicit_theme_exists(None)
        self.assertEqual([e.id for e in errors], ["corliss.E003"])

    @override_settings(
        THEME_FROM_ENV="",
        THEME_DIR=settings.BASE_DIR / "themes" / "unthemed.example",
    )
    def test_a_derived_theme_with_no_folder_is_the_default_look(self):
        self.assertEqual(check_explicit_theme_exists(None), [])

    @override_settings(
        THEME_FROM_ENV="staging.sharedcomputer.network",
        THEME_DIR=settings.BASE_DIR / "themes" / "staging.sharedcomputer.network",
    )
    def test_a_hand_set_theme_that_exists_passes(self):
        self.assertEqual(check_explicit_theme_exists(None), [])
