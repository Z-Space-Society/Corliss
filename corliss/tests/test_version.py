import tempfile
from pathlib import Path

from django.test import SimpleTestCase

from corliss import version

REPO = version.REPO_URL


class UrlForTests(SimpleTestCase):
    """Every shape `git describe --tags --always --dirty` can produce."""

    def test_exact_tag_links_to_the_tag_page(self):
        self.assertEqual(
            version.url_for("v0.2.0"), f"{REPO}/releases/tag/v0.2.0"
        )

    def test_pre_release_tag_is_still_read_as_a_tag(self):
        # The `-rc1` suffix must not be mistaken for describe's own
        # `-<distance>-g<sha>` suffix.
        self.assertEqual(
            version.url_for("v0.3.0-rc1"), f"{REPO}/releases/tag/v0.3.0-rc1"
        )

    def test_commits_past_a_tag_link_to_the_commit(self):
        self.assertEqual(
            version.url_for("v0.2.0-3-gabc1234"), f"{REPO}/commit/abc1234"
        )

    def test_untagged_checkout_links_to_the_commit(self):
        self.assertEqual(version.url_for("abc1234"), f"{REPO}/commit/abc1234")

    def test_dirty_tree_links_nowhere(self):
        # The running code is not any commit GitHub could show, in either shape.
        self.assertIsNone(version.url_for("v0.2.0-3-gabc1234-dirty"))
        self.assertIsNone(version.url_for("v0.2.0-dirty"))

    def test_unresolved_version_links_nowhere(self):
        self.assertIsNone(version.url_for(""))


class ResolveTests(SimpleTestCase):
    def setUp(self):
        version.resolve.cache_clear()
        self.addCleanup(version.resolve.cache_clear)

    def test_falls_back_to_pyproject_without_a_git_dir(self):
        """The tarball/image case: no .git, so the declared version stands in."""
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "pyproject.toml").write_text(
                '[project]\nname = "corliss"\nversion = "1.2.3"\n'
            )
            self.assertEqual(version.resolve(base), "v1.2.3")

    def test_returns_empty_string_when_nothing_is_resolvable(self):
        """Fails soft — the footer omits the version rather than 500ing."""
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(version.resolve(Path(tmp)), "")

    def test_resolves_something_for_this_checkout(self):
        # Shape only, never a literal: this must not break on every release, or
        # on a developer's dirty tree.
        resolved = version.resolve(Path(__file__).resolve().parent.parent.parent)
        self.assertTrue(resolved)
        # Linkable unless the tree is dirty, which is the one unlinkable state.
        self.assertTrue(version.url_for(resolved) or resolved.endswith("-dirty"))
