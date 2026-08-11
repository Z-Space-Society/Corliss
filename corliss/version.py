"""Which build of Corliss is this? — resolved once, for the footer.

Two sources, in order of truthfulness:

1. **`git describe --tags --always --dirty`** off the app's own checkout. This is
   what the code on disk *actually is*, and it can say things a declared version
   cannot: three commits past the tag, or a modified working tree. The cluster
   deploy is a full clone at a **tag** (the `corliss` Ansible role in zai-ops),
   so on the CT this resolves to exactly the released version.
2. **`pyproject.toml`'s `version`**, prefixed with `v`. The fallback for a tree
   with no `.git` at all (a tarball, an image build). `bin/release` keeps that
   value and the tag in lockstep, so the two sources agree by construction.

Resolution **fails soft**, unlike `corliss.signing`'s fail-closed key loading:
not knowing the version is a cosmetic problem, so every failure path ends in `""`
and the footer simply omits the version rather than 500ing the whole site.

Deliberately stdlib-only and Django-free — `corliss.settings` imports this at
module scope, so it must not import `django.conf`.
"""

import re
import subprocess
import tomllib
from functools import cache
from pathlib import Path

# The canonical home of this code. Not a setting and not env-driven: it is a fact
# about the codebase, identical in every deployment.
REPO_URL = "https://github.com/Z-Space-Society/Corliss"

# `git describe` output for a checkout *past* its nearest tag:
# `v0.2.0-3-gabc1234` — tag, commit distance, then `g` + the abbreviated sha.
# Anchored on that trailing `-<n>-g<sha>` shape rather than on any assumption
# about how tags are named, so a `v0.2.0-rc1` tag is still read as a tag.
_DESCRIBED = re.compile(r"^(?P<tag>.+)-\d+-g(?P<sha>[0-9a-f]{7,40})$")

# `--always` falls back to a bare abbreviated sha when no tag is reachable.
_BARE_SHA = re.compile(r"^[0-9a-f]{7,40}$")

# `--dirty` appends this when the working tree has uncommitted changes.
_DIRTY = "-dirty"


def _describe(base_dir: Path) -> str:
    """`git describe` in `base_dir`, or `""` if that can't be answered.

    Swallows every failure mode on purpose: no `.git`, no git binary, no
    reachable commit, a hung filesystem. The timeout matters because this runs
    during settings import — a wedged git must not hang worker startup.
    """
    if not (base_dir / ".git").exists():
        return ""
    try:
        completed = subprocess.run(
            ["git", "describe", "--tags", "--always", "--dirty"],
            cwd=base_dir,
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if completed.returncode != 0:
        return ""
    return completed.stdout.strip()


def _declared(base_dir: Path) -> str:
    """`pyproject.toml`'s `version` as a `v`-prefixed tag name, or `""`."""
    try:
        with (base_dir / "pyproject.toml").open("rb") as fh:
            declared = tomllib.load(fh)["project"]["version"]
    except (OSError, KeyError, tomllib.TOMLDecodeError):
        return ""
    return f"v{declared}" if declared else ""


@cache
def resolve(base_dir: Path) -> str:
    """The running version, e.g. `v0.2.0` or `v0.2.0-3-gabc1234-dirty`.

    Cached per directory: one `git` subprocess per process at startup, not one
    per request. Call `resolve.cache_clear()` in tests that fabricate a tree.
    """
    return _describe(Path(base_dir)) or _declared(Path(base_dir))


def url_for(version: str) -> str | None:
    """Where `version` can be read on GitHub, or `None` if nowhere can.

    An exact tag links to its tag page; a checkout past a tag (or an untagged
    one) links to the commit. A `-dirty` tree links **nowhere**: the code being
    served isn't any commit GitHub could show, so an honest footer offers no
    link at all rather than a plausible-looking lie.
    """
    if not version or version.endswith(_DIRTY):
        return None
    described = _DESCRIBED.match(version)
    if described:
        return f"{REPO_URL}/commit/{described['sha']}"
    if _BARE_SHA.match(version):
        return f"{REPO_URL}/commit/{version}"
    return f"{REPO_URL}/releases/tag/{version}"
