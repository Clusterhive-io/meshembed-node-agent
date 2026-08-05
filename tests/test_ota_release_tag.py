"""OTA must tell the installer WHICH version it asked for.

The self-update broke silently across v0.3.41-v0.3.44 and nobody noticed until
operators reported that clicking "Update" did nothing:

  * install.sh carries `RELEASE_TAG="${MESHEMBED_RELEASE_TAG:-v0.3.40}"` — a
    fallback for bare `curl | bash` installs.
  * The daemon passed MESHEMBED_PACKAGE_URL (so pip installed the RIGHT
    version) but NOT MESHEMBED_RELEASE_TAG.
  * install.sh's post-install guard compares the freshly installed version
    against RELEASE_TAG. It got the stale literal, mismatched, and called
    `fail` — aborting AFTER a successful install and refusing to restart.

Net: the upgrade landed on disk every time, then the installer declared "the
upgrade did not land in the daemon's interpreter" and rolled nothing back, so
the daemon kept running the old code forever.

These tests pin the invariant that prevents a recurrence: whatever tag the
package URL is built from, the guard must be told the same tag.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

_ROOT = Path(__file__).resolve().parents[1]
_WORKER = (_ROOT / "meshembed_node" / "worker.py").read_text()


def test_daemon_passes_the_release_tag_to_the_installer():
    """THE regression. Without this the guard compares against a stale literal."""
    assert 'env["MESHEMBED_RELEASE_TAG"] = target_tag' in _WORKER


def test_release_tag_and_package_url_come_from_the_same_target():
    """They must never be able to disagree — that disagreement WAS the bug."""
    assert 'refs/tags/{target_tag}.tar.gz' in _WORKER
    assert 'env["MESHEMBED_RELEASE_TAG"] = target_tag' in _WORKER


@pytest.mark.parametrize("installer", ["install.sh", "install-mac.sh"])
def test_installer_fallback_tag_is_overridable(installer):
    """The literal must stay an env-overridable FALLBACK. If someone hardcodes
    it, OTA silently pins the fleet to whatever that literal says."""
    body = (_ROOT / installer).read_text()
    m = re.search(r'RELEASE_TAG="\$\{MESHEMBED_RELEASE_TAG:-(v[0-9.]+)\}"', body)
    assert m, f"{installer}: RELEASE_TAG must be an overridable fallback"


@pytest.mark.parametrize("installer", ["install.sh", "install-mac.sh"])
def test_installer_fallback_is_not_the_version_that_broke_ota(installer):
    """v0.3.40 is the exact stale value that silently wedged every update from
    v0.3.41 onward. Catching it here is cheap; catching it in the fleet was not."""
    body = (_ROOT / installer).read_text()
    m = re.search(r'RELEASE_TAG="\$\{MESHEMBED_RELEASE_TAG:-(v[0-9.]+)\}"', body)
    assert m.group(1) != "v0.3.40", (
        f"{installer} still falls back to v0.3.40 — the stale tag that broke OTA"
    )


def test_both_shell_installers_agree_on_the_fallback():
    """A split-brain fallback means Linux and macOS nodes pin to different
    versions on a bare install."""
    tags = []
    for installer in ("install.sh", "install-mac.sh"):
        body = (_ROOT / installer).read_text()
        tags.append(
            re.search(r'RELEASE_TAG="\$\{MESHEMBED_RELEASE_TAG:-(v[0-9.]+)\}"', body).group(1)
        )
    assert tags[0] == tags[1], f"installer fallbacks disagree: {tags}"
