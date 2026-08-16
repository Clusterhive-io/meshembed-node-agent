"""OTA must work identically on all three platforms it claims to support.

The Linux self-update bug (see test_ota_release_tag.py) was fixed in v0.3.45 and
the Linux fleet moved to v0.3.46. macOS and Windows did not — and the reason is
a second, independent defect that the Linux fix never touched:

  * `worker._perform_self_update` sets **MESHEMBED_PACKAGE_URL** (and, since
    v0.3.45, MESHEMBED_RELEASE_TAG).
  * install.ps1 read **MESHEMBED_PACKAGE_SOURCE** — a name nothing has ever set.

So on Windows the OTA target was silently discarded and pip re-installed
whatever literal was hardcoded in the script. That literal sat at v0.3.40 from
v0.3.41 through v0.3.44, so a Windows node "updated" to the version it was
already running, reported success, and stayed put. Forever, and without an error
anywhere.

Two things made it invisible for four releases:

  1. Neither install.ps1 nor install-mac.sh had the post-install version guard
     that catches an upgrade which did not land. Only install.sh did.
  2. sign-release.py's stale-tag guard only knew the shell pattern, so it
     verified install.sh and install-mac.sh and skipped install.ps1 entirely.

These tests pin the contract across all three: same env var names, same
overridable fallback, same post-install verification, same release-time guard.
"""
from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

_ROOT = Path(__file__).resolve().parents[1]
_INSTALLERS = ("install.sh", "install-mac.sh", "install.ps1")


def _body(name: str) -> str:
    return (_ROOT / name).read_text()


def _sign_release():
    """sign-release.py has a hyphen, so it needs a path-based import."""
    path = _ROOT.parent / "scripts" / "sign-release.py"
    spec = importlib.util.spec_from_file_location("sign_release", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── the env-var contract between daemon and installer ────────────────────────

def test_daemon_sets_package_url_not_package_source():
    """Pin the name the daemon actually exports, so the installers below are
    being checked against reality rather than against each other."""
    worker = (_ROOT / "meshembed_node" / "worker.py").read_text()
    assert 'env["MESHEMBED_PACKAGE_URL"]' in worker
    assert 'env["MESHEMBED_PACKAGE_SOURCE"]' not in worker


@pytest.mark.parametrize("installer", _INSTALLERS)
def test_every_installer_reads_the_variable_the_daemon_sets(installer):
    """THE Windows regression: install.ps1 read a name nobody sets, so the OTA
    target was discarded and the hardcoded literal won."""
    assert "MESHEMBED_PACKAGE_URL" in _body(installer), (
        f"{installer} ignores the OTA target — self-update will silently no-op"
    )


def test_windows_still_accepts_the_legacy_variable_name():
    """Nodes running a pre-v0.3.47 daemon are unaffected either way, but a node
    pinned by hand to MESHEMBED_PACKAGE_SOURCE must not break on upgrade."""
    body = _body("install.ps1")
    assert "MESHEMBED_PACKAGE_SOURCE" in body
    assert body.index("MESHEMBED_PACKAGE_URL") < body.index("MESHEMBED_PACKAGE_SOURCE"), (
        "the daemon's variable must take precedence over the legacy alias"
    )


# ── the fallback tag, on every platform ──────────────────────────────────────

@pytest.mark.parametrize("installer", _INSTALLERS)
def test_fallback_tag_is_env_overridable(installer):
    """A hardcoded tag pins the fleet to that version no matter what OTA asks
    for. install.ps1 had exactly that, which is why Windows never moved."""
    pattern = _sign_release().FALLBACK_TAG_PATTERNS[installer]
    assert re.search(pattern, _body(installer)), (
        f"{installer}: release tag must be an env-overridable fallback"
    )


def test_windows_has_no_tarball_url_with_a_baked_in_version():
    """The specific shape of the bug: a literal tag inside the download URL,
    which no env var could reach."""
    assert not re.search(r"archive/refs/tags/v[0-9]", _body("install.ps1")), (
        "install.ps1 hardcodes a tag in the package URL — build it from "
        "$ReleaseTag so MESHEMBED_RELEASE_TAG can override it"
    )


def test_all_three_installers_agree_on_the_fallback():
    """Split-brain fallbacks mean a bare install pins each OS to a different
    version, and the divergence surfaces only as odd fleet-wide behaviour."""
    mod = _sign_release()
    tags = {
        i: re.search(mod.FALLBACK_TAG_PATTERNS[i], _body(i)).group(1)
        for i in _INSTALLERS
    }
    assert len(set(tags.values())) == 1, f"installer fallbacks disagree: {tags}"


@pytest.mark.parametrize("installer", _INSTALLERS)
def test_fallback_is_not_the_tag_that_broke_ota(installer):
    mod = _sign_release()
    tag = re.search(mod.FALLBACK_TAG_PATTERNS[installer], _body(installer)).group(1)
    assert tag != "v0.3.40", f"{installer} still falls back to the stale v0.3.40"


# ── the post-install guard, on every platform ────────────────────────────────

@pytest.mark.parametrize("installer", _INSTALLERS)
def test_installer_verifies_the_upgrade_actually_landed(installer):
    """pip exiting 0 includes the no-op case, and the interpreter pip writes to
    is not necessarily the one the service runs. Without this check the daemon
    restarts on the OLD code and reports the OLD version — indistinguishable
    from 'the operator never clicked update'."""
    body = _body(installer)
    assert "post-install check" in body, (
        f"{installer} has no post-install version verification"
    )
    assert "importlib.metadata" in body, (
        f"{installer} must ask the target interpreter what it actually has"
    )


@pytest.mark.parametrize("installer", ("install-mac.sh", "install.ps1"))
def test_expected_version_is_derived_from_the_url_actually_used(installer):
    """Deriving it from the fallback literal instead is what made the Linux
    guard fire wrongly: a caller that sets only MESHEMBED_PACKAGE_URL would be
    compared against a stale constant. Reading the tag back out of the URL
    cannot disagree with the package that was installed, and it lets a custom
    source (local wheel, branch tarball) skip the check instead of failing it."""
    assert re.search(r"/tags/v.*tar", _body(installer)), (
        f"{installer}: expected version must come from the resolved package URL"
    )


# ── the release-time guard ───────────────────────────────────────────────────

def test_sign_release_guard_covers_every_installer():
    """install.ps1 was absent from this map, so its stale tag was never checked
    at release time while the other two were."""
    assert set(_sign_release().FALLBACK_TAG_PATTERNS) == set(_INSTALLERS)


def test_sign_release_refuses_when_it_cannot_read_the_tag():
    """Silently skipping an unreadable installer is how the gap persisted. If
    the guard cannot verify a file, it must not sign it."""
    src = (_ROOT.parent / "scripts" / "sign-release.py").read_text()
    assert "cannot locate the fallback release tag" in src


# ── re-establish / fresh must exist on all three platforms ─────────────────

def test_all_installers_expose_the_fresh_escape():
    """A node-facing change lands on linux, mac AND windows or it is not done.

    The Windows OTA bug (MESHEMBED_PACKAGE_SOURCE vs MESHEMBED_PACKAGE_URL)
    happened precisely because the platforms drifted: a fix went to one and the
    others silently kept the old behaviour. Nodes are operator-owned machines
    that are hard to reach, so a per-platform gap is expensive to correct later.

    Re-establish is the DEFAULT everywhere; this pins the opt-out that discards
    reputation, since that is the flag whose absence would silently change
    behaviour between platforms.
    """
    sh = (_ROOT / "install.sh").read_text(encoding="utf-8")
    mac = (_ROOT / "install-mac.sh").read_text(encoding="utf-8")
    ps1 = (_ROOT / "install.ps1").read_text(encoding="utf-8")

    assert "FRESH_NODE" in sh, "install.sh has no FRESH_NODE escape"
    assert "FRESH_NODE" in mac, "install-mac.sh has no FRESH_NODE escape"
    assert "$Fresh" in ps1, "install.ps1 has no -Fresh switch"

    for name, body in (("install.sh", sh), ("install-mac.sh", mac)):
        assert "--fresh" in body, f"{name} never passes --fresh to register"
    assert '"--fresh"' in ps1, "install.ps1 never passes --fresh to register"


def test_the_register_cli_accepts_fresh():
    """The installers are only as good as the flag they forward."""
    cli = (_ROOT / "meshembed_node" / "__main__.py").read_text(encoding="utf-8")
    assert '"--fresh"' in cli, "register has no --fresh argument"
    assert '"fresh":' in cli, "the register payload does not carry `fresh`"


def test_register_honours_the_backend_node_id():
    """On a RE-ESTABLISH the backend returns the EXISTING node's id, which differs
    from the uuid the CLI generated. Echoing our own would write the wrong id into
    .env and the daemon would poll as a node that does not exist."""
    cli = (_ROOT / "meshembed_node" / "__main__.py").read_text(encoding="utf-8")
    assert 'node_id = data.get("node_id") or node_id' in cli, (
        "the backend's node_id must win, or re-establish writes a stale identity"
    )
