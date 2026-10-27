"""RC-2 (auditor 2026-10-23 18:39Z): a node on the pre-release 0.3.78rc1 upgrades to v0.3.78 final through the normal
comparisons, and rc1 is never treated as newer than 0.3.78 (daemon, root updater, both installers' tag check)."""
import subprocess
from pathlib import Path

import pytest

from meshembed_node import updater as U
from meshembed_node import worker as W

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("lo,hi", [
    ("0.3.78rc1", "v0.3.78"), ("v0.3.78-rc1", "0.3.78"), ("0.3.78a1", "0.3.78"),
    ("0.3.77", "0.3.78rc1"), ("0.3.78", "0.3.79rc1"),
])
def test_daemon_order(lo, hi):
    assert W._version_tuple(lo) < W._version_tuple(hi)


def test_a_post_release_never_sorts_below_its_final():
    assert W._version_tuple("0.3.78.post1") >= W._version_tuple("0.3.78")      # we cut none; never a downgrade


def test_the_old_bug_is_gone():
    assert W._version_tuple("0.3.78rc1") == (0, 3, 78, 0)        # was (0, 3, 781)
    assert W._version_tuple("v0.3.41") == (0, 3, 41, 1) and W._version_tuple("garbage") == (0, 0, 0, 0)


def test_daemon_upgrades_from_rc_and_refuses_back(monkeypatch):
    import meshembed_node
    monkeypatch.setattr(meshembed_node, "__version__", "0.3.78rc1")
    monkeypatch.delenv("MESHEMBED_ALLOW_DOWNGRADE", raising=False)
    W._reject_downgrade("v0.3.78")                                  # rc1 -> final: allowed
    with pytest.raises(RuntimeError):
        W._reject_downgrade("v0.3.77")                              # never back below the rc's base


def test_root_updater_from_rc(tmp_path):
    d = tmp_path / "lib" / "python3.12" / "site-packages" / "meshembed_node-0.3.78rc1.dist-info"
    d.mkdir(parents=True)
    assert U.installed_version(tmp_path) == "0.3.78rc1"
    U.check("v0.3.78", "0.3.78rc1", None, 1e9)                     # final is newer than its rc: allowed
    with pytest.raises(U.Refused):
        U.check("v0.3.77", "0.3.78rc1", None, 1e9)                  # anti-rollback holds
    with pytest.raises(U.Refused):
        U.check("v0.3.78", "0.3.78", None, 1e9)                     # equal final still refused


def test_ota_tags_stay_final_only():
    assert not U.TAG_RE.fullmatch("v0.3.78-rc1") and not W._INSTALLER_TAG_RE.match("v0.3.78-rc1")


@pytest.mark.parametrize("name", ["install.sh", "install-mac.sh"])
def test_installer_tag_check_on_an_rc_tag_fails_closed(name):
    s = (ROOT / name).read_text()
    fn = s[s.index("_tag_at_least() {"):]
    fn = fn[:fn.index("\n}\n") + 3]
    # an rc tag is "at least" the SUMS threshold -> SUMS REQUIRED (fail closed), never skipped
    out = subprocess.run(["bash", "-c", fn + '_tag_at_least v0.3.78-rc1 v0.3.66 && echo yes || echo no'],
                         capture_output=True, text=True)
    assert out.stdout.strip() == "yes"


def test_the_post_install_guard_checks_an_rc_tag_too():
    """The rc tag is DASHLESS (v0.3.78rc1) so it equals the PEP 440 version the venv reports (0.3.78rc1); every
    installer's guard derives the same expected version from it, none skips it."""
    assert "v0.3.78rc1".lstrip("v") == "0.3.78rc1"
    mac = (ROOT / "install-mac.sh").read_text()
    line = [l for l in mac.splitlines() if l.startswith("_WANT=$(printf '%s' \"$PACKAGE_URL\"")][0]
    url = "https://github.com/Clusterhive-io/meshembed-node-agent/archive/refs/tags/v0.3.78rc1.tar.gz"
    out = subprocess.run(["bash", "-c", f'PACKAGE_URL="{url}"; ' + line.split("   # pre-releases")[0] + '; printf "%s" "$_WANT"'],
                         capture_output=True, text=True)
    assert out.stdout == "0.3.78rc1"
    assert "/tags/v([0-9][0-9A-Za-z.]*)\\.tar\\.gz$" in (ROOT / "install.ps1").read_text()
    import re
    m = re.search(r"/tags/v([0-9][0-9A-Za-z.]*)\.tar\.gz$", url)
    assert m and m.group(1) == "0.3.78rc1"


def test_an_unknown_running_version_compares_nothing(monkeypatch):
    import meshembed_node
    monkeypatch.setattr(meshembed_node, "__version__", "0.0.0+unknown")
    monkeypatch.delenv("MESHEMBED_ALLOW_DOWNGRADE", raising=False)
    W._reject_downgrade("v0.3.70")                                   # never refused for an unknown running version


def test_sign_release_reads_an_rc_tag():
    """RC-2: sign-release.py must read v0.3.78rc1 from all three installers (else signing an rc refuses)."""
    import importlib.util
    import re
    spec = importlib.util.spec_from_file_location("sr", ROOT.parent / "scripts" / "sign-release.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    bodies = {"install.sh": 'RELEASE_TAG="${MESHEMBED_RELEASE_TAG:-v0.3.78rc1}"',
              "install-mac.sh": 'RELEASE_TAG="${MESHEMBED_RELEASE_TAG:-v0.3.78rc1}"',
              "install.ps1": '$ReleaseTag = if ($env:MESHEMBED_RELEASE_TAG) { $env:MESHEMBED_RELEASE_TAG } else { "v0.3.78rc1" }'}
    for name, body in bodies.items():
        assert re.search(mod.FALLBACK_TAG_PATTERNS[name], body).group(1) == "v0.3.78rc1"
