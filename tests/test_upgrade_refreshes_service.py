"""An upgrade must refresh the service definition, not just the code.

v0.3.48 fixed the supervisors so a node restarts after a CLEAN exit — the
failure mode that had silently killed three production nodes on three different
dates. Then it reached none of them, because both installers skip the service
definition on the upgrade path:

    install-mac.sh   "Skipping LaunchAgent setup (existing plist already in place)."
    install.ps1      "Reusing existing task '$taskName' (no admin needed)..."

So the release updated the Python package and left `KeepAlive` /
`RestartCount` exactly as they were. Every node that needs the fix is BY
DEFINITION an existing install, which made the whole release nearly inert: the
operator's Mac had to be patched by hand with PlistBuddy, and MINIPC ran new
code on its old task.

Separately, `launchctl kickstart` was observed hanging on a real operator
machine in BOTH forms — with `-k` (documented: it SIGTERMs and blocks) and
without. bootout/bootstrap does not wait on the old instance, and re-reads the
plist as a side effect, which is exactly what a definition refresh needs.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

_ROOT = Path(__file__).resolve().parents[1]
_MAC = (_ROOT / "install-mac.sh").read_text()
_PS1 = (_ROOT / "install.ps1").read_text()


def _upgrade_block(src: str, start: str, end: str) -> str:
    """Slice the upgrade branch. The end marker must be searched for AFTER the
    start — `} else {` occurs earlier in install.ps1 too."""
    i = src.find(start)
    assert i != -1, f"upgrade branch start not found ({start!r}) — installer restructured?"
    j = src.find(end, i)
    assert j > i, f"upgrade branch end not found ({end!r}) — installer restructured?"
    return src[i:j + len(end)]


_MAC_UPGRADE = _upgrade_block(_MAC, 'if [ "$UPGRADE_ONLY" -eq 1 ]; then\n    LABEL=', "Upgrade complete")
# End on the branch's real last statement. `} else {` would match the inner
# if/else of the refresh logic and truncate the block mid-way.
_PS1_UPGRADE = _upgrade_block(
    _PS1, "if ($UpgradeOnly -and $existingTask7)", "$script:state.task_created = $true"
)


# ── macOS ────────────────────────────────────────────────────────────────────

def test_macos_upgrade_repairs_keepalive():
    """THE regression: the upgrade path left KeepAlive as the SuccessfulExit
    dict, so a clean exit stayed dead."""
    assert "KeepAlive" in _MAC_UPGRADE, "upgrade path never inspects KeepAlive"
    assert "Add :KeepAlive bool true" in _MAC_UPGRADE


def test_macos_patches_in_place_rather_than_rewriting_the_plist():
    """A rewrite would have to reproduce MESHEMBED_NODE_API_KEY / NODE_ID /
    NODE_PRIVKEY from whatever the script happens to have loaded. Getting that
    wrong silently destroys the node's identity; PlistBuddy cannot lose keys it
    never touches."""
    assert "PlistBuddy" in _MAC_UPGRADE
    assert "cat > \"$PLIST\"" not in _MAC_UPGRADE and "tee \"$PLIST\"" not in _MAC_UPGRADE


def test_macos_keeps_a_throttle_alongside_keepalive():
    """KeepAlive=true with no throttle turns a boot loop into a hot loop."""
    assert "ThrottleInterval" in _MAC_UPGRADE


def test_macos_does_not_touch_the_agent_during_ota():
    """On OTA the daemon is our PARENT and re-execs itself. Unloading the job
    would kill it before it can. Patching the plist file is still fine — it
    edits a file, it does not signal the job."""
    assert "MESHEMBED_PACKAGE_URL" in _MAC_UPGRADE
    ota = _MAC_UPGRADE[_MAC_UPGRADE.find("MESHEMBED_PACKAGE_URL"):]
    ota = ota[:ota.find("elif")]
    assert "bootout" not in ota and "pkill" not in ota, (
        "the OTA branch must not stop the daemon that launched it"
    )


def test_macos_manual_restart_does_not_use_kickstart():
    """Observed hanging on a real operator machine in both forms."""
    assert not re.search(r"^\s*launchctl kickstart", _MAC, flags=re.M), (
        "kickstart hangs; use bootout/bootstrap"
    )


def test_macos_manual_restart_uses_bootout_then_bootstrap():
    assert "launchctl bootout" in _MAC_UPGRADE
    assert "launchctl bootstrap" in _MAC_UPGRADE
    assert _MAC_UPGRADE.index("bootout") < _MAC_UPGRADE.index("bootstrap")


def test_macos_has_a_fallback_for_older_launchctl():
    """bootstrap does not exist on older macOS; load -w is the legacy path."""
    assert "launchctl load -w" in _MAC_UPGRADE


# ── Windows ──────────────────────────────────────────────────────────────────

def test_windows_upgrade_refreshes_the_task():
    assert "Set-ScheduledTask" in _PS1_UPGRADE, (
        "upgrade path never updates the task definition"
    )


def test_windows_upgrade_adds_the_clean_exit_watchdog():
    """RestartCount only covers non-zero exits; the repetition covers exit 0."""
    assert "RepetitionInterval" in _PS1_UPGRADE
    assert "IgnoreNew" in _PS1_UPGRADE, "without it the repetition stacks daemons"


def test_windows_upgrade_avoids_register_which_needs_admin():
    """Register-ScheduledTask -Force throws Access Denied 0x80070005 on an
    existing task; Set-ScheduledTask on your own task does not.

    Comments are stripped first — the code comment explains WHY Register is
    avoided, and a naive substring check matches its own rationale."""
    code = "\n".join(
        l for l in _PS1_UPGRADE.splitlines() if not l.lstrip().startswith("#")
    )
    assert "Register-ScheduledTask" not in code


def test_windows_refresh_cannot_abort_the_install():
    """A task still running with old settings beats an install that dies at the
    last step."""
    assert "try {" in _PS1_UPGRADE and "} catch {" in _PS1_UPGRADE


def test_windows_refresh_is_conditional_not_unconditional():
    """Rewriting the task on every upgrade would churn it needlessly and risk
    clobbering a deliberate local change."""
    assert "$needsUpdate" in _PS1_UPGRADE
