"""An unattended node must come back on its own after ANY exit.

Prod evidence, 2026-08-05: MINIPC polled cleanly every 30s and then stopped
dead mid-poll on 17 July -- 4,760 successful polls, no errors, no retries, then
silence. The machine was never off; browser traffic from the same IP reached the
dashboard the day I looked. The daemon process was simply gone and nothing
brought it back. MAC and PAPA show the same shape on different dates.

Both service definitions only restarted on *failure*:

  * launchd had `KeepAlive = {SuccessfulExit: false, Crashed: true}` -- restart
    on a crash, stay dead on a clean exit.
  * Task Scheduler had `RestartCount 999`, which only fires on a NON-ZERO exit.

The daemon's drain handler exits 0 on SIGTERM, and the OTA path deliberately
exits so the supervisor relaunches it on the new code. So the single most likely
way for a node to stop was also the one case neither supervisor covered.

These tests pin the rule: the only exit that should stick is one the operator
asked for.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

_ROOT = Path(__file__).resolve().parents[1]
_MAC = (_ROOT / "install-mac.sh").read_text()
_PS1 = (_ROOT / "install.ps1").read_text()


def test_macos_restarts_on_any_exit_not_only_on_crash():
    """THE macOS regression: SuccessfulExit=false is 'leave it dead if it exited
    cleanly', which is exactly what the drain path does."""
    assert re.search(r"<key>KeepAlive</key>\s*<true/>", _MAC), (
        "KeepAlive must be plain true; the SuccessfulExit=false dict leaves a "
        "cleanly-exited daemon dead until the next login"
    )
    assert "<key>SuccessfulExit</key>" not in _MAC


def test_macos_still_throttles_restarts():
    """KeepAlive=true without a throttle turns a boot-loop into a hot loop."""
    assert re.search(r"<key>ThrottleInterval</key>\s*<integer>\d+</integer>", _MAC)


def test_macos_still_starts_at_load():
    assert re.search(r"<key>RunAtLoad</key>\s*<true/>", _MAC)


def test_windows_has_a_watchdog_for_clean_exits():
    """RestartCount only covers non-zero exits. A repeating trigger is what
    covers exit 0, since MultipleInstances=IgnoreNew makes it a no-op while the
    daemon is alive."""
    assert "RepetitionInterval" in _PS1, (
        "no repeating trigger: a clean exit stays dead until the next logon"
    )
    assert "-MultipleInstances IgnoreNew" in _PS1, (
        "without IgnoreNew the repetition would stack duplicate daemons"
    )


def test_windows_watchdog_cannot_break_installation():
    """.Repetition is not assignable on every PowerShell build. Registering no
    task at all would be far worse than the gap this closes, so the assignment
    must degrade rather than throw."""
    idx = _PS1.find("RepetitionInterval")
    assert idx != -1
    window = _PS1[max(0, idx - 600):idx + 600]
    assert "try {" in window and "} catch {" in window, (
        "the repetition setup must be wrapped so a failure degrades to "
        "restart-on-failure instead of aborting the install"
    )


def test_windows_keeps_restart_on_failure_too():
    """The watchdog is belt-and-braces, not a replacement: restart-on-failure
    still recovers a crash in ~1 minute rather than up to 5."""
    assert "-RestartCount 999" in _PS1
    assert "-RestartInterval" in _PS1


def test_both_platforms_still_start_unattended():
    """A node that only runs when someone is watching is not a node."""
    assert "-AtLogOn" in _PS1
    assert "-StartWhenAvailable" in _PS1
