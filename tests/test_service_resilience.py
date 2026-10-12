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
    task at all would be far worse than the gap this closes, so EVERY place that
    configures a repetition must degrade rather than throw.

    There are two such sites since v0.3.49 — fresh install and upgrade-refresh —
    so this checks each one is enclosed, rather than peeking at a fixed window
    around the first (which silently stopped covering the second)."""
    sites = [m.start() for m in re.finditer(r"RepetitionInterval", _PS1)]
    assert sites, "no repetition configured at all"
    for idx in sites:
        before, after = _PS1[:idx], _PS1[idx:]
        assert "try {" in before, (
            f"repetition at offset {idx} is not inside a try block"
        )
        assert "} catch {" in after, (
            f"repetition at offset {idx} has no catch after it — a failure here "
            f"would abort the install instead of degrading to restart-on-failure"
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


# --- v0.3.73 L1: N-135493 (2026-10-10) died to a closed console, 0xC000013A, ---
# --- and nothing restarted it for 14 h. --------------------------------------

def test_windows_task_runs_without_a_console_window():
    """The task runs pythonw.exe when the venv has it, on BOTH paths (fresh
    install and the upgrade refresh), so there is no console to close."""
    assert '"pythonw.exe"' in _PS1 and "$taskExe = $pythonwPath" in _PS1, "fresh install still runs python.exe"
    assert "'pythonw.exe'" in _PS1 and "$act.Execute = $pw" in _PS1, "upgrade does not switch to pythonw.exe"
    assert re.search(r"-match 'python\\\.exe\$'", _PS1), "upgrade must only rewrite python.exe (not loop on pythonw.exe)"


def test_windows_watchdog_is_its_own_trigger_not_a_grafted_repetition():
    """.Repetition is not assignable on every PowerShell build; when the graft
    failed the node had NO watchdog. The watchdog is now a standalone time
    trigger whose repetition is set at creation."""
    assert ".Repetition = $" not in _PS1, "a .Repetition assignment is back"
    assert "-Trigger $triggers" in _PS1, "the fresh task must register the watchdog next to the logon trigger"
    assert "$t.Triggers = @($t.Triggers) + $watchdog" in _PS1, "upgrade must ADD the watchdog, keeping existing triggers"
    assert "MSFT_TaskTimeTrigger" in _PS1, "upgrade must detect an existing standalone watchdog"
    assert len(re.findall(r"-RepetitionInterval \(New-TimeSpan -Minutes 2\)", _PS1)) == 2, "both paths, 2 min"


def test_self_update_installer_has_no_console_window_on_windows():
    """A console the user can close mid-update kills the update."""
    src = (_ROOT / "meshembed_node" / "worker.py").read_text()
    assert 'creationflags=(0x08000000 if os.name == "nt" else 0)' in src


def test_daemon_logging_survives_pythonw_without_stdout(monkeypatch, tmp_path):
    """pythonw.exe has sys.stdout None: logging must still set up (file only)."""
    import logging
    import sys
    from meshembed_node import __main__ as m
    monkeypatch.setattr(sys, "stdout", None)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    root = logging.getLogger()
    saved = root.handlers[:]
    root.handlers = []
    try:
        m._setup_logging()
        assert not any(isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler)
                       for h in root.handlers)
    finally:
        for h in root.handlers:
            h.close()
        root.handlers = saved
