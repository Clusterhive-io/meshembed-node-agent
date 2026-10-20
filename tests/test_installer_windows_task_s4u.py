"""install.ps1 registers the Windows task to run without a logged-on user when it can (v0.3.76).

Operator set 160 this way 2026-10-16; auditor 15:17Z: S4U is the more secure choice (no stored
credential), with conditions checked here: S4U with NO password, least privilege, it launches the
NODE, and elevation is required to convert (upgrades never need admin).
"""
import re
from pathlib import Path

PS1 = (Path(__file__).resolve().parents[1] / "install.ps1").read_text(encoding="utf-8")


def test_s4u_principal_without_a_password_and_least_privilege():
    assert re.search(r"New-ScheduledTaskPrincipal[^\n]*-LogonType S4U[^\n]*-RunLevel Limited", PS1)
    assert "-Password" not in PS1 and "Get-Credential" not in PS1, "S4U stores no credential"
    assert "-RunLevel Highest" not in PS1


def test_only_an_elevated_run_uses_s4u_and_upgrades_never_require_it():
    assert "$useS4U = Test-Elevated" in PS1
    assert "New-NodeTaskPrincipal $useS4U" in PS1                        # fresh install
    i = PS1.index("if ($t.Principal.LogonType -ne 'S4U')")             # upgrade: convert only if elevated
    block = PS1[i:i + 1600]
    assert "if ($useS4U)" in block and "elevated PowerShell" in block


def test_boot_trigger_and_hidden_come_with_s4u():
    assert PS1.count("New-ScheduledTaskTrigger -AtStartup") == 2       # fresh + upgrade conversion
    assert "-Hidden" in PS1 and "$t.Settings.Hidden = $true" in PS1


def test_the_task_still_launches_the_node():
    assert '-Argument "-m meshembed_node run"' in PS1
    assert "pythonw.exe" in PS1
