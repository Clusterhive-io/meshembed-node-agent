"""FX-4-W (0.3.86): the daemon reads its OWN token at start (admin_token.py) and the installer warns about an Administrators account.
Auditor C1-C4 (2026-11-17 17:31:48Z): detect Administrators ENABLED / integrity >= High (NOT TokenElevationType Full), WARN not refuse,
a read that fails is "could_not_check" never silence, no Get-LocalGroupMember. The real ctypes read is Windows-only and is NOT run here:
every test drives the pure parts through the `read` seam (the TT-3 pattern); the Windows read is proven on 160 by the PB-W card."""
import logging
import re
from pathlib import Path

import pytest

from meshembed_node import admin_token as AT

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
PS1 = (ROOT / "install.ps1").read_text(encoding="utf-8")
MEDIUM, HIGH, SYSTEM = 0x2000, 0x3000, 0x4000


# ---- classify: the three cases the auditor named (C1) ----
def test_the_160_case_admins_enabled_at_medium_integrity_is_detected():
    """Default elevation type (an unfiltered S4U token) with Administrators ENABLED: what TokenElevationType Full would have MISSED."""
    assert AT.classify(True, MEDIUM) == AT.ADMINS_ENABLED


def test_a_full_elevated_token_is_detected():
    assert AT.classify(True, HIGH) == AT.ADMINS_ENABLED


def test_a_high_integrity_token_without_administrators_enabled_is_the_second_signal():
    assert AT.classify(False, HIGH) == AT.INTEGRITY_HIGH
    assert AT.classify(False, SYSTEM) == AT.INTEGRITY_HIGH


def test_a_limited_standard_token_is_ok():
    assert AT.classify(False, MEDIUM) == AT.OK
    assert AT.classify(False, 0x1000) == AT.OK                      # low integrity


# ---- check / warn_at_start ----
def test_check_is_none_off_windows_and_never_runs_the_read():
    def boom():
        raise AssertionError("must not run off Windows")
    assert AT.check("linux", boom) is None and AT.check("darwin", boom) is None
    assert AT.warn_at_start("linux", boom) is None


def test_a_failed_read_is_could_not_check_logged_never_a_pass(caplog):
    def broken():
        raise OSError("CheckTokenMembership")
    with caplog.at_level(logging.WARNING, logger="meshembed.admin_token"):
        assert AT.check("win32", broken) == AT.COULD_NOT_CHECK
    assert "could_not_check" in caplog.text and "OSError" in caplog.text


def test_warn_at_start_warns_with_the_closed_line_and_refuses_nothing(caplog, monkeypatch):
    monkeypatch.setattr(AT, "_state", {})
    with caplog.at_level(logging.INFO, logger="meshembed.admin_token"):
        code = AT.warn_at_start("win32", lambda: (True, MEDIUM))
    assert code == AT.ADMINS_ENABLED and AT.last() == AT.ADMINS_ENABLED          # returns normally: WARN only
    assert "admin_token: admins_enabled (FX-4-W" in caplog.text
    assert code in AT.CODES


def test_warn_at_start_ok_logs_info_only(caplog, monkeypatch):
    monkeypatch.setattr(AT, "_state", {})
    with caplog.at_level(logging.INFO, logger="meshembed.admin_token"):
        assert AT.warn_at_start("win32", lambda: (False, MEDIUM)) == AT.OK
    assert "admin_token: ok" in caplog.text and not [r for r in caplog.records if r.levelno >= logging.WARNING]


def test_mutation_a_check_that_always_says_ok_fails_the_160_case(monkeypatch):
    monkeypatch.setattr(AT, "classify", lambda a, r: AT.OK)                      # the check removed
    with pytest.raises(AssertionError):
        assert AT.check("win32", lambda: (True, MEDIUM)) == AT.ADMINS_ENABLED


def test_the_vocabulary_is_closed_and_the_sid_is_builtin_administrators():
    assert AT.CODES == ("ok", "admins_enabled", "integrity_high", "could_not_check")
    assert AT.ADMINISTRATORS_SID == "S-1-5-32-544" and AT.HIGH_INTEGRITY_RID == 0x3000


# ---- wiring: start, hardware_info, status ----
def test_w2_the_check_runs_once_per_start_right_after_the_crash_dumps_line_and_cannot_block_the_start():
    """0.3.87 W2 (PB-W 160): 0.3.86 called the check in _cmd_run AND _start_daemon (two lines per start) and before 'crash dumps:' (the read
    script's since-last-start window begins at that line, so it missed both). One call site, in worker.run(), after that line."""
    src = (ROOT / "meshembed_node" / "__main__.py").read_text(encoding="utf-8")
    assert "_admin_token" not in src and "warn_at_start" not in src            # no call site left in the entry point
    w = (ROOT / "meshembed_node" / "worker.py").read_text(encoding="utf-8")
    run = w[w.index("def run(cfg: Config)"):]
    assert run.count("warn_at_start()") == 1 and w.count("warn_at_start()") == 1
    assert run.index('log.info("crash dumps: %s"') < run.index("_safe.record_start()") < run.index("warn_at_start()")   # auditor 13:00:24Z
    block = run[run.index("try:\n        from . import admin_token"):run.index("warn_at_start()") + 80]
    assert "except Exception" in block                                           # the check never blocks or raises


def test_hardware_info_and_status_carry_the_closed_code():
    w = (ROOT / "meshembed_node" / "worker.py").read_text(encoding="utf-8")
    assert 'hw["admin_token"] = _atc' in w and "_at.last()" in w
    m = (ROOT / "meshembed_node" / "maintenance.py").read_text(encoding="utf-8")
    assert '"admin_token": _admin_token_now()' in m and "admins_enabled" in m


# ---- the installer warning (C3) ----
def test_the_installer_warns_and_does_not_use_get_localgroupmember():
    assert "Get-LocalGroupMember" not in PS1.replace("NOT Get-LocalGroupMember", "")          # only the comment names it
    fn = PS1[PS1.index("function Get-NodeAccountAdminState"):PS1.index("function Test-NodeTaskAccountIsThisRun")]
    assert "S-1-5-32-544" in fn and "WindowsIdentity]::GetCurrent()" in fn and "$id.Groups" in fn
    assert "catch { return 'could_not_check' }" in fn                              # a failed read says so
    warn = PS1[PS1.index("function Write-NodeAccountAdminWarning"):PS1.index("# FX-2 (P2-F3")]
    assert "'admin'" in warn and "'could_not_check'" in warn and "FX-4-W" in warn
    assert "FailWithDiagnostic" not in warn and "exit" not in warn                 # a warning only: nothing is refused


def test_r1_the_deny_only_administrators_sid_of_a_filtered_token_counts():
    """#204 R1 (auditor 21:12:39Z / 21:49:57Z): WindowsIdentity.Groups lists only ENABLED groups; an UN-elevated admin account's filtered
    token carries Administrators DENY-ONLY. The deny-only claim, then `whoami /groups /fo csv` (matched as the QUOTED csv field) count."""
    fn = PS1[PS1.index("function Get-NodeAccountAdminState"):PS1.index("function Test-NodeTaskAccountIsThisRun")]
    assert "http://schemas.microsoft.com/ws/2008/06/identity/claims/denyonlysid" in fn and "$id.Claims" in fn
    assert "whoami /groups /fo csv" in fn and "$LASTEXITCODE -eq 0 -and $who" in fn
    assert "[regex]::Escape('\"' + $admins.Value + '\"')" in fn                    # the quoted csv field, not a bare substring
    # 0.3.87 W1: whoami is the PRIMARY read; the .NET reads are only the fallback, and the fallback never answers not_admin
    assert fn.index("& whoami /groups") < fn.index("$id.Groups") < fn.index("$denySid =")
    assert fn.count("return 'not_admin'") == 1 and fn.count("return 'admin'") == 3
    assert fn.rindex("return 'could_not_check'") > fn.index("$denySid =")           # nothing found in the fallback = could not check


def test_r1_the_whoami_match_is_the_quoted_field_and_a_bare_substring_does_not_match():
    sid = "S-1-5-32-544"
    pat = re.escape('"' + sid + '"')                                                # [regex]::Escape of the quoted field
    csv = '"Group Name","Type","SID","Attributes"\n"BUILTIN\\Administrators","Alias","S-1-5-32-544","Group used for deny only"'
    assert re.search(pat, csv)                                                       # a deny-only line from a filtered token
    assert not re.search(pat, '"x","Alias","S-1-5-32-5440","Group used for deny only"')   # a longer SID is not Administrators
    assert not re.search(pat, "note: S-1-5-32-544 appears in prose")                 # not a csv field


def test_r2_the_task_account_is_compared_by_sid_not_by_name():
    fn = PS1[PS1.index("function Test-NodeTaskAccountIsThisRun"):PS1.index("function Write-NodeAccountAdminWarning")]
    assert "NTAccount" in fn and "Translate([Security.Principal.SecurityIdentifier])" in fn and "WindowsIdentity]::GetCurrent().User" in fn
    assert "-match '^S-1-'" in fn and "catch { return $false }" in fn               # a SID UserId is used as is; a failed translation = not this run
    warn = PS1[PS1.index("function Write-NodeAccountAdminWarning"):PS1.index("# FX-2 (P2-F3")]
    assert "Test-NodeTaskAccountIsThisRun $TaskUserId" in warn and "could not check this task's own account" in warn
    assert "-ne [Security.Principal.WindowsIdentity]::GetCurrent().Name" not in PS1  # never a name compare


def test_the_warning_runs_after_the_principal_check_on_install_and_on_upgrade():
    assert PS1.index("Assert-RegisteredNodeTaskPrincipal $taskName\nWrite-NodeAccountAdminWarning ") > 0   # fresh install: no argument
    assert PS1.count("Write-NodeAccountAdminWarning") == 3                         # the definition, the install call, the upgrade call
    up = PS1[PS1.index("# FX-4 on upgrade"):]
    assert up.index("Write-NodeAccountAdminWarning $t.Principal.UserId") < up.index("MultipleInstances -ne 'IgnoreNew'")


def test_w1_whoami_csv_is_matched_by_the_sid_column_in_any_language():
    """0.3.87 W1: 160's whoami prints Spanish ("Grupo usado solo para denegar"); the match is the quoted SID field, never the words."""
    pat = re.escape('"S-1-5-32-544"')
    es = ('"Nombre de grupo","Tipo","SID","Atributos"\n"Todos","Grupo conocido","S-1-1-0","Grupo obligatorio, Habilitado por defecto, Grupo habilitado"\n'
          '"BUILTIN\\Administradores","Alias","S-1-5-32-544","Grupo usado solo para denegar"')
    assert re.search(pat, es)
    no_admin = '"Group Name","Type","SID","Attributes"\n"Everyone","Well-known group","S-1-1-0","Mandatory group"\n"BUILTIN\\Users","Alias","S-1-5-32-545","Mandatory group"'
    assert not re.search(pat, no_admin)
