"""v0.3.78 final: the fixes from pause proof 2 on 160 (P2-F1..P2-F4) with the auditor's FX-1, FX-2 and FX-4.

The PowerShell behaviour (NodeProcs tri-state, bystanders, the Arguments rewrite, the principal check) is exercised on
Windows by tests/Test-PauseIdentity.ps1 against mocks; these are the CI pins on the same text, plus the daemon's half
(P2-F4: a paused start imports nothing heavy and opens no socket), which runs here for real.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PS1 = (ROOT / "install.ps1").read_text(encoding="utf-8")
SH = (ROOT / "install.sh").read_text(encoding="utf-8")
TOOL = PS1[PS1.index("$PauseToolSource = @'"):PS1.index("\n'@\n")]


def _fn(src, name):
    i = src.index(f"function {name}")
    return src[i:src.index("\n}\n", i) + 2]


# --- P2-F1 -----------------------------------------------------------------------------------------------------------
def test_f1_no_online_and_polling_line_on_a_paused_node():
    tail = PS1[PS1.index("# --- Final banner"):]
    i = tail.index("Node is online and polling for work.")
    branch = tail[tail.index("if (Test-NodePaused) {"):i]
    assert "Node is PAUSED ($PauseMarker): installed, NOT started." in branch and "} else {" in branch
    assert PS1.count("Node is online and polling for work.") == 1
    summary = SH[SH.index("# ── Summary"):]
    assert 'if node_paused; then echo "  Paused:  yes' in summary


# --- P2-F2 / P2-F3 / FX-1 --------------------------------------------------------------------------------------------
def test_identity_is_read_from_the_tasks_own_action_never_hard_coded():
    ta, np = _fn(TOOL, "TaskAction"), _fn(TOOL, "NodeProcs")
    assert "$t.Actions[0].Execute" in ta and "$t.Actions[0].Arguments" in ta
    assert "[regex]::Escape($_)" in np and "')$'" in np                   # every tail is anchored at the end
    assert not re.search(r"meshembed_node", ta), "TaskAction reads the task, nothing hard-coded (P2-F3)"
    # R-1: the task's OWN Arguments come first; the two known module forms are only ADDED (counting more is safe)
    forms = [l for l in np.splitlines() if "meshembed_node" in l and not l.lstrip().startswith("#")]
    assert forms == ["    $forms = @($a.Args, '-m meshembed_node', '-m meshembed_node run') | Select-Object -Unique"], forms
    assert "StartsWith(" not in np, "same path, not a prefix (P2-F2)"
    assert "[string]::Equals($p, $a.Exe, 'OrdinalIgnoreCase')" in np


def test_cannot_tell_is_never_stopped():
    ta, np, ns = _fn(TOOL, "TaskAction"), _fn(TOOL, "NodeProcs"), _fn(TOOL, "NodeStopped")
    assert "IsPathRooted($exe)) { return $null }" in ta
    assert "if (-not $args0) { return $null }" in ta
    assert "return ,@(" in np, "an empty array must reach the caller as an array, not as $null"
    assert "(-not $_.CommandLine) -or" in np                              # unreadable command line = possible daemon
    assert "-not $p -and [string]::Equals($_.Name, $a.Leaf" in np          # unreadable path = image name
    assert "($null -ne $p) -and ($p.Count -eq 0)" in ns and "$a.State -ne 'Running'" in ns


def test_pause_succeeds_only_when_stopped_and_status_says_unknown():
    pause = TOOL[TOOL.index("'Pause' {"):TOOL.index("'Resume' {")]
    assert "-not (NodeStopped)" in pause
    assert pause.index("if (-not (NodeStopped)) {") < pause.index("Write-Output 'paused'")
    assert "(NodeProcs).Count" not in TOOL, "a $null NodeProcs has Count 0: never test it that way"
    status = TOOL[TOOL.index("'Status' {"):]
    assert "Write-Output 'unknown'" in status
    assert "$a.State -eq 'Running') { Write-Output 'running' }" in status


# --- FX-2 ------------------------------------------------------------------------------------------------------------
def test_fx2_rewrites_only_the_exact_legacy_arguments():
    fx2 = _fn(PS1, "Resolve-NodeTaskArguments")
    assert "$cur -ceq '-m meshembed_node') { return 'rewrite' }" in fx2
    assert "$cur -ceq '-m meshembed_node run') { return 'keep' }" in fx2 and "return 'warn'" in fx2
    up = PS1[PS1.index("if ($UpgradeOnly -and $existingTask7) {"):PS1.index("Step \"Create Task Scheduler entry\"")]
    use = up[up.index("$fx2 = Resolve-NodeTaskArguments $act.Arguments"):]
    use = use[:use.index("\n        }\n")]
    assert "if ($fx2 -eq 'rewrite') {" in use and "$act.Arguments = '-m meshembed_node run'" in use
    assert "} elseif ($fx2 -eq 'warn') {" in use and "left untouched" in use
    assert use.count("$act.Arguments =") == 1


# --- FX-4 ------------------------------------------------------------------------------------------------------------
def test_fx4_principal_is_the_users_own_limited_account():
    fx4 = _fn(PS1, "Test-NodeTaskPrincipal")
    assert "$pr.GroupId" in fx4 and "-ne 'Limited'" in fx4
    assert "$me -in 'S-1-5-18', 'S-1-5-19', 'S-1-5-20') { return $false }" in fx4   # never vouched for by a service run
    # C-2: judged by the TOKEN (SID, domain\\user), never by environment variables; a domain must match too
    assert "$env:" not in fx4 and "[Security.Principal.WindowsIdentity]::GetCurrent()" in fx4
    assert "if ($uid -eq $me) { return $true }" in fx4 and "$mine = @($id.Name -split" in fx4
    assert "[string]::Equals($theirs[0], $mine[0], 'OrdinalIgnoreCase') -and" in fx4
    s4u = _fn(PS1, "New-NodeTaskPrincipal")
    assert "-UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType S4U -RunLevel Limited" in s4u
    assert "-RunLevel Highest" not in PS1


def test_fx4_checked_on_upgrade_and_on_a_fresh_install():
    up = PS1[PS1.index("if ($UpgradeOnly -and $existingTask7) {"):PS1.index("Step \"Create Task Scheduler entry\"")]
    chk = up[up.index("if (-not (Test-NodeTaskPrincipal $t.Principal)) {"):]
    assert "if ($useS4U -and -not (Test-RunAsSystem)) {" in chk           # corrected only by an elevated person
    assert "-Principal (New-NodeTaskPrincipal $true)" in chk and "RunLevel Limited" in chk
    assert "NOT corrected by this run" in chk                             # otherwise said loudly, never silent
    # C-3: "re-registered as you" only after the read-back passes
    c3 = chk[chk.index("Register-ScheduledTask"):]
    assert c3.index("if (Test-NodeTaskPrincipal $t.Principal) {") < c3.index("re-registered as you, RunLevel Limited")
    assert "re-registering did NOT fix it" in c3
    fresh = PS1[PS1.index("Step \"Create Task Scheduler entry\""):PS1.index("}  # end fresh-install task registration")]
    reg = fresh.index("Register-ScheduledTask -TaskName $taskName -InputObject $task -Force")
    assert fresh.index("Assert-RegisteredNodeTaskPrincipal $taskName") > reg
    # C-1: a wrong principal is removed (or disabled) BEFORE the install fails, and nothing starts it
    c1 = _fn(PS1, "Assert-RegisteredNodeTaskPrincipal")
    assert c1.index("Unregister-ScheduledTask -TaskName $Name -Confirm:$false") < c1.index("FailWithDiagnostic")
    assert c1.index("Disable-ScheduledTask -TaskName $Name") < c1.index("FailWithDiagnostic")
    assert "Start-ScheduledTask" not in c1


def test_the_windows_check_script_extracts_what_exists():
    ps = (ROOT / "tests" / "Test-PauseIdentity.ps1").read_text(encoding="utf-8")
    assert "function TaskAction {" in TOOL and "\nif ($Action -ne 'Status'" in TOOL
    assert "function Test-NodeTaskPrincipal(" in PS1 and "\n$useS4U = Test-Elevated" in PS1
    main = PS1[PS1.index("function Test-NodeTaskPrincipal("):PS1.index("\n$useS4U = Test-Elevated")]
    assert "function Assert-RegisteredNodeTaskPrincipal(" in main and "function Resolve-NodeTaskArguments(" in main
    assert "function Get-ScheduledTask {" in ps and "function Get-CimInstance {" in ps      # mocks, never the real ones
    for verb in ("Register", "Set", "Start", "Stop", "Disable", "Enable", "Unregister"):   # mocked if used at all
        for m in re.finditer(verb + r"-ScheduledTask", ps):
            assert f"function {verb}-ScheduledTask {{" in ps, f"{verb}-ScheduledTask used without a mock"


# --- P2-F4: the pause check first, before anything heavy or networked ------------------------------------------------
_PROBE = r"""
import json, os, socket, sys
marker, plat, argv = sys.argv[1], sys.argv[2], sys.argv[3:]
class _NoSocket(socket.socket):
    def __init__(self, *a, **k):
        raise AssertionError("a socket was built")
socket.socket = _NoSocket
import meshembed_node.pause as P
for k in list(P.MARKERS):
    P.MARKERS[k] = marker
class _Exit(Exception):
    pass
def _fake_exit(code):
    raise _Exit(code)
P.enforce.__defaults__ = (plat, None, _fake_exit)
P.paused.__defaults__ = (plat, None)
from meshembed_node import __main__ as M
sys.argv = ["meshembed_node"] + argv
try:
    M.main()
    code = "returned"
except _Exit as e:
    code = e.args[0]
heavy = [m for m in ("meshembed_node.worker", "meshembed_node.config", "meshembed_node.encoder", "requests", "psutil",
                     "meshembed_node.fingerprint") if m in sys.modules]
print(json.dumps({"code": code, "heavy": heavy}))
"""


@pytest.mark.parametrize("plat,code", [("linux", 75), ("win32", 0)])
@pytest.mark.parametrize("argv", [["run"], []], ids=["run", "bare"])
def test_f4_a_paused_start_imports_nothing_heavy_and_opens_no_socket(tmp_path, plat, code, argv):
    marker = tmp_path / "paused"
    marker.write_text("")
    env = {"HOME": str(tmp_path), "USERPROFILE": str(tmp_path), "PATH": "/usr/bin:/bin", "PYTHONPATH": str(ROOT)}
    out = subprocess.run([sys.executable, "-c", _PROBE, str(marker), plat, *argv], env=env, cwd=str(tmp_path),
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr[-800:]
    res = json.loads(out.stdout.strip().splitlines()[-1])
    assert res == {"code": code, "heavy": []}
    assert "node paused by marker (start)" in (tmp_path / ".meshembed" / "node.log").read_text()


def test_f4_the_heavy_imports_left_module_level():
    src = (ROOT / "meshembed_node" / "__main__.py").read_text(encoding="utf-8")
    top = [l for l in src.splitlines() if re.match(r"(from|import) ", l)]
    assert not any(re.search(r"\b(worker|config|requests|encoder|psutil)\b", l) for l in top), top
    start = src[src.index("def _start_daemon"):src.index("def _cmd_run")]
    assert start.index('_pause.enforce("start")') < start.index("from .config import Config")
    assert start.index('_pause.enforce("start")') < start.index("from .worker import")
