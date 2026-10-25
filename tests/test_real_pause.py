"""The node's REAL pause (DESIGN_H1 blocker 0.1; auditor design GO 2026-10-23 14:38Z, P-a..P-c), daemon + three
installers. The 160 / sandbox-node proofs are separate (real Task Scheduler / systemd)."""
import os
import re
import subprocess
from pathlib import Path

import pytest

from meshembed_node import pause as P

ROOT = Path(__file__).resolve().parents[1]
SH, MAC, PS1 = ((ROOT / f).read_text() for f in ("install.sh", "install-mac.sh", "install.ps1"))
WORKER = (ROOT / "meshembed_node" / "worker.py").read_text()


# --- the daemon (P-a, P-c) --------------------------------------------------------------------------------------------
@pytest.mark.parametrize("make", [
    lambda p: p.write_text(""),                                  # empty
    lambda p: p.write_text("code=garbage\x00\xff"),              # malformed content: never parsed
    lambda p: (p.write_text("x"), os.chmod(p, 0)),               # unreadable
    lambda p: p.symlink_to(p.parent / "missing-target"),         # a DANGLING symlink still pauses (lexists)
    lambda p: p.mkdir(),                                         # even a directory
])
def test_presence_alone_pauses(tmp_path, make):
    m = tmp_path / "paused"
    make(m)
    assert P.paused(path=str(m)) is True
    codes = []
    P.enforce("start", platform="linux", path=str(m), _exit=codes.append)
    assert codes == [75]


def test_no_marker_runs(tmp_path):
    codes = []
    P.enforce("poll", platform="linux", path=str(tmp_path / "nothing"), _exit=codes.append)
    assert codes == [] and P.paused(path=str(tmp_path / "nothing")) is False


def test_a_marker_not_admin_owned_is_honoured_and_reported(tmp_path, caplog):
    """P-a: ownership decides who can REMOVE it, never whether it counts (ignoring it would fail OPEN)."""
    m = tmp_path / "paused"
    m.write_text("")                                              # owned by this (non-root) test user
    assert P.admin_owned(str(m), platform="linux") is False
    codes = []
    with caplog.at_level("WARNING"):
        P.enforce("start", platform="linux", path=str(m), _exit=codes.append)
    assert codes == [75] and "NOT admin-owned" in caplog.text


def test_exit_codes_and_paths():
    assert P.paused_exit_code("linux") == 75 and P.paused_exit_code("darwin") == 0 and P.paused_exit_code("win32") == 0
    assert P.marker_path("linux") == "/etc/meshembed-node/paused"
    assert P.marker_path("darwin") == "/Library/Application Support/MeshEmbed/paused"
    assert P.marker_path("win32").endswith(os.path.join("MeshEmbed", "node-paused"))
    assert P.admin_owned("x", platform="win32") is None          # the tool's -Status checks the ACL there


def test_the_daemon_never_writes_or_removes_the_marker():
    """P-b on the daemon side: the module only looks."""
    src = (ROOT / "meshembed_node" / "pause.py").read_text()
    for forbidden in ("unlink", "remove(", "rmtree", "write_text", "open(", "rename", "replace("):
        assert forbidden not in src.split('"""', 2)[-1], forbidden


def test_checked_first_in_run_and_before_every_poll():
    """P-c: before any network call, model load, update check or heartbeat."""
    run = WORKER[WORKER.index("def run(cfg: Config) -> None:"):]
    first_code = [l.strip() for l in run.splitlines()[1:] if l.strip() and not l.strip().startswith("#")][:2]
    assert first_code == ["from . import pause as _pause", '_pause.enforce("start")']
    loop = WORKER[WORKER.index("def _worker_loop("):WORKER.index("def run(cfg: Config)")]
    assert loop.index('_pause.enforce("poll")') < loop.index("resp = _poll(")


# --- Linux installer ---------------------------------------------------------------------------------------------------
def test_linux_unit_does_not_restart_a_paused_node():
    assert "RestartPreventExitStatus=75" in SH                    # new units
    fn = SH[SH.index("_harden_unit() {"):]
    assert "! grep -q '^Restart=no$'" in fn[:4000]                       # any Restart= but "no" (auditor 14:49Z nit)


@pytest.mark.parametrize("restart,added", [("always", True), ("on-failure", True), ("on-abnormal", True),
                                           ("no", False)])
def test_upgrade_adds_the_line_for_any_restart_policy(tmp_path, restart, added):
    block = SH[SH.index("            # any Restart= other than"):]
    block = block[:block.index("            fi\n") + len("            fi\n")]
    unit = tmp_path / "u.service"
    unit.write_text(f"[Service]\nRestart={restart}\nRestartSec=5\n")
    script = 'info(){ :; }\nS=""\nf="' + str(unit) + '"\n' + block
    subprocess.run(["bash", "-c", script], check=True)
    text = unit.read_text()
    assert ("RestartPreventExitStatus=75" in text) is added
    if added:
        assert text.index(f"Restart={restart}") < text.index("RestartPreventExitStatus=75") < text.index("RestartSec")
        subprocess.run(["bash", "-c", script], check=True)                  # idempotent
        assert unit.read_text().count("RestartPreventExitStatus=75") == 1


def test_linux_paused_check_is_defined_before_every_use():
    first_def = SH.index("node_paused() {")
    uses = [m.start() for m in re.finditer(r"\bnode_paused\b", SH) if m.start() != first_def]
    assert uses and min(uses) > first_def


def test_linux_installer_never_starts_or_reenables_a_paused_node():
    """P-b: every start / restart / enable path is behind node_paused, and nothing outside the tool removes it."""
    for call in ("systemctl enable --now meshembed-node.service", "systemctl restart meshembed-node.service"):
        for m in re.finditer(re.escape(call), SH):
            window = SH[max(0, m.start() - 400):m.start()]
            if "echo" in SH[SH.rfind("\n", 0, m.start()):m.start()]:
                continue                                          # printed instructions, not a call
            assert "node_paused" in window, (call, SH[m.start() - 120:m.start()])
    tool = SH[SH.index("cat > /usr/local/sbin/meshembed-node-pause << 'PAUSE'"):SH.index("\nPAUSE\n")]
    outside = SH.replace(tool, "")
    assert not re.search(r'rm [^\n]*(PAUSE_MARKER|meshembed-node/paused)', outside)


def _linux_tool(tmp_path):
    tool = SH[SH.index("<< 'PAUSE'\n") + len("<< 'PAUSE'\n"):SH.index("\nPAUSE\n")]
    tool = tool.replace("M=/etc/meshembed-node/paused", f"M={tmp_path}/etc/paused").replace(
        "install -d -m 0755 -o root -g root /etc/meshembed-node", f"mkdir -p {tmp_path}/etc")
    stub = (f'id(){{ echo 0; }}\nchown(){{ :; }}\nstat(){{ echo 0; }}\n'
            f'systemctl(){{ echo "systemctl $*" >> {tmp_path}/calls; [ "$1" = is-active ] && return 1; return 0; }}\n')
    f = tmp_path / "tool.sh"
    f.write_text(tool.replace("set -eu\n", "set -eu\n" + stub, 1))
    return f


def test_linux_tool_pause_status_resume(tmp_path):
    f = _linux_tool(tmp_path)
    run = lambda *a: subprocess.run(["sh", str(f), *a], capture_output=True, text=True)   # noqa: E731
    assert run("pause", "Bad Code").returncode == 2                 # closed codes only
    out = run("pause", "stage_run")
    assert out.stdout.strip() == "paused" and (tmp_path / "etc" / "paused").exists()
    assert re.fullmatch(r"code=stage_run\nat=\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\n", (tmp_path / "etc" / "paused").read_text())
    assert "systemctl disable --now meshembed-node.service" in (tmp_path / "calls").read_text()
    assert run("status").stdout.strip() == "paused"
    assert run("resume").stdout.strip() == "running" and not (tmp_path / "etc" / "paused").exists()


# --- macOS and Windows installers --------------------------------------------------------------------------------------
def test_macos_installer_never_bootstraps_a_paused_node():
    assert 'PAUSE_MARKER="/Library/Application Support/MeshEmbed/paused"' in MAC
    assert MAC.index("node_paused() {") < MAC.index("elif node_paused; then")
    fresh = MAC[MAC.index('LAUNCHCTL_TARGET="gui/$(id -u)"'):]
    assert fresh.index("if node_paused; then") < fresh.index('launchctl bootstrap "$LAUNCHCTL_TARGET"')
    tool = MAC[MAC.index("<< 'PAUSE'"):MAC.index("\nPAUSE\n")]
    assert not re.search(r'rm [^\n]*PAUSE_MARKER', MAC.replace(tool, ""))


def test_windows_installer_never_starts_a_paused_node():
    assert '$PauseMarker = Join-Path $env:ProgramData "MeshEmbed\\node-paused"' in PS1
    assert "-Force -ErrorAction SilentlyContinue" in PS1[PS1.index("function Test-NodePaused"):][:200]  # links count
    up = PS1.index("if ($UpgradeOnly -and $existingTask7 -and (Test-NodePaused))")
    assert up < PS1.index("Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue\n")
    fresh = PS1.index("} elseif (Test-NodePaused) {")
    assert fresh < PS1.index("Start-ScheduledTask -TaskName $taskName\nStart-Sleep -Seconds 3")
    tool = PS1[PS1.index("$PauseToolSource = @'"):PS1.index("\n'@\n")]
    outside = PS1.replace(tool, "")
    assert not re.search(r"Remove-Item[^\n]*(PauseMarker|node-paused)", outside)
    for needle in ("Disable-ScheduledTask -TaskName $task", "refused: run elevated", "'^[a-z_]{1,40}$'",
                   "paused (marker NOT admin-owned)", "SetAccessRuleProtection($true, $false)"):
        assert needle in tool, needle


def test_every_root_install_path_installs_the_pause_tool():
    """Proof 1 (2026-10-23): the root SELF-UPDATE branch (MESHEMBED_PACKAGE_URL set) skipped install_pause_tool, so a
    node upgraded that way would never get the tool. Every root branch that writes the unit now installs it."""
    self_update = SH[SH.index('if [ -n "${MESHEMBED_PACKAGE_URL:-}" ]; then'):SH.index('info "Auto-update: the daemon')]
    root = self_update[self_update.index('if [ "$EUID" -eq 0 ]; then'):self_update.index("elif sudo -n")]
    assert "install_pause_tool" in root
    manual = SH[SH.index('info "Restarting meshembed-node.service so the new code takes effect..."'):]
    assert "install_pause_tool" in manual[:manual.index("elif sudo -n")]
