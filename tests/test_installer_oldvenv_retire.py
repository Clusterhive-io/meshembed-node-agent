"""OLDVENV-1 (v0.3.85; OV-1 harness: every call runs under set -euo pipefail at the call site's shape; design rev 1 03f77e2d, auditor D1-D3 2026-11-11T18:09:17Z): a ROOT run that moved the daemon onto
its venv RETIRES the venv the unit ran from before (moved aside, root-only, never deleted). Any failed check leaves it in
place and says why. The function is run from install.sh itself, with a scratch "home" in place of /home (the only
substitution), the real pgrep / realpath, and this interpreter as the installer's python (RETIRE_UID / RETIRE_GID = the
test user, since the tests do not run as root)."""
import os
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit
ROOT = Path(__file__).resolve().parents[1]
INSTALL = (ROOT / "install.sh").read_text()
START = "retire_prev_venv() {"
FUNC = INSTALL[INSTALL.index(START):INSTALL.index("    return 0\n}\n", INSTALL.index(START)) + len("    return 0\n}\n")]
STUBS = 'info(){ echo "INFO $*"; }\nok(){ echo "OK $*"; }\nwarn(){ echo "WARN $*"; }\n'
TODAY = time.strftime("%Y%m%d", time.gmtime())


def _func(home: Path) -> str:
    allowed = "/home/?*|/root|/root/*"
    assert FUNC.count(allowed) == 1
    return FUNC.replace(allowed, f"{home}/?*")


def _venv(path: Path, dist: bool = True) -> Path:
    sp = path / "lib" / "python3.12" / "site-packages"
    sp.mkdir(parents=True)
    if dist:
        (sp / "meshembed_node-0.3.80.dist-info").mkdir()
    (path / "bin").mkdir()
    return path


def _run(home: Path, prev: str, cur: str = "/opt/meshembed-node/.venv", venv_py: str = sys.executable,
         argv_tail: str = ""):
    env = dict(os.environ, VENV_PY=venv_py, RETIRE_UID=str(os.getuid()), RETIRE_GID=str(os.getgid()))
    # OV-1: exactly the call site's shape: the installer's errexit, the call as the LAST command of an && list inside an
    # if / else, then a marker. Every test asserts the marker: a refusal must never abort the installer.
    script = ("set -euo pipefail\n" + STUBS + _func(home)
              + 'systemctl_restart_ok(){ return 0; }\nnode_paused(){ return 1; }\n'
              + 'if node_paused; then echo PAUSED\n'
              + f'else systemctl_restart_ok && ok "Daemon restarted" && retire_prev_venv "{prev}" "{cur}"; fi\n'
              + 'echo INSTALLER-CONTINUES\necho "RETIRED=${RETIRED_VENV:-}"\n')
    p = subprocess.run(["bash", "-c", script + argv_tail], capture_output=True, text=True, env=env)
    out = p.stdout + p.stderr
    assert p.returncode == 0 and "INSTALLER-CONTINUES" in out, ("the installer must continue", p.returncode, out)
    return p.returncode, out


def test_t1_a_previous_home_venv_is_moved_aside_and_made_owner_only(tmp_path):
    prev = _venv(tmp_path / "u" / ".meshembed" / ".venv")
    rc, out = _run(tmp_path, str(prev))
    new = prev.parent / f".venv.retired-{TODAY}"
    assert rc == 0 and "OK previous venv retired" in out, out
    assert f"RETIRED={new}" in out, out                         # F4: recorded for the manifest
    assert not prev.exists() and new.is_dir() and not new.is_symlink()
    assert stat.S_IMODE(new.stat().st_mode) == 0o700
    assert (new / "lib" / "python3.12" / "site-packages" / "meshembed_node-0.3.80.dist-info").is_dir()   # never deleted


def test_t2_the_venv_in_use_is_never_touched(tmp_path):
    prev = _venv(tmp_path / "u" / ".meshembed" / ".venv")
    rc, out = _run(tmp_path, str(prev), cur=str(prev) + "/")
    assert rc == 0 and "previous venv" not in out and prev.is_dir(), out


def test_t3_a_symlinked_previous_venv_is_left_and_its_target_untouched(tmp_path):
    target = tmp_path / "elsewhere"
    target.mkdir(mode=0o755)
    target.chmod(0o755)   # CI runner umask is 077: mkdir(mode=) alone yields 0700 there
    (tmp_path / "u" / ".meshembed").mkdir(parents=True)
    link = tmp_path / "u" / ".meshembed" / ".venv"
    link.symlink_to(target)
    rc, out = _run(tmp_path, str(link))
    assert "not a real directory" in out and link.is_symlink(), out
    assert stat.S_IMODE(target.stat().st_mode) == 0o755


def test_t3b_a_swap_to_a_symlink_after_the_shell_checks_is_refused_by_the_helper(tmp_path):
    """The race of D1: everything the shell checked passes, then the venv is swapped for a symlink before the helper
    runs. The helper's own lstat (and O_NOFOLLOW) refuses; the link's target keeps its owner and mode."""
    prev = _venv(tmp_path / "u" / ".meshembed" / ".venv")
    target = tmp_path / "victim"
    target.mkdir(mode=0o755)
    target.chmod(0o755)   # CI runner umask is 077: mkdir(mode=) alone yields 0700 there
    swapper = tmp_path / "swap-then-python"
    swapper.write_text(f'#!/bin/sh\nrm -rf "{prev}" && ln -s "{target}" "{prev}"\nexec "{sys.executable}" "$@"\n')
    swapper.chmod(0o755)
    rc, out = _run(tmp_path, str(prev), venv_py=str(swapper))
    assert "changed during the checks" in out and "RETIRED=\n" in out, out   # F4: nothing recorded on a refusal
    assert prev.is_symlink() and stat.S_IMODE(target.stat().st_mode) == 0o755
    assert not (prev.parent / f".venv.retired-{TODAY}").exists()


def test_t4_a_directory_without_a_meshembed_install_is_left(tmp_path):
    prev = _venv(tmp_path / "u" / ".meshembed" / ".venv", dist=False)
    rc, out = _run(tmp_path, str(prev))
    assert "holds no meshembed_node install" in out and prev.is_dir(), out


def test_t5_a_venv_a_process_runs_from_is_left(tmp_path):
    prev = _venv(tmp_path / "u" / ".meshembed" / ".venv")
    (prev / "bin" / "python").write_bytes(Path("/bin/sleep").read_bytes())
    (prev / "bin" / "python").chmod(0o755)
    proc = subprocess.Popen([str(prev / "bin" / "python"), "30"])
    try:
        time.sleep(0.3)
        rc, out = _run(tmp_path, str(prev))
    finally:
        proc.kill()
        proc.wait()
    assert "a process still runs from" in out and prev.is_dir(), out


def test_t5b_the_venv_path_in_the_callers_own_argv_is_not_a_false_stop(tmp_path):
    prev = _venv(tmp_path / "u" / ".meshembed" / ".venv")
    rc, out = _run(tmp_path, str(prev), argv_tail=f"# {prev}/bin/python is only in this shell's argv\n")
    assert "OK previous venv retired" in out and "a process still runs" not in out, out


def test_t9_a_symlinked_parent_is_left(tmp_path):
    real_parent = tmp_path / "u" / "real"
    _venv(real_parent / ".venv")
    (tmp_path / "u" / ".meshembed").symlink_to(real_parent)
    prev = tmp_path / "u" / ".meshembed" / ".venv"
    rc, out = _run(tmp_path, str(prev))
    assert "its parent is a symlink" in out and (real_parent / ".venv").is_dir(), out


def test_t10_a_parent_outside_any_home_is_left(tmp_path):
    prev = _venv(tmp_path / "srv" / ".venv")
    rc, out = _run(tmp_path / "homes", str(prev))
    assert "not under a home directory" in out and prev.is_dir(), out


def test_t11_an_existing_retired_name_is_never_overwritten(tmp_path):
    prev = _venv(tmp_path / "u" / ".meshembed" / ".venv")
    taken = prev.parent / f".venv.retired-{TODAY}"
    taken.mkdir()
    (taken / "keep").write_text("x")
    rc, out = _run(tmp_path, str(prev))
    assert "already exists" in out and prev.is_dir() and (taken / "keep").read_text() == "x", out


def test_t12_the_previous_venv_is_read_before_any_unit_rewrite_and_retired_only_after_the_restart():
    cap = INSTALL.index('PREV_VENV="$(systemctl show -p ExecStart --value meshembed-node.service')
    for later in ("_harden_unit() {", "install_updater_units_from_unit\n", 'systemctl restart meshembed-node.service'):
        assert cap < INSTALL.index(later), later
    call = INSTALL.index('&& retire_prev_venv "$PREV_VENV" "$VENV_DIR"')
    restart = INSTALL.rindex('systemctl restart meshembed-node.service && ok "Daemon restarted', 0, call)
    assert call - restart < 200                                  # chained to the restart's success, nowhere else
    assert INSTALL.count('retire_prev_venv "$PREV_VENV"') == 1   # never on the paused / self-update / sudo paths
