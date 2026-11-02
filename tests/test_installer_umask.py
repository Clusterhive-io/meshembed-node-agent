"""UM-1 (2026-11-02, 187): a root caller's restrictive umask (027/077) must not decide the modes the de-rooted daemon
needs. /opt/meshembed-node came out 0700 root, the meshembed user could not traverse it, and ExecStartPre returned
203. The installer now gives the venv's parent and the unit file explicit modes, never the caller's umask."""
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = (ROOT / "install.sh").read_text()


def _venv_block() -> str:
    start = INSTALL.index('if [ "$(id -u)" -eq 0 ]; then\n    VENV_DIR=')
    end = INSTALL.index("\nfi\n", start) + 4
    return INSTALL[start:end]


def test_a_root_install_makes_the_venv_parent_0755_under_umask_077():
    script = ('umask 077\nid(){ [ "$1" = -u ] && echo 0; }\n'
              'install(){ echo "CALLED install $*"; }\n' + _venv_block() + 'echo "VENV=$VENV_DIR"\n')
    p = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    assert "CALLED install -d -m 0755 -o root -g root /opt/meshembed-node" in p.stdout
    assert "VENV=/opt/meshembed-node/.venv" in p.stdout


def test_an_unprivileged_install_does_not_touch_opt():
    script = ('umask 077\nid(){ [ "$1" = -u ] && echo 1000; }\n'
              'install(){ echo "CALLED install $*"; }\nHOME=/home/u\n' + _venv_block() + 'echo "VENV=$VENV_DIR"\n')
    p = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert "CALLED" not in p.stdout and "VENV=/home/u/.meshembed/.venv" in p.stdout


def test_the_mode_really_wins_over_the_umask(tmp_path):
    # the same install -d -m 0755 line, run for real (without -o/-g: the test is not root) under umask 077
    d = tmp_path / "opt-meshembed-node"
    subprocess.run(["bash", "-c", f'umask 077; install -d -m 0755 "{d}"'], check=True)
    assert oct(d.stat().st_mode & 0o777) == "0o755"


def test_every_move_of_the_unit_file_is_followed_by_an_explicit_0644():
    moves = [m.start() for m in re.finditer(r'mv /tmp/meshembed-node\.service "\$SERVICE_FILE"', INSTALL)]
    assert len(moves) == 2                                       # the root path and the passwordless-sudo path
    for i in moves:
        assert re.search(r'chmod 0644 "\$SERVICE_FILE"', INSTALL[i:i + 160]), INSTALL[i:i + 160]


# --- UM-1a (auditor 2026-11-02 09:48:05Z): never re-mode a parent the installer did not create -----------------------
def _root_run(venv_dir: str):
    script = ('id(){ [ "$1" = -u ] && echo 0; }\ninstall(){ echo "CALLED install $*"; }\n'
              'fail(){ echo "FAIL $*"; exit 1; }\n' + f'MESHEMBED_VENV_DIR="{venv_dir}"\n' + _venv_block() + "echo DONE\n")
    p = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    return p.returncode, p.stdout


def test_an_existing_shared_parent_keeps_its_mode_1777(tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o1777)
    rc, out = _root_run(f"{shared}/.venv")
    assert rc == 0 and "CALLED" not in out and "DONE" in out
    assert oct(shared.stat().st_mode & 0o7777) == "0o1777"            # sticky bit and world-write untouched


def test_an_existing_untraversable_parent_fails_clearly_and_is_not_changed(tmp_path):
    closed = tmp_path / "closed"
    closed.mkdir()
    closed.chmod(0o750)
    rc, out = _root_run(f"{closed}/.venv")
    assert rc == 1 and "not traversable" in out and "CALLED" not in out
    assert oct(closed.stat().st_mode & 0o7777) == "0o750"


def test_a_new_custom_parent_is_created_0755(tmp_path):
    rc, out = _root_run(f"{tmp_path}/new-parent/.venv")
    assert rc == 0 and f"CALLED install -d -m 0755 -o root -g root {tmp_path}/new-parent" in out
