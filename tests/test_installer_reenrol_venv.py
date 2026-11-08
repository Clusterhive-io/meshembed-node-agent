"""RE-1 (2026-11-02): re-enrolling a node with an invite into the SAME venv path. "uv venv" refused the existing venv
AFTER the old daemon had been stopped (rc 1, the node left down), and behind it the old-install cleanup compared
OLD_VENV with "$VENV_DIR/.venv" although VENV_DIR IS the venv, so a same-path re-enrolment would have removed the
LIVE venv right after installing its unit."""
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = (ROOT / "install.sh").read_text()


def _block(start: str, end: str) -> str:
    a = INSTALL.index(start)
    return INSTALL[a:INSTALL.index(end, a) + len(end)]


VENV_BLOCK = _block("    ensure_uv\n    # RE-1", '    VENV_PY="$VENV_DIR/bin/python"\n')
CLEANUP = _block('    if [ "$SERVICE_INSTALLED" -eq 1 ] && [ -n "${OLD_VENV:-}" ]', "    fi\n")
STUBS = ('id(){ [ "$1" = -u ] && echo "${FAKE_UID:-1000}"; }\n'
         'ensure_uv(){ :; }\ninfo(){ echo "INFO $*"; }\nfail(){ echo "FAIL $*"; exit 1; }\n'
         'uv(){ echo "CALLED uv $*"; mkdir -p "$4/bin"; }\nrm(){ echo "CALLED rm $*"; }\nsudo(){ echo "CALLED sudo $*"; }\n')


def _run(script: str):
    p = subprocess.run(["bash", "-c", STUBS + script], capture_output=True, text=True)
    return p.returncode, p.stdout


def _python(path: Path, ok: bool):
    path.mkdir(parents=True)
    (path / "python").write_text(f"#!/bin/sh\necho RAN-THE-VENV-PYTHON >&2\nexit {0 if ok else 1}\n")
    (path / "python").chmod(0o755)


def test_a_usable_venv_at_the_same_path_is_reused_not_recreated(tmp_path):
    _python(tmp_path / "venv" / "bin", ok=True)
    rc, out = _run(f'VENV_DIR="{tmp_path}/venv"; BASE_PY=3.12\n' + VENV_BLOCK + 'echo "VENV_PY=$VENV_PY"\n')
    assert rc == 0 and "Reusing the existing virtualenv" in out and "CALLED uv" not in out, out
    assert f"VENV_PY={tmp_path}/venv/bin/python" in out


def test_an_unusable_venv_is_refused_and_never_removed(tmp_path):
    _python(tmp_path / "venv" / "bin", ok=False)                 # e.g. a Python 3.13 venv left behind
    rc, out = _run(f'VENV_DIR="{tmp_path}/venv"; BASE_PY=3.12\n' + VENV_BLOCK)
    assert rc == 1 and "not a usable Python 3.10-3.12 virtualenv" in out and "CALLED" not in out, out
    assert (tmp_path / "venv" / "bin" / "python").exists()


def test_a_fresh_path_gets_a_new_venv(tmp_path):
    rc, out = _run(f'VENV_DIR="{tmp_path}/venv"; BASE_PY=3.12\n' + VENV_BLOCK)
    assert rc == 0 and f"CALLED uv venv --seed --python 3.12 {tmp_path}/venv" in out, out


def test_the_cleanup_never_removes_the_venv_it_just_installed_into():
    for old in ("/opt/meshembed-node/.venv", "/opt/meshembed-node/.venv/"):
        rc, out = _run(f'SERVICE_INSTALLED=1; VENV_DIR=/opt/meshembed-node/.venv; OLD_VENV="{old}"\n'
                       + CLEANUP.replace('[ -d "$OLD_VENV" ]', "true"))
        assert rc == 0 and "CALLED rm" not in out, (old, out)


def test_the_cleanup_still_removes_a_previous_install_elsewhere():
    rc, out = _run('SERVICE_INSTALLED=1; VENV_DIR=/opt/meshembed-node/.venv; OLD_VENV=/home/mmj/.meshembed/.venv\n'
                   + CLEANUP.replace('[ -d "$OLD_VENV" ]', "true"))
    assert "CALLED rm -rf /home/mmj/.meshembed/.venv" in out, out


def test_as_root_a_venv_not_owned_by_root_is_refused_and_never_executed(tmp_path):
    """RE1-a: the test's files belong to the (non-root) test user, so as "root" (FAKE_UID=0) the reuse is refused
    BEFORE the venv's interpreter runs, and nothing is removed."""
    _python(tmp_path / "venv" / "bin", ok=True)
    p = subprocess.run(["bash", "-c", STUBS + f'FAKE_UID=0; VENV_DIR="{tmp_path}/venv"; BASE_PY=3.12\n' + VENV_BLOCK],
                       capture_output=True, text=True)
    assert p.returncode == 1 and "is not a root-owned virtualenv" in p.stdout, p.stdout
    assert "RAN-THE-VENV-PYTHON" not in p.stderr and "CALLED" not in p.stdout
    assert (tmp_path / "venv" / "bin" / "python").exists()


def test_as_the_installing_user_its_own_venv_is_reused(tmp_path):
    _python(tmp_path / "venv" / "bin", ok=True)
    rc, out = _run(f'FAKE_UID=1000; VENV_DIR="{tmp_path}/venv"; BASE_PY=3.12\n' + VENV_BLOCK)
    assert rc == 0 and "Reusing the existing virtualenv" in out, out


def test_as_root_a_group_writable_parent_is_refused_and_the_venv_never_executed(tmp_path):
    """RE1-b: the PARENT's mode too (a writable parent lets another user swap the venv between check and run). The
    test cannot make root-owned files, so it shows the refusal fires even when ownership is what fails first, and
    that the parent-mode test is in the same guard (the control below removes it)."""
    _python(tmp_path / "par" / "venv" / "bin", ok=True)
    (tmp_path / "par").chmod(0o777)
    p = subprocess.run(["bash", "-c", STUBS + f'FAKE_UID=0; VENV_DIR="{tmp_path}/par/venv"; BASE_PY=3.12\n' + VENV_BLOCK],
                       capture_output=True, text=True)
    assert p.returncode == 1 and "is not a root-owned virtualenv" in p.stdout and "RAN-THE-VENV-PYTHON" not in p.stderr


def test_the_parent_mode_test_is_in_the_guard():
    assert '[ -z "$(find "$(dirname "$VENV_DIR")" -maxdepth 0 -perm /022)" ]' in VENV_BLOCK


def test_a_root_install_makes_uvs_lock_file_root_only():
    i = INSTALL.index('_venv_lock="$(dirname "$(dirname "$VENV_PY")")/.lock"')
    block = INSTALL[i:INSTALL.index("\nfi\n", i) + 4]
    assert 'chmod 0644 "$_venv_lock"' in block and '[ "$(id -u)" -eq 0 ]' in block and '[ ! -L "$_venv_lock" ]' in block
    assert i < INSTALL.index("# ── GUARD: confirm the upgrade landed")      # after the last uv step
