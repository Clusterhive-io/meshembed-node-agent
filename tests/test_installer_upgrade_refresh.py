"""IOP-4 (IO-CAP real-systemd proof 2026-11-01; auditor rulings 19:46:20Z and 19:54:48Z): an upgrade-only run (every
OTA takes it) refreshes the limits / serve units it owns, only where they already exist, through an atomic writer that
never follows a symlink, and never starts a stopped unit. The real-systemd half (a stopped .path stays stopped; a
running serve unit keeps its MainPID) is proven on the release candidate (the IO-CAP proof's P12 re-run).
IOCAP-UPG (auditor 2026-11-08T18:57:48Z, IC-3): the LIMITS applier is the exception -- where it is absent on a
hardened root node, the upgrade INSTALLS it (enabled), unless the owner's opt-out was recorded (limits-disabled)."""
import os
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
INSTALL = (ROOT / "install.sh").read_text()


def _fn(name: str) -> str:
    start = INSTALL.index(f"{name}() {{")
    end = INSTALL.index("\n}\n", start) + 3
    return INSTALL[start:end]


def _bash(script: str, env=None):
    e = {**os.environ, "MESHEMBED_INSTALLER_TEST_MODE": "1", "MESHEMBED_TEST_ROOT_UID": str(os.getuid()), **(env or {})}
    return subprocess.run(["bash", "-c", "set -euo pipefail\nwarn(){ echo \"WARN $*\"; }\nok(){ echo \"OK $*\"; }\n"
                           "logger(){ echo \"LOGGED $*\"; }\n" + script], capture_output=True, text=True, env=e)


# --- IOP-4b: the atomic writer -------------------------------------------------------------------------------------
def test_a_unit_is_written_atomically_with_mode_0644(tmp_path):
    f = tmp_path / "x.service"
    f.write_text("old\n")
    p = _bash(_fn("_write_unit_atomic") + f'printf "new\\n" | _write_unit_atomic "{f}"\necho DONE\n')
    assert p.returncode == 0 and p.stdout.endswith("DONE\n")
    assert f.read_text() == "new\n" and oct(f.stat().st_mode & 0o777) == "0o644"
    assert not [x for x in tmp_path.iterdir() if x.name.startswith(".x.service.")]      # no temp file left


def test_a_symlinked_target_is_refused_and_its_target_untouched(tmp_path):
    victim = tmp_path / "victim"; victim.write_text("precious\n")
    f = tmp_path / "x.service"; f.symlink_to(victim)
    p = _bash(_fn("_write_unit_atomic") + f'printf "evil\\n" | _write_unit_atomic "{f}"\necho DONE\n')
    assert p.returncode == 0 and p.stdout.endswith("DONE\n")                 # the install goes on
    assert "WARN refused to write" in p.stdout and "LOGGED -t meshembed-install refused to write" in p.stdout
    assert victim.read_text() == "precious\n" and f.is_symlink()


def test_a_symlinked_directory_is_refused(tmp_path):
    real = tmp_path / "real"; real.mkdir()
    link = tmp_path / "link"; link.symlink_to(real)
    p = _bash(_fn("_write_unit_atomic") + f'printf "x\\n" | _write_unit_atomic "{link}/a.service"\necho DONE\n')
    assert "WARN refused to write" in p.stdout and not (real / "a.service").exists()


def test_a_directory_not_owned_by_root_is_refused(tmp_path):
    f = tmp_path / "a.service"
    p = _bash(_fn("_write_unit_atomic") + f'printf "x\\n" | _write_unit_atomic "{f}"\n',
              env={"MESHEMBED_TEST_ROOT_UID": "0"} if os.getuid() != 0 else {"MESHEMBED_TEST_ROOT_UID": "12345"})
    assert "WARN refused to write" in p.stdout and not f.exists()


def test_the_test_hook_is_ignored_outside_test_mode(tmp_path):
    f = tmp_path / "a.service"
    p = _bash(_fn("_write_unit_atomic") + f'printf "x\\n" | _write_unit_atomic "{f}"\n',
              env={"MESHEMBED_INSTALLER_TEST_MODE": "0"})
    if os.getuid() != 0:
        assert "WARN refused to write" in p.stdout and not f.exists()       # root is required for real


# --- IOP-4: which units an upgrade-only run refreshes -------------------------------------------------------------
NODE_UNIT = "[Service]\nUser=meshembed\nEnvironment=HOME=/var/lib/meshembed-node\nProtectSystem=strict\n"


def _refresh(tmp_path, *, node_unit=NODE_UNIT, limits=False, serve=False, node_id=True):
    sd = tmp_path / "sd"; sd.mkdir()
    if node_unit is not None:
        (sd / "meshembed-node.service").write_text(node_unit)
    if limits:
        (sd / "meshembed-limits-apply.service").write_text("[Service]\n")
    if serve:
        (sd / "meshembed-serve-launch.service").write_text("[Service]\n")
    nid = tmp_path / "node-id"
    if node_id:
        nid.write_text("abcd1234\n")
    stubs = ('install_limits_units(){ echo "LIMITS refresh=${UNITS_REFRESH:-0} $*"; }\n'
             'install_serve_units(){ echo "SERVE refresh=${UNITS_REFRESH:-0} serve=${MESHEMBED_ENABLE_SERVE:-0} $*"; }\n'
             'VENV_PY=/opt/meshembed-node/.venv/bin/python\n')
    p = _bash(stubs + _fn("_systemd_dir") + _fn("_node_unit_layout") + _fn("refresh_owned_units_from_unit")
              + "refresh_owned_units_from_unit\necho DONE\n",
              env={"MESHEMBED_SYSTEMD_DIR_OVERRIDE": str(sd), "MESHEMBED_NODE_ID_FILE_OVERRIDE": str(nid)})
    assert p.returncode == 0 and p.stdout.endswith("DONE\n"), p.stdout + p.stderr
    return p.stdout


def test_a_host_without_limits_units_gains_them_installed_but_never_serve(tmp_path):
    """IOCAP-UPG IC-3 (auditor 2026-11-08T18:57:48Z): a hardened node installed before IO-CAP gets the applier on
    upgrade, in INSTALL mode (enabled + started, like a fresh root install); serving stays opt-in (never added)."""
    out = _refresh(tmp_path)
    assert "LIMITS refresh=0 meshembed /var/lib/meshembed-node /opt/meshembed-node/.venv" in out and "SERVE" not in out


def test_existing_limits_units_are_refreshed_in_refresh_mode(tmp_path):
    out = _refresh(tmp_path, limits=True)
    assert "LIMITS refresh=1 meshembed /var/lib/meshembed-node /opt/meshembed-node/.venv" in out and "SERVE" not in out


def test_an_opted_in_serve_launcher_is_refreshed_with_its_node_id(tmp_path):
    out = _refresh(tmp_path, serve=True)
    assert "SERVE refresh=1 serve=1 meshembed /var/lib/meshembed-node /opt/meshembed-node/.venv abcd1234" in out


def test_no_node_id_no_serve_refresh(tmp_path):
    assert "SERVE" not in _refresh(tmp_path, serve=True, node_id=False)


@pytest.mark.parametrize("unit", [None, "[Service]\nUser=root\nEnvironment=HOME=/root\nProtectSystem=strict\n",
                                  "[Service]\nUser=meshembed\nEnvironment=HOME=/var/lib/meshembed-node\n"])
def test_a_non_hardened_or_missing_node_unit_refreshes_nothing(tmp_path, unit):
    out = _refresh(tmp_path, node_unit=unit, limits=True, serve=True)
    assert "LIMITS" not in out and "SERVE" not in out


# --- IOP-4a: the refresh branch never enables, never starts a pass, never restarts the node or a serve unit -------
@pytest.mark.parametrize("fn", ["install_limits_units", "install_serve_units"])
def test_the_refresh_branch_only_try_restarts_its_own_path_and_timer_units(fn):
    body = _fn(fn)
    branch = body[body.index('if [ "${UNITS_REFRESH:-0}" = 1 ]'):]
    branch = branch[:branch.index("    fi\n")]
    assert "try-restart" in branch and "enable" not in branch and "systemctl start" not in branch
    for unit in branch.split("systemctl try-restart", 1)[1].split(">/dev/null", 1)[0].split():
        assert unit.strip("\\") in ("", "meshembed-limits-apply.path", "meshembed-limits-apply.timer",
                                    "meshembed-limits-reconcile.path", "meshembed-serve-launch.path",
                                    "meshembed-serve-launch.timer")


@pytest.mark.parametrize("fn", ["install_limits_units", "install_serve_units"])
def test_every_unit_file_of_these_installers_goes_through_the_atomic_writer(fn):
    body = _fn(fn)
    assert "cat > /etc/systemd" not in body and 'cat > "/etc/systemd' not in body
    assert body.count("_write_unit_atomic ") == 4


def test_both_upgrade_only_root_branches_refresh_the_owned_units():
    up = INSTALL[INSTALL.index('if [ "$UPGRADE_ONLY" -eq 1 ]; then\n    info "Skipping register'):INSTALL.index("Upgrade complete")]
    assert up.count("refresh_owned_units_from_unit") == 2



# --- IOCAP-UPG: the opt-out is recorded and honoured (executed: the real install_limits_units up to the request file) --
def _limits(tmp_path, env_extra, marker_exists=False):
    mk = tmp_path / "etc" / "limits-disabled"
    if marker_exists:
        mk.parent.mkdir(parents=True, exist_ok=True)
        mk.write_text("")
    venv = tmp_path / "venv"; (venv / "bin").mkdir(parents=True)                 # the layout guard needs bin/python
    (venv / "bin" / "python").write_text("#!/bin/sh\n"); (venv / "bin" / "python").chmod(0o755)
    stubs = ('id(){ echo 0; }\nuname(){ echo Linux; }\ninfo(){ echo "INFO $*"; }\nmake_user_request_file(){ :; }\n')
    env = {"MESHEMBED_LIMITS_MARKER_OVERRIDE": str(mk), **env_extra}
    if "MESHEMBED_ENABLE_LIMITS" not in env_extra:
        env["MESHEMBED_ENABLE_LIMITS"] = ""          # placeholder, removed below: "unset" must really be unset
    e = {k: v for k, v in env.items() if not (k == "MESHEMBED_ENABLE_LIMITS" and v == "")}
    base = {k: v for k, v in os.environ.items() if k != "MESHEMBED_ENABLE_LIMITS"}
    p = subprocess.run(["bash", "-c", "set -euo pipefail\nwarn(){ echo \"WARN $*\"; }\nok(){ echo \"OK $*\"; }\n"
                        + stubs + _fn("_limits_disabled_marker") + _fn("install_limits_units")
                        + "install_limits_units meshembed " + str(tmp_path / "home") + " " + str(venv) + "\necho DONE\n"],
                       capture_output=True, text=True,
                       env={**base, "MESHEMBED_INSTALLER_TEST_MODE": "1", **e})
    assert p.returncode == 0 and p.stdout.endswith("DONE\n"), p.stdout + p.stderr
    return p.stdout, mk.exists()


def test_an_opt_out_is_recorded_and_installs_nothing(tmp_path):
    out, marked = _limits(tmp_path, {"MESHEMBED_ENABLE_LIMITS": "0"})
    assert marked and "recorded in" in out and "request file" not in out


def test_a_recorded_opt_out_is_honoured_by_a_later_run(tmp_path):
    out, marked = _limits(tmp_path, {}, marker_exists=True)
    assert marked and "opted out earlier" in out and "request file" not in out


def test_an_explicit_opt_in_removes_the_marker_and_proceeds(tmp_path):
    out, marked = _limits(tmp_path, {"MESHEMBED_ENABLE_LIMITS": "1"}, marker_exists=True)
    assert not marked and "no regular request file" in out          # reached the install steps


def test_no_marker_and_no_flag_proceeds_to_install(tmp_path):
    out, marked = _limits(tmp_path, {})
    assert not marked and "no regular request file" in out and "opted out" not in out


def test_the_marker_lives_in_root_owned_etc_outside_test_mode():
    body = _fn("_limits_disabled_marker")
    assert "/etc/meshembed-node/limits-disabled" in body and 'MESHEMBED_INSTALLER_TEST_MODE:-}" = 1' in body
