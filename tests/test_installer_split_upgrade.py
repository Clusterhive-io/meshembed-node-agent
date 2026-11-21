"""SPLIT-UPGRADE (auditor option A 2026-11-16T11:37:21Z): a root re-run of install.sh with MESHEMBED_ENABLE_SPLIT=1 adds the split
launcher on the UPGRADE path (an existing node keeps its id, key and pool). Until now install_split_units ran only on a fresh install: the
upgrade path exits before it, so an enrolled node (187, ASUS, 4a455425) could never get meshembed-split-launch.* and never reported a runtime
set. Shape and guards are W3b's (test_installer_serve_upgrade): SV-1 de-rooted node user, refused before anything changes, never on the
daemon's own self-update, opt-in only, the restart that follows makes the daemon read MESHEMBED_ENABLE_SPLIT=1."""
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = (ROOT / "install.sh").read_text()

STUBS = ('warn(){ echo "WARN $*"; }\nok(){ echo "OK $*"; }\ninfo(){ echo "INFO $*"; }\n'
         'fail(){ echo "FAIL $*"; exit 1; }\n')


def _fn(name: str) -> str:
    start = INSTALL.index(f"{name}() {{\n")
    return INSTALL[start:INSTALL.index("\n}\n", start) + 3]


def _line(name: str) -> str:
    start = INSTALL.index(f"{name}() {{")
    return INSTALL[start:INSTALL.index("\n", start) + 1]


def _early_block() -> str:
    start = INSTALL.index('if [ "$UPGRADE_ONLY" -eq 1 ] && [ "${MESHEMBED_ENABLE_SPLIT:-0}" = "1" ]')
    return INSTALL[start:INSTALL.index("\nfi\n", start) + 4]


def _systemctl(vals: dict) -> str:
    cases = "".join(f'    {k}) echo "{v}";;\n' for k, v in vals.items())
    return 'systemctl(){ [ "$1" = show ] || return 0; case "$3" in\n' + cases + "    *) echo;;\n  esac; }\n"


GOOD = {"LoadState": "loaded", "NeedDaemonReload": "no", "User": "meshembed", "ProtectSystem": "strict", "NoNewPrivileges": "yes"}


def _early(reason="", split="1", package_url="", uid=0, os_name="Linux"):
    script = (STUBS + f'id(){{ [ "$1" = -u ] && echo {uid}; }}\nuname(){{ echo {os_name}; }}\n'
              + f'serve_user_refusal(){{ printf "%s" "{reason}"; }}\nUPGRADE_ONLY=1\n'
              + (f"MESHEMBED_ENABLE_SPLIT={split}\n" if split else "")
              + (f"MESHEMBED_PACKAGE_URL={package_url}\n" if package_url else "")
              + _early_block() + "echo REACHED\n")
    p = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    return p.returncode, p.stdout


def test_early_refusal_stops_before_anything_changes():
    rc, out = _early(reason="the node unit is not hardened")
    assert rc == 1 and "MESHEMBED_ENABLE_SPLIT=1 refused: the node unit is not hardened" in out and "Nothing was changed" in out
    assert "REACHED" not in out


def test_early_check_passes_a_de_rooted_node():
    assert _early() == (0, "REACHED\n")


def test_early_check_refuses_a_non_root_run():
    rc, out = _early(uid=1000)
    assert rc == 1 and "Linux root runs only" in out and "MESHEMBED_ENABLE_SPLIT=1" in out


def test_early_check_refuses_a_non_linux_host():
    rc, out = _early(os_name="Darwin")
    assert rc == 1 and "Linux root runs only" in out


def test_no_opt_in_no_check():
    assert _early(reason="x", split="")[0] == 0


def test_the_opt_in_set_to_zero_is_no_opt_in():
    assert _early(reason="x", split="0")[0] == 0


def test_the_self_update_never_takes_the_split_opt_in():
    assert _early(reason="x", package_url="https://example.invalid/pkg")[0] == 0


def _from_unit(tmp_path, reason="", split="1", with_env=True, user="meshembed"):
    home = tmp_path / "home"
    (home / ".meshembed").mkdir(parents=True, exist_ok=True)
    if with_env:
        (home / ".meshembed" / ".env").write_text("MESHEMBED_NODE_ID=node-abc\nMESHEMBED_NODE_API_KEY=k\n")
    vals = dict(GOOD, User=user, Environment=f"PYTHONUNBUFFERED=1 HOME={home} HF_HOME={home}/.cache/huggingface")
    script = (STUBS + _systemctl(vals) + _line("serve_unit_val") + f'serve_user_refusal(){{ printf "%s" "{reason}"; }}\n'
              + 'install_split_units(){ echo "CALLED install_split_units $*"; }\n'
              + f'VENV_PY=/opt/meshembed/venv/bin/python\nMESHEMBED_ENABLE_SPLIT={split}\n'
              + _fn("install_split_units_from_unit") + "install_split_units_from_unit; echo DONE\n")
    p = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    return p.returncode, p.stdout


def test_upgrade_installs_the_launcher_for_the_unit_user_home_and_node_id(tmp_path):
    rc, out = _from_unit(tmp_path)
    assert rc == 0 and f"CALLED install_split_units meshembed {tmp_path}/home /opt/meshembed/venv node-abc" in out


def test_upgrade_rechecks_sv1_and_installs_nothing_when_refused(tmp_path):
    rc, out = _from_unit(tmp_path, reason="the node daemon runs as root")
    assert rc == 0 and "CALLED" not in out and "WARN split launcher NOT installed: the node daemon runs as root" in out


def test_upgrade_without_the_opt_in_installs_nothing(tmp_path):
    rc, out = _from_unit(tmp_path, split="0")
    assert rc == 0 and "CALLED" not in out


def test_upgrade_with_an_unrecognised_layout_installs_nothing(tmp_path):
    rc, out = _from_unit(tmp_path, with_env=False)
    assert rc == 0 and "CALLED" not in out and "unit layout not recognised" in out


def test_nothing_reads_the_unit_file_directly():
    body = _fn("install_split_units_from_unit")
    assert "/etc/systemd/system/meshembed-node.service" not in body and "sed -n 's/^User=" not in body


def test_placement():
    up = INSTALL.index("# ── Upgrade path: harden the unit, restart the running daemon, then exit")
    exit0 = INSTALL.index("Upgrade complete.", up)
    # both functions are defined before the upgrade branch runs (bash defines functions as it reads; the branch exits before later text)
    assert INSTALL.index("install_split_units() {") < up and INSTALL.index("install_split_units_from_unit() {") < up
    branch = INSTALL[up:exit0]
    ota = branch[branch.index('if [ -n "${MESHEMBED_PACKAGE_URL:-}" ]; then'):branch.index("Auto-update: the daemon will re-exec")]
    assert "install_split_units_from_unit" not in ota                      # never on a self-update
    root = branch[branch.index('info "Restarting meshembed-node.service'):]
    call, restart = root.index("install_split_units_from_unit"), root.index("systemctl restart meshembed-node.service")
    assert call < restart                                                  # the restart picks up MESHEMBED_ENABLE_SPLIT=1
    assert root.index("install_serve_units_from_unit") < call              # serve first, then split: both before the one restart
    early = INSTALL.index('if [ "$UPGRADE_ONLY" -eq 1 ] && [ "${MESHEMBED_ENABLE_SPLIT:-0}" = "1" ]')
    assert INSTALL.index("UPGRADE_ONLY=0\nfi\n") < early < INSTALL.index("# ── Invite token")
    # the fresh install path is unchanged: it still installs the launcher with the fresh service user
    assert 'install_split_units "$SVC_USER" "$SVC_HOME"' in INSTALL


def test_the_launcher_text_is_unchanged_by_the_move():
    """The function was MOVED up (it must exist before the upgrade branch exits); its body is what the fresh install ran before."""
    body = _fn("install_split_units")
    for needle in ("meshembed-split-launch.service", "meshembed-split-launch.path", "meshembed-split-launch.timer",
                   "wireguard_unavailable", "append_node_env_flag \"$u\" \"$h\" MESHEMBED_ENABLE_SPLIT", "/etc/meshembed-node/wg", "NoNewPrivileges=yes",
                   "ProtectSystem=strict", "User=root"):
        assert needle in body
    assert re.search(r"split_launch --request \$h/\.meshembed/split-request --revoke \$h/\.meshembed/split-revoke --owner \$u", body)


# ---- SU-1 (auditor 2026-11-16T11:40:59Z): the opt-in lines are never appended by ROOT through a path the node user controls ----------------
import getpass
import os


def _append(tmp_path, home, user=None, key="MESHEMBED_ENABLE_SPLIT", foreign=""):
    """foreign = a path suffix whose `stat -c %U` the stub reports as another user (the file/dir owned by someone else)."""
    user = user or getpass.getuser()
    log = tmp_path / "runuser.log"
    statstub = (f'stat(){{ case "$3" in *{foreign}) echo someone-else;; *) /usr/bin/stat "$@";; esac; }}\n' if foreign else "")
    script = (STUBS + statstub + f'runuser(){{ echo "runuser $*" >> "{log}"; shift 3; "$@"; }}\n'   # drop "-u USER --": the stub runs as the test user
              + INSTALL[INSTALL.index("units_note() {"):INSTALL.index("\n}\n", INSTALL.index("units_note() {")) + 3]
              + INSTALL[INSTALL.index("AS_USER_DEFERRED=77"):INSTALL.index("\nensure_user_dir() {")] + "\n"       # U1: units_note + as_user
              + _fn("append_node_env_flag") + f'append_node_env_flag "{user}" "{home}" {key}; echo "RC=$?"\n')
    p = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    return p.stdout, (log.read_text() if log.exists() else "")


def _home(tmp_path, env_text="MESHEMBED_NODE_ID=n1\n"):
    home = tmp_path / "home"
    (home / ".meshembed").mkdir(parents=True)
    (home / ".meshembed" / ".env").write_text(env_text)
    return home


def test_su1_a_real_dir_and_file_owned_by_the_node_user_get_the_line_once_and_as_that_user(tmp_path):
    home = _home(tmp_path)
    out, log = _append(tmp_path, home)
    assert "RC=0" in out and (home / ".meshembed" / ".env").read_text() == "MESHEMBED_NODE_ID=n1\nMESHEMBED_ENABLE_SPLIT=1\n"
    assert f"runuser -u {getpass.getuser()} --" in log, "the append is done AS the node user, not by root"
    _append(tmp_path, home)                                                         # idempotent: no duplicate line
    assert (home / ".meshembed" / ".env").read_text().count("MESHEMBED_ENABLE_SPLIT=1") == 1


def test_su1_a_symlinked_env_is_refused_and_the_target_is_untouched(tmp_path):
    home = _home(tmp_path)
    victim = tmp_path / "victim"
    victim.write_text("root file\n")
    (home / ".meshembed" / ".env").unlink()
    os.symlink(victim, home / ".meshembed" / ".env")
    out, log = _append(tmp_path, home)
    assert "RC=1" in out and "NOT written" in out and victim.read_text() == "root file\n" and log == ""


def test_su1_a_symlinked_meshembed_dir_is_refused_and_nothing_is_written_outside(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / ".env").write_text("A=1\n")
    os.symlink(elsewhere, home / ".meshembed")
    out, log = _append(tmp_path, home)
    assert "RC=1" in out and (elsewhere / ".env").read_text() == "A=1\n" and log == ""


def test_su1_a_file_not_owned_by_the_node_user_is_refused(tmp_path):
    home = _home(tmp_path)
    out, log = _append(tmp_path, home, user="somebody-else")
    assert "RC=1" in out and "MESHEMBED_ENABLE_SPLIT" not in (home / ".meshembed" / ".env").read_text() and log == ""


def test_su1_a_missing_env_is_not_created_by_root(tmp_path):
    home = tmp_path / "home"
    (home / ".meshembed").mkdir(parents=True)
    out, log = _append(tmp_path, home)
    assert "RC=1" in out and not (home / ".meshembed" / ".env").exists() and log == ""


def test_su1_no_root_append_into_the_node_env_remains_in_the_installer():
    assert not re.search(r'>>\s*"\$h/\.meshembed/\.env"', INSTALL), "a root '>>' into the node user's .env is back"
    for key in ("MESHEMBED_ENABLE_SPLIT", "MESHEMBED_SERVE", "MESHEMBED_AGENT_HOST"):
        assert f'append_node_env_flag "$u" "$h" {key}' in INSTALL


def test_su1_the_env_file_alone_owned_by_another_user_is_refused(tmp_path):
    home = _home(tmp_path)
    out, log = _append(tmp_path, home, foreign="/.env")
    assert "RC=1" in out and "MESHEMBED_ENABLE_SPLIT" not in (home / ".meshembed" / ".env").read_text() and log == ""


def test_su1_the_meshembed_dir_alone_owned_by_another_user_is_refused(tmp_path):
    home = _home(tmp_path)
    out, log = _append(tmp_path, home, foreign="/.meshembed")
    assert "RC=1" in out and "MESHEMBED_ENABLE_SPLIT" not in (home / ".meshembed" / ".env").read_text() and log == ""


# ---- PATH-TRIGGER (0.3.86): the split launcher has a 30 s safety-net timer, like the serve launcher; the daemon waits long enough ----
def test_the_split_launch_timer_is_a_30s_safety_net_and_the_old_timer_is_restarted():
    import re
    body = _fn("install_split_units")
    unit = re.search(r"meshembed-split-launch\.timer << UNIT\n(.*?)\nUNIT", body, re.S).group(1)
    assert "OnUnitInactiveSec=30s" in unit and "OnBootSec=60s" in unit and "AccuracySec=1s" in unit
    assert "OnUnitActiveSec" not in unit                                           # the 5-min tick is gone
    assert "PathExists=$h/.meshembed/split-request" in body                       # the .path unit stays (level-triggered, PATH-TRIGGER)
    assert "systemctl restart meshembed-split-launch.timer" in body               # an active timer keeps its old schedule otherwise


def test_the_daemon_waits_for_the_launcher_longer_than_the_safety_net_period_plus_a_pass():
    import inspect
    from meshembed_node import split_handoff as H
    assert inspect.signature(H.request_overlay).parameters["wait_s"].default >= 90.0


def test_a_launcher_that_answers_late_inside_the_wait_still_brings_the_overlay_up(tmp_path):
    """The timer-only path: the request is written, no .path start, the safety-net pass answers a few seconds later."""
    import json
    import threading
    import time
    from meshembed_node import split_handoff as H
    req, state = tmp_path / "split-request", tmp_path / "state"
    state.mkdir()

    def late_launcher():
        time.sleep(0.6)
        (state / "last-result.json").write_text(json.dumps({"plan_id": "sp-late", "result": "ok", "code": "probe_overlay_up", "at": int(time.time())}))
    threading.Thread(target=late_launcher, daemon=True).start()
    assert H.request_overlay({"plan": {"plan_id": "sp-late"}}, path=req, state_dir=state, wait_s=10.0) is True
    assert json.loads(req.read_text())["plan"]["plan_id"] == "sp-late"             # the request was written for the launcher


def test_ic3b_h1b_an_existing_setting_is_left_exactly_as_it_is(tmp_path):
    # carried from the train's IC3B-H1b test: the owner turned the flag off, the installer must not overwrite or duplicate it
    home = _home(tmp_path, "MESHEMBED_SERVE=0\nB=2\n")
    out, _ = _append(tmp_path, home, key="MESHEMBED_SERVE")
    assert "RC=0" in out and (home / ".meshembed" / ".env").read_text() == "MESHEMBED_SERVE=0\nB=2\n"


def test_the_split_launch_path_unit_is_level_triggered_and_restarted():
    """PATH-TRIGGER: PathExists on both files (a rename over an existing watched file starts nothing on systemd 255 / 26.04)."""
    import re
    body = _fn("install_split_units")
    unit = re.search(r"meshembed-split-launch\.path << UNIT\n(.*?)\nUNIT", body, re.S).group(1)
    assert "PathExists=$h/.meshembed/split-request" in unit and "PathExists=$h/.meshembed/split-revoke" in unit
    assert not any(l.startswith("PathModified") for l in unit.splitlines())      # no edge-triggered directive left for these two files
    assert "Unit=meshembed-split-launch.service" in unit
    assert "systemctl restart meshembed-split-launch.path" in body                # an active unit keeps its old watch otherwise


def test_s2_a_probe_plan_writes_the_lease_so_the_launchers_first_timer_pass_keeps_the_overlay(tmp_path):
    """0.3.87 S2 (asus1 read 11-20: no split-keep, overlay torn down at ~31 s): request_overlay writes the SO-2 lease entry for the probe plan
    the way handoff() does; the launcher's own freshness check then holds at its first (~30 s) and its later passes, up to LEASE_S."""
    import json
    import os
    import time
    from meshembed_node import split_handoff as H
    from meshembed_node import split_launch as L
    req, state = tmp_path / "split-request", tmp_path / "state"
    state.mkdir()
    t0 = time.time()
    assert H.request_overlay({"plan": {"plan_id": "sp-probe"}}, path=req, state_dir=state, wait_s=0.2) is False     # the overlay never comes up here
    keep = tmp_path / "split-keep"
    assert json.loads(keep.read_text())["sp-probe"] >= int(t0)                      # but the lease WAS written at hand-off
    assert oct(keep.stat().st_mode & 0o777) == "0o600"
    uid = os.getuid()
    assert L.lease_fresh(keep, uid, "sp-probe", t0 + 31)                            # the first safety-net pass (OnUnitInactiveSec=30s)
    assert L.lease_fresh(keep, uid, "sp-probe", t0 + 170)                           # still inside LEASE_S
    assert not L.lease_fresh(keep, uid, "sp-probe", t0 + L.LEASE_S + 30)            # a lease only SHORTENS a plan: it does expire


def test_s2_the_lease_is_renewed_when_the_overlay_comes_up(tmp_path):
    import json
    import threading
    import time
    from meshembed_node import split_handoff as H
    req, state = tmp_path / "split-request", tmp_path / "state"
    state.mkdir()

    def launcher():
        time.sleep(1.2)
        (state / "last-result.json").write_text(json.dumps({"plan_id": "sp-p2", "result": "ok", "code": "probe_overlay_up", "at": int(time.time())}))
    threading.Thread(target=launcher, daemon=True).start()
    assert H.request_overlay({"plan": {"plan_id": "sp-p2"}}, path=req, state_dir=state, wait_s=10.0) is True
    assert json.loads((tmp_path / "split-keep").read_text())["sp-p2"] >= int(time.time()) - 2     # renewed at "up", a fresh LEASE_S for the measure
