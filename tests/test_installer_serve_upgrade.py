"""W3b (auditor 2026-11-02 08:05:21Z): a root re-run of install.sh with MESHEMBED_ENABLE_SERVE=1 adds the serve launcher
on the UPGRADE path (an existing node keeps its id, key and pool), but ONLY for a de-rooted daemon user (SV-1): not root,
a hardened unit (ProtectSystem=strict), no admin group, no sudoers entry. Refused before anything changes; never on the
daemon's own self-update."""
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = (ROOT / "install.sh").read_text()


def _fn(name: str) -> str:
    start = INSTALL.index(f"{name}() {{\n")
    end = INSTALL.index("\n}\n", start) + 3
    return INSTALL[start:end]


def _early_block() -> str:
    start = INSTALL.index('if [ "$UPGRADE_ONLY" -eq 1 ] && [ "${MESHEMBED_ENABLE_SERVE:-0}" = "1" ]')
    end = INSTALL.index("\nfi\n", start) + 4
    return INSTALL[start:end]


STUBS = ('warn(){ echo "WARN $*"; }\nok(){ echo "OK $*"; }\ninfo(){ echo "INFO $*"; }\n'
         'fail(){ echo "FAIL $*"; exit 1; }\n')


def _systemctl(vals: dict) -> str:
    """A stub for `systemctl show -p <P> --value meshembed-node.service`: the EFFECTIVE values (what a drop-in changes)."""
    cases = "".join(f'    {k}) echo "{v}";;\n' for k, v in vals.items())
    return 'systemctl(){ [ "$1" = show ] || return 0; case "$3" in\n' + cases + "    *) echo;;\n  esac; }\n"


GOOD = {"LoadState": "loaded", "NeedDaemonReload": "no", "User": "meshembed", "ProtectSystem": "strict",
        "NoNewPrivileges": "yes"}


def _refusal(tmp_path, groups="meshembed video", sudo_out="", **over):
    vals = dict(GOOD, **over)
    script = (STUBS + f'id(){{ echo "{groups}"; }}\n' + f"sudo(){{ printf '%s' '{sudo_out}'; }}\n" + _systemctl(vals)
              + _line("serve_unit_val") + _fn("serve_user_refusal") + 'r="$(serve_user_refusal)"; echo "REASON=[$r]"\n')
    p = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    return re.search(r"REASON=\[(.*)\]", p.stdout).group(1)


def _line(name: str) -> str:
    start = INSTALL.index(f"{name}() {{")
    return INSTALL[start:INSTALL.index("\n", start) + 1]


def test_sv1_passes_the_dedicated_de_rooted_user(tmp_path):
    assert _refusal(tmp_path) == ""


def test_sv1_refuses_a_unit_without_user(tmp_path):
    assert "runs as root" in _refusal(tmp_path, User="")


def test_sv1_refuses_root(tmp_path):
    assert "runs as root" in _refusal(tmp_path, User="root")


def test_sv1_refuses_an_unhardened_unit_like_187(tmp_path):
    assert "not hardened" in _refusal(tmp_path, User="automation", ProtectSystem="no")


def test_sv1_refuses_admin_groups(tmp_path):
    for g in ("sudo", "wheel", "admin", "adm"):
        assert "admin group" in _refusal(tmp_path, groups=f"meshembed video {g}")


def test_sv1_does_not_mistake_a_similar_group_name(tmp_path):
    assert _refusal(tmp_path, groups="meshembed sudoers-docs admins") == ""


def test_sv1_refuses_a_sudoers_entry(tmp_path):
    out = "User meshembed may run the following commands on host:\n    (ALL) NOPASSWD: ALL"
    assert "sudoers entry" in _refusal(tmp_path, sudo_out=out)


def test_sv1_refuses_a_unit_that_is_not_loaded(tmp_path):
    assert "not loaded" in _refusal(tmp_path, LoadState="not-found")


def test_sv1_refuses_a_unit_changed_on_disk_without_reload(tmp_path):
    assert "daemon-reload" in _refusal(tmp_path, NeedDaemonReload="yes")


# SV-1a: the unit file says meshembed + strict, a drop-in overrides it; the EFFECTIVE values decide
def test_sv1a_a_drop_in_user_override_to_a_sudo_user_is_refused(tmp_path):
    out = "User automation may run the following commands on 187:\n    (ALL) NOPASSWD: ALL"
    assert "sudoers entry" in _refusal(tmp_path, User="automation", sudo_out=out)


def test_sv1a_a_drop_in_protectsystem_false_is_refused(tmp_path):
    assert "not hardened" in _refusal(tmp_path, ProtectSystem="no")


def test_sv1a_no_new_privileges_off_is_refused(tmp_path):
    assert "not hardened" in _refusal(tmp_path, NoNewPrivileges="no")


def test_sv1a_nothing_reads_the_unit_file_directly():
    for fn in ("serve_user_refusal", "install_serve_units_from_unit"):
        body = _fn(fn)
        assert "/etc/systemd/system/meshembed-node.service" not in body and "sed -n 's/^User=" not in body


def _early(tmp_path, reason="", serve="1", package_url="", uid=0):
    script = (STUBS + f'id(){{ [ "$1" = -u ] && echo {uid}; }}\nuname(){{ echo Linux; }}\n'
              + f'serve_user_refusal(){{ printf "%s" "{reason}"; }}\nUPGRADE_ONLY=1\n'
              + (f"MESHEMBED_ENABLE_SERVE={serve}\n" if serve else "")
              + (f"MESHEMBED_PACKAGE_URL={package_url}\n" if package_url else "")
              + _early_block() + "echo REACHED\n")
    p = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    return p.returncode, p.stdout


def test_early_refusal_stops_before_anything_changes(tmp_path):
    rc, out = _early(tmp_path, reason="the node unit is not hardened")
    assert rc == 1 and "refused: the node unit is not hardened" in out and "Nothing was changed" in out
    assert "REACHED" not in out


def test_early_check_passes_a_de_rooted_node(tmp_path):
    assert _early(tmp_path) == (0, "REACHED\n")


def test_early_check_refuses_a_non_root_run(tmp_path):
    rc, out = _early(tmp_path, uid=1000)
    assert rc == 1 and "Linux root runs only" in out


def test_no_opt_in_no_check(tmp_path):
    assert _early(tmp_path, reason="x", serve="")[0] == 0


def test_the_self_update_never_takes_the_serve_opt_in(tmp_path):
    assert _early(tmp_path, reason="x", package_url="https://example.invalid/pkg")[0] == 0


def _from_unit(tmp_path, reason="", serve="1"):
    home = tmp_path / "home"
    (home / ".meshembed").mkdir(parents=True, exist_ok=True)
    (home / ".meshembed" / ".env").write_text("MESHEMBED_NODE_ID=node-abc\nMESHEMBED_NODE_API_KEY=k\n")
    vals = dict(GOOD, Environment=f"PYTHONUNBUFFERED=1 HOME={home} HF_HOME={home}/.cache/huggingface")
    script = (STUBS + _systemctl(vals) + _line("serve_unit_val") + f'serve_user_refusal(){{ printf "%s" "{reason}"; }}\n'
              + 'install_serve_units(){ echo "CALLED install_serve_units $*"; }\n'
              + f'VENV_PY=/opt/meshembed/venv/bin/python\nMESHEMBED_ENABLE_SERVE={serve}\n'
              + _fn("install_serve_units_from_unit") + "install_serve_units_from_unit; echo DONE\n")
    p = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    return p.returncode, p.stdout


def test_upgrade_installs_the_launcher_for_the_unit_user_home_and_node_id(tmp_path):
    rc, out = _from_unit(tmp_path)
    assert rc == 0 and f"CALLED install_serve_units meshembed {tmp_path}/home /opt/meshembed/venv node-abc" in out


def test_upgrade_rechecks_sv1_and_installs_nothing_when_refused(tmp_path):
    rc, out = _from_unit(tmp_path, reason="the node daemon runs as root")
    assert rc == 0 and "CALLED" not in out and "WARN serve launcher NOT installed: the node daemon runs as root" in out


def test_upgrade_without_the_opt_in_installs_nothing(tmp_path):
    rc, out = _from_unit(tmp_path, serve="0")
    assert rc == 0 and "CALLED" not in out


def test_placement():
    up = INSTALL.index("# ── Upgrade path: harden the unit, restart the running daemon, then exit")
    exit0 = INSTALL.index("Upgrade complete.", up)
    # defined before the upgrade branch runs (bash defines functions as it reads)
    assert INSTALL.index("install_serve_units() {") < up and INSTALL.index("install_serve_units_from_unit() {") < up
    branch = INSTALL[up:exit0]
    ota = branch[branch.index('if [ -n "${MESHEMBED_PACKAGE_URL:-}" ]; then'):branch.index("Auto-update: the daemon will re-exec")]
    assert "install_serve_units_from_unit" not in ota                     # never on a self-update
    root = branch[branch.index('info "Restarting meshembed-node.service'):]
    call, restart = root.index("install_serve_units_from_unit"), root.index("systemctl restart meshembed-node.service")
    assert call < restart                                                  # the restart picks up MESHEMBED_SERVE=1
    # the early refusal sits after the re-enrol override and before anything is installed or registered
    early = INSTALL.index('if [ "$UPGRADE_ONLY" -eq 1 ] && [ "${MESHEMBED_ENABLE_SERVE:-0}" = "1" ]')
    assert INSTALL.index("UPGRADE_ONLY=0\nfi\n") < early < INSTALL.index("# ── Invite token")
    # the fresh install path is unchanged: it still calls the launcher with the fresh service user
    assert 'install_serve_units "$SVC_USER" "$SVC_HOME"' in INSTALL
