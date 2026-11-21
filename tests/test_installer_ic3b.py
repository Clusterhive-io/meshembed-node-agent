"""IC-3b (v0.3.85; the 2026-11-13 IC-3 finding): the v0.3.84 upgrade did not install the limits applier on three hardened hosts, and
nothing on the host said why (the root updater threw the installer's output away). F1: ONE layout reader that asks systemd for the
MERGED unit (drop-ins included). F2: the request directory is created AS THE USER, never by root inside the user's tree (auditor
D1). F3: every exit of the unit installers prints one tagged line (MESHEMBED_UNITS <set> <state>)."""
import os
import re
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


def _asu() -> str:
    """U1: the as_user helper block of install.sh (the harnesses below stub runuser/setpriv; the real functions call as_user)."""
    return INSTALL[INSTALL.index("AS_USER_DEFERRED=77"):INSTALL.index("\nensure_user_dir() {")] + "\n"


def _bash(script: str, env=None):
    """Run at the installer's own errexit shape: set -euo pipefail, the helper stubs, a marker after the call (OV-1 lesson)."""
    e = {**os.environ, "MESHEMBED_INSTALLER_TEST_MODE": "1", "MESHEMBED_TEST_ROOT_UID": str(os.getuid()), **(env or {})}
    pre = ("set -euo pipefail\nwarn(){ echo \"WARN $*\"; }\nok(){ echo \"OK $*\"; }\ninfo(){ echo \"INFO $*\"; }\n"
           "logger(){ :; }\n" + _fn("units_note"))
    return subprocess.run(["bash", "-c", pre + script], capture_output=True, text=True, env=e)


ME = os.environ.get("USER") or subprocess.run(["id", "-un"], capture_output=True, text=True).stdout.strip()


# ---- F1: the layout reader -------------------------------------------------------------------------------------------
def _layout(tmp_path, *, main_unit, merged, systemctl_rc=0, via_systemctl=True):
    """merged = what `systemctl show` prints for User / ProtectSystem / Environment (drop-ins included)."""
    sd = tmp_path / "sd"; sd.mkdir(exist_ok=True)
    (sd / "meshembed-node.service").write_text(main_unit)
    stub = ('systemctl(){ if [ "$#" -ge 4 ] && [ "$1" = show ]; then\n'
            f'  [ {systemctl_rc} -eq 0 ] || return {systemctl_rc}\n'
            '  case "$3" in User) echo "${M_USER}";; ProtectSystem) echo "${M_PS}";; Environment) echo "${M_ENV}";; esac\n'
            '  fi; }\n')
    env = {"MESHEMBED_SYSTEMD_DIR_OVERRIDE": str(sd), **{k: v for k, v in merged.items()}}
    if via_systemctl:
        env["MESHEMBED_TEST_LAYOUT_SYSTEMCTL"] = "1"
    # A DIRECT call (not inside $(...), where bash drops errexit): the strictest shape, so a missing `|| true` on a failing
    # pipeline aborts the script before CONTINUES (the OV-1 class).
    env["LAYOUT_OUT"] = str(tmp_path / "layout.out")
    p = _bash(stub + _fn("_systemd_dir") + _fn("_node_unit_layout")
              + '_node_unit_layout > "$LAYOUT_OUT"\necho "LAYOUT=[$(cat "$LAYOUT_OUT")]"\necho CONTINUES\n', env)
    return p


MAIN_NO_HARDENING = "[Service]\nExecStart=/opt/meshembed-node/.venv/bin/python -m meshembed_node\n"        # nothing the old grep needs
MERGED_OK = {"M_USER": "meshembed", "M_PS": "strict", "M_ENV": "LANG=C.UTF-8 HOME=/var/lib/meshembed-node PYTHONUNBUFFERED=1"}


def test_f1_a_hardening_line_in_a_dropin_is_seen_through_the_merged_unit(tmp_path):
    # The IC-3 case: User / HOME / ProtectSystem are NOT in the main file (they live in a drop-in), but systemd's merged view has them.
    p = _layout(tmp_path, main_unit=MAIN_NO_HARDENING, merged=MERGED_OK)
    assert p.returncode == 0 and "LAYOUT=[meshembed /var/lib/meshembed-node]" in p.stdout and p.stdout.endswith("CONTINUES\n"), p.stdout + p.stderr


def test_f1_negative_control_the_old_main_file_grep_misses_exactly_that_case(tmp_path):
    p = _layout(tmp_path, main_unit=MAIN_NO_HARDENING, merged=MERGED_OK, via_systemctl=False)       # the tests' file-grep branch = the old logic
    assert p.returncode == 0 and "LAYOUT=[]" in p.stdout


@pytest.mark.parametrize("merged,why", [
    ({**MERGED_OK, "M_USER": "root"}, "a root service is not a hardened node"),
    ({**MERGED_OK, "M_PS": "no"}, "ProtectSystem is not strict"),
    ({**MERGED_OK, "M_PS": ""}, "ProtectSystem unset"),
    ({**MERGED_OK, "M_ENV": "LANG=C.UTF-8"}, "no HOME in the environment"),
    ({**MERGED_OK, "M_USER": ""}, "no user"),
])
def test_f1_a_layout_that_is_not_a_hardened_node_prints_nothing(tmp_path, merged, why):
    p = _layout(tmp_path, main_unit=MAIN_NO_HARDENING, merged=merged)
    assert p.returncode == 0 and "LAYOUT=[]" in p.stdout and p.stdout.endswith("CONTINUES\n"), why


def test_f1_a_failing_systemctl_does_not_abort_the_installer_under_errexit(tmp_path):
    # OV-1 class: `h=$(systemctl ... | tr | sed | head)` under set -euo pipefail must not kill the installer.
    p = _layout(tmp_path, main_unit=MAIN_NO_HARDENING, merged=MERGED_OK, systemctl_rc=1)
    assert p.returncode == 0 and "LAYOUT=[]" in p.stdout and p.stdout.endswith("CONTINUES\n"), p.stdout + p.stderr


def test_f1_both_callers_use_the_same_reader():
    assert "_node_unit_layout" in _fn("install_updater_units_from_unit")
    assert "_node_unit_layout" in _fn("refresh_owned_units_from_unit")
    assert "sed -n 's/^User=//p'" not in _fn("install_updater_units_from_unit")        # no private grep left in the updater refresh


def test_f1_the_updater_refresh_gets_the_dropin_layout_too(tmp_path):
    sd = tmp_path / "sd"; sd.mkdir()
    (sd / "meshembed-node.service").write_text(MAIN_NO_HARDENING)
    stub = ('systemctl(){ case "$3" in User) echo meshembed;; ProtectSystem) echo strict;; Environment) echo "HOME=/var/lib/meshembed-node";; esac; }\n'
            'install_updater_units(){ echo "UPDATER $*"; }\nVENV_PY=/opt/meshembed-node/.venv/bin/python\n')
    p = _bash(stub + _fn("_systemd_dir") + _fn("_node_unit_layout") + _fn("install_updater_units_from_unit")
              + "install_updater_units_from_unit\necho CONTINUES\n",
              {"MESHEMBED_SYSTEMD_DIR_OVERRIDE": str(sd), "MESHEMBED_TEST_LAYOUT_SYSTEMCTL": "1"})
    assert "UPDATER meshembed /var/lib/meshembed-node /opt/meshembed-node/.venv" in p.stdout and p.stdout.endswith("CONTINUES\n"), p.stdout + p.stderr


# ---- F2: the request directory is created as the user, root never writes in the user's tree ----------------------------
RUNUSER = ('runuser(){ shift 3; if [ "$1" = env ]; then shift; while [ "$1" = -i ] || [ "${1#*=}" != "$1" ]; do shift; done; fi; '    # U1-b: as_user wraps the command in env -i VAR=..
           'echo "RUNUSER $*" >> "$RU_LOG"; "$@"; }\n')      # runuser -u <user> -- cmd ...


def _mur(tmp_path, home, user=ME):
    (tmp_path / "ru.log").write_text("")
    f = f"{home}/.meshembed/limits-request"
    return _bash(RUNUSER + _asu() + _fn("ensure_user_dir") + _fn("make_user_request_file") + f'make_user_request_file "{user}" "{f}"\necho CONTINUES\n',
                 {"RU_LOG": str(tmp_path / "ru.log")}), f


def test_f2_a_missing_dot_meshembed_is_created_as_the_user_0700_then_the_file_0600(tmp_path):
    home = tmp_path / "home"; home.mkdir()
    p, f = _mur(tmp_path, home)
    d = home / ".meshembed"
    assert p.returncode == 0 and p.stdout.endswith("CONTINUES\n") and "WARN" not in p.stdout, p.stdout + p.stderr
    assert d.is_dir() and oct(d.stat().st_mode & 0o777) == "0o700"
    assert Path(f).is_file() and oct(Path(f).stat().st_mode & 0o777) == "0o600"
    log = (tmp_path / "ru.log").read_text()
    assert "RUNUSER mkdir -m 0700 -- " in log and "RUNUSER sh -c" in log            # BOTH steps ran through runuser


def test_f2_a_symlinked_directory_is_refused_and_its_target_untouched(tmp_path):
    home = tmp_path / "home"; home.mkdir()
    victim = tmp_path / "victim"; victim.mkdir(); victim.chmod(0o755)
    (home / ".meshembed").symlink_to(victim)
    p, f = _mur(tmp_path, home)
    assert p.returncode == 0 and "is a symlink" in p.stdout and p.stdout.endswith("CONTINUES\n")
    assert oct(victim.stat().st_mode & 0o777) == "0o755" and not (victim / "limits-request").exists()
    assert (tmp_path / "ru.log").read_text() == ""                                     # nothing ran as anyone


def test_f2_a_directory_owned_by_someone_else_is_refused(tmp_path):
    home = tmp_path / "home"; (home / ".meshembed").mkdir(parents=True)
    p, f = _mur(tmp_path, home, user="not-the-owner-zz")
    assert p.returncode == 0 and "is not a directory owned by not-the-owner-zz" in p.stdout and p.stdout.endswith("CONTINUES\n")
    assert not Path(f).exists()


def test_f2_a_symlinked_request_file_is_left_alone(tmp_path):
    home = tmp_path / "home"; (home / ".meshembed").mkdir(parents=True)
    target = tmp_path / "t"; target.write_text("keep\n")
    (home / ".meshembed" / "limits-request").symlink_to(target)
    p, f = _mur(tmp_path, home)
    assert "is a symlink" in p.stdout and target.read_text() == "keep\n"


def test_f2_root_never_creates_chowns_or_chmods_in_the_users_tree_source_level():
    for fn in ("make_user_request_file", "ensure_user_dir"):
        code = "\n".join(l for l in _fn(fn).splitlines() if not l.lstrip().startswith("#"))
        for banned in ("install -d", "mkdir -p", "chown", "install -o"):
            assert banned not in code, (fn, banned)
        # every mkdir / chmod / write is behind as_user (U1: the ONE place a user switch happens)
        assert re.findall(r"^\s*(?!.*as_user)(?!.*warn)(?!.*stat -c).*\b(?:mkdir|chmod)\b", code, re.M) == [], fn
    assert 'ensure_user_dir "$u" "$d" 0700' in _fn("make_user_request_file")
    h = _fn("ensure_user_dir")
    assert 'as_user "$u" mkdir -m "$m" -- "$d"' in h and 'as_user "$u" chmod "$m" -- "$d"' in h


# ---- IC3B-H1 (auditor 2026-11-13T17:23:11Z, HIGH): the updater installer's request directory ------------------------------
def _eud(tmp_path, d, user=ME, mode="0700"):
    (tmp_path / "ru.log").write_text("")
    return _bash(RUNUSER + _asu() + _fn("ensure_user_dir") + f'ensure_user_dir "{user}" "{d}" {mode} && echo RC0 || echo RC1\necho CONTINUES\n',
                 {"RU_LOG": str(tmp_path / "ru.log")})


def test_h1_the_old_root_command_really_follows_a_symlink_and_remodes_its_target(tmp_path):
    # The auditor's demonstration, kept as a control: GNU `install -d` on a symlink re-modes the TARGET. (As root, -o / -g would chown it too.)
    victim = tmp_path / "victim"; victim.mkdir(); victim.chmod(0o755)
    link = tmp_path / ".meshembed"; link.symlink_to(victim)
    subprocess.run(["install", "-d", "-m", "0700", str(link)], check=True)
    assert oct(victim.stat().st_mode & 0o777) == "0o700"              # the hazard is real: the link's target was modified


def test_h1_a_daemon_planted_symlink_is_refused_and_its_target_is_untouched(tmp_path):
    victim = tmp_path / "victim"; victim.mkdir(); victim.chmod(0o755)
    link = tmp_path / ".meshembed"; link.symlink_to(victim)
    p = _eud(tmp_path, link)
    assert "RC1" in p.stdout and "is a symlink" in p.stdout and p.stdout.endswith("CONTINUES\n"), p.stdout + p.stderr
    assert oct(victim.stat().st_mode & 0o777) == "0o755"             # NOT re-moded: root did nothing through the link
    assert (tmp_path / "ru.log").read_text() == ""                   # and nothing ran at all (not even as the user)


def test_h1_a_symlink_swapped_in_after_the_first_test_is_still_not_followed_by_root(tmp_path):
    # The window the old code had: dir absent at the first test, a link by the time the mkdir runs. The mkdir runs AS THE USER and
    # the owner / symlink tests run again after it, so the swap yields a refusal, never a root write.
    victim = tmp_path / "victim"; victim.mkdir(); victim.chmod(0o755)
    d = tmp_path / ".meshembed"
    swap = f'runuser(){{ shift 3; ln -s "{victim}" "{d}" 2>/dev/null || true; "$@" 2>/dev/null || true; }}\n'     # the mkdir "loses the race"
    p = _bash(swap + _asu() + _fn("ensure_user_dir") + f'ensure_user_dir "{ME}" "{d}" 0700 && echo RC0 || echo RC1\necho CONTINUES\n')
    assert "RC1" in p.stdout and p.stdout.endswith("CONTINUES\n"), p.stdout + p.stderr
    assert oct(victim.stat().st_mode & 0o777) == "0o755"


def test_h1_a_missing_directory_is_created_as_the_user_with_the_mode(tmp_path):
    d = tmp_path / "h" / ".meshembed"; d.parent.mkdir()
    p = _eud(tmp_path, d)
    assert "RC0" in p.stdout and oct(d.stat().st_mode & 0o777) == "0o700"
    assert "RUNUSER mkdir -m 0700 -- " in (tmp_path / "ru.log").read_text()


def test_h1_b3_an_existing_loose_directory_is_tightened_to_0700_AS_THE_USER(tmp_path):
    d = tmp_path / ".meshembed"; d.mkdir(); d.chmod(0o755)                     # e.g. left by an older root install
    p = _eud(tmp_path, d)
    assert "RC0" in p.stdout and oct(d.stat().st_mode & 0o777) == "0o700"
    assert "RUNUSER chmod 0700 -- " in (tmp_path / "ru.log").read_text()


def test_h1_an_existing_correct_directory_is_left_alone(tmp_path):
    d = tmp_path / ".meshembed"; d.mkdir(); d.chmod(0o700)
    p = _eud(tmp_path, d)
    assert "RC0" in p.stdout and (tmp_path / "ru.log").read_text() == ""       # no mkdir, no chmod


def test_h1_a_directory_owned_by_someone_else_or_a_file_is_refused(tmp_path):
    d = tmp_path / ".meshembed"; d.mkdir()
    assert "RC1" in _eud(tmp_path, d, user="not-the-owner-zz").stdout
    f = tmp_path / "afile"; f.write_text("x")
    assert "RC1" in _eud(tmp_path, f).stdout


def test_h1_the_updater_installer_uses_it_and_a_refusal_skips_the_rest_with_a_note(tmp_path):
    body = _fn("install_updater_units")
    assert 'ensure_user_dir "$u" "$h/.meshembed" 0700' in body and 'install -d -m 0700 -o "$u"' not in body
    stubs = ('id(){ echo 0; }\nensure_user_dir(){ return 1; }\ninstall(){ echo "ROOT_INSTALL_CALLED $*"; }\n'
             'cat(){ echo "ROOT_CAT_CALLED"; }\nsystemctl(){ echo "SYSTEMCTL_CALLED"; }\n')
    venv = tmp_path / "venv"; (venv / "bin").mkdir(parents=True); (venv / "bin" / "python").write_text("#!/bin/sh\n"); (venv / "bin" / "python").chmod(0o755)
    p = _bash(stubs + body + f'install_updater_units meshembed /var/lib/meshembed-node "{venv}"\necho CONTINUES\n')
    assert "MESHEMBED_UNITS updater skipped:state_dir" in p.stdout and p.stdout.endswith("CONTINUES\n"), p.stdout + p.stderr
    assert "ROOT_INSTALL_CALLED" not in p.stdout and "ROOT_CAT_CALLED" not in p.stdout and "SYSTEMCTL_CALLED" not in p.stdout


# ---- F3: one tagged line per exit of install_limits_units ---------------------------------------------------------------
def test_f3_every_early_exit_of_install_limits_units_prints_a_tagged_line():
    body = _fn("install_limits_units").splitlines()
    exits = [i for i, l in enumerate(body) if re.search(r"\breturn 0\b", l)]
    assert len(exits) >= 7, exits
    untagged = []
    for n, i in enumerate(exits):
        if n == 0:
            continue                                                                     # the first is "not root / not Linux": not applicable
        window = "\n".join(body[max(0, i - 2):i + 1])
        if "units_note limits" not in window:
            untagged.append(body[i].strip()[:80])
    assert not untagged, untagged


def _ilu(tmp_path, *, user="meshembed", home="/var/lib/meshembed-node", venv="/nonexistent", marker=None, env=None):
    tmp_path = tmp_path / f"case{len(list(tmp_path.glob('case*')))}"                  # a fresh dir per call: the marker must not leak between cases
    tmp_path.mkdir()
    mk = tmp_path / "limits-disabled"
    if marker:
        mk.write_text("")
    stubs = ('id(){ if [ "${1:-}" = -u ]; then echo 0; else command id "$@"; fi; }\n'
             'uname(){ echo Linux; }\n'
             'install(){ command install "$@" 2>/dev/null || true; }\n')
    e = {"MESHEMBED_LIMITS_MARKER_OVERRIDE": str(mk), **(env or {})}
    return _bash(stubs + _fn("_limits_disabled_marker") + _fn("install_limits_units")
                 + f'install_limits_units "{user}" "{home}" "{venv}"\necho CONTINUES\n', e)


def test_f3_opt_out_earlier_user_layout_exits_print_their_reason(tmp_path):
    assert "MESHEMBED_UNITS limits skipped:opted_out_earlier" in _ilu(tmp_path, marker=True).stdout
    assert "MESHEMBED_UNITS limits skipped:user_not_recognised" in _ilu(tmp_path, user="Bad User!").stdout
    p = _ilu(tmp_path, venv="/nonexistent/venv")
    assert "MESHEMBED_UNITS limits skipped:layout_not_recognised" in p.stdout and p.stdout.endswith("CONTINUES\n")
    p = _ilu(tmp_path, env={"MESHEMBED_ENABLE_LIMITS": "0"}, venv="/nonexistent")
    assert "MESHEMBED_UNITS limits opted_out" in p.stdout


def test_f3_the_refresh_caller_tags_a_missing_layout(tmp_path):
    sd = tmp_path / "sd"; sd.mkdir()
    (sd / "meshembed-node.service").write_text("[Service]\nUser=root\n")               # not a hardened node
    p = _bash('VENV_PY=/opt/meshembed-node/.venv/bin/python\n' + _fn("_systemd_dir") + _fn("_node_unit_layout")
              + _fn("refresh_owned_units_from_unit") + "refresh_owned_units_from_unit\necho CONTINUES\n",
              {"MESHEMBED_SYSTEMD_DIR_OVERRIDE": str(sd)})
    assert "MESHEMBED_UNITS limits skipped:layout_not_recognised" in p.stdout and p.stdout.endswith("CONTINUES\n")


def test_f3_the_updater_installer_tags_its_exits():
    body = _fn("install_updater_units")
    assert "units_note updater skipped:layout_not_recognised" in body
    assert "units_note updater installed_without_heal" in body and "units_note updater installed\n" in body
    assert body.count("units_note updater skipped:enable_failed") == 2


def test_f3_the_note_format_is_the_closed_one_the_updater_will_accept():
    for reason in re.findall(r"units_note (?:limits|updater) ([a-z_:]+)", INSTALL):
        assert re.fullmatch(r"[a-z_]+(?::[a-z_]+)?", reason), reason
    p = _bash('units_note limits skipped:no_request_file\n')
    assert p.stdout == "MESHEMBED_UNITS limits skipped:no_request_file\n"


# ---- IC3B-H1b (LOW, same class): the opt-in flags are appended to the user's .env AS THE USER ---------------------------------
# (the helper tests that lived here moved to test_installer_split_upgrade.py: the train now uses master's append_node_env_flag, SU-1,
#  auditor GO 2026-11-17T10:23:45Z; the control below and the call-site test stay)
def test_h1b_the_old_root_append_really_writes_through_a_symlink(tmp_path):
    # control, as for H1: `>>` follows a link, so a root append through a daemon-controlled .env lands in the link's target
    target = tmp_path / "target"; target.write_text("precious\n")
    link = tmp_path / ".env"; link.symlink_to(target)
    subprocess.run(["bash", "-c", f"printf 'MESHEMBED_SERVE=1\\n' >> '{link}'"], check=True)
    assert target.read_text() == "precious\nMESHEMBED_SERVE=1\n"


def test_h1b_the_three_opt_in_installers_use_it_and_root_appends_nothing_itself():
    for fn, key in (("install_serve_units", "MESHEMBED_SERVE"), ("install_split_units", "MESHEMBED_ENABLE_SPLIT"),
                    ("install_agent_host_units", "MESHEMBED_AGENT_HOST")):
        body = _fn(fn)
        assert f'append_node_env_flag "$u" "$h" {key}' in body, fn
        assert '>> "$h/.meshembed/.env"' not in body, fn
    code = "\n".join(l for l in INSTALL.splitlines() if not l.lstrip().startswith("#"))
    assert re.findall(r'>>\s*"\$h/\.meshembed/', code) == []                         # no root redirect into the user's tree is left
