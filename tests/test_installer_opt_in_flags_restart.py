"""E3a-1 finding (2026-10-28): the opt-in units (split / agent host / serve) append their flag to the daemon's .env AFTER
the daemon was started, so a fresh install reported serve_off until its first restart. The installer now restarts the
daemon once when the .env changed, never starts a paused node, and never aborts the install (set -euo pipefail)."""
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = (ROOT / "install.sh").read_text()


def _fn() -> str:
    start = INSTALL.index("apply_opt_in_flags() {\n")
    end = INSTALL.index("\n}\n", start) + 3
    return INSTALL[start:end]


def _run(tmp_path, change: bool, paused: bool = False, restart_rc: int = 0):
    envf = tmp_path / ".env"
    envf.write_text("MESHEMBED_NODE_ID=x\n")
    script = ("set -euo pipefail\nwarn(){ echo \"WARN $*\"; }\nok(){ echo \"OK $*\"; }\n"
              f"node_paused(){{ return {0 if paused else 1}; }}\n"
              f"systemctl(){{ echo CALLED systemctl \"$@\"; return {restart_rc}; }}\n" + _fn()
              + f'before="$(sha256sum "{envf}" 2>/dev/null || true)"\n'
              + (f"printf 'MESHEMBED_SERVE=1\\n' >> \"{envf}\"\n" if change else "")
              + f'apply_opt_in_flags "$before" "{envf}"\necho DONE\n')
    p = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    return p.returncode, p.stdout


def test_unchanged_env_restarts_nothing(tmp_path):
    rc, out = _run(tmp_path, change=False)
    assert rc == 0 and "CALLED" not in out and out.endswith("DONE\n")


def test_a_new_flag_restarts_the_daemon_once(tmp_path):
    rc, out = _run(tmp_path, change=True)
    assert rc == 0 and out.count("CALLED systemctl") == 1
    assert "CALLED systemctl try-restart meshembed-node.service" in out      # try-restart: never STARTS a stopped unit


def test_a_paused_node_is_never_restarted(tmp_path):
    rc, out = _run(tmp_path, change=True, paused=True)
    assert rc == 0 and "CALLED" not in out


def test_a_failed_restart_warns_and_the_install_goes_on(tmp_path):
    rc, out = _run(tmp_path, change=True, restart_rc=1)
    assert rc == 0 and "WARN could not restart" in out and out.endswith("DONE\n")


def test_a_missing_env_file_does_not_abort(tmp_path):
    script = ("set -euo pipefail\nwarn(){ :; }\nok(){ :; }\nnode_paused(){ return 1; }\n"
              "systemctl(){ echo CALLED; }\n" + _fn()
              + f'b="$(sha256sum "{tmp_path}/none" 2>/dev/null || true)"\napply_opt_in_flags "$b" "{tmp_path}/none"\n'
              "echo DONE\n")
    p = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert p.returncode == 0 and p.stdout == "DONE\n"


def test_the_root_path_hashes_before_the_opt_in_units_and_applies_after():
    i = INSTALL.index('_env_before="$(sha256sum "$SVC_HOME/.meshembed/.env" 2>/dev/null || true)"')
    calls = [INSTALL.index(c, i) for c in ("install_split_units \"$SVC_USER\"", "install_agent_host_units \"$SVC_USER\"",
                                           "install_serve_units \"$SVC_USER\"",
                                           'apply_opt_in_flags "$_env_before" "$SVC_HOME/.meshembed/.env"')]
    assert calls == sorted(calls)
    assert INSTALL.rindex("systemctl enable --now meshembed-node.service", 0, i) < i   # the daemon start comes first
    assert re.search(r'grep -q \'\^MESHEMBED_SERVE=\'', INSTALL)                      # the flag write it applies
