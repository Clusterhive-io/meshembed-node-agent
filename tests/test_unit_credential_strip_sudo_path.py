"""The node API key leaves the world-readable unit on the passwordless-sudo upgrade path too (v0.3.76).

2026-10-17, 187: verify-coloc found the node key inline in /etc/systemd/system/meshembed-node.service (0644, readable
by every local uid through `systemctl show`). install.sh's _harden_unit moved credentials into the 0600 .env only when
the installer ran as ROOT; 187 updates as its own user through `sudo -n`, and that branch only bumped Restart=. These
tests run the REAL function from install.sh with stubbed sudo/systemctl against a temp unit, as a non-root caller.
"""
import os
import re
import subprocess
from pathlib import Path

INSTALL = (Path(__file__).resolve().parents[1] / "install.sh").read_text()


def _fn() -> str:
    start = INSTALL.index("        _harden_unit() {\n")
    end = INSTALL.index("\n        }\n", start) + len("\n        }\n")
    return INSTALL[start:end]


def _run(tmp_path, env_lines, sudo_ok=True):
    home = tmp_path / "home"
    (home / ".meshembed").mkdir(parents=True)
    (home / ".meshembed" / ".env").write_text("\n".join(env_lines) + "\n")
    unit = tmp_path / "meshembed-node.service"
    unit.write_text(
        "[Service]\n"
        f"Environment=HOME={home}\n"
        "Environment=MESHEMBED_NODE_API_KEY=msh_node_SECRET\n"
        "Environment=MESHEMBED_NODE_ID=nid\n"
        "Environment=MESHEMBED_BACKEND=https://b\n"
        "Restart=on-failure\n"
        "ExecStart=/opt/x/bin/python -m meshembed_node run\n")
    script = (
        "set -e\n"
        'info(){ echo "INFO $*"; }\nwarn(){ echo "WARN $*"; }\n'
        "systemctl(){ :; }\n"
        + ("sudo(){ [ \"$1\" = -n ] && shift; \"$@\"; }\n" if sudo_ok else "sudo(){ return 1; }\n")
        + _fn()
        + f'MESHEMBED_INSTALLER_TEST_MODE=1 MESHEMBED_UNIT_FILE_OVERRIDE="{unit}" _harden_unit "sudo -n"\n'
    )
    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    return unit.read_text(), out.stdout, home


FULL = ["MESHEMBED_BACKEND=https://b", "MESHEMBED_NODE_API_KEY=msh_node_SECRET", "MESHEMBED_NODE_ID=nid"]


def test_the_sudo_path_moves_the_key_out_of_the_unit(tmp_path):
    unit, out, home = _run(tmp_path, FULL)
    assert "MESHEMBED_NODE_API_KEY" not in unit and "MESHEMBED_NODE_ID" not in unit and "MESHEMBED_BACKEND" not in unit
    assert re.search(rf"^Environment=HOME={re.escape(str(home))}\nEnvironmentFile=-{re.escape(str(home))}/\.meshembed/\.env$",
                     unit, re.M), unit
    assert "Restart=always" in unit and "credentials now read from" in out


def test_without_all_three_values_in_the_env_the_unit_is_left_alone(tmp_path):
    unit, out, _ = _run(tmp_path, FULL[:2])               # no MESHEMBED_NODE_ID in the .env
    assert "Environment=MESHEMBED_NODE_API_KEY=msh_node_SECRET" in unit, "never strand the daemon without credentials"
    assert "EnvironmentFile=" not in unit


def test_a_refused_sudo_says_so_loudly_and_changes_nothing(tmp_path):
    unit, out, _ = _run(tmp_path, FULL, sudo_ok=False)
    assert "Environment=MESHEMBED_NODE_API_KEY=msh_node_SECRET" in unit
    assert "WARN" in out and "still inline" in out and "msh_node_SECRET" not in out


def test_both_sudo_branches_use_the_same_function():
    assert INSTALL.count('_harden_unit "sudo -n"') == 2
    assert "sudo -n sed -i 's|^Restart=on-failure|Restart=always|'" not in INSTALL, "no more Restart-only sudo branch"


def test_the_unit_path_override_is_a_test_hook_only(tmp_path):
    """auditor 2026-10-20 17:31Z: without MESHEMBED_INSTALLER_TEST_MODE=1 the environment cannot point the root sed
    at another file; the function falls back to the real unit path (absent or not writable here: no edit)."""
    unit = tmp_path / "meshembed-node.service"
    body = "[Service]\nRestart=on-failure\nEnvironment=MESHEMBED_NODE_API_KEY=k\n"
    unit.write_text(body)
    script = ('set -e\ninfo(){ echo "INFO $*"; }\nwarn(){ echo "WARN $*"; }\nsystemctl(){ :; }\n'
              "sudo(){ return 1; }\n" + _fn() + f'MESHEMBED_UNIT_FILE_OVERRIDE="{unit}" _harden_unit ""\n')
    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                         env={k: v for k, v in os.environ.items() if k != "MESHEMBED_INSTALLER_TEST_MODE"})
    assert out.returncode == 0, out.stderr
    assert unit.read_text() == body and "hardened" not in out.stdout
    assert 'f=/etc/systemd/system/meshembed-node.service' in _fn()
