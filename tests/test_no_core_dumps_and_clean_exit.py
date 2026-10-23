"""No core dumps of the node daemon, and a completed drain ends the process without native finalisers (v0.3.76).

2026-10-17, 187 (M60): `systemctl stop meshembed-node` during the M1-F drain ended in "code=dumped, status=6/ABRT".
A core of this process holds its environment (the node API key) and memory that can include customer document text,
and systemd-coredump keeps it under /var/lib/systemd/coredump. The unit now says LimitCORE=0 (fresh installs and
upgrades), and after run() returns the daemon exits like the drain watchdog does (flush logs, os._exit(0)).
"""
import logging
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = (ROOT / "install.sh").read_text()


def _fn() -> str:
    start = INSTALL.index("        _harden_unit() {\n")
    end = INSTALL.index("\n        }\n", start) + len("\n        }\n")
    return INSTALL[start:end]


def _harden(tmp_path, body, sudo="sudo -n"):
    unit = tmp_path / "meshembed-node.service"
    unit.write_text(body)
    script = ("set -e\n" 'info(){ echo "INFO $*"; }\nwarn(){ echo "WARN $*"; }\n' "systemctl(){ :; }\n"
              "sudo(){ [ \"$1\" = -n ] && shift; \"$@\"; }\n" + _fn()
              + f'MESHEMBED_INSTALLER_TEST_MODE=1 MESHEMBED_UNIT_FILE_OVERRIDE="{unit}" _harden_unit "{sudo}"\n')
    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    return unit.read_text(), out.stdout


def test_fresh_unit_template_disables_core_dumps():
    start = INSTALL.index("ExecStart=$VENV_PY -m meshembed_node run")
    assert "\nLimitCORE=0\n" in INSTALL[start:start + 600]


def test_upgrade_adds_limitcore_once_after_restart(tmp_path):
    body = "[Service]\nEnvironment=HOME=/h\nRestart=on-failure\nExecStart=/x run\n"
    unit, out = _harden(tmp_path, body)
    assert "Restart=always\nLimitCORE=0\n" in unit and "LimitCORE=0" in out
    unit2, _ = _harden(tmp_path, unit)                      # a second upgrade adds nothing
    assert unit2.count("LimitCORE=") == 1


def test_an_operator_limitcore_is_left_alone(tmp_path):
    body = "[Service]\nRestart=always\nLimitCORE=infinity\nExecStart=/x run\n"
    unit, _ = _harden(tmp_path, body, sudo="")
    assert unit.count("LimitCORE=") == 1 and "LimitCORE=infinity" in unit


def test_exit_after_drain_flushes_and_exits_zero():
    from meshembed_node.worker import exit_after_drain

    flushed, codes = [], []

    class H(logging.Handler):
        def emit(self, record):
            pass

        def flush(self):
            flushed.append(True)

    h = H()
    logging.getLogger().addHandler(h)
    try:
        exit_after_drain(_exit=codes.append)
    finally:
        logging.getLogger().removeHandler(h)
    assert codes == [0] and flushed


def test_both_daemon_entry_paths_end_with_exit_after_drain():
    main = (ROOT / "meshembed_node" / "__main__.py").read_text()
    assert main.count("    run(cfg)\n    exit_after_drain()\n") == 1
    assert main.count("        run(cfg)\n        exit_after_drain()\n") == 1
