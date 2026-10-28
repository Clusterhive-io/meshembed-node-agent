"""AR1 G9 / S6: the installer's agent-host half. Opt-in (MESHEMBED_AGENT_HOST=1), Linux root installs only, the unit
installed DISABLED and byte-identical to agent-unit/meshembed-agent.service; macOS / Windows have no agent host."""
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = (ROOT / "install.sh").read_text()
UNIT = (ROOT / "agent-unit" / "meshembed-agent.service").read_text()


def _fn() -> str:
    start = INSTALL.index("install_agent_host_units() {\n")
    end = INSTALL.index("\n}\n", start) + 3
    return INSTALL[start:end]


def test_the_installed_unit_is_the_reviewed_file():
    body = re.search(r"cat > /etc/systemd/system/meshembed-agent.service << 'UNIT'\n(.*?)\nUNIT\n", _fn(), re.S)
    assert body and body.group(1) + "\n" == UNIT


def test_installed_disabled_and_called_from_the_root_path():
    fn = _fn()
    assert "systemctl enable" not in fn and "systemctl start" not in fn
    assert 'install_agent_host_units "$SVC_USER" "$SVC_HOME"' in INSTALL
    assert "d /run/meshembed 0750 %s mesh-agent" in fn                      # the socket dir (auditor 13:58Z)
    assert "--shell /usr/sbin/nologin mesh-agent" in fn and "--no-create-home" in fn


def _run(env_flag, uname="Linux", uid="0", user="meshembed"):
    script = ("set -u\nwarn(){ echo \"WARN $*\"; }\nok(){ echo \"OK $*\"; }\n"
              f"id(){{ echo {uid}; }}\nuname(){{ echo {uname}; }}\n"
              "getent(){ echo \"CALLED getent\"; return 1; }\ngroupadd(){ echo CALLED groupadd; }\n"
              "useradd(){ echo CALLED useradd; }\ninstall(){ echo CALLED install; }\n"
              "systemctl(){ echo CALLED systemctl \"$@\"; }\n" + _fn()
              + f'MESHEMBED_AGENT_HOST={env_flag} install_agent_host_units "{user}" /nonexistent-home\n')
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True).stdout


def test_off_by_default_and_refusals():
    assert _run("0") == ""                                                    # no flag: nothing at all
    assert "Linux root installs only" in _run("1", uname="Darwin") and "CALLED" not in _run("1", uname="Darwin")
    assert "Linux root installs only" in _run("1", uid="1000")
    out = _run("1", user="bad user;rm")
    assert "service user not recognised" in out and "CALLED" not in out


def test_macos_and_windows_refuse_the_agent_host():
    """S6 / three installers: a designation on macOS or Windows is refused with a closed reason; nothing is set up."""
    for f in ("install-mac.sh", "install.ps1"):
        src = (ROOT / f).read_text()
        assert "meshembed-agent" not in src and "mesh-agent" not in src                # no user, no unit
        assert "agent_host_linux_only" in src and src.count("MESHEMBED_AGENT_HOST") == 1


def test_mac_refusal_runs(tmp_path):
    lines = (ROOT / "install-mac.sh").read_text().splitlines()
    i = [n for n, l in enumerate(lines) if "MESHEMBED_AGENT_HOST" in l][0]
    script = 'info(){ echo "INFO $*"; }\n' + lines[i]
    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                         env={"MESHEMBED_AGENT_HOST": "1", "PATH": "/usr/bin:/bin"}).stdout
    assert "agent_host_linux_only" in out


def test_host_config_dir_is_root_with_the_daemon_group():
    assert 'install -d -m 0750 -o root -g "$(id -gn "$u")" /etc/meshembed-agent' in _fn()   # W1
