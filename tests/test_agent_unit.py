"""AR1 G9: units-lint for meshembed-agent.service (auditor 13:19Z S1, S4, S6) and the G0 agent profile."""
from pathlib import Path

import pytest

from meshembed_node import agent_g0 as G

UNIT = (Path(__file__).resolve().parents[1] / "agent-unit" / "meshembed-agent.service").read_text()
LINES = [l.strip() for l in UNIT.splitlines() if l.strip() and not l.strip().startswith("#")]
KV = {}
for l in LINES:
    if "=" in l and not l.startswith("["):
        k, v = l.split("=", 1)
        KV.setdefault(k, []).append(v)


REQUIRED = {
    "User": "mesh-agent", "PrivateNetwork": "yes", "RestrictAddressFamilies": "AF_UNIX", "NoNewPrivileges": "yes",
    "CapabilityBoundingSet": "", "AmbientCapabilities": "", "ProtectSystem": "strict", "ProtectHome": "yes",
    "PrivateTmp": "yes", "PrivateDevices": "yes", "ProtectProc": "invisible", "ProcSubset": "pid",
    "ProtectKernelTunables": "yes", "ProtectKernelModules": "yes", "ProtectKernelLogs": "yes",
    "ProtectControlGroups": "yes", "ProtectClock": "yes", "ProtectHostname": "yes", "MemoryDenyWriteExecute": "yes",
    "LockPersonality": "yes", "RestrictNamespaces": "yes", "RestrictRealtime": "yes", "RestrictSUIDSGID": "yes",
    "KeyringMode": "private", "RemoveIPC": "yes", "UMask": "0077", "SystemCallArchitectures": "native",
    "StateDirectory": "mesh-agent", "StateDirectoryMode": "0700",
}


@pytest.mark.parametrize("key,value", sorted(REQUIRED.items()))
def test_the_sandbox_directive(key, value):
    assert KV.get(key) == [value], (key, KV.get(key))


def test_no_environment_no_network_no_lane_key():
    assert "EnvironmentFile" not in KV and "Environment" not in KV and "PassEnvironment" not in KV  # G9
    assert KV["SystemCallFilter"] == ["@system-service", "~@privileged"]
    assert not any(k.startswith("IPAddress") for k in KV)            # moot: PrivateNetwork=yes (S1)
    creds = KV.get("LoadCredential", []) + KV.get("LoadCredentialEncrypted", [])
    assert [c.split(":", 1)[0] for c in creds] == ["state-key"]      # never the lane key (S1)
    assert KV.get("ReadWritePaths") == [""]                          # nothing beyond the StateDirectory
    assert KV["ExecStartPre"] == ["/opt/meshembed-node/.venv/bin/python -I -m meshembed_node.agent_g0"]
    assert KV["ExecStart"] == ["/opt/meshembed-node/.venv/bin/python -I -m meshembed_node.agent_host"]
    assert "WantedBy" in KV                                          # installable; shipped DISABLED by the installer


@pytest.mark.parametrize("env,code", [
    ({"PATH": "/usr/bin"}, "ok"),
    ({"PATH": "/usr/bin", "LLAMA_ARG_THREADS": "4"}, "g0_forbidden_env"),
    ({"PATH": "/usr/bin", "PYTHONPATH": "/tmp/x"}, "g0_forbidden_env"),
    ({"PATH": "/usr/bin", "LD_PRELOAD": "/tmp/x.so"}, "g0_forbidden_env"),
    ({"PATH": "/usr/bin", "MESHEMBED_BACKEND": "https://x"}, "g0_forbidden_env"),      # no backend URL (S1)
    ({"PATH": "/usr/bin", "pythonwarnings": "x"}, "g0_forbidden_env"),
    ({"PATH": "/usr/bin", "SOMETHING_NEW": "1"}, "g0_unexpected_env"),
])
def test_g0_environment(env, code, tmp_path):
    assert G.check(env, creds_dir=None) == code


def test_g0_credentials(tmp_path):
    (tmp_path / "state-key").write_bytes(b"k" * 32)
    assert G.check({"PATH": "/usr/bin"}, creds_dir=str(tmp_path)) == "ok"
    (tmp_path / "lane-key").write_text("meah_x")
    assert G.check({"PATH": "/usr/bin"}, creds_dir=str(tmp_path)) == "g0_unexpected_credential"
