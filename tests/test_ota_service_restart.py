"""A self-update must not be killed by its own service restart (v0.3.70 rollout, 2026-10-04).

On 186 (systemd + passwordless sudo) install.sh's upgrade path ran `systemctl restart` during a
SELF-update. The stop took the unit's whole cgroup down -- the installer included -- after the
package had landed, and the daemon logged installer_exit_-15 for a successful update.
- install.sh: during a self-update it edits the unit but never restarts it (the daemon re-execs).
- worker: an installer killed by a signal counts as applied only if the target is on disk.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]


def _upgrade_block() -> str:
    src = (ROOT / "install.sh").read_text()
    start = src.index("# ── Upgrade path: harden the unit")
    end = src.index('    echo "${bold}Upgrade complete.${reset}"\n    exit 0\nfi\n', start)
    return src[start:end] + '    echo "${bold}Upgrade complete.${reset}"\n    exit 0\nfi\n'


HARNESS = r"""
set -euo pipefail
info() { echo "INFO: $*"; }; ok() { echo "OK: $*"; }
bold=""; reset=""; UPGRADE_ONLY=1
systemctl() { echo "systemctl $*" >> "$CALLS"; return 0; }
sudo() { echo "sudo $*" >> "$CALLS"; shift; [ "$1" = "systemctl" ] && { shift; systemctl "$@"; }; return 0; }
"""


@pytest.mark.parametrize("ota", [True, False])
def test_install_sh_never_restarts_the_unit_during_a_self_update(tmp_path, ota):
    calls = tmp_path / "calls"
    calls.touch()
    script = tmp_path / "up.sh"
    script.write_text(HARNESS + _upgrade_block())
    env = {**os.environ, "CALLS": str(calls)}
    env.pop("MESHEMBED_PACKAGE_URL", None)
    if ota:
        env["MESHEMBED_PACKAGE_URL"] = "https://github.com/x/archive/refs/tags/v9.9.9.tar.gz"
    p = subprocess.run(["bash", str(script)], capture_output=True, text=True, env=env, timeout=60)
    assert p.returncode == 0, p.stdout + p.stderr
    restarts = [l for l in calls.read_text().splitlines() if "restart" in l]
    if ota:
        assert restarts == [], f"a self-update restarted the unit: {restarts}"
        assert "re-exec itself" in p.stdout
    else:
        assert restarts, "a manual upgrade must still restart the service"


class _Resp:
    content = b"#!/usr/bin/env bash\n" + b"#" * 200
    text = "meshembed-relsig-v1 0000000000000000 00"

    def raise_for_status(self):
        pass


def _run_update(monkeypatch, installer_rc: int, on_disk: str):
    import platform
    import requests
    from meshembed_node import release_verify, worker

    monkeypatch.setattr(requests, "get", lambda *a, **k: _Resp())
    monkeypatch.setattr(release_verify, "verify_blob", lambda data, sig: "testkey")
    monkeypatch.setattr(platform, "system", lambda: "Linux")

    def fake_run(cmd, *a, **k):
        if cmd[0] == "bash":
            return subprocess.CompletedProcess(cmd, installer_rc, "installer output", "")
        return subprocess.CompletedProcess(cmd, 0, on_disk + "\n", "")

    monkeypatch.setattr(subprocess, "run", fake_run)

    class _Exec(Exception):
        pass

    def fake_execv(*a):
        raise _Exec()

    monkeypatch.setattr(os, "execv", fake_execv)
    try:
        worker._perform_self_update("v9.9.9")
    except _Exec:
        return "re-exec"


def test_installer_killed_after_the_target_landed_counts_as_applied(monkeypatch):
    assert _run_update(monkeypatch, -15, "9.9.9") == "re-exec"


def test_installer_killed_before_the_target_landed_is_still_a_failure(monkeypatch):
    with pytest.raises(RuntimeError, match="installer_exit_-15"):
        _run_update(monkeypatch, -15, "0.0.1")


def test_a_nonzero_exit_is_a_failure_even_if_the_version_matches(monkeypatch):
    """Only a SIGNAL after landing is forgiven; an installer that exits 1 failed."""
    with pytest.raises(RuntimeError, match="installer_exit_1"):
        _run_update(monkeypatch, 1, "9.9.9")


def test_fresh_install_does_not_need_USER_set():
    """`curl | bash` from a non-login shell has no USER; under set -u that ended the
    install after registration (sandbox fresh-install smoke, 2026-10-04)."""
    src = (ROOT / "install.sh").read_text()
    assert 'SVC_USER="$USER"' not in src
    line = next(l for l in src.splitlines() if l.startswith("SVC_USER="))
    p = subprocess.run(["bash", "-c", f"set -u; unset USER; {line}; echo \"$SVC_USER\""],
                       capture_output=True, text=True, timeout=30)
    assert p.returncode == 0 and p.stdout.strip(), p.stderr
