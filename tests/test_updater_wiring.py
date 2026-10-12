"""Wiring of the privilege-separated updater: the daemon side and the units
install.sh renders (docs/DESIGN_NODE_PRIVSEP_UPDATER.md; auditor criteria 1-6, B3).
The end-to-end proof is the containerised hardened OTA N -> N+1 (separate harness)."""
from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path

import pytest

from meshembed_node import worker

pytestmark = pytest.mark.unit

_ROOT = Path(__file__).resolve().parents[1]
_SH = (_ROOT / "install.sh").read_text()


def _fn(name: str) -> str:
    m = re.search(rf"^{name}\(\) \{{\n(.*?)^\}}", _SH, re.S | re.M)
    assert m, f"{name} not found in install.sh"
    return m.group(1)


# --- daemon side -----------------------------------------------------------------------

def test_a_writable_install_is_not_hardened(monkeypatch):
    monkeypatch.setattr(worker.os, "access", lambda p, m: True)
    monkeypatch.setattr(worker.os.path, "exists", lambda p: True)
    assert worker._hardened_with_updater() is False


def test_hardened_only_with_the_updater_present(monkeypatch):
    monkeypatch.setattr(worker.os, "access", lambda p, m: False)
    monkeypatch.setattr(worker.os.path, "exists", lambda p: False)
    assert worker._hardened_with_updater() is False         # no updater: old path (and its error)
    monkeypatch.setattr(worker.os.path, "exists", lambda p: p == worker.UPDATER_PATH_UNIT)
    assert worker._hardened_with_updater() is True


def test_the_request_is_only_the_tag_0600(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    worker._request_privileged_update("v0.3.73")
    f = tmp_path / ".meshembed" / "update-request"
    assert f.read_text() == "v0.3.73\n"
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / ".meshembed").stat().st_mode) == 0o700
    assert not list((tmp_path / ".meshembed").glob(".update-request.*"))   # temp renamed away


def test_a_hardened_daemon_delegates_without_running_or_fetching(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(worker, "_hardened_with_updater", lambda: True)
    monkeypatch.setattr(worker, "_reject_downgrade", lambda t: None)
    def no_net(*a, **k):
        raise AssertionError("a hardened daemon must not fetch or run the installer")
    import requests
    monkeypatch.setattr(requests, "get", no_net)
    assert worker._perform_self_update("v0.3.73") == "delegated"
    assert (tmp_path / ".meshembed" / "update-request").read_text() == "v0.3.73\n"


def test_an_unsafe_tag_is_refused_before_any_request(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(worker, "_hardened_with_updater", lambda: True)
    with pytest.raises(RuntimeError, match="unsafe_installer_tag"):
        worker._perform_self_update("v0.3.73; id")
    assert not (tmp_path / ".meshembed" / "update-request").exists()


def test_updater_results_become_last_update_error(tmp_path, monkeypatch):
    res = tmp_path / "last-result"
    monkeypatch.setattr(worker, "UPDATER_RESULT", str(res))
    assert worker._delegated_update_error("v0.3.73") is None            # pending
    res.write_text(json.dumps({"tag": "v0.3.73", "result": "ok", "code": "installer_exit_0"}))
    assert worker._delegated_update_error("v0.3.73") is None            # landed
    res.write_text(json.dumps({"tag": "v0.3.73", "result": "refused", "code": "installer_signature_invalid"}))
    assert worker._delegated_update_error("v0.3.73") == "v0.3.73: updater_refused:installer_signature_invalid"
    assert worker._delegated_update_error("v0.3.74") is None            # another tag's result


# --- the units install.sh renders ------------------------------------------------------

def test_the_updater_service_is_root_fixed_env_no_env_file():
    f = _fn("install_updater_units")
    svc = f[f.index("meshembed-node-update.service << UNIT"):f.index("UNIT\n", f.index("meshembed-node-update.service << UNIT") + 40)]
    assert "User=root" in svc and "Type=oneshot" in svc
    assert "EnvironmentFile" not in svc                                   # the daemon's .env never reaches root
    assert "Environment=PATH=/usr/sbin:/usr/bin:/sbin:/bin" in svc
    assert "-I -m meshembed_node.updater --request $h/.meshembed/update-request --owner $u --venv $v" in svc
    assert "StartLimitBurst" in svc and "TimeoutStartSec=900" in svc and "NoNewPrivileges=yes" in svc


def test_the_path_unit_watches_only_the_request():
    f = _fn("install_updater_units")
    assert "PathModified=$h/.meshembed/update-request" in f
    assert f.count("PathModified=") == 1 and "PathExists" not in f and "DirectoryNotEmpty" not in f


def test_request_dir_modes_b3():
    f = _fn("install_updater_units")
    assert 'install -d -m 0700 -o "$u" -g "$u" "$h/.meshembed"' in f
    assert "install -d -m 0755 -o root -g root /var/lib/meshembed-node-updater" in f
    assert '[ "$(id -u)" -eq 0 ] || return 0' in f                           # root installs only


def test_installed_only_for_a_hardened_existing_unit():
    f = _fn("install_updater_units_from_unit")
    assert "grep -q '^ProtectSystem=strict'" in f and '[ "$u" != "root" ]' in f


def test_the_daemon_unit_keeps_its_hardening_criterion_5():
    """The updater work must not loosen the daemon: strict + ProtectHome + user drop,
    no /opt in ReadWritePaths, the interpreter check still there."""
    assert 'HARDEN_FS_BLOCK="ProtectSystem=strict\nProtectHome=true\nPrivateTmp=true\nReadWritePaths=$SVC_HOME"' in _SH
    assert "ReadWritePaths=/opt" not in _SH and "ReadWritePaths=$VENV" not in _SH
    assert "test -x \"$VENV_PY\"" in _SH
    assert 'UV_PYTHON_INSTALL_DIR="${MESHEMBED_UV_PYTHON_DIR:-$(dirname "$VENV_DIR")/uv-python}"' in _SH


def test_called_on_fresh_hardened_installs_and_on_upgrades():
    assert '[ "$SVC_HARDEN_FS" -eq 1 ] && install_updater_units' in _SH
    assert _SH.count("install_updater_units_from_unit\n") >= 2                # both root upgrade branches
