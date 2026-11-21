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
    # U4 (0.3.87): level-triggered, as the split launcher in 0.3.86: PathExists, no edge-triggered directive left
    assert "PathExists=$h/.meshembed/update-request" in f
    assert not any(l.startswith("PathModified") for l in f.splitlines()) and sum(l.startswith("PathExists=") for l in f.splitlines()) == 1 and "DirectoryNotEmpty" not in f
    assert f.count("systemctl restart meshembed-node-update.path") == 2          # an already-active unit adopts the new directive
    assert f.count("systemctl is-active meshembed-node-update.path") == 2 and "is-enabled meshembed-node-update.path" not in f   # U4-b


def test_request_dir_modes_b3():
    # B3: the request directory is 0700 and the daemon user's. IC3B-H1 (auditor 2026-11-13T17:23:11Z): it is created / re-moded AS THE
    # USER through ensure_user_dir, NEVER by a root `install -d -o` inside the daemon-owned home (GNU install -d follows a symlink).
    f = _fn("install_updater_units")
    assert 'ensure_user_dir "$u" "$h/.meshembed" 0700' in f
    assert 'install -d -m 0700 -o "$u"' not in f and "chown" not in f.split("ensure_user_dir", 1)[1].split("meshembed-node-updater", 1)[0]
    helper = _fn("ensure_user_dir")
    assert 'as_user "$u" mkdir -m "$m"' in helper and 'as_user "$u" chmod "$m"' in helper     # U1: through the one as_user helper
    assert "install -d -m 0755 -o root -g root /var/lib/meshembed-node-updater" in f                # a ROOT-owned path: its parent is root's
    assert '[ "$(id -u)" -eq 0 ] || return 0' in f                           # root installs only


def test_installed_only_for_a_hardened_existing_unit():
    # IC-3b F1: the hardened criterion now lives in the ONE shared layout reader (the merged unit: drop-ins included), and the
    # updater refresh must go through it; the criterion itself is unchanged: strict + a non-root user + a HOME.
    f = _fn("install_updater_units_from_unit")
    assert "_node_unit_layout" in f
    m = re.search(r"^_node_unit_layout\(\) \{[^\n]*\n(.*?)^\}", _SH, re.S | re.M)       # its opening line carries a comment
    assert m, "_node_unit_layout not found in install.sh"
    r = m.group(1)
    assert '[ "$ps" = strict ]' in r and '[ "$u" != root ]' in r and "ProtectSystem=strict" in r


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


def test_u4_the_daemon_never_replaces_a_pending_request_but_does_replace_an_empty_or_stale_one(tmp_path, monkeypatch):
    import os as _os, time as _t
    monkeypatch.setenv("HOME", str(tmp_path))
    worker._request_privileged_update("v0.3.73")
    f = tmp_path / ".meshembed" / "update-request"
    with pytest.raises(RuntimeError, match="update_request_pending"):
        worker._request_privileged_update("v0.3.74")                 # pending + recent: the caller retries after its backoff
    assert f.read_text() == "v0.3.73\n"
    f.write_bytes(b"")                                               # an empty leftover of the old truncate protocol
    worker._request_privileged_update("v0.3.74")
    assert f.read_text() == "v0.3.74\n"
    old = _t.time() - 3600                                           # an updater that never ran (an old unit): replaced after 10 minutes
    _os.utime(f, (old, old))
    worker._request_privileged_update("v0.3.75")
    assert f.read_text() == "v0.3.75\n"
