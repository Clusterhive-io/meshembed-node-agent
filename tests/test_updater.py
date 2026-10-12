"""The privilege-separated updater: the auditor's criteria 1-6 and build
conditions B1-B3 as tests (docs/DESIGN_NODE_PRIVSEP_UPDATER.md)."""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from meshembed_node import updater as U

pytestmark = pytest.mark.unit

UID = os.getuid()
INSTALLER = b"#!/bin/bash\n" + b"echo upgrading\n" * 10


def _request(tmp_path: Path, content: bytes = b"v0.3.73\n", mode: int = 0o600) -> Path:
    p = tmp_path / "update-request"
    p.write_bytes(content)
    os.chmod(p, mode)
    return p


def _venv(tmp_path: Path, version: str = "0.3.72") -> Path:
    v = tmp_path / "venv"
    (v / "lib" / "python3.12" / "site-packages" / f"meshembed_node-{version}.dist-info").mkdir(parents=True, exist_ok=True)
    return v


# --- criterion 1/B3: the request file ----------------------------------------------

def test_a_valid_request_is_read_and_truncated(tmp_path):
    p = _request(tmp_path)
    assert U.read_request(p, UID) == "v0.3.73"
    assert p.read_bytes() == b""                               # never re-fires


@pytest.mark.parametrize("content", [
    b"v0.3.73; rm -rf /", b"https://evil/v0.3.73", b"v0.3", b"../../v0.3.73", b"v0.3.73 --force",
    b"$(id)", b"V0.3.73", b"\n",
])
def test_anything_but_a_bare_tag_is_refused(tmp_path, content):
    with pytest.raises(U.Refused, match="request_bad_tag"):
        U.read_request(_request(tmp_path, content), UID)


def test_a_symlinked_request_is_refused(tmp_path):
    target = tmp_path / "elsewhere"
    target.write_bytes(b"v0.3.73\n")
    link = tmp_path / "update-request"
    link.symlink_to(target)
    with pytest.raises(U.Refused, match="request_unreadable"):
        U.read_request(link, UID)


def test_wrong_owner_open_mode_and_oversize_are_refused(tmp_path):
    with pytest.raises(U.Refused, match="request_wrong_owner"):
        U.read_request(_request(tmp_path), UID + 1)
    with pytest.raises(U.Refused, match="request_mode_too_open"):
        U.read_request(_request(tmp_path, mode=0o644), UID)
    with pytest.raises(U.Refused, match="request_too_large"):
        U.read_request(_request(tmp_path, b"v0.3.73" + b" " * 100), UID)


# --- B1 + criterion 3: versions ----------------------------------------------------

def test_installed_version_is_read_without_executing_anything(tmp_path):
    assert U.installed_version(_venv(tmp_path, "0.3.72")) == "0.3.72"


def test_no_readable_installed_version_refuses(tmp_path):
    (tmp_path / "venv").mkdir()
    with pytest.raises(U.Refused, match="installed_version_unreadable"):
        U.installed_version(tmp_path / "venv")


@pytest.mark.parametrize("tag, installed, code", [
    ("v0.3.72", "0.3.72", "not_newer_than_installed"),          # equal
    ("v0.3.71", "0.3.72", "not_newer_than_installed"),          # downgrade
    ("v0.3.69", "0.3.60", "tag_below_minimum"),                 # pre fixed-SUMS installer (B2)
])
def test_check_refuses(tag, installed, code):
    with pytest.raises(U.Refused, match=code):
        U.check(tag, installed, None, now=1000.0)


def test_check_allows_newer_and_rate_limits():
    U.check("v0.3.73", "0.3.72", None, now=1000.0)
    with pytest.raises(U.Refused, match="rate_limited"):
        U.check("v0.3.73", "0.3.72", last_run_at=1000.0 - 60, now=1000.0)


def test_allow_downgrade_env_is_ignored(monkeypatch):
    monkeypatch.setenv("MESHEMBED_ALLOW_DOWNGRADE", "1")
    with pytest.raises(U.Refused, match="not_newer_than_installed"):
        U.check("v0.3.71", "0.3.72", None, now=1000.0)


# --- criterion 4: signature ---------------------------------------------------------

def _site(sig_ok=True, inst=INSTALLER, codes=(200, 200)):
    def get(url):
        return (codes[1], b"sig-line") if url.endswith(".sig") else (codes[0], inst)
    return get


def test_the_url_is_fixed_and_only_the_tag_varies(monkeypatch):
    seen = []
    monkeypatch.setattr("meshembed_node.release_verify.verify_blob", lambda d, s: "a138d7d0cf3d361a")
    U.fetch_verified_installer("v0.3.73", lambda u: (seen.append(u), (200, INSTALLER if not u.endswith(".sig") else b"s"))[1])
    assert seen == ["https://raw.githubusercontent.com/Clusterhive-io/meshembed-node-agent/refs/tags/v0.3.73/install.sh",
                    "https://raw.githubusercontent.com/Clusterhive-io/meshembed-node-agent/refs/tags/v0.3.73/install.sh.sig"]


def test_a_bad_or_missing_signature_refuses(monkeypatch):
    def bad(d, s):
        raise ValueError("signature mismatch")
    monkeypatch.setattr("meshembed_node.release_verify.verify_blob", bad)
    with pytest.raises(U.Refused, match="installer_signature_invalid"):
        U.fetch_verified_installer("v0.3.73", _site())
    with pytest.raises(U.Refused, match="installer_signature_unavailable:404"):
        U.fetch_verified_installer("v0.3.73", _site(codes=(200, 404)))


def test_allow_unsigned_env_is_ignored(monkeypatch):
    monkeypatch.setenv("MESHEMBED_ALLOW_UNSIGNED_INSTALLER", "1")
    def bad(d, s):
        raise ValueError("no")
    monkeypatch.setattr("meshembed_node.release_verify.verify_blob", bad)
    with pytest.raises(U.Refused, match="installer_signature_invalid"):
        U.fetch_verified_installer("v0.3.73", _site())


def test_both_release_keys_are_trusted():
    from meshembed_node import release_verify as rv
    ids = {rv.key_id(k) for k in rv._TRUSTED_RELEASE_KEYS}
    assert {"a138d7d0cf3d361a", "f36c830ffd678cf4"} <= ids


# --- criterion 2/6: how the installer runs -----------------------------------------

def test_installer_runs_with_argv_and_a_clean_env(tmp_path, monkeypatch):
    monkeypatch.setenv("MESHEMBED_NODE_API_KEY", "secret-from-daemon-env")
    calls = []
    def run(argv, **kw):
        calls.append((argv, kw))
        return subprocess.CompletedProcess(argv, 0, "", "")
    rc = U.run_installer(INSTALLER, "v0.3.73", tmp_path / "venv", tmp_path, run=run)
    (argv, kw), = calls
    assert rc == 0 and argv[0] == "bash" and len(argv) == 2 and kw["shell"] is False
    env = kw["env"]
    assert env["MESHEMBED_RELEASE_TAG"] == "v0.3.73"
    assert "MESHEMBED_PACKAGE_URL" not in env                  # installer restarts the unit itself
    assert "MESHEMBED_NODE_API_KEY" not in env and "MESHEMBED_ALLOW_UNSIGNED_INSTALLER" not in env
    assert not list(tmp_path.glob("install-*.sh"))              # temp installer removed


# --- one run, end to end ------------------------------------------------------------

def test_run_once_happy_path(tmp_path, monkeypatch):
    monkeypatch.setattr("meshembed_node.release_verify.verify_blob", lambda d, s: "a138d7d0cf3d361a")
    ran = []
    run = lambda argv, **kw: (ran.append(argv), subprocess.CompletedProcess(argv, 0, "", ""))[1]
    out = U.run_once(_request(tmp_path), UID, _venv(tmp_path), state_dir=tmp_path / "state",
                     now=1000.0, get=_site(), run=run)
    assert out == "ok" and len(ran) == 1
    res = json.loads((tmp_path / "state" / "last-result").read_text())
    assert res == {"tag": "v0.3.73", "result": "ok", "code": "installer_exit_0", "at": 1000}


def test_run_once_refusal_runs_nothing_and_records_a_code(tmp_path):
    ran = []
    out = U.run_once(_request(tmp_path, b"v0.3.71\n"), UID, _venv(tmp_path), state_dir=tmp_path / "state",
                     now=1000.0, get=_site(), run=lambda *a, **k: ran.append(a))
    assert out == "refused:not_newer_than_installed" and ran == []
    assert json.loads((tmp_path / "state" / "last-result").read_text())["result"] == "refused"


def test_a_second_request_within_ten_minutes_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr("meshembed_node.release_verify.verify_blob", lambda d, s: "k")
    ok = lambda argv, **kw: subprocess.CompletedProcess(argv, 1, "", "")
    st = tmp_path / "state"
    U.run_once(_request(tmp_path), UID, _venv(tmp_path), state_dir=st, now=1000.0, get=_site(), run=ok)
    out = U.run_once(_request(tmp_path), UID, _venv(tmp_path), state_dir=st, now=1060.0, get=_site(), run=ok)
    assert out == "refused:rate_limited"


def test_main_refuses_when_not_root(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("running as root")
    assert U.main(["--request", str(tmp_path / "r"), "--owner", "nobody", "--venv", str(tmp_path)]) == 2


def test_our_own_truncation_retrigger_is_a_silent_no_op(tmp_path):
    """PathModified fires again on the truncate: that run must not overwrite the result."""
    st = tmp_path / "state"
    st.mkdir()
    (st / "last-result").write_text('{"tag": "v0.3.73", "result": "ok"}')
    out = U.run_once(_request(tmp_path, b""), UID, _venv(tmp_path), state_dir=st, now=1000.0,
                     get=_site(), run=lambda *a, **k: None)
    assert out == "none"
    assert json.loads((st / "last-result").read_text())["result"] == "ok"
