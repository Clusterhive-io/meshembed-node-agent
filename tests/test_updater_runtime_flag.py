"""INF-HARD (docs/DESIGN_INF_HARD_RUNTIME_OPT_IN_2026-11-07.md, auditor DESIGN GO 2026-11-07T07:15:37Z): the owner's
Inference opt-in reaches the root updater as ONE fixed flag line, and the root side re-checks everything itself.
C4's list: the hardened-shape happy path, its negative control, the hostile requests, runtime already present, a lower
tag with the flag, and the daemon side (the flag only for the runtime opt-in; an ordinary request byte-for-byte as
before)."""
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
ENV_KEYS = {"PATH", "HOME", "LANG", "MESHEMBED_RELEASE_TAG", "MESHEMBED_DAEMON_PYTHON"}


def _request(tmp_path: Path, content: bytes) -> Path:
    p = tmp_path / "update-request"
    p.write_bytes(content)
    os.chmod(p, 0o600)
    return p


def _venv(tmp_path: Path, version: str = "0.3.83", runtime: bool = False) -> Path:
    sp = tmp_path / "venv" / "lib" / "python3.12" / "site-packages"
    (sp / f"meshembed_node-{version}.dist-info").mkdir(parents=True, exist_ok=True)
    if runtime:
        (sp / "llama_cpp_python-0.3.35.dist-info").mkdir(parents=True, exist_ok=True)
    return tmp_path / "venv"


def _get(url):
    return (200, b"sig-line") if url.endswith(".sig") else (200, INSTALLER)


@pytest.fixture
def signed(monkeypatch):
    monkeypatch.setattr("meshembed_node.release_verify.verify_blob", lambda d, s: "a138d7d0cf3d361a")


def _run_once(tmp_path, content, venv):
    calls = []

    def run(argv, **kw):
        calls.append(kw["env"])
        return subprocess.CompletedProcess(argv, 0, "", "")
    out = U.run_once(_request(tmp_path, content), UID, venv, state_dir=tmp_path / "state", now=1000.0, get=_get,
                     run=run)
    return out, calls


# --- the root side ------------------------------------------------------------------

def test_the_flag_line_is_read_as_one_boolean(tmp_path):
    assert U.read_request(_request(tmp_path, b"v0.3.83\nruntime=1\n"), UID) == ("v0.3.83", True)
    assert U.read_request(_request(tmp_path, b"v0.3.83\nruntime=1"), UID) == ("v0.3.83", True)
    assert U.read_request(_request(tmp_path, b"v0.3.83\n"), UID) == ("v0.3.83", False)


def test_hardened_equal_version_with_the_flag_and_no_runtime_installs_it(tmp_path, signed):
    out, envs = _run_once(tmp_path, b"v0.3.83\nruntime=1\n", _venv(tmp_path))
    assert out == "ok" and len(envs) == 1
    assert envs[0]["MESHEMBED_ENABLE_LLM"] == "1"
    assert set(envs[0]) == ENV_KEYS | {"MESHEMBED_ENABLE_LLM"}              # nothing else was added
    assert json.loads((tmp_path / "state" / "last-result").read_text())["code"] == "installer_exit_0"


def test_negative_control_the_same_without_the_flag_is_refused_as_today(tmp_path, signed):
    out, envs = _run_once(tmp_path, b"v0.3.83\n", _venv(tmp_path))
    assert out == "refused:not_newer_than_installed" and envs == []


@pytest.mark.parametrize("content", [
    b"v0.3.83\nMESHEMBED_PUBKEY_OVERRIDE=x\n",        # an env-like line
    b"v0.3.83\nruntime=yes\n",
    b"v0.3.83\nruntime=1 \n",                         # trailing junk
    b"v0.3.83\nruntime=1\nruntime=1\n",               # a third line
    b"v0.3.83\nRUNTIME=1\n",
    b"v0.3.83\n\n",                                   # an empty second line
    b"v0.3.83\nruntime=1\nMESHEMBED_ALLOW_UNSIGNED_INSTALLER=1\n",
])
def test_hostile_requests_are_refused_and_run_nothing(tmp_path, signed, content):
    out, envs = _run_once(tmp_path, content, _venv(tmp_path))
    assert out == "refused:request_bad_flag" and envs == []


def test_an_oversized_request_is_refused(tmp_path, signed):
    out, envs = _run_once(tmp_path, b"v0.3.83\nruntime=1\n" + b"#" * 60, _venv(tmp_path))
    assert out == "refused:request_too_large" and envs == []


def test_a_bad_tag_with_the_flag_is_still_a_bad_tag(tmp_path, signed):
    out, envs = _run_once(tmp_path, b"v0.3.83; id\nruntime=1\n", _venv(tmp_path))
    assert out == "refused:request_bad_tag" and envs == []


def test_runtime_already_present_is_refused_no_reinstall_loop(tmp_path, signed):
    out, envs = _run_once(tmp_path, b"v0.3.83\nruntime=1\n", _venv(tmp_path, runtime=True))
    assert out == "refused:runtime_already_present" and envs == []


def test_a_lower_tag_with_the_flag_is_refused_anti_rollback(tmp_path, signed):
    out, envs = _run_once(tmp_path, b"v0.3.82\nruntime=1\n", _venv(tmp_path))
    assert out == "refused:not_newer_than_installed" and envs == []


def test_a_newer_tag_with_the_flag_upgrades_with_the_runtime(tmp_path, signed):
    out, envs = _run_once(tmp_path, b"v0.3.84\nruntime=1\n", _venv(tmp_path))
    assert out == "ok" and envs[0]["MESHEMBED_ENABLE_LLM"] == "1"


def test_an_ordinary_update_never_carries_the_runtime_variable(tmp_path, signed):
    out, envs = _run_once(tmp_path, b"v0.3.84\n", _venv(tmp_path))
    assert out == "ok" and set(envs[0]) == ENV_KEYS


def test_the_rate_limit_applies_to_the_flag_too(tmp_path, signed):
    st = tmp_path / "state"
    ok = lambda argv, **kw: subprocess.CompletedProcess(argv, 1, "", "")     # the install failed: the runtime is absent
    U.run_once(_request(tmp_path, b"v0.3.83\nruntime=1\n"), UID, _venv(tmp_path), state_dir=st, now=1000.0,
               get=_get, run=ok)
    out = U.run_once(_request(tmp_path, b"v0.3.83\nruntime=1\n"), UID, _venv(tmp_path), state_dir=st, now=1060.0,
                     get=_get, run=ok)
    assert out == "refused:rate_limited"


def test_runtime_presence_is_read_from_dist_info_without_executing_anything(tmp_path):
    assert U.runtime_present(_venv(tmp_path)) is False
    assert U.runtime_present(_venv(tmp_path, runtime=True)) is True


def test_installer_env_adds_the_variable_only_for_a_true_boolean(tmp_path):
    assert set(U.installer_env("v0.3.83", tmp_path)) == ENV_KEYS
    assert "MESHEMBED_ENABLE_LLM" not in U.installer_env("v0.3.83", tmp_path, runtime="1")   # only True, not truthy
    assert U.installer_env("v0.3.83", tmp_path, runtime=True)["MESHEMBED_ENABLE_LLM"] == "1"


# --- the daemon side ----------------------------------------------------------------

def _worker_request(tmp_path, monkeypatch, **kw):
    from meshembed_node import worker as W
    monkeypatch.setenv("HOME", str(tmp_path))
    W._request_privileged_update("v0.3.83", **kw)
    p = tmp_path / ".meshembed" / "update-request"
    assert oct(p.stat().st_mode & 0o777) == "0o600"
    return p.read_bytes()


def test_an_ordinary_request_is_byte_for_byte_as_before(tmp_path, monkeypatch):
    assert _worker_request(tmp_path, monkeypatch) == b"v0.3.83\n"          # an older updater keeps reading it


def test_the_runtime_opt_in_writes_the_flag_line_the_updater_accepts(tmp_path, monkeypatch):
    raw = _worker_request(tmp_path, monkeypatch, runtime=True)
    assert raw == b"v0.3.83\nruntime=1\n"
    assert U.read_request(_request(tmp_path, raw), UID) == ("v0.3.83", True)


def test_perform_self_update_on_a_hardened_install_carries_the_flag_only_for_enable_llm(tmp_path, monkeypatch):
    from meshembed_node import worker as W
    sent = []
    monkeypatch.setattr(W, "_hardened_with_updater", lambda: True)
    monkeypatch.setattr(W, "_request_privileged_update", lambda tag, runtime=False: sent.append((tag, runtime)))
    monkeypatch.setattr(W, "_reject_downgrade", lambda tag: None)
    assert W._perform_self_update("v0.3.83", enable_llm=True) == "delegated"
    assert W._perform_self_update("v0.3.84") == "delegated"
    assert sent == [("v0.3.83", True), ("v0.3.84", False)]


def test_the_loop_keeps_serving_after_a_delegated_runtime_install_so_the_verdict_is_reported():
    """No loop harness exists; the structure is pinned instead: the install_runtime_now block treats "delegated" like
    the ordinary update (track the tag, keep serving), so the updater's refusal reaches last_update_error; before
    INF-HARD it exited and the verdict was never reported."""
    import inspect
    from meshembed_node import worker as W
    src = inspect.getsource(W)
    block = src[src.index("_outcome = _perform_self_update(target, enable_llm=True)"):
                src.index('log.warning("runtime install returned without exiting -- exiting now")')]
    assert 'if _outcome == "delegated":' in block and '_DELEGATED["tag"] = target' in block and "continue" in block
