"""The operator's inference switch, on the daemon side (v0.3.58).

Three things must hold: the dashboard decision is persisted so a reinstall by
hand keeps it; an explicit OFF stops advertising generation models even with
the runtime installed; and the one-shot install signal re-runs the SIGNED
installer for our own version with MESHEMBED_ENABLE_LLM=1 in its environment
-- the runtime never arrives any other way.
"""
from __future__ import annotations

import os
import pathlib
import sys
import types

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from meshembed_node import worker  # noqa: E402

pytestmark = pytest.mark.unit


def test_the_decision_is_persisted_and_replaced_not_duplicated(tmp_path, monkeypatch):
    monkeypatch.setattr(pathlib.Path, "home", lambda: tmp_path)
    env_file = tmp_path / ".meshembed" / ".env"
    worker._persist_env_flag("MESHEMBED_ENABLE_LLM", "1")
    assert env_file.read_text().strip().splitlines() == ["MESHEMBED_ENABLE_LLM=1"]
    env_file.write_text("MESHEMBED_BACKEND=http://x\nMESHEMBED_ENABLE_LLM=0\n")
    worker._persist_env_flag("MESHEMBED_ENABLE_LLM", "1")
    lines = env_file.read_text().strip().splitlines()
    assert lines == ["MESHEMBED_BACKEND=http://x", "MESHEMBED_ENABLE_LLM=1"]


def test_an_explicit_off_from_the_dashboard_stops_advertising(monkeypatch):
    monkeypatch.setattr(worker, "_LLM_ENABLED_BY_BACKEND", False)
    assert worker._llm_installed(cfg=None) == []


def test_undecided_and_on_leave_the_runtime_to_decide(monkeypatch):
    fake = types.SimpleNamespace(installed_llm_models=lambda: [{"model_id": "m", "sha": "s"}])
    monkeypatch.setitem(sys.modules, "meshembed_node.llm", fake)
    for state in (None, True):
        monkeypatch.setattr(worker, "_LLM_ENABLED_BY_BACKEND", state)
        assert worker._llm_installed(cfg=None) == [{"model_id": "m", "sha": "s"}]


def test_the_install_signal_reruns_our_own_signed_installer_with_the_flag(tmp_path, monkeypatch):
    """Everything the real path does is kept except the network and the
    process replacement: the installer bytes come from a fake fetch, the
    signature gate is the documented escape hatch (unit test only), the
    subprocess is recorded, and os.execv is caught."""
    import requests as _rq
    import subprocess as _sp

    monkeypatch.setattr(pathlib.Path, "home", lambda: tmp_path)
    monkeypatch.setenv("MESHEMBED_ALLOW_UNSIGNED_INSTALLER", "1")
    monkeypatch.delenv("MESHEMBED_ENABLE_LLM", raising=False)
    from meshembed_node import __version__ as cur
    target = f"v{cur}"

    class _R:
        status_code = 200
        text = "x" * 300
        content = b"#!/bin/bash\n" + b"# " + b"x" * 300 + b"\n"
        def raise_for_status(self): pass
    monkeypatch.setattr(_rq, "get", lambda *a, **k: _R())

    calls = []
    def fake_run(argv, env=None, **kw):
        calls.append({"argv": argv, "env": dict(env or {})})
        if "importlib.metadata" in " ".join(argv):
            return types.SimpleNamespace(returncode=0, stdout=cur + "\n", stderr="")
        return types.SimpleNamespace(returncode=0, stdout="ok", stderr="")
    monkeypatch.setattr(_sp, "run", fake_run)

    class _Exec(Exception): pass
    def fake_execv(*a, **k): raise _Exec()
    monkeypatch.setattr(os, "execv", fake_execv)
    monkeypatch.setattr(worker, "_reject_downgrade", lambda t: None)

    with pytest.raises((_Exec, SystemExit)):
        worker._perform_self_update(target, enable_llm=True)

    installer = calls[0]
    assert installer["env"]["MESHEMBED_ENABLE_LLM"] == "1"
    assert installer["env"]["MESHEMBED_RELEASE_TAG"] == target
    assert target in installer["env"]["MESHEMBED_PACKAGE_URL"]
    assert (tmp_path / ".meshembed" / ".env").read_text().strip() == "MESHEMBED_ENABLE_LLM=1", (
        "the decision is persisted for the next reinstall")


def test_a_plain_update_does_not_set_the_flag(tmp_path, monkeypatch):
    import requests as _rq
    import subprocess as _sp
    monkeypatch.setattr(pathlib.Path, "home", lambda: tmp_path)
    monkeypatch.setenv("MESHEMBED_ALLOW_UNSIGNED_INSTALLER", "1")
    monkeypatch.delenv("MESHEMBED_ENABLE_LLM", raising=False)
    from meshembed_node import __version__ as cur
    class _R:
        status_code = 200; text = "x" * 300
        content = b"#!/bin/bash\n" + b"# " + b"x" * 300 + b"\n"
        def raise_for_status(self): pass
    monkeypatch.setattr(_rq, "get", lambda *a, **k: _R())
    calls = []
    def fake_run(argv, env=None, **kw):
        calls.append(dict(env or {}))
        if "importlib.metadata" in " ".join(argv):
            return types.SimpleNamespace(returncode=0, stdout=cur + "\n", stderr="")
        return types.SimpleNamespace(returncode=0, stdout="ok", stderr="")
    monkeypatch.setattr(_sp, "run", fake_run)
    class _Exec(Exception): pass
    monkeypatch.setattr(os, "execv", lambda *a, **k: (_ for _ in ()).throw(_Exec()))
    monkeypatch.setattr(worker, "_reject_downgrade", lambda t: None)
    with pytest.raises((_Exec, SystemExit)):
        worker._perform_self_update(f"v{cur}")
    assert "MESHEMBED_ENABLE_LLM" not in calls[0]
    assert not (tmp_path / ".meshembed" / ".env").exists()
