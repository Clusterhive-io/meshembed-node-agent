"""An unused generation model does not stay resident forever.

N-23711 (2026-10-11, docs/INCIDENT_2026-10-11_N23711_LLM_CANARY_THRASH.md) kept a
7B resident above its 6 GB cgroup between canaries and swapped the host. The
runner now frees the model after MESHEMBED_LLM_IDLE_TTL_S (default 300 s).
"""
from __future__ import annotations

import sys
import threading

import pytest

from meshembed_node import llm

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _llama_cpp_stub(monkeypatch):
    """generate() imports llama_cpp; the runtime is absent on the sandbox and in
    CI, and these tests never reach it (same stub as test_llm.py)."""
    try:
        import llama_cpp  # noqa: F401
    except ImportError:
        import types
        stub = types.ModuleType("llama_cpp")
        stub.LogitsProcessorList = list
        monkeypatch.setitem(sys.modules, "llama_cpp", stub)
    yield


class _Model:
    def reset(self):
        pass

    def create_completion(self, **kw):
        return {"choices": [{"text": "ok"}], "usage": {"prompt_tokens": 1, "completion_tokens": 1}}


def _resident(monkeypatch):
    r = llm.LlamaRunner()
    r._model, r._loaded_id = _Model(), "m"
    monkeypatch.setattr(llm, "_LOADED", ("m", 4.0))
    return r


def test_an_idle_model_is_unloaded_after_the_ttl(monkeypatch):
    r = _resident(monkeypatch)
    assert r.unload_if_idle(ttl_s=300, now=r._last_used + 301) is True
    assert r._model is None and r._loaded_id is None
    assert llm._loaded_id() is None                # the next poll reports it not loaded


def test_a_recently_used_model_stays(monkeypatch):
    r = _resident(monkeypatch)
    assert r.unload_if_idle(ttl_s=300, now=r._last_used + 299) is False
    assert r._loaded_id == "m" and llm._loaded_id() == "m"


def test_using_the_model_restarts_the_clock(monkeypatch):
    r = _resident(monkeypatch)
    old = r._last_used
    spec = llm.ModelSpec(model_id="m", file="x.gguf", sha256="0" * 64, size_mb=1,
                         min_ram_gb=0.1, context=2048)
    r.generate(spec, {"prompt": "hi"}, {})
    assert r._last_used >= old
    assert r.unload_if_idle(ttl_s=300, now=r._last_used + 10) is False


def test_a_ttl_of_zero_keeps_todays_behaviour(monkeypatch):
    r = _resident(monkeypatch)
    assert r.unload_if_idle(ttl_s=0, now=r._last_used + 10**6) is False
    assert r._loaded_id == "m"


def test_a_runner_in_use_is_never_unloaded(monkeypatch):
    """The lock is held across generation: a busy runner is skipped, not waited on."""
    r = _resident(monkeypatch)
    held, release = threading.Event(), threading.Event()

    def busy():
        with r._lock:
            held.set()
            release.wait(5)

    t = threading.Thread(target=busy)
    t.start()
    held.wait(5)
    try:
        assert r.unload_if_idle(ttl_s=1, now=r._last_used + 10**6) is False
        assert r._loaded_id == "m"
    finally:
        release.set()
        t.join(5)


def test_nothing_loaded_is_a_no_op():
    assert llm.LlamaRunner().unload_if_idle(ttl_s=1) is False


def test_the_ttl_comes_from_the_environment(monkeypatch):
    monkeypatch.delenv("MESHEMBED_LLM_IDLE_TTL_S", raising=False)
    assert llm.idle_ttl_s() == 300.0
    monkeypatch.setenv("MESHEMBED_LLM_IDLE_TTL_S", "60")
    assert llm.idle_ttl_s() == 60.0
    monkeypatch.setenv("MESHEMBED_LLM_IDLE_TTL_S", "soon")
    assert llm.idle_ttl_s() == 300.0
