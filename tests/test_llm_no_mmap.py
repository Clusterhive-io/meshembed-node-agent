"""CPU LLM loads read the weights into the process (use_mmap=False) so the whole working set is
anon memory: exactly what admission counts, never evicted under memory pressure
(docs/FINDING_2026-10-12_MMAP_MEMORY_BUDGET.md). GPU offload keeps llama.cpp's default."""
from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

from meshembed_node import llm

pytestmark = pytest.mark.unit


@pytest.fixture
def loads(monkeypatch, tmp_path):
    calls = []

    class FakeLlama:
        def __init__(self, **kw):
            calls.append(kw)
            if kw.get("n_gpu_layers") and getattr(FakeLlama, "gpu_fails", False):
                raise RuntimeError("cuda out of memory")

    monkeypatch.setitem(sys.modules, "llama_cpp", types.SimpleNamespace(Llama=FakeLlama))
    monkeypatch.setattr(llm, "ensure_model", lambda spec: tmp_path / "m.gguf")
    monkeypatch.delenv("MESHEMBED_LLM_USE_MMAP", raising=False)
    monkeypatch.setattr(llm, "_LOADED", llm._LOADED)       # _load() sets this module global; restore it
    spec = types.SimpleNamespace(model_id="m", context=4096, size_mb=1800)
    return calls, FakeLlama, spec


def test_a_cpu_load_does_not_mmap(loads, monkeypatch):
    calls, _, spec = loads
    monkeypatch.setattr(llm, "gpu_layers_choice", lambda: 0)
    llm.LlamaRunner()._load(spec)
    assert calls[-1]["use_mmap"] is False and calls[-1]["n_gpu_layers"] == 0


def test_gpu_offload_keeps_the_default(loads, monkeypatch):
    calls, _, spec = loads
    monkeypatch.setattr(llm, "gpu_layers_choice", lambda: 99)
    llm.LlamaRunner()._load(spec)
    assert "use_mmap" not in calls[-1] and calls[-1]["n_gpu_layers"] == 99


def test_the_cpu_fallback_after_a_failed_offload_does_not_mmap(loads, monkeypatch):
    calls, fake, spec = loads
    fake.gpu_fails = True
    monkeypatch.setattr(llm, "gpu_layers_choice", lambda: 99)
    llm.LlamaRunner()._load(spec)
    assert [c.get("use_mmap") for c in calls] == [None, False] and calls[-1]["n_gpu_layers"] == 0


def test_the_escape_hatch_restores_mmap(loads, monkeypatch):
    calls, _, spec = loads
    monkeypatch.setattr(llm, "gpu_layers_choice", lambda: 0)
    monkeypatch.setenv("MESHEMBED_LLM_USE_MMAP", "1")
    llm.LlamaRunner()._load(spec)
    assert "use_mmap" not in calls[-1]


def test_the_daemon_reports_how_it_holds_weights(monkeypatch):
    monkeypatch.delenv("MESHEMBED_LLM_USE_MMAP", raising=False)
    monkeypatch.setattr(llm, "gpu_layers_choice", lambda: 0)
    assert llm.load_mode() == "no_mmap"
    monkeypatch.setattr(llm, "gpu_layers_choice", lambda: 99)
    assert llm.load_mode() == "mmap"
    monkeypatch.setattr(llm, "gpu_layers_choice", lambda: 0)
    monkeypatch.setenv("MESHEMBED_LLM_USE_MMAP", "1")
    assert llm.load_mode() == "mmap"
