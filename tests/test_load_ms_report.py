"""F6b (node half): a generation item reports how long it spent loading the model.

N-23711 (2026-10-11): canary subjobs of 1,107,777 ms wall held 13.4 s of compute;
the rest was the model load swapping. The runner times its own load
(Generation.load_seconds, 0.0 when the model was resident) and _report sends it
as load_ms, so the backend can flag a load-dominated result.
"""
from __future__ import annotations

import sys
from unittest.mock import MagicMock

import pytest

from meshembed_node import llm

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _llama_cpp_stub(monkeypatch):
    """generate() imports llama_cpp; the runtime is absent on the sandbox and in
    CI (same stub as test_llm.py)."""
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


SPEC = llm.ModelSpec(model_id="m", file="x.gguf", sha256="0" * 64, size_mb=1,
                     min_ram_gb=0.1, context=2048)


def test_a_cold_load_is_timed(monkeypatch):
    r = llm.LlamaRunner()
    clock = iter([100.0, 103.5])                       # load starts, load ends

    def _load(spec):
        r._model, r._loaded_id = _Model(), spec.model_id
        return r._model

    monkeypatch.setattr(r, "_load", _load)
    real = llm.time.perf_counter
    monkeypatch.setattr(llm.time, "perf_counter", lambda: next(clock, real()))
    g = r.generate(SPEC, {"prompt": "hi"}, {})
    assert g.load_seconds == pytest.approx(3.5)


def test_a_resident_model_reports_no_load():
    r = llm.LlamaRunner()
    r._model, r._loaded_id = _Model(), "m"
    assert r.generate(SPEC, {"prompt": "hi"}, {}).load_seconds == 0.0


def _patch_post(monkeypatch):
    from meshembed_node import worker
    captured = {}

    class _Resp:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return {"ok": True}

    def _fake_post(url, json=None, headers=None, timeout=None):
        captured["payload"] = json
        return _Resp()

    monkeypatch.setattr(worker.requests, "post", _fake_post)
    return worker, captured


def _cfg():
    cfg = MagicMock()
    cfg.node_id, cfg.api_key, cfg.backend_url = "node-test", "k", "http://backend.invalid"
    cfg.machine_fingerprint = "a" * 64
    cfg.gpu_uuid = "GPU-x"
    cfg.node_privkey = ""  # unsigned -> skip result signing (as test_payload_decrypt)
    return cfg


BASE = {"job_id": "j", "subjob_id": "s", "chunk_index": 0, "callback_token": "t", "texts": ["a"]}


def test_report_carries_load_ms(monkeypatch):
    worker, captured = _patch_post(monkeypatch)
    worker._report(_cfg(), BASE, ["x"], 0.1, 1000, None, load_ms=950)
    assert captured["payload"]["load_ms"] == 950


def test_report_omits_load_ms_when_not_measured(monkeypatch):
    """Embeddings and declined items: no field, so the backend stores NULL."""
    worker, captured = _patch_post(monkeypatch)
    worker._report(_cfg(), BASE, [[0.1]], 0.1, 1000, None)
    assert "load_ms" not in captured["payload"]
