"""Loading a model must not un-advertise it (2026-09-18)."""
from __future__ import annotations

import pathlib
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from meshembed_node import llm  # noqa: E402

pytestmark = pytest.mark.unit


def _cat():
    mk = lambda mid, size, ram: SimpleNamespace(model_id=mid, file=mid + ".gguf", sha256="a" * 64,
                                                size_mb=size, min_ram_gb=ram, context=2048)
    return {"s": mk("s", 469, 1.5), "m": mk("m", 1840, 4.0), "l": mk("l", 4466, 8.0)}


def test_the_loaded_models_memory_is_added_back(monkeypatch):
    cat = _cat()
    monkeypatch.setattr(llm, "runtime_available", lambda: True)
    monkeypatch.setattr(llm, "_verified_path", lambda spec: "/x/" + spec.file)
    monkeypatch.setattr(llm, "_usable_ram_gb", lambda: 3.3)          # what the OS reports with the 3B resident
    monkeypatch.setattr(llm, "_LOADED", ("m", 1840 / 1024))
    got = {s.model_id for s in llm.servable_models(cat)}
    assert "m" in got, "the model we are running must stay advertised"
    assert "s" in got and "l" not in got


def test_without_the_correction_the_deadlock_reproduces(monkeypatch):
    cat = _cat()
    monkeypatch.setattr(llm, "runtime_available", lambda: True)
    monkeypatch.setattr(llm, "_verified_path", lambda spec: "/x/" + spec.file)
    monkeypatch.setattr(llm, "_LOADED", None)
    assert {s.model_id for s in llm.servable_models(cat, ram_gb=3.3)} == {"s"}


def test_readiness_counts_the_loaded_model_as_fitting(monkeypatch):
    monkeypatch.setattr(llm, "runtime_available", lambda: True)
    monkeypatch.setattr(llm, "load_catalog", lambda *a, **k: _cat())
    monkeypatch.setattr(llm, "_verified_path", lambda spec: "/x/" + spec.file)
    monkeypatch.setattr(llm, "_usable_ram_gb", lambda: 3.3)
    monkeypatch.setattr(llm, "_LOADED", ("m", 1840 / 1024))
    monkeypatch.setattr(llm, "MIRROR", "http://m")
    r = llm.readiness()
    assert r["fits"] >= 2 and r["ram_gb"] == 5.1
