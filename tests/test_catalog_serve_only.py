"""F-1..F-3 + F-a..F-c (auditor 2026-10-28 12:28Z): a serve_only catalogue entry (the 18.56 GB Qwen3-30B-A3B of E3)
is never pre-warmed, never advertised, never loaded for a job; only the serve duty sees it, for a verified plan."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from meshembed_node import llm
from meshembed_node import serve_duty as SDY

pytestmark = pytest.mark.unit

SMALL = {"model_id": "meshembed/qwen3-4b-q8", "file": "qwen3-4b-q8_0.gguf", "sha256": "a" * 64, "size_mb": 4167,
         "min_ram_gb": 6.0, "context": 4096}
BIG = {"model_id": "meshembed/qwen3-30b-a3b-q4", "file": "Qwen3-30B-A3B-Q4_K_M.gguf", "sha256": "b" * 64,
       "size_mb": 17697, "min_ram_gb": 22.0, "context": 8192, "serve_only": True,
       "url": "https://huggingface.co/Qwen/Qwen3-30B-A3B-GGUF/resolve/e4d4bafdfb96a411a163846265362aceb0b9c63a/"
              "Qwen3-30B-A3B-Q4_K_M.gguf"}


@pytest.fixture
def catalog(tmp_path, monkeypatch):
    p = tmp_path / "llm_catalog.json"
    p.write_text(json.dumps({"models": [SMALL, BIG]}))
    real = llm.load_catalog
    monkeypatch.setattr(llm, "load_catalog",
                        lambda path=p, include_serve_only=False: real(path, include_serve_only=include_serve_only))
    return p


def test_default_catalogue_hides_serve_only(catalog):
    assert set(llm.load_catalog()) == {"meshembed/qwen3-4b-q8"}
    assert set(llm.load_catalog(include_serve_only=True)) == {"meshembed/qwen3-4b-q8", "meshembed/qwen3-30b-a3b-q4"}
    assert llm.spec_for("meshembed/qwen3-30b-a3b-q4") is None          # job-time load path: model_not_in_catalog


def test_warm_never_fetches_serve_only_on_a_big_unpinned_node(catalog, monkeypatch):
    fetched = []
    monkeypatch.setattr(llm, "runtime_available", lambda: True)
    monkeypatch.setattr(llm, "_usable_ram_gb", lambda: 64.0)
    monkeypatch.setattr(llm, "_total_ram_gb", lambda: 64.0)
    monkeypatch.setattr(llm, "_verified_path", lambda spec: None)
    monkeypatch.setattr(llm, "_free_disk_gb", lambda d: 500.0)
    monkeypatch.setattr(llm, "ensure_model", lambda spec, timeout=1800: fetched.append(spec.model_id) or Path("/x"))
    llm.warm_models(None)                                                # no pins: the "spread" case
    assert fetched == ["meshembed/qwen3-4b-q8"]                          # never the 30B


def test_servable_and_advertised_exclude_serve_only(catalog, monkeypatch):
    monkeypatch.setattr(llm, "runtime_available", lambda: True)
    monkeypatch.setattr(llm, "_usable_ram_gb", lambda: 64.0)
    monkeypatch.setattr(llm, "_verified_path", lambda spec: Path("/present"))   # even with the file on disk (F-c)
    assert [s.model_id for s in llm.servable_models()] == ["meshembed/qwen3-4b-q8"]
    assert [m["model_id"] for m in llm.installed_llm_models()] == ["meshembed/qwen3-4b-q8"]


def test_serve_duty_stages_a_serve_only_model_for_its_plan(catalog, monkeypatch, tmp_path):
    src = tmp_path / "cache.gguf"
    src.write_bytes(b"weights")
    seen = []
    monkeypatch.setattr(llm, "ensure_model", lambda spec, timeout=1800: seen.append(spec.model_id) or src)
    assert SDY.model_id_from_catalogue("b" * 64) == "meshembed/qwen3-30b-a3b-q4"
    assert SDY.stage_from_catalogue("b" * 64, staging=tmp_path / "serve-models") is True
    assert seen == ["meshembed/qwen3-30b-a3b-q4"]
    staged = tmp_path / "serve-models" / f"{'b' * 64}.gguf"
    assert staged.read_bytes() == b"weights" and staged.stat().st_nlink == 1


def test_the_v0378_catalogue_is_unchanged_and_the_shape_stays_strict(tmp_path):
    shipped = llm.load_catalog()                                         # the real llm_catalog.json of this tree
    assert shipped and all(not s.serve_only for s in shipped.values())
    full = llm.load_catalog(include_serve_only=True)
    # v0.3.79 ships exactly ONE serve-only entry: Qwen3-30B-A3B at the K8 pin and the pinned upstream revision
    assert set(full) - set(shipped) == {"meshembed/qwen3-30b-a3b-q4"}
    q = full["meshembed/qwen3-30b-a3b-q4"]
    assert q.serve_only and q.sha256 == "0d003f6662faee786ed5da3e31b29c978de5ae5d275c8794c606a7f3c01aa8f5"
    assert "/resolve/e4d4bafdfb96a411a163846265362aceb0b9c63a/" in q.url and q.file == "Qwen3-30B-A3B-Q4_K_M.gguf"
    bad = tmp_path / "c.json"
    bad.write_text(json.dumps({"models": [dict(SMALL, surprise=1)]}))
    assert llm.load_catalog(bad) == {}                                   # an unknown key still refuses (F-b)


def test_the_source_is_the_mirror_or_the_pinned_revision(monkeypatch):
    spec = llm.ModelSpec(**BIG)
    monkeypatch.setattr(llm, "MIRROR", "http://192.168.30.188/gguf")
    assert llm._source_url(spec) == "http://192.168.30.188/gguf/Qwen3-30B-A3B-Q4_K_M.gguf"
    monkeypatch.setattr(llm, "MIRROR", None)
    assert "/resolve/e4d4bafdfb96a411a163846265362aceb0b9c63a/" in llm._source_url(spec)   # never "main" (F-a)
