"""asus1 2026-11-08 (orchestrator 17:16:34Z): a SERVE-ONLY generation id in the operator's pin list
(meshembed/qwen3-30b-a3b-q4) reached the encoder, which fetched it from Hugging Face as a sentence-transformers model
("encoder.predownload_failed ... exc=401"). The default load_catalog() leaves serve-only entries out, so the
embedding-only filter must ask for them. The REAL catalogue file is used here, not a stub."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from meshembed_node import llm, worker  # noqa: E402

SERVE_ONLY = "meshembed/qwen3-30b-a3b-q4"


def test_the_real_catalogue_marks_the_30b_serve_only_and_hides_it_by_default():
    assert SERVE_ONLY not in llm.load_catalog()                                  # why the old filter missed it
    assert llm.load_catalog(include_serve_only=True)[SERVE_ONLY].serve_only


def test_the_encoder_never_gets_a_serve_only_or_any_generation_id():
    pinned = ["BAAI/bge-m3", SERVE_ONLY, "meshembed/qwen3-4b-q8", "intfloat/multilingual-e5-small"]
    assert worker._embedding_only(pinned) == ["BAAI/bge-m3", "intfloat/multilingual-e5-small"]


def test_negative_control_the_default_catalogue_lets_the_serve_only_id_through():
    """What v0.3.83 did: with the default load_catalog() the 30B passes as an 'embedding' id."""
    llm_ids = set(llm.load_catalog())
    assert [m for m in ["BAAI/bge-m3", SERVE_ONLY] if m not in llm_ids] == ["BAAI/bge-m3", SERVE_ONLY]
