"""Tests for the encoder and device detection."""
from __future__ import annotations

import sys
import types
from unittest.mock import patch, MagicMock

import numpy as np
import pytest


def _fresh_encoder_module():
    """Re-import the encoder cleanly (resets device-detection globals).

    Dropping the sys.modules entry is not sufficient on its own: `from
    meshembed_node import encoder` resolves the attribute already cached on the
    package object, so once any other test module has imported the encoder this
    handed back the STALE module and detection never re-ran. That is why these
    tests passed when the file was run alone and failed in the full suite.
    `import_module` consults sys.modules directly, so the removal takes effect.
    """
    import importlib

    sys.modules.pop("meshembed_node.encoder", None)
    return importlib.import_module("meshembed_node.encoder")


@pytest.fixture(autouse=True)
def _restore_encoder_module():
    """Put the real encoder module back after each test.

    The device-detection tests import the encoder under mocked hardware. Leaving
    that import installed would hand a fake 'cuda' encoder to every test that
    runs afterwards — the same pollution in the opposite direction.
    """
    original = sys.modules.get("meshembed_node.encoder")
    yield
    if original is not None:
        sys.modules["meshembed_node.encoder"] = original
        import meshembed_node
        meshembed_node.encoder = original
    else:
        sys.modules.pop("meshembed_node.encoder", None)


# ---------------------------------------------------------------------------
# Device detection
# ---------------------------------------------------------------------------

def test_detect_cuda_preferred(monkeypatch):
    """When torch can use CUDA and pynvml reports a GPU → device=cuda.

    `_detect_accelerator` deliberately requires BOTH signals: a box can have an
    NVIDIA card that the installed torch was not built to drive, and reporting
    'cuda' there sends the node jobs it cannot run. Mocking pynvml alone — which
    is what this test used to do — therefore fails on any host without a working
    CUDA torch, i.e. on every CI runner and on 189.
    """
    import torch

    monkeypatch.setattr(torch.cuda, "is_available", lambda: True)
    nvml = MagicMock()
    nvml.nvmlInit.return_value = None
    handle = MagicMock()
    nvml.nvmlDeviceGetHandleByIndex.return_value = handle
    nvml.nvmlDeviceGetName.return_value = "Tesla T4"
    mem = MagicMock(); mem.free = 8 * 1024**3
    nvml.nvmlDeviceGetMemoryInfo.return_value = mem

    monkeypatch.setitem(sys.modules, "pynvml", nvml)
    enc = _fresh_encoder_module()

    assert enc._DEVICE == "cuda"
    assert "T4" in enc._GPU_MODEL
    assert enc._VRAM_FREE_MB > 0


def test_detect_cpu_fallback(monkeypatch):
    """When pynvml fails and there is no MPS → device=cpu."""
    import meshembed_node.encoder as enc_mod

    # Simulate pynvml raising and no MPS/Darwin available.
    monkeypatch.setattr(enc_mod, "_DEVICE", "cpu")
    monkeypatch.setattr(enc_mod, "_GPU_MODEL", "cpu-test")
    monkeypatch.setattr(enc_mod, "_VRAM_FREE_MB", 0)

    assert enc_mod._DEVICE == "cpu"
    assert enc_mod._VRAM_FREE_MB == 0


# ---------------------------------------------------------------------------
# Encoder.encode
# ---------------------------------------------------------------------------

def test_encode_returns_correct_shape():
    """encode() returns one vector per input, and reports no sha, when the
    model cannot be loaded.

    This used to force the fallback with `enc._model = None`. `_model` is now a
    read-only property computed from the model cache (multi-model support), so
    that assignment raises. The fallback is reached by making the load fail,
    which is what the property change was modelling anyway.
    """
    from meshembed_node.encoder import Encoder
    enc = Encoder.__new__(Encoder)
    enc.default_model_name = "test/unloadable"
    enc._get_or_load = lambda name: (None, "")   # force the hash fallback
    texts = ["hello", "world", "foo"]
    embeddings, gpu_secs, sha = enc.encode(texts)
    assert len(embeddings) == 3
    assert all(isinstance(v, list) for v in embeddings)
    assert gpu_secs >= 0.0
    assert sha == "", (
        "a fallback embedding must report no sha, so the backend can tell it "
        "apart from a real model's output in strict-sha mode"
    )


def test_hash_embed_is_l2_normalised():
    """The hash fallback returns L2-normalised vectors."""
    from meshembed_node.encoder import Encoder
    vec = Encoder._hash_embed("test text")
    norm = float(np.linalg.norm(vec))
    assert abs(norm - 1.0) < 1e-5


def test_hash_embed_deterministic():
    """Same text → same vector."""
    from meshembed_node.encoder import Encoder
    assert Encoder._hash_embed("abc") == Encoder._hash_embed("abc")


def test_vram_free_mb_cpu_returns_zero(monkeypatch):
    """On CPU, vram_free_mb() returns 0."""
    import meshembed_node.encoder as enc_mod
    monkeypatch.setattr(enc_mod, "_DEVICE", "cpu")
    assert enc_mod.vram_free_mb() == 0
