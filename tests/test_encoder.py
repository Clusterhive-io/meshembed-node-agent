"""Tests for the encoder and device detection."""
from __future__ import annotations

import sys
import types
from unittest.mock import patch, MagicMock

import numpy as np
import pytest


def _fresh_encoder_module():
    """Re-import the encoder cleanly (resets device-detection globals)."""
    for mod in list(sys.modules.keys()):
        if "meshembed_node.encoder" in mod or mod == "meshembed_node.encoder":
            del sys.modules[mod]
    from meshembed_node import encoder
    return encoder


# ---------------------------------------------------------------------------
# Device detection
# ---------------------------------------------------------------------------

def test_detect_cuda_preferred(monkeypatch):
    """When pynvml is available and CUDA works → device=cuda."""
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
    """encode() returns a list of vectors with the same length as the input."""
    from meshembed_node.encoder import Encoder
    enc = Encoder.__new__(Encoder)
    enc._model = None  # force hash fallback
    texts = ["hello", "world", "foo"]
    embeddings, gpu_secs = enc.encode(texts)
    assert len(embeddings) == 3
    assert all(isinstance(v, list) for v in embeddings)
    assert gpu_secs >= 0.0


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
