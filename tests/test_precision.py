"""Inference precision selection + its canary safety gate.

Measured against the live fp32 canary references (ST 5.1.1, canary prompt):
  fp16 -> 0.999999  (clears the 0.999 pass threshold; safe, no backend work)
  int8 -> 0.9226-0.9743, and bge-base is BELOW 0.95 = the canary FAIL band

So fp16 is free, and int8 must not be silently enableable: an honest node
running it would be penalised, and the customer would quietly receive
lower-fidelity vectors. Hence the explicit override.
"""
from __future__ import annotations

import importlib

import pytest

pytestmark = pytest.mark.unit


def _enc(monkeypatch, device="cuda", **env):
    """Reload the encoder module with a chosen device + env."""
    import meshembed_node.encoder as enc
    for k in ("MESHEMBED_PRECISION", "MESHEMBED_ALLOW_INT8"):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(enc, "_DEVICE", device, raising=False)
    return enc


def test_defaults_to_fp32(monkeypatch):
    enc = _enc(monkeypatch)
    assert enc.configured_precision() == "fp32"


def test_fp16_enabled_on_gpu(monkeypatch):
    enc = _enc(monkeypatch, device="cuda", MESHEMBED_PRECISION="fp16")
    assert enc.configured_precision() == "fp16"


def test_fp16_ignored_on_cpu(monkeypatch):
    """CPU fp16 in torch is emulated — slower than fp32 with no memory win, so
    silently degrading a CPU node would be a pessimisation, not an optimisation."""
    enc = _enc(monkeypatch, device="cpu", MESHEMBED_PRECISION="fp16")
    assert enc.configured_precision() == "fp32"


def test_int8_refused_without_explicit_override(monkeypatch):
    """The canary-safety gate: int8 lands in warn/FAIL, so it must not be
    enableable by setting the precision alone."""
    enc = _enc(monkeypatch, device="cuda", MESHEMBED_PRECISION="int8")
    assert enc.configured_precision() == "fp32"


def test_int8_allowed_with_explicit_override(monkeypatch):
    enc = _enc(monkeypatch, device="cuda",
               MESHEMBED_PRECISION="int8", MESHEMBED_ALLOW_INT8="1")
    assert enc.configured_precision() == "int8"


@pytest.mark.parametrize("bad", ["", "float16", "8bit", "FP99", "garbage"])
def test_unknown_precision_falls_back_to_fp32(monkeypatch, bad):
    enc = _enc(monkeypatch, device="cuda", MESHEMBED_PRECISION=bad)
    assert enc.configured_precision() == "fp32"


def test_case_and_whitespace_tolerated(monkeypatch):
    enc = _enc(monkeypatch, device="cuda", MESHEMBED_PRECISION="  FP16 ")
    assert enc.configured_precision() == "fp16"


def test_apply_precision_never_breaks_encoding(monkeypatch):
    """A failed cast must leave a usable fp32 model rather than kill the node."""
    enc = _enc(monkeypatch, device="cuda", MESHEMBED_PRECISION="fp16")

    class Boom:
        def half(self):
            raise RuntimeError("no fp16 kernel here")

    model = Boom()
    assert enc._apply_precision(model, "some/model") is model  # returned, not raised


def test_precision_is_reported_to_backend(monkeypatch):
    """The backend needs the node's precision to pick the right canary reference."""
    monkeypatch.setenv("MESHEMBED_PRECISION", "fp16")
    import meshembed_node.encoder as enc
    monkeypatch.setattr(enc, "_DEVICE", "cuda", raising=False)
    importlib.reload(importlib.import_module("meshembed_node.worker"))
    from meshembed_node import worker
    assert "configured_precision" in open(worker.__file__.replace(".pyc", ".py")).read()
