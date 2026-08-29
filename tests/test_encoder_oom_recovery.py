"""CUDA-OOM recovery: evict idle cached models and retry, don't fail the subjob.

Prod 2026-08-16 (Tesla M60, 8 GB): the LRU cache held 3 models resident, VRAM
hit 3.75 MiB free, and every encode died — as "CUDA out of memory" or as
CUBLAS_STATUS_NOT_INITIALIZED (cublasCreate cannot allocate its workspace).
Failing a customer's subjob while sitting on gigabytes of EVICTABLE idle models
is absurd: drop everything but the active model and retry once.
"""
from __future__ import annotations

import time

import pytest

from meshembed_node.encoder import Encoder, _is_cuda_oom

pytestmark = pytest.mark.unit


class _FakeModel:
    """Encodes fine unless told to fail the first N calls with a given error."""

    def __init__(self, fail_first: int = 0, message: str = ""):
        self.fail_remaining = fail_first
        self.message = message
        self.calls = 0

    def encode(self, texts, **_kw):
        self.calls += 1
        if self.fail_remaining > 0:
            self.fail_remaining -= 1
            raise RuntimeError(self.message)
        return [[0.1, 0.2, 0.3] for _ in texts]


def _encoder_with_cache(active: _FakeModel) -> Encoder:
    enc = Encoder("active-model", preload=False)
    enc._cache["idle-model-a"] = (_FakeModel(), "sha-a", time.time())
    enc._cache["idle-model-b"] = (_FakeModel(), "sha-b", time.time())
    enc._cache["active-model"] = (active, "sha-active", time.time())
    return enc


def test_cublas_failure_evicts_idle_models_and_retries():
    active = _FakeModel(
        fail_first=1,
        message="CUDA error: CUBLAS_STATUS_NOT_INITIALIZED when calling `cublasCreate(handle)`",
    )
    enc = _encoder_with_cache(active)

    embeddings, _, sha = enc.encode(["hola", "adios"], "active-model")

    assert active.calls == 2, "must retry after freeing memory"
    assert len(embeddings) == 2 and sha == "sha-active"
    assert set(enc._cache) == {"active-model"}, "idle models must be evicted"


def test_plain_cuda_oom_is_also_recovered():
    active = _FakeModel(
        fail_first=1,
        message="CUDA out of memory. Tried to allocate 96.00 MiB",
    )
    enc = _encoder_with_cache(active)
    embeddings, _, _ = enc.encode(["x"], "active-model")
    assert len(embeddings) == 1 and active.calls == 2


def test_non_oom_error_still_raises_and_keeps_cache():
    active = _FakeModel(fail_first=1, message="dimension mismatch: 384 vs 768")
    enc = _encoder_with_cache(active)
    with pytest.raises(RuntimeError, match="dimension mismatch"):
        enc.encode(["x"], "active-model")
    assert active.calls == 1, "no blind retry on a real bug"
    assert len(enc._cache) == 3, "cache untouched — eviction is for OOM only"


def test_persistent_oom_raises_after_one_retry():
    active = _FakeModel(fail_first=2, message="CUDA out of memory")
    enc = _encoder_with_cache(active)
    with pytest.raises(RuntimeError, match="out of memory"):
        enc.encode(["x"], "active-model")
    assert active.calls == 2, "exactly one retry — a second failure is real"


def test_oom_matcher_shapes():
    assert _is_cuda_oom(RuntimeError("CUBLAS_STATUS_ALLOC_FAILED"))
    assert _is_cuda_oom(RuntimeError("CUDA error: out of memory"))
    assert not _is_cuda_oom(RuntimeError("connection reset by peer"))
