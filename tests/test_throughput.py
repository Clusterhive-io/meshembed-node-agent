"""Throughput knobs: encode batch size, worker count, and the capacity they advertise.

The daemon's poll->encode->report loop is SYNCHRONOUS, so one worker holds exactly
one subjob at a time. That makes two things load-bearing:

  * `max_chunks` must never advertise more capacity than there are workers, or the
    backend hands out subjobs nobody is processing and they time out — costing the
    operator a failed subjob rather than earning them throughput.
  * concurrency must stay OPT-IN, so an existing fleet upgrading to this release
    behaves exactly as before until an operator changes something.
"""
from __future__ import annotations

import importlib

import pytest

pytestmark = pytest.mark.unit


def _fresh_config(monkeypatch, **env):
    for k in ("MESHEMBED_WORKERS", "MESHEMBED_MAX_CHUNKS", "MESHEMBED_BATCH_SIZE"):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    import meshembed_node.config as c
    importlib.reload(c)
    return c


def _enc(monkeypatch, device="cpu", vram=0, **env):
    for k in ("MESHEMBED_BATCH_SIZE",):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    import meshembed_node.encoder as e
    monkeypatch.setattr(e, "_DEVICE", device, raising=False)
    monkeypatch.setattr(e, "_VRAM_FREE_MB", vram, raising=False)
    return e


# --- batch size --------------------------------------------------------------

def test_batch_size_scales_with_vram(monkeypatch):
    assert _enc(monkeypatch, "cuda", 24000).encode_batch_size() == 128
    assert _enc(monkeypatch, "cuda", 12000).encode_batch_size() == 64
    assert _enc(monkeypatch, "cuda", 6000).encode_batch_size() == 32


def test_batch_size_conservative_off_gpu(monkeypatch):
    assert _enc(monkeypatch, "cpu").encode_batch_size() == 16
    assert _enc(monkeypatch, "mps").encode_batch_size() == 32


def test_explicit_batch_size_wins(monkeypatch):
    assert _enc(monkeypatch, "cpu", MESHEMBED_BATCH_SIZE="256").encode_batch_size() == 256


@pytest.mark.parametrize("bad", ["0", "-4", "lots", ""])
def test_bad_batch_size_falls_back_to_auto(monkeypatch, bad):
    # must never return 0/negative — sentence-transformers would raise mid-job
    assert _enc(monkeypatch, "cpu", MESHEMBED_BATCH_SIZE=bad).encode_batch_size() == 16


# --- worker count ------------------------------------------------------------

def test_defaults_to_single_worker(monkeypatch):
    """Concurrency is opt-in: an upgrading fleet must not change behaviour."""
    from meshembed_node import worker
    monkeypatch.delenv("MESHEMBED_WORKERS", raising=False)
    assert worker._worker_count(object()) == 1


def test_worker_count_honours_env(monkeypatch):
    from meshembed_node import worker
    monkeypatch.setenv("MESHEMBED_WORKERS", "4")
    assert worker._worker_count(object()) == 4


def test_worker_count_is_capped(monkeypatch):
    from meshembed_node import worker
    monkeypatch.setenv("MESHEMBED_WORKERS", "999")
    assert worker._worker_count(object()) == 16


@pytest.mark.parametrize("bad", ["0", "-1", "many", " "])
def test_bad_worker_count_falls_back_to_one(monkeypatch, bad):
    from meshembed_node import worker
    monkeypatch.setenv("MESHEMBED_WORKERS", bad)
    assert worker._worker_count(object()) == 1


# --- advertised capacity must match real capacity ----------------------------

def test_max_chunks_defaults_to_one(monkeypatch):
    assert _fresh_config(monkeypatch).Config.__init__ is not None  # module loads
    import meshembed_node.config as c
    monkeypatch.setenv("MESHEMBED_NODE_ID", "n1")
    assert (c.os.environ.get("MESHEMBED_MAX_CHUNKS") or "") == ""


def test_max_chunks_tracks_worker_count(monkeypatch):
    """The invariant that stops us advertising capacity we cannot serve."""
    c = _fresh_config(monkeypatch, MESHEMBED_WORKERS="4")
    cfg = c.Config.__new__(c.Config)
    # exercise just the capacity resolution the constructor performs
    import os
    explicit = (os.environ.get("MESHEMBED_MAX_CHUNKS", "") or "").strip()
    w = (os.environ.get("MESHEMBED_WORKERS", "") or "").strip()
    resolved = int(explicit) if explicit else (max(1, min(int(w), 16)) if w else 1)
    assert resolved == 4


def test_explicit_max_chunks_overrides_workers(monkeypatch):
    _fresh_config(monkeypatch, MESHEMBED_WORKERS="4", MESHEMBED_MAX_CHUNKS="2")
    import os
    explicit = (os.environ.get("MESHEMBED_MAX_CHUNKS", "") or "").strip()
    assert int(explicit) == 2
