"""One model is downloaded by one thread at a time; a second caller waits and finds it.

Node 23711, 2026-09-27: warm passes from boot, a pins change and a mirror change
(plus a job needing the model) ran concurrently; two threads wrote the same
.part file, one renamed it away and the other failed with FileNotFoundError, and
the 3B was fetched again every ~40 s.
"""
from __future__ import annotations

import threading
import time

import pytest

import meshembed_node.llm as llm

pytestmark = pytest.mark.unit


def test_concurrent_callers_download_once(monkeypatch, tmp_path):
    spec = next(iter(llm.load_catalog().values()))
    done = {"path": None}
    calls = []

    def fake_verified(s):
        return done["path"]

    def fake_download(s, timeout):
        calls.append(threading.current_thread().name)
        time.sleep(0.3)                       # a slow download
        done["path"] = tmp_path / "model.gguf"
        return done["path"]

    monkeypatch.setattr(llm, "_verified_path", fake_verified)
    monkeypatch.setattr(llm, "_download", fake_download)
    results = []
    ts = [threading.Thread(target=lambda: results.append(llm.ensure_model(spec)), name=f"t{i}") for i in range(4)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert len(calls) == 1, f"downloaded {len(calls)} times"
    assert results == [tmp_path / "model.gguf"] * 4


def test_a_second_warm_pass_does_not_start_while_one_runs(monkeypatch):
    import meshembed_node.worker as worker
    import meshembed_node.llm as llm_mod
    started = []
    gate = threading.Event()

    def slow_warm(pinned=None):
        started.append(1)
        gate.wait(2)
        return []

    monkeypatch.setattr(llm_mod, "warm_models", slow_warm)
    t = threading.Thread(target=worker._llm_warm)
    t.start()
    time.sleep(0.1)
    worker._llm_warm()                        # returns at once: one is running
    gate.set()
    t.join()
    worker._llm_warm()                        # the lock was released: this one runs
    assert len(started) == 2
