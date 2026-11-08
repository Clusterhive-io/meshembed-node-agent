"""CANARY-HOLD (b) (bed run 2, 2026-11-04; auditor SL-Q3 + 2026-11-04T23:23:27Z): the backend may ask a node to drop
its BATCH copy of a model (get_job unload_models) so a serve split of the same model can form. The node:
- advertises that it honours the signal (hw.serve.unload == 1), so an older daemon is never asked;
- drops ONLY the named model, and only between items (a runner in use is skipped, never waited on);
- treats the value as a claim channel: catalogue LLM ids only, deduplicated, bounded; anything else is ignored.
The loaded:false the backend believes is the next poll's ordinary installed_models report (llm._loaded_id())."""
from __future__ import annotations

import threading

import pytest

from meshembed_node import llm, worker

pytestmark = pytest.mark.unit


class _Model:
    pass


def _resident(monkeypatch, mid="m"):
    r = llm.LlamaRunner()
    r._model, r._loaded_id = _Model(), mid
    monkeypatch.setattr(llm, "_LOADED", (mid, 4.0))
    return r


def test_the_named_model_is_dropped_and_the_next_report_says_so(monkeypatch):
    r = _resident(monkeypatch)
    assert r.unload_for_split("m") is True
    assert r._model is None and r._loaded_id is None and llm._loaded_id() is None


def test_another_model_is_never_dropped_on_that_signal(monkeypatch):
    r = _resident(monkeypatch)
    assert r.unload_for_split("other") is False
    assert r._loaded_id == "m" and llm._loaded_id() == "m"


def test_nothing_loaded_is_a_no_op():
    assert llm.LlamaRunner().unload_for_split("m") is False


def test_a_runner_in_use_is_skipped_never_waited_on(monkeypatch):
    """Mid-item = the lock is held across generation: the signal waits for the next poll, the item finishes."""
    r = _resident(monkeypatch)
    held, release = threading.Event(), threading.Event()

    def busy():
        with r._lock:
            held.set()
            release.wait(5)

    t = threading.Thread(target=busy)
    t.start()
    held.wait(5)
    try:
        assert r.unload_for_split("m") is False and r._loaded_id == "m"
    finally:
        release.set()
        t.join(5)
    assert r.unload_for_split("m") is True                       # the next poll, between items


def test_the_value_is_catalogue_ids_only(monkeypatch):
    known = {"meshembed/a-q4", "meshembed/b-q4"}
    monkeypatch.setattr(llm, "spec_for", lambda mid, catalog=None: object() if mid in known else None)
    assert worker._unload_ids(["meshembed/a-q4", "meshembed/a-q4", "meshembed/b-q4"]) == ["meshembed/a-q4",
                                                                                         "meshembed/b-q4"]
    assert worker._unload_ids(["../../etc/passwd", 7, None, {"x": 1}, "meshembed/unknown"]) == []
    for hostile in ("meshembed/a-q4", {"meshembed/a-q4": 1}, None, 3):
        assert worker._unload_ids(hostile) == [], hostile
    many = ["meshembed/a-q4"] * 50 + ["meshembed/b-q4"]
    assert worker._unload_ids(many) == ["meshembed/a-q4"]        # bounded: only the first UNLOAD_MODELS_MAX entries


def test_the_daemon_advertises_it():
    assert worker._hardware_info()["serve"]["unload"] == 1


def test_a_non_dict_serve_status_never_breaks_the_report(monkeypatch):
    """CH-N1 (auditor 2026-11-06T06:39:19Z): the advert must not make _hardware_info raise whatever status() returns."""
    class _Duty:
        def status(self):
            return "not-a-dict"
    monkeypatch.setattr(worker, "_SERVE_DUTY", _Duty())
    hw = worker._hardware_info()
    # node-rel-next (EP1-n + CANARY-HOLD composed): EP1's dict(status, stream=1) raises on a non-dict status inside the
    # guarded block, so the report is the error dict; CH-N1's point holds: _hardware_info never raises
    assert hw["serve"] == {"ready": False, "reason": "error", "unload": 1}

