"""The work heartbeat (docs/DESIGN_FAST_FLIP.md).

Every HEARTBEAT_S the daemon tells the backend which subjobs it holds, so an
assignment lost on the way (job-b9ee84c5, 2026-09-27, 30 min stuck) or a node
that froze flips in seconds instead of waiting out the reaper.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from meshembed_node import worker

pytestmark = pytest.mark.unit


def _cfg():
    cfg = MagicMock()
    cfg.backend_url, cfg.api_key, cfg.node_id = "http://b", "k", "node-hb"
    return cfg


@pytest.fixture(autouse=True)
def _clean():
    worker._HELD.clear()
    worker._DRAIN.clear()
    yield
    worker._HELD.clear()
    worker._DRAIN.clear()


def test_the_payload_lists_only_what_workers_hold():
    worker._HELD.update({0: "subjob-b", 1: None, 2: "subjob-a"})
    p = worker._heartbeat_payload(_cfg())
    assert p == {"node_id": "node-hb", "process_boot_id": worker.PROCESS_BOOT_ID,
                 "holding": ["subjob-a", "subjob-b"], "gate_reason": None}


def _run_loop(side_effect, n_calls):
    """Drive _heartbeat_loop for n_calls posts; return the waits it asked for."""
    waits, calls = [], []

    def fake_sleep(s):
        waits.append(s)
        return len(calls) >= n_calls

    def fake_post(*a, **k):
        calls.append(a)
        return side_effect(len(calls))

    with patch.object(worker, "_sleep_or_drain", fake_sleep), patch.object(worker, "_post", fake_post):
        worker._heartbeat_loop(_cfg())
    return waits, calls


def test_it_beats_every_heartbeat_interval():
    waits, calls = _run_loop(lambda i: {"released": 0}, 3)
    assert len(calls) == 3 and calls[0][1] == "/node_heartbeat"
    assert waits == [worker.HEARTBEAT_S] * 4


def _http_error(status):
    resp = MagicMock(status_code=status)
    return requests.HTTPError(response=resp)


def test_an_old_backend_without_the_endpoint_is_asked_rarely():
    def se(i):
        raise _http_error(404)
    waits, _ = _run_loop(se, 2)
    assert waits == [worker.HEARTBEAT_S, 600.0, 600.0]


def test_a_transient_failure_never_stops_the_heartbeat():
    def se(i):
        if i == 1:
            raise requests.ConnectionError("down")
        return {}
    waits, calls = _run_loop(se, 3)
    assert len(calls) == 3 and waits == [worker.HEARTBEAT_S] * 4


def test_drain_ends_the_loop():
    worker._DRAIN.set()
    with patch.object(worker, "_post") as post:
        worker._heartbeat_loop(_cfg())
    post.assert_not_called()


def test_a_refused_heartbeat_backs_off_and_never_raises():
    def se(i):
        raise _http_error(401)
    waits, _ = _run_loop(se, 2)
    assert waits == [worker.HEARTBEAT_S, 600.0, 600.0]
