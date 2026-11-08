"""RT-1a (NG-3, auditor 2026-11-01 20:54:16Z / 21:05:00Z): a COMPLETED report is re-sent on a connection error,
a timeout, 502, 503 or 504, with bounded pauses that end before the item's own timeout. A failure or a decline is
sent once (the backend would count a re-sent one twice); a 4xx or a 500 is never retried.

INC-AF3B-502: a 502 while the backend was recreated lost finished answers, because the report was one POST."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import requests

from meshembed_node import worker

pytestmark = pytest.mark.unit

BASE = {"job_id": "j", "subjob_id": "s", "chunk_index": 0, "callback_token": "t", "texts": ["a"],
        "timeout_seconds": 120}


def _cfg():
    cfg = MagicMock()
    cfg.node_id, cfg.api_key, cfg.backend_url = "node-test", "k", "http://backend.invalid"
    cfg.machine_fingerprint = "a" * 64
    cfg.gpu_uuid = "GPU-x"
    cfg.node_privkey = ""
    return cfg


class _Resp:
    def __init__(self, code):
        self.status_code = code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code}")


@pytest.fixture
def wire(monkeypatch):
    """answers: an int (HTTP status) or an exception instance, one per POST. Time is fake: sleep advances it."""
    state = {"answers": [], "posts": [], "sleeps": [], "now": 1000.0}

    def _post(url, json=None, headers=None, timeout=None):
        state["posts"].append({"payload": json, "timeout": timeout, "at": state["now"]})
        a = state["answers"].pop(0)
        if isinstance(a, Exception):
            raise a
        return _Resp(a)

    def _sleep(s):
        state["sleeps"].append(s)
        state["now"] += s

    monkeypatch.setattr(worker.requests, "post", _post)
    monkeypatch.setattr(worker.time, "sleep", _sleep)
    monkeypatch.setattr(worker.time, "monotonic", lambda: state["now"])
    return state


def _send(error=None, received_at=1000.0, assignment=BASE):
    return worker._report(_cfg(), assignment, [] if error else [[0.1]], 0.1, 1000, error, received_at=received_at)


@pytest.mark.parametrize("first", [502, 503, 504, requests.ConnectionError("reset"), requests.Timeout("read")])
def test_a_completed_report_is_re_sent_after_a_transient_failure(wire, first):
    wire["answers"] = [first, 200]
    assert _send() is True
    assert len(wire["posts"]) == 2 and wire["sleeps"] == [2.0]
    assert wire["posts"][0]["payload"] == wire["posts"][1]["payload"], "the same report, the same token"


def test_the_retries_are_bounded(wire):
    wire["answers"] = [503, 503, 503, 503]
    assert _send() is False
    assert len(wire["posts"]) == 4 and wire["sleeps"] == [2.0, 4.0, 8.0]


@pytest.mark.parametrize("code", [400, 401, 403, 404, 409, 422, 500])
def test_an_answer_from_the_backend_is_never_retried(wire, code):
    wire["answers"] = [code]
    assert _send() is False
    assert len(wire["posts"]) == 1 and wire["sleeps"] == []


@pytest.mark.parametrize("error", ["encode_error:oom", "declined:insufficient_memory"])
@pytest.mark.parametrize("first", [502, requests.ConnectionError("reset")])
def test_a_failure_or_a_decline_is_sent_once(wire, error, first):
    """The backend would count a re-sent failure twice (retry_count + 1, a second row): never retried."""
    wire["answers"] = [first]
    assert _send(error=error) is False
    assert len(wire["posts"]) == 1 and wire["sleeps"] == []


def test_the_last_attempt_ends_before_the_items_timeout(wire):
    """Received at t=1000 with a 16 s timeout, 10 s of work: attempts at 1010 and 1012; a third after a 4 s pause
    would start at 1016, the item's end, so it is not made."""
    wire["answers"] = [502, 502, 200]
    item = dict(BASE, timeout_seconds=16)
    wire["now"] = 1010.0
    assert _send(assignment=item) is False
    assert [p["at"] for p in wire["posts"]] == [1010.0, 1012.0]
    assert all(p["at"] + p["timeout"] <= 1016.0 for p in wire["posts"]), "no attempt can outlive the item"


def test_no_time_left_sends_nothing(wire):
    wire["answers"] = [200]
    wire["now"] = 1119.5                                     # 0.5 s before the 120 s timeout
    assert _send() is False and wire["posts"] == []


def test_without_a_receipt_time_the_retries_still_apply(wire):
    """A caller that does not pass received_at (none in the daemon today) keeps a 60 s request timeout."""
    wire["answers"] = [502, 200]
    assert _send(received_at=None) is True
    assert [p["timeout"] for p in wire["posts"]] == [60.0, 60.0]
