"""Graceful drain (SIGTERM) + ban awareness in the daemon loop.

Drain: stopping a node must finish the subjob in flight and exit cleanly, instead
of orphaning it (which cost the operator an availability/reputation hit for a
shutdown they initiated).

Ban: the backend enforces a ban with assignment=None, which is indistinguishable
from "no work". The `banned` flag makes it explicit so the daemon can tell the
operator and stop hammering the poll endpoint.
"""
from __future__ import annotations

import signal
import threading
import time

import pytest

from meshembed_node import worker

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _clear_drain():
    """The drain event is module-level; reset around every test."""
    worker._DRAIN.clear()
    yield
    worker._DRAIN.clear()


# --- _sleep_or_drain ---------------------------------------------------------

def test_sleep_or_drain_returns_false_when_not_draining():
    t0 = time.monotonic()
    assert worker._sleep_or_drain(0.05) is False
    assert time.monotonic() - t0 >= 0.04  # actually slept


def test_sleep_or_drain_returns_true_immediately_when_draining():
    worker._DRAIN.set()
    t0 = time.monotonic()
    assert worker._sleep_or_drain(30) is True
    # The whole point: shutdown doesn't wait out a 30s poll backoff.
    assert time.monotonic() - t0 < 1.0


def test_sleep_or_drain_wakes_early_when_drain_set_mid_sleep():
    def _later():
        time.sleep(0.05)
        worker._DRAIN.set()
    threading.Thread(target=_later, daemon=True).start()
    t0 = time.monotonic()
    assert worker._sleep_or_drain(10) is True
    assert time.monotonic() - t0 < 2.0


# --- signal handlers ---------------------------------------------------------

def test_sigterm_sets_drain_without_killing_process():
    worker._install_drain_handlers()
    assert not worker._DRAIN.is_set()
    signal.raise_signal(signal.SIGTERM)   # must NOT terminate the test process
    assert worker._DRAIN.is_set(), "SIGTERM should request drain, not kill"


def test_second_signal_forces_immediate_exit():
    worker._install_drain_handlers()
    signal.raise_signal(signal.SIGTERM)          # first: graceful
    assert worker._DRAIN.is_set()
    with pytest.raises(SystemExit):              # second: operator wants out now
        signal.raise_signal(signal.SIGTERM)


def test_sigint_also_drains():
    worker._install_drain_handlers()
    signal.raise_signal(signal.SIGINT)
    assert worker._DRAIN.is_set()


# --- ban awareness -----------------------------------------------------------

def test_banned_response_shape_is_backwards_compatible():
    """A pre-ban-awareness backend omits the fields; .get() must not explode."""
    legacy = {"assignment": None}
    assert not legacy.get("banned")
    assert legacy.get("ban_reason") is None


def test_banned_response_carries_reason():
    resp = {"assignment": None, "banned": True,
            "ban_reason": "security_event:as_jump"}
    assert resp.get("banned") is True
    assert "as_jump" in resp.get("ban_reason")
