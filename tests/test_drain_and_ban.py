"""Graceful drain (SIGTERM) + ban awareness in the daemon loop.

Drain: stopping a node must finish the subjob in flight and exit cleanly, instead
of orphaning it (which cost the operator an availability/reputation hit for a
shutdown they initiated).

Ban: the backend enforces a ban with assignment=None, which is indistinguishable
from "no work". The `banned` flag makes it explicit so the daemon can tell the
operator and stop hammering the poll endpoint.
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
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


# --- bounded drain (2026-10-01: a node held 9.7 GB and outlived the 90 s stop) ---

class _Cfg:
    backend_url = "http://backend.invalid"
    node_id = "node-1"
    api_key = "k"


def _capture_post(monkeypatch, fail=False):
    posted = []

    def fake_post(base, path, payload, api_key, timeout=60):
        if fail:
            raise ConnectionError("backend down")
        posted.append((path, payload, timeout))
        return {}
    monkeypatch.setattr(worker, "_post", fake_post)
    return posted


def test_watchdog_releases_held_work_then_exits(monkeypatch):
    posted = _capture_post(monkeypatch)
    monkeypatch.setattr(worker, "_HELD", {0: "sub-1", 1: None})
    exits = []
    t0 = time.monotonic()
    worker._drain_watchdog(_Cfg(), 0.1, _exit=exits.append)
    assert time.monotonic() - t0 >= 0.09            # waited the grace first
    assert exits == [0]
    # "Holding nothing" is the heartbeat contract for: release it now.
    assert posted == [("/node_heartbeat", {"node_id": "node-1",
                                           "process_boot_id": worker.PROCESS_BOOT_ID,
                                           "holding": []}, 5)]


def test_watchdog_exits_even_with_nothing_held(monkeypatch):
    posted = _capture_post(monkeypatch)
    monkeypatch.setattr(worker, "_HELD", {0: None})
    exits = []
    worker._drain_watchdog(_Cfg(), 0.01, _exit=exits.append)
    assert exits == [0] and posted == []            # a hang elsewhere is still bounded


def test_watchdog_exits_when_the_release_fails(monkeypatch):
    _capture_post(monkeypatch, fail=True)
    monkeypatch.setattr(worker, "_HELD", {0: "sub-1"})
    exits = []
    worker._drain_watchdog(_Cfg(), 0.01, _exit=exits.append)
    assert exits == [0]


def test_first_signal_starts_the_watchdog_only_for_the_daemon(monkeypatch):
    started = []
    monkeypatch.setattr(worker, "_drain_watchdog",
                        lambda cfg, grace, _exit=None: started.append((cfg, grace)))
    try:
        worker._install_drain_handlers()            # no cfg (tests, tools): no watchdog
        signal.raise_signal(signal.SIGTERM)
        time.sleep(0.05)
        assert started == []
        worker._DRAIN.clear()
        cfg = _Cfg()
        worker._install_drain_handlers(cfg)
        signal.raise_signal(signal.SIGTERM)
        for _ in range(100):
            if started:
                break
            time.sleep(0.01)
        assert started == [(cfg, worker.DRAIN_GRACE_S)]
    finally:
        # Never leave a daemon-mode handler installed: a later SIGTERM in the
        # suite would start a real watchdog that exits the test process.
        worker._install_drain_handlers()


@pytest.mark.skipif(os.name != "posix", reason="POSIX signals; the Windows stop path is TerminateProcess")
def test_a_real_process_holding_work_exits_within_the_grace(tmp_path):
    """End to end in a child process: daemon-mode handlers, a subjob held
    forever (a generation item that will not finish), SIGTERM. The process must
    be gone shortly after the grace, with exit code 0, instead of hanging until
    the service manager's SIGKILL."""
    code = (
        "import time\n"
        "from meshembed_node import worker\n"
        "class C: backend_url='http://127.0.0.1:9'; node_id='n'; api_key='k'\n"
        "worker._HELD[0] = 'sub-forever'\n"
        "worker._install_drain_handlers(C())\n"
        "print('ready', flush=True)\n"
        "while True: time.sleep(0.1)\n"
    )
    # The child must import the package the way this test did, whatever the cwd
    # (test-protocol runs from the repo root, where meshembed_node is not on the path).
    pkg_root = os.path.dirname(os.path.dirname(os.path.abspath(worker.__file__)))
    env = dict(os.environ, MESHEMBED_DRAIN_GRACE_S="1",
               PYTHONPATH=os.pathsep.join(filter(None, [pkg_root, os.environ.get("PYTHONPATH")])))
    proc = subprocess.Popen([sys.executable, "-c", code], env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)
    try:
        # Import-time notices (e.g. "torch not installed") may precede "ready".
        seen = []
        for _ in range(50):
            line = proc.stdout.readline()
            if not line or line.strip() == "ready":
                break
            seen.append(line)
        if not line:
            proc.kill()
            pytest.fail("child did not start: " + "".join(seen)[-2000:])
        t0 = time.monotonic()
        proc.send_signal(signal.SIGTERM)
        rc = proc.wait(timeout=15)
        elapsed = time.monotonic() - t0
    finally:
        if proc.poll() is None:
            proc.kill()
    assert rc == 0
    assert 0.9 <= elapsed < 8, elapsed      # the grace, plus a refused release POST


def test_default_grace_fits_every_service_manager():
    # launchd SIGKILLs after ExitTimeOut (20 s default); systemd after 90 s.
    assert 0 < worker.DRAIN_GRACE_S < 20


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


def test_a_bad_drain_grace_falls_back_to_15():
    """A typo in MESHEMBED_DRAIN_GRACE_S must not stop the daemon from starting."""
    for raw in (None, "", "15s", "abc", "-3", "0", "nan", "inf"):
        assert worker._drain_grace(raw) == 15.0, raw
    assert worker._drain_grace("7.5") == 7.5
