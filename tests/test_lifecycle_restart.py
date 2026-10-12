"""L2 (node half): the owner's Start / Stop / Restart from the dashboard.

restart_now (one-shot on a poll) drains the daemon -- no new work, finish what
is held -- and run() then restarts the process: re-exec in place on Linux/macOS,
exit 3 on Windows for the scheduled task to relaunch (same as a self-update).
'stopped' needs no action: the backend sends no work.
"""
from __future__ import annotations

import pytest

from meshembed_node import worker

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _reset():
    worker._RESTART.clear()
    worker._DRAIN.clear()
    worker._LAST_DESIRED_STATE = None
    yield
    worker._RESTART.clear()
    worker._DRAIN.clear()
    worker._LAST_DESIRED_STATE = None


def test_restart_now_drains_and_marks_the_restart():
    assert worker._apply_lifecycle({"restart_now": True, "desired_state": "running"}) is True
    assert worker._RESTART.is_set() and worker._DRAIN.is_set()


def test_an_ordinary_poll_changes_nothing():
    assert worker._apply_lifecycle({"desired_state": "running", "restart_now": False}) is False
    assert not worker._RESTART.is_set() and not worker._DRAIN.is_set()


def test_an_older_backend_without_the_fields_changes_nothing():
    assert worker._apply_lifecycle({"assignment": None}) is False
    assert not worker._DRAIN.is_set()


def test_stopped_is_logged_once_and_never_drains(caplog):
    with caplog.at_level("WARNING"):
        for _ in range(3):
            assert worker._apply_lifecycle({"desired_state": "stopped"}) is False
        worker._apply_lifecycle({"desired_state": "running"})
    msgs = [r.getMessage() for r in caplog.records]
    assert sum("Stopped by the owner" in m for m in msgs) == 1
    assert sum("Started by the owner" in m for m in msgs) == 1
    assert not worker._DRAIN.is_set()


def test_no_restart_requested_means_run_just_returns():
    calls = []
    worker._restart_if_requested(_execv=lambda *a: calls.append(a), _exit=lambda c: calls.append(c))
    assert calls == []


def test_posix_re_executes_in_place(monkeypatch):
    calls = []
    monkeypatch.setattr(worker.platform, "system", lambda: "Linux")
    worker._RESTART.set()
    worker._restart_if_requested(_execv=lambda exe, argv: calls.append((exe, argv)), _exit=calls.append)
    (exe, argv), = calls
    assert argv[1:] == ["-m", "meshembed_node", "run"]


def test_windows_exits_non_zero_for_the_task_to_relaunch(monkeypatch):
    calls = []
    monkeypatch.setattr(worker.platform, "system", lambda: "Windows")
    worker._RESTART.set()
    worker._restart_if_requested(_execv=lambda *a: calls.append(("execv", a)), _exit=calls.append)
    assert calls == [3]
