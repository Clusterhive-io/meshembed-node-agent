"""Deleting a node from the dashboard must actually decommission it.

It did not. Two mechanisms both failed, in opposite directions:

  BEFORE key revocation — the daemon kept its credentials, `/get_job`
  auto-registers an unknown node_id, and the row reappeared within seconds. The
  deletion was undone by the node itself. Observed 2026-08-08: node-187 was
  deleted from the UI and came straight back with a new node_number.

  AFTER key revocation (shipped the same day) — the daemon got 401 for ever.
  `_poll` catches every exception identically, so a revoked credential looked
  exactly like a network blip: `get_job failed` every 30 seconds, indefinitely,
  with no path back to a working state without someone SSHing to the box.

Neither is "erase the node and start clean", which is what deleting it means.

THE RISK RUNS THE OTHER WAY TOO. A daemon that unenrolls itself too eagerly is
far worse than one that retries: a backend serving 401s during a bad deploy could
unenroll the entire fleet, and every node would then need manual re-enrollment.
So these tests pin BOTH directions — it must trigger on a real revocation, and it
must NOT trigger on anything else.
"""
from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


class _Resp:
    def __init__(self, status_code):
        self.status_code = status_code


class _Err(Exception):
    def __init__(self, status_code=None):
        super().__init__(f"http {status_code}")
        self.response = _Resp(status_code) if status_code else None


@pytest.fixture
def worker(monkeypatch):
    from meshembed_node import worker as w

    monkeypatch.setattr(w, "_revoked_strikes", 0, raising=False)
    return w


class _Cfg:
    """Permissive Config stub.

    `_poll` reads a long and growing list of attributes to build its payload.
    Enumerating them here means this test breaks whenever an unrelated field is
    added to the poll — so unknown attributes return None instead. What is under
    test is the error path, not the payload.
    """

    backend_url = "https://example.invalid"
    node_id = "n-1"
    api_key = "k"
    model = "m"
    max_chunks = 1
    agent_version = "0.0.0"

    def __getattr__(self, name):
        return None


def _cfg():
    return _Cfg()


def test_strike_threshold_is_not_one(worker):
    """A single 401 must not unenroll. A backend briefly serving errors during a
    deploy would otherwise take the whole fleet out, and every node would need
    manual re-enrollment."""
    assert worker._REVOKED_STRIKES >= 3


def test_credentials_are_moved_not_deleted(worker):
    """If this ever fires wrongly the old identity must still be recoverable. A
    node that destroyed its key and gained nothing is a worse failure than one
    that merely stopped."""
    import inspect

    src = inspect.getsource(worker._self_decommission)
    assert "shutil.move" in src
    assert "unlink" not in src and "os.remove" not in src


def test_decommission_tells_the_operator_how_to_recover(worker):
    """The log line is the only thing a human will see. It must carry the exact
    command, because by then the node is not in the dashboard to ask."""
    import inspect

    src = inspect.getsource(worker._self_decommission)
    assert "install.sh" in src and "INVITE=" in src


def test_a_network_error_never_counts_as_revocation(worker, monkeypatch):
    """THE property that keeps this safe. `_poll` catches every exception the
    same way, so an error with no HTTP status — DNS failure, timeout, connection
    refused — must leave the strike count untouched."""
    monkeypatch.setattr(worker, "_post", lambda *a, **k: (_ for _ in ()).throw(_Err(None)))
    monkeypatch.setattr(worker, "GPU_MODEL", "test", raising=False)
    monkeypatch.setattr(worker, "vram_free_mb", lambda: 0, raising=False)
    monkeypatch.setattr(worker, "_resolve_cf_loc", lambda: None, raising=False)

    for _ in range(worker._REVOKED_STRIKES * 3):
        assert worker._poll(_cfg()) == {}
    assert worker._revoked_strikes == 0, "a network error was counted as a rejection"


def test_a_500_never_counts_as_revocation(worker, monkeypatch):
    """A backend that is broken is not a backend that has revoked us."""
    monkeypatch.setattr(worker, "_post", lambda *a, **k: (_ for _ in ()).throw(_Err(500)))
    monkeypatch.setattr(worker, "GPU_MODEL", "test", raising=False)
    monkeypatch.setattr(worker, "vram_free_mb", lambda: 0, raising=False)
    monkeypatch.setattr(worker, "_resolve_cf_loc", lambda: None, raising=False)

    for _ in range(worker._REVOKED_STRIKES * 3):
        worker._poll(_cfg())
    assert worker._revoked_strikes == 0


def test_repeated_401_eventually_decommissions(worker, monkeypatch):
    """The case that makes deletion mean something."""
    monkeypatch.setattr(worker, "_post", lambda *a, **k: (_ for _ in ()).throw(_Err(401)))
    monkeypatch.setattr(worker, "GPU_MODEL", "test", raising=False)
    monkeypatch.setattr(worker, "vram_free_mb", lambda: 0, raising=False)
    monkeypatch.setattr(worker, "_resolve_cf_loc", lambda: None, raising=False)

    called = {}

    def _fake_decom(cfg, reason):
        called["reason"] = reason
        raise SystemExit(0)

    monkeypatch.setattr(worker, "_self_decommission", _fake_decom)

    with pytest.raises(SystemExit):
        for _ in range(worker._REVOKED_STRIKES):
            worker._poll(_cfg())
    assert "401" in called["reason"]


def test_one_success_clears_the_strikes(worker, monkeypatch):
    """A flapping backend must not accumulate strikes across hours until it
    crosses the threshold on unrelated failures."""
    monkeypatch.setattr(worker, "GPU_MODEL", "test", raising=False)
    monkeypatch.setattr(worker, "vram_free_mb", lambda: 0, raising=False)
    monkeypatch.setattr(worker, "_resolve_cf_loc", lambda: None, raising=False)

    monkeypatch.setattr(worker, "_post", lambda *a, **k: (_ for _ in ()).throw(_Err(401)))
    worker._poll(_cfg())
    assert worker._revoked_strikes == 1

    monkeypatch.setattr(worker, "_post", lambda *a, **k: {"assignment": None})
    worker._poll(_cfg())
    assert worker._revoked_strikes == 0, "a successful poll must reset the count"
