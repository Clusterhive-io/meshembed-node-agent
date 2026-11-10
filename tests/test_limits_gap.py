"""LIMITS-GAP (auditor LOW-MEDIUM + DESIGN GO 2026-11-09T10:51:29Z; developer2; rides v0.3.84 r4).

The owner's node-side limits (only_when_idle, pause_when_busy, reserves) were learned only from a get_job reply, so
the FIRST pull after every daemon start (every OTA restart, fleet-wide) ran with none, and a failed poll ({}) wiped
them for the next pull until a heartbeat answered. Now: (i) limits change only on a reply that carries them;
(ii) nothing is pulled until a heartbeat or a reply has carried them; a refused / failed heartbeat never pulls blind.
"""
import pytest

from meshembed_node import pause, worker

pytestmark = pytest.mark.unit      # so CI's T1 (scripts/run-tests.sh unit) runs it

OWNER = {"only_when_idle": True, "max_ram_gb": 1.0}


class _Stop(BaseException):
    pass


class _Cfg:
    poll_min_s = 0.0
    poll_max_s = 0.0
    backend_url = "http://backend.invalid"
    api_key = "k"
    node_id = "n"

    def __getattr__(self, name):
        return None


class _Enc:
    def installed_models(self):
        return []

    def set_served_models(self, ids):
        pass


class _HTTPErr(Exception):
    def __init__(self, status):
        super().__init__(f"HTTP {status}")
        self.response = type("R", (), {"status_code": status})()


@pytest.fixture
def loop(monkeypatch):
    """Drive the REAL _worker_loop. Records the limits each gate check saw and how many polls / sleeps happened."""
    state = {"gates": [], "polls": 0, "sleeps": 0, "hb_posts": 0}
    monkeypatch.setattr(worker, "_HB_LIMITS", worker._UNSET)
    monkeypatch.setattr(worker, "_gate_reason", lambda limits: state["gates"].append(dict(limits or {})) or None)
    monkeypatch.setattr(pause, "enforce", lambda *a, **k: None)
    monkeypatch.setattr(worker, "_llm_installed", lambda cfg: [])
    monkeypatch.setattr(worker, "_adopt_mirror", lambda *a, **k: False)
    monkeypatch.setattr(worker, "_sync_io_limits", lambda limits: None)

    class _T:
        def __init__(self, *a, **k):
            pass

        def start(self):
            pass
    monkeypatch.setattr(worker.threading, "Thread", _T)
    monkeypatch.setenv("MESHEMBED_QUOTE_EVERY_N_POLLS", "1000")
    monkeypatch.setenv("MESHEMBED_PROBE_EVERY_N_POLLS", "1000")

    def run(replies, heartbeat, max_sleeps=50):
        replies = list(replies)

        def fake_poll(cfg, **kw):
            state["polls"] += 1
            if not replies:
                raise _Stop()
            return replies.pop(0)

        def fake_post(base, path, payload, api_key, timeout=60):
            assert path == "/node_heartbeat"
            state["hb_posts"] += 1
            return heartbeat(state["hb_posts"])

        def fake_sleep(s):
            state["sleeps"] += 1
            if state["sleeps"] >= max_sleeps:
                raise _Stop()
            return False
        monkeypatch.setattr(worker, "_poll", fake_poll)
        monkeypatch.setattr(worker, "_post", fake_post)
        monkeypatch.setattr(worker, "_sleep_or_drain", fake_sleep)
        with pytest.raises(_Stop):
            worker._worker_loop(_Cfg(), _Enc(), 0, True)
        return state
    return run


def test_the_first_pull_after_a_start_runs_with_the_owners_limits(loop):
    st = loop([{"resource_limits": OWNER}], heartbeat=lambda n: {"ok": True, "resource_limits": OWNER})
    assert st["hb_posts"] == 1, "one synchronous heartbeat before the first pull"
    assert st["gates"][0] == OWNER, "the first PULL gate saw the owner's limits, not {}"


@pytest.mark.parametrize("status", [401, 403, 404])
def test_a_refused_heartbeat_never_pulls_blind(loop, status):
    def refused(n):
        raise _HTTPErr(status)
    st = loop([{"resource_limits": OWNER}], heartbeat=refused, max_sleeps=4)
    assert st["polls"] == 0, "no pull while the owner's limits are unknown"
    assert st["hb_posts"] >= 3, "it keeps retrying"
    assert st["gates"] == [], "no gate decision on unknown limits either"


def test_a_heartbeat_reply_without_limits_does_not_count_as_known(loop):
    st = loop([{"resource_limits": OWNER}], heartbeat=lambda n: {"ok": True}, max_sleeps=3)
    assert st["polls"] == 0


def test_it_pulls_once_a_later_heartbeat_answers(loop):
    def late(n):
        if n < 3:
            raise ConnectionError("down")
        return {"ok": True, "resource_limits": OWNER}
    st = loop([{"resource_limits": OWNER}], heartbeat=late)
    assert st["hb_posts"] == 3 and st["polls"] >= 1
    assert st["gates"][0] == OWNER


def test_a_failed_poll_keeps_the_owners_limits(loop, monkeypatch):
    """(i): {} from a failed poll no longer wipes node_limits. The heartbeat answered once at start and never again
    (the loop's own override is then the same value), and every gate, after-poll ones included, sees the owner's."""
    st = loop([{"resource_limits": OWNER}, {}, {"resource_limits": OWNER}],
              heartbeat=lambda n: {"ok": True, "resource_limits": OWNER})
    assert st["gates"] and all(g == OWNER for g in st["gates"]), st["gates"]


def test_an_owner_who_clears_every_limit_is_known_not_unknown(loop):
    """resource_limits: null / {} from the backend = the owner set none: known, so the node pulls."""
    st = loop([{"resource_limits": None}], heartbeat=lambda n: {"ok": True, "resource_limits": None})
    assert st["polls"] >= 1 and st["gates"][0] == {}


# ── LG-2: a node that stops pulling says why ────────────────────────────────

def test_a_refused_heartbeat_is_loud_and_visible(loop, monkeypatch, tmp_path, caplog):
    import json
    import logging
    from meshembed_node import maintenance
    monkeypatch.setenv("HOME", str(tmp_path))
    caplog.set_level(logging.WARNING)

    def refused(n):
        raise _HTTPErr(401)
    st = loop([], heartbeat=refused, max_sleeps=4)
    assert st["polls"] == 0
    warns = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING and "limits:" in r.getMessage()]
    assert len(warns) == 1 and "REFUSED (HTTP 401)" in warns[0], warns   # once per reason, not every retry
    state = json.loads((tmp_path / ".meshembed" / "pull_state.json").read_text())
    assert state["reason"] == "heartbeat_refused_401" and isinstance(state["since"], int)
    assert oct((tmp_path / ".meshembed" / "pull_state.json").stat().st_mode & 0o777) == "0o600"
    assert maintenance._pull_state()["reason"] == "heartbeat_refused_401"


def test_the_state_clears_once_the_limits_are_known(loop, monkeypatch, tmp_path):
    from meshembed_node import maintenance
    monkeypatch.setenv("HOME", str(tmp_path))

    def late(n):
        if n < 2:
            raise _HTTPErr(403)
        return {"ok": True, "resource_limits": OWNER}
    st = loop([{"resource_limits": OWNER}], heartbeat=late)
    assert st["polls"] >= 1
    assert not (tmp_path / ".meshembed" / "pull_state.json").exists()
    assert maintenance._pull_state() is None


def test_status_shows_only_the_closed_reason_set(monkeypatch, tmp_path):
    from meshembed_node import maintenance
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".meshembed").mkdir()
    (tmp_path / ".meshembed" / "pull_state.json").write_text('{"reason": "<script>", "since": "x"}')
    assert maintenance._pull_state() == {"paused": "limits_unknown", "reason": "unknown", "since": None}
