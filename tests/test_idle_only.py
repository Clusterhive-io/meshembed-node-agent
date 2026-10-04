"""Only when idle (design B2 step 2), daemon side.

The owner's choice "work only while nobody uses this machine": a gate checked
before pulling work (an item in progress always finishes), unknown idle time
never counts as away, the reason is reported on the heartbeat, and the limits
come back on the heartbeat so a gated daemon (which does not poll) still sees
the owner switch the mode off.
"""
import pytest

from meshembed_node import resources, worker

pytestmark = pytest.mark.unit

IDLE_ONLY = {"run_only_when_idle": True, "idle_after_s": 600}


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.setattr(worker, "_GATE", None)
    monkeypatch.setattr(worker, "_HB_LIMITS", worker._UNSET)
    # No real power/heat/RAM readings in these tests.
    monkeypatch.setattr(resources, "power_block_reason", lambda limits: None)
    monkeypatch.setattr(resources, "too_hot", lambda limits: None)
    monkeypatch.setattr(resources, "over_ram_cap", lambda limits: None)
    resources._IDLE_MEASURABLE.update({"at": 0.0, "value": None})


# ── the rule ────────────────────────────────────────────────────────────────

def test_not_set_never_blocks():
    assert resources.idle_only_block(None, idle=0) is None
    assert resources.idle_only_block({"pause_when_busy": True}, idle=0) is None


def test_owner_active_blocks_until_idle_after():
    assert resources.idle_only_block(IDLE_ONLY, idle=30) == "owner_active"
    assert resources.idle_only_block(IDLE_ONLY, idle=599) == "owner_active"
    assert resources.idle_only_block(IDLE_ONLY, idle=600) is None


def test_unknown_idle_is_never_away(monkeypatch):
    # A headless box, no display, no xprintidle: in idle-only mode it must NOT work.
    monkeypatch.setattr(resources, "human_idle_seconds", lambda: None)
    assert resources.idle_only_block(IDLE_ONLY) == "idle_unknown"


def test_idle_after_has_a_floor_on_the_machine_too():
    # A backend bug or an old setting must not turn the gate into "always away".
    assert resources.idle_only_block({"run_only_when_idle": True, "idle_after_s": 5}, idle=60) == "owner_active"
    assert resources.idle_only_block({"run_only_when_idle": True, "idle_after_s": 5}, idle=120) is None
    assert resources.idle_only_block({"run_only_when_idle": True, "idle_after_s": "junk"}, idle=700) is None


def test_idle_measurable_is_cached(monkeypatch):
    calls = []
    monkeypatch.setattr(resources, "human_idle_seconds", lambda: calls.append(1) or 12.0)
    assert resources.idle_measurable() is True
    assert resources.idle_measurable() is True
    assert len(calls) == 1


# ── the gate in the daemon ──────────────────────────────────────────────────

def test_gate_reason_reports_owner_active(monkeypatch):
    monkeypatch.setattr(resources, "human_idle_seconds", lambda: 10.0)
    assert worker._gate_reason(IDLE_ONLY) == "owner_active"
    assert worker._should_pause(IDLE_ONLY) is True


def test_gate_opens_once_the_owner_is_away(monkeypatch):
    monkeypatch.setattr(resources, "human_idle_seconds", lambda: 3600.0)
    assert worker._gate_reason(IDLE_ONLY) is None
    assert worker._should_pause(IDLE_ONLY) is False


def test_battery_still_wins_over_idle_only(monkeypatch):
    monkeypatch.setattr(resources, "human_idle_seconds", lambda: 3600.0)
    monkeypatch.setattr(resources, "power_block_reason", lambda limits: "on_battery")
    assert worker._gate_reason(IDLE_ONLY) == "on_battery"


def test_every_reason_is_in_the_shared_vocabulary(monkeypatch):
    monkeypatch.setattr(resources, "human_idle_seconds", lambda: None)
    assert worker._gate_reason(IDLE_ONLY) in worker.GATE_REASONS


# ── reporting and the limits round trip ─────────────────────────────────────

class _Cfg:
    backend_url = "http://backend.invalid"
    node_id = "node-1"
    api_key = "k"


def test_heartbeat_carries_the_gate(monkeypatch):
    monkeypatch.setattr(worker, "_GATE", "owner_active")
    assert worker._heartbeat_payload(_Cfg())["gate_reason"] == "owner_active"


def _one_heartbeat(monkeypatch, response):
    monkeypatch.setattr(worker, "_post", lambda *a, **k: response)
    calls = iter([False, True])                         # one beat, then drain
    monkeypatch.setattr(worker, "_sleep_or_drain", lambda s: next(calls))
    worker._heartbeat_loop(_Cfg())


def test_heartbeat_brings_back_the_limits(monkeypatch):
    _one_heartbeat(monkeypatch, {"ok": True, "released": 0, "resource_limits": None})
    assert worker._HB_LIMITS == {}                       # the owner cleared every limit


def test_an_older_backend_leaves_the_poll_limits_in_charge(monkeypatch):
    _one_heartbeat(monkeypatch, {"ok": True, "released": 0})
    assert worker._HB_LIMITS is worker._UNSET


def test_the_hardware_report_says_whether_idle_is_measurable(monkeypatch):
    monkeypatch.setattr(resources, "human_idle_seconds", lambda: None)
    assert worker._hardware_info()["idle_measurable"] is False


# ── Windows: a service (session 0) cannot see the user's input ──────────────

class _FakeWin:
    def __init__(self, session, idle_ms=5000, tick=1_000_000):
        self.session, self.idle_ms, self.tick = session, idle_ms, tick
        self.kernel32 = self
        self.user32 = self
        self.lastinput_called = False

    def GetCurrentProcessId(self):
        return 4242

    def ProcessIdToSessionId(self, pid, ref):
        ref._obj.value = self.session
        return 1

    def GetTickCount(self):
        return self.tick

    def GetLastInputInfo(self, ref):
        self.lastinput_called = True
        ref._obj.dwTime = self.tick - self.idle_ms
        return 1


@pytest.mark.parametrize("session,expected", [(0, None), (1, 5.0)])
def test_windows_session_zero_is_unknown_not_away(monkeypatch, session, expected):
    import ctypes
    import platform
    fake = _FakeWin(session)
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    monkeypatch.setattr(ctypes, "windll", fake, raising=False)
    assert resources.human_idle_seconds() == expected
    assert fake.lastinput_called is (session != 0)
