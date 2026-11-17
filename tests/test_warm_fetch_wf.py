"""WARM_FETCH (P1-SPREAD; v0.3.85; auditor DESIGN GO 2026-11-09T10:20:10Z: WF-1..WF-5, WF-C1..WF-C3, WF-D1 / WF-D2;
WF-3b accepted 10:51:29Z). developer2.

A ticked generation model was never downloaded to 4 of the operator's office machines: the warm pass skipped it on
a reading of FREE memory taken at one moment, silently, and nothing retried. Now the download decision is
STRUCTURAL (could this machine ever run it next to the owner's reserve and under the owner's cap), a skip is logged
once per change, a timer retries, the owner's guards hold every fetch back, and failed fetches back off.
"""
import hashlib
import logging

import pytest

from meshembed_node import llm, pause, resources, worker

pytestmark = pytest.mark.unit

M4B = "meshembed/qwen3-4b-q8"


def _spec(**over):
    kw = dict(model_id=M4B, file="q4b.gguf", sha256="c" * 64, size_mb=4167, min_ram_gb=6.0, context=4096)
    kw.update(over)
    return llm.ModelSpec(**kw)


@pytest.fixture
def box(monkeypatch, tmp_path):
    """An office box: 8 GB total, no cgroup limit, 1 GB node reserve, room on disk, nothing on disk yet, no guard."""
    st = {"fetch": [], "spec": _spec()}
    monkeypatch.setattr(llm, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(llm, "MIRROR", "https://mirror.example.org/gguf")
    monkeypatch.setattr(llm, "runtime_available", lambda: True)
    monkeypatch.setattr(llm, "prune_retired", lambda *a, **k: [])
    monkeypatch.setattr(llm, "load_catalog", lambda *a, **k: {st["spec"].model_id: st["spec"]})
    monkeypatch.setattr(llm, "_usable_ram_gb", lambda: 2.0)           # a BUSY moment: the old rule skipped here
    monkeypatch.setattr(llm, "_total_ram_gb", lambda: 8.0)
    monkeypatch.setattr("meshembed_node.membudget.cgroup_memory", lambda *a, **k: {"limit": None})
    monkeypatch.setattr(llm, "_free_disk_gb", lambda p: 300.0)
    monkeypatch.setattr(llm, "_verified_path", lambda s: None)
    monkeypatch.setenv("MESHEMBED_RAM_RESERVE_MB", "1024")
    monkeypatch.setattr(llm, "ensure_model", lambda s, **k: st["fetch"].append(s.model_id) or None)
    monkeypatch.setattr(pause, "paused", lambda *a, **k: False)
    monkeypatch.setattr(resources, "power_block_reason", lambda limits=None: None)
    monkeypatch.setattr(resources, "too_hot", lambda limits, temp=None: None)
    monkeypatch.setattr(resources, "idle_only_block", lambda limits, idle=None: None)
    monkeypatch.setattr(resources, "weights_fetch_allowed", lambda limits, metered=None: True)
    monkeypatch.setattr(llm, "_LIMITS", {})
    monkeypatch.setattr(llm, "_PINNED", None)
    monkeypatch.setattr(llm, "_PINS_PENDING", False)
    monkeypatch.setattr(llm, "_MISSING", {})
    monkeypatch.setattr(llm, "_SKIP_LOGGED", {})
    monkeypatch.setattr(llm, "_GATE_LOGGED", [None])
    monkeypatch.setattr(llm, "_FETCH_FAILS", {})
    monkeypatch.setattr(llm, "_LAST_FETCH_ERROR", None)
    return st


# ── WF-3 / WF-3b: the structural fit ────────────────────────────────────────

def test_a_busy_moment_no_longer_stops_the_download(box):
    """F-1: 8 GB total, 2 GB free right now, 1 GB reserve: the old rule (free - reserve = 1 < 6) skipped silently.
    Structural: 8 - 1 = 7 >= 6 -> fetched. Running an item stays gated live (fits_now / capacity_fit)."""
    llm.warm_models([M4B])
    assert box["fetch"] == [M4B]


def test_a_machine_that_can_never_run_it_does_not_fetch(box, monkeypatch, caplog):
    monkeypatch.setattr(llm, "_total_ram_gb", lambda: 6.5)            # 6.5 - 1 = 5.5 < 6
    caplog.set_level(logging.WARNING)
    llm.warm_models([M4B])
    assert box["fetch"] == []
    assert llm._MISSING == {M4B: "ram_structural"}
    assert any("not fetching meshembed/qwen3-4b-q8 -- ram_structural" in r.getMessage() for r in caplog.records)


def test_the_cgroup_budget_bounds_the_structural_fit(box, monkeypatch):
    """F-5: a 16 GB host whose unit has MemoryHigh=6G can never load a 6 GB model (the N-23711 class)."""
    monkeypatch.setattr(llm, "_total_ram_gb", lambda: 16.0)
    monkeypatch.setattr("meshembed_node.membudget.cgroup_memory", lambda *a, **k: {"limit": 6 * 1024 ** 3})
    llm.warm_models([M4B])
    assert box["fetch"] == [] and llm._MISSING == {M4B: "ram_structural"}


def test_the_owners_reserve_bounds_the_download_too(box, monkeypatch):
    """WF-3b: max(node reserve, owner reserve_ram_gb). 8 - 3 = 5 < 6."""
    llm.set_limits({"reserve_ram_gb": 3.0})
    llm.warm_models([M4B])
    assert box["fetch"] == [] and llm._MISSING == {M4B: "ram_structural"}


def test_a_model_the_owners_cap_can_never_hold_is_not_fetched(box):
    llm.set_limits({"max_ram_gb": 4.5})                               # N-4002850's case
    llm.warm_models([M4B])
    assert box["fetch"] == [] and llm._MISSING == {M4B: "ram_cap"}


# ── WF-1: a skip is logged with its numbers, once per change ────────────────

def test_a_skip_is_logged_once_not_every_pass(box, monkeypatch, caplog):
    monkeypatch.setattr(llm, "_total_ram_gb", lambda: 6.5)
    caplog.set_level(logging.WARNING)
    for _ in range(3):
        llm.warm_models([M4B])
    lines = [r.getMessage() for r in caplog.records if "not fetching" in r.getMessage()]
    assert len(lines) == 1 and "room 6.5 GB - reserve 1.0 GB < needs 6.0 GB" in lines[0]


# ── WF-C1 / WF-D1: the owner's guards hold every fetch back, without network ──

@pytest.mark.parametrize("guard", ["paused", "on_battery", "too_hot", "owner_active", "metered"])
def test_each_guard_holds_the_download_back(box, monkeypatch, caplog, guard):
    if guard == "paused":
        monkeypatch.setattr(pause, "paused", lambda *a, **k: True)
    elif guard == "on_battery":
        monkeypatch.setattr(resources, "power_block_reason", lambda limits=None: "on_battery")
    elif guard == "too_hot":
        monkeypatch.setattr(resources, "too_hot", lambda limits, temp=None: 91.0)
    elif guard == "owner_active":
        monkeypatch.setattr(resources, "idle_only_block", lambda limits, idle=None: "owner_active")
    else:
        monkeypatch.setattr(resources, "weights_fetch_allowed", lambda limits, metered=None: False)
    caplog.set_level(logging.WARNING)
    llm.warm_models([M4B])
    llm.warm_models([M4B])
    assert box["fetch"] == [], "no download (and so no network) while a guard holds"
    assert llm._MISSING == {M4B: "guard"}
    held = [r.getMessage() for r in caplog.records if "warm pass held" in r.getMessage()]
    assert len(held) == 1 and guard in held[0], held          # once per change, not per pass


def test_the_pass_resumes_when_the_guard_clears(box, monkeypatch):
    monkeypatch.setattr(resources, "power_block_reason", lambda limits=None: "on_battery")
    llm.warm_models([M4B])
    monkeypatch.setattr(resources, "power_block_reason", lambda limits=None: None)
    llm.warm_models([M4B])
    assert box["fetch"] == [M4B]


# ── WF-C2: the same digest-verified fetch on every path ─────────────────────

def test_a_wrong_digest_is_refused_and_deleted_on_the_warm_path(box, monkeypatch, tmp_path):
    body = b"not the pinned weights"
    box["spec"] = _spec(sha256=hashlib.sha256(b"the real weights").hexdigest())
    monkeypatch.undo()                                                 # back to the real ensure_model ...
    for k, v in (("CACHE_DIR", tmp_path), ("MIRROR", "https://mirror.example.org/gguf"),
                 ("runtime_available", lambda: True), ("prune_retired", lambda *a, **k: []),
                 ("load_catalog", lambda *a, **k: {box["spec"].model_id: box["spec"]}),
                 ("_total_ram_gb", lambda: 8.0), ("_free_disk_gb", lambda p: 300.0), ("_LIMITS", {}),
                 ("_PINNED", None), ("_PINS_PENDING", False), ("_MISSING", {}), ("_SKIP_LOGGED", {}),
                 ("_GATE_LOGGED", [None]), ("_FETCH_FAILS", {}), ("_FETCH_BACKOFF_S", (0, 0, 0))):
        monkeypatch.setattr(llm, k, v)
    monkeypatch.setattr("meshembed_node.membudget.cgroup_memory", lambda *a, **k: {"limit": None})
    monkeypatch.setattr(llm, "fetch_gate", lambda: None)

    class FakeResp:
        def raise_for_status(self): pass
        def iter_content(self, n): yield body
        def __enter__(self): return self
        def __exit__(self, *a): return False
    import requests
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp())
    assert llm.warm_models([M4B]) == []
    assert not any(tmp_path.iterdir()), "the wrong bytes are not left on disk"
    assert llm._MISSING == {M4B: "fetch_error"} and M4B in llm._FETCH_FAILS


# ── WF-C3: backoff on failure, reset on a tick or mirror change ─────────────

def test_a_failed_fetch_backs_off(box):
    llm.warm_models([M4B])                                             # ensure_model returns None = a failure
    llm.warm_models([M4B])
    assert box["fetch"] == [M4B], "the second pass is inside the backoff: no new download attempt"
    assert llm._MISSING == {M4B: "fetch_error"}
    n, until = llm._FETCH_FAILS[M4B]
    assert n == 1


def test_the_backoff_doubles_and_is_capped(box):
    for _ in range(10):
        llm._record_fetch_failure(M4B, now=0.0)
    n, until = llm._FETCH_FAILS[M4B]
    assert n == 10 and until == llm.FETCH_BACKOFF_CAP_S                # 30 min * 2^9 > 24 h -> capped


def test_a_tick_change_resets_the_backoff(box):
    llm.set_pinned([M4B])
    llm.warm_models([M4B])
    llm.warm_models([M4B, "BAAI/bge-small-en-v1.5"])                  # the owner changed the ticks
    assert box["fetch"] == [M4B, M4B]


def test_a_mirror_change_resets_the_backoff(box, monkeypatch):
    monkeypatch.setattr(worker, "_schedule_warm", lambda pinned: None)
    monkeypatch.setattr(worker, "_persist_env_flag", lambda *a, **k: None)
    llm._record_fetch_failure(M4B)
    assert worker._adopt_mirror("https://new-mirror.example.org/gguf") is True
    assert llm._FETCH_FAILS == {}


# ── WF-5 / WF-D2: readiness tells the owner why, by class only ──────────────

def test_readiness_names_each_missing_ticked_model_by_class(box, monkeypatch):
    monkeypatch.setattr(llm, "gpu_info", lambda: {})
    monkeypatch.setattr(llm, "gpu_offload_available", lambda: False)
    llm.set_limits({"max_ram_gb": 4.5})
    llm.warm_models([M4B])
    r = llm.readiness()
    assert r["pinned_missing"] == [{"model_id": M4B, "reason": "ram_cap"}]
    assert set(r["pinned_missing"][0]) == {"model_id", "reason"}, "the class only: no numbers, no paths"


def test_no_ticks_no_pinned_missing_list(box, monkeypatch):
    monkeypatch.setattr(llm, "gpu_info", lambda: {})
    monkeypatch.setattr(llm, "gpu_offload_available", lambda: False)
    llm.set_limits({"max_ram_gb": 4.5})
    llm.warm_models(None)
    assert llm.readiness()["pinned_missing"] == []


# ── WF-2: the timer ─────────────────────────────────────────────────────────

def test_the_timer_waits_for_the_ticks_then_warms_with_them(monkeypatch):
    calls, sleeps = [], {"n": 0}

    def fake_sleep(s):
        sleeps["n"] += 1
        return sleeps["n"] > 2                                         # two wakes, then "drain"
    monkeypatch.setattr(worker, "_sleep_or_drain", fake_sleep)
    monkeypatch.setattr(worker, "_llm_warm", lambda pinned=None: calls.append(pinned))
    monkeypatch.setattr(llm, "_PINS_PENDING", True)
    monkeypatch.setattr(llm, "_PINNED", {"b", "a"})
    seq = iter([True, False])
    orig = fake_sleep

    def sleep_then_ticks(s):
        r = orig(s)
        llm._PINS_PENDING = next(seq, False)                           # pending on the first wake, known on the second
        return r
    monkeypatch.setattr(worker, "_sleep_or_drain", sleep_then_ticks)
    worker._warm_timer_loop()
    assert calls == [["a", "b"]], calls


def test_the_daemon_starts_the_timer():
    import inspect
    assert "target=_warm_timer_loop" in inspect.getsource(worker)


# ── WF-R1: a failing CPU cap never drops the owner's RAM limits ─────────────

def test_a_failing_cpu_cap_does_not_drop_the_owners_limits(box, monkeypatch):
    """apply_cpu_cap raising used to skip set_limits in the same try block (silently, at DEBUG). With WF-3b the
    owner's max_ram_gb / reserve_ram_gb decide downloads, so they must reach llm whatever the CPU cap does."""
    def boom(limits):
        raise RuntimeError("cgroup write refused")
    monkeypatch.setattr(resources, "apply_cpu_cap", boom)
    owner = {"max_ram_gb": 4.5, "pause_when_busy": False}
    replies = [{"resource_limits": owner, "pinned_models": [M4B]}]

    class _Stop(BaseException):
        pass

    def fake_poll(cfg, **kw):
        if not replies:
            raise _Stop()
        return replies.pop(0)

    class _Cfg:
        poll_min_s = 0.0
        poll_max_s = 0.0

        def __getattr__(self, n):
            return None

    class _Enc:
        def installed_models(self):
            return []

        def set_served_models(self, ids):
            pass

    class _T:
        def __init__(self, *a, **k):
            pass

        def start(self):
            pass
    monkeypatch.setattr(worker, "_poll", fake_poll)
    monkeypatch.setattr(worker, "_HB_LIMITS", {})
    monkeypatch.setattr(worker, "_gate_reason", lambda limits: None)
    monkeypatch.setattr(pause, "enforce", lambda *a, **k: None)
    monkeypatch.setattr(worker, "_llm_installed", lambda cfg: [])
    monkeypatch.setattr(worker, "_sleep_or_drain", lambda s: False)
    monkeypatch.setattr(worker, "_adopt_mirror", lambda *a, **k: False)
    monkeypatch.setattr(worker, "_sync_io_limits", lambda limits: None)
    monkeypatch.setattr(worker.threading, "Thread", _T)
    with pytest.raises(_Stop):
        worker._worker_loop(_Cfg(), _Enc(), 0, True)
    assert llm._current_limits() == owner
    llm.warm_models([M4B])
    assert box["fetch"] == [] and llm._MISSING == {M4B: "ram_cap"}
