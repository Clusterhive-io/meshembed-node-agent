"""UNTICK-RUN / BP-N (auditor MEDIUM-HIGH + DESIGN GO 2026-11-09T10:25:37Z; developer2).

The owner's ticks (pinned_models) are consent on a third party's machine. Before BP-N the daemon advertised every
generation model on disk whether ticked or not (installed_llm_models = servable_models, no tick filter), kept
advertising a model after the owner unticked it, fetched every catalogue model that fit in a boot warm pass with no
list, and a FAILED poll ({}) cleared the field of play and started a warm pass with no allow-list.
"""
import pytest

from meshembed_node import llm, pause, worker

pytestmark = pytest.mark.unit      # so CI's T1 (scripts/run-tests.sh unit) runs it

TICKED = "meshembed/ticked-4b"
UNTICKED = "meshembed/unticked-7b"


def _spec(mid):
    return llm.ModelSpec(model_id=mid, file=mid.split("/")[1] + ".gguf", sha256="b" * 64,
                         size_mb=4000, min_ram_gb=6.0, context=4096)


@pytest.fixture
def node(monkeypatch, tmp_path):
    """A runtime node with room for both models and both verified on disk; ticks / pending as each test sets."""
    cat = {m: _spec(m) for m in (TICKED, UNTICKED)}
    monkeypatch.setattr(llm, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(llm, "runtime_available", lambda: True)
    monkeypatch.setattr(llm, "load_catalog", lambda *a, **k: cat)
    monkeypatch.setattr(llm, "_usable_ram_gb", lambda: 30.0)
    monkeypatch.setattr(llm, "_total_ram_gb", lambda: 39.0)
    monkeypatch.setattr(llm, "_loaded_gb", lambda: 0.0)
    monkeypatch.setattr(llm, "_loaded_id", lambda: None)
    monkeypatch.setattr(llm, "jinja2_safe", lambda: True)
    monkeypatch.setattr(llm, "execution_class", lambda: {})
    monkeypatch.setattr(llm, "_offload_facts", lambda k: {})
    monkeypatch.setattr(llm, "load_mode", lambda: "no_mmap")
    monkeypatch.setattr(llm, "gpu_info", lambda: {})
    monkeypatch.setattr(llm, "gpu_offload_available", lambda: False)
    monkeypatch.setattr(llm, "_free_disk_gb", lambda p: 300.0)
    monkeypatch.setattr(llm, "_LAST_FETCH_ERROR", None)
    monkeypatch.setattr(llm, "_verified_path", lambda s: tmp_path / s.file)
    monkeypatch.setattr(llm, "_PINNED", None)
    monkeypatch.setattr(llm, "_PINS_PENDING", False)
    return monkeypatch


def _ads():
    return sorted(m["model_id"] for m in llm.installed_llm_models())


# ── BP-N1: advertise only what the owner allows ─────────────────────────────

def test_an_unticked_model_on_disk_is_not_advertised(node):
    llm.set_pinned([TICKED, "BAAI/bge-small-en-v1.5"])
    assert _ads() == [TICKED]


def test_unticking_withdraws_the_model_at_the_next_reply(node):
    llm.set_pinned([TICKED, UNTICKED])
    assert _ads() == [TICKED, UNTICKED]
    llm.set_pinned([TICKED])                               # the owner unticks; the weights stay on disk
    assert _ads() == [TICKED]


def test_ticks_holding_only_embedding_ids_advertise_no_generation_model(node):
    """BB-1: a non-empty list is an allow-list over ALL ids, so embedding-only ticks permit no LLM."""
    llm.set_pinned(["BAAI/bge-small-en-v1.5"])
    assert _ads() == []


@pytest.mark.parametrize("ticks", [[], None, ["", None]])
def test_no_ticks_means_no_allow_list_as_today(node, ticks):
    llm.set_pinned(ticks)
    assert _ads() == [TICKED, UNTICKED]


def test_before_the_first_reply_no_generation_model_is_advertised(node):
    llm.mark_pins_pending()
    assert _ads() == []
    assert llm.readiness()["models_ready"] == 0
    llm.set_pinned([])                                     # the first reply: no ticks
    assert _ads() == [TICKED, UNTICKED]


def test_readiness_counts_only_what_may_be_advertised(node):
    llm.set_pinned([TICKED])
    assert llm.readiness()["models_ready"] == 1


def test_a_loaded_unticked_model_is_not_advertised_either(node):
    node.setattr(llm, "_loaded_id", lambda: UNTICKED)
    llm.set_pinned([TICKED])
    assert _ads() == [TICKED]


# ── BP-N2: no fetch before the ticks are known ──────────────────────────────

def test_the_daemon_starts_no_boot_warm_pass():
    import inspect
    src = inspect.getsource(worker)
    assert "meshembed-llm-warm-boot" not in src
    assert "mark_pins_pending()" in src


class _Stop(BaseException):
    pass


class _Cfg:
    poll_min_s = 0.0
    poll_max_s = 0.0

    def __getattr__(self, name):
        return None


class _Enc:
    def __init__(self):
        self.served = []

    def installed_models(self):
        return []

    def set_served_models(self, ids):
        self.served.append(list(ids or []))


def _drive_loop(monkeypatch, replies):
    """Run the REAL _worker_loop over the given get_job replies; record encoder applications and warm passes."""
    replies = list(replies)
    warm_calls = []

    def fake_poll(cfg, **kw):
        if not replies:
            raise _Stop()
        return replies.pop(0)

    class _T:
        def __init__(self, target=None, args=(), kwargs=None, name=None, daemon=None):
            self.target, self.args = target, args

        def start(self):
            if self.target is worker._llm_warm:
                warm_calls.append(self.args[0] if self.args else "NO-ARGS")
            elif getattr(self.target, "__name__", "") == "set_served_models":
                self.target(*self.args)

    monkeypatch.setattr(worker, "_poll", fake_poll)
    monkeypatch.setattr(worker, "_HB_LIMITS", {})          # limits known (none set): LIMITS-GAP never blocks here
    monkeypatch.setattr(worker, "_gate_reason", lambda limits: None)
    monkeypatch.setattr(pause, "enforce", lambda where, *a, **k: None)
    monkeypatch.setattr(worker, "_llm_installed", lambda cfg: [])
    monkeypatch.setattr(worker, "_sleep_or_drain", lambda s: False)
    monkeypatch.setattr(worker, "_adopt_mirror", lambda *a, **k: False)
    monkeypatch.setattr(worker.threading, "Thread", _T)
    monkeypatch.setenv("MESHEMBED_QUOTE_EVERY_N_POLLS", "1000")
    monkeypatch.setenv("MESHEMBED_PROBE_EVERY_N_POLLS", "1000")
    enc = _Enc()
    with pytest.raises(_Stop):
        worker._worker_loop(_Cfg(), enc, 0, True)
    return enc, warm_calls


def test_the_first_reply_with_no_ticks_still_runs_a_warm_pass(node):
    """F-6: served_applied used to start as frozenset(), equal to [] -> no pass at all once the boot pass is gone."""
    llm.mark_pins_pending()
    enc, warm = _drive_loop(node, [{"pinned_models": None}])
    assert warm == [None]
    assert llm._PINS_PENDING is False and llm._PINNED is None


def test_a_failed_poll_changes_neither_the_ticks_nor_the_field_of_play(node):
    """A network error returns {}: it must not clear the encoder's allow-list nor start a warm pass with none."""
    ticks = ["BAAI/bge-small-en-v1.5", TICKED]
    enc, warm = _drive_loop(node, [{"pinned_models": ticks}, {}, {"pinned_models": ticks}])
    assert enc.served == [["BAAI/bge-small-en-v1.5"]], "applied once; the failed poll and the same reply change nothing"
    assert warm == [ticks]
    assert llm._PINNED == set(ticks)
    assert _ads() == [TICKED]


def test_an_untick_reaches_both_halves_at_the_next_reply(node):
    enc, warm = _drive_loop(node, [{"pinned_models": [TICKED, UNTICKED]}, {"pinned_models": [TICKED]}])
    assert warm == [[TICKED, UNTICKED], [TICKED]]
    assert _ads() == [TICKED]


# ── the execution path stays as designed (the belt is server-side) ──────────

def test_no_tick_decline_on_the_execution_path():
    """Agreed in the DESIGN GO: a 'declined:not_pinned' would count as a node failure unless the backend believes
    it (_decline_is_free), so the execution belt is the backend's (bb-gen-ticks). This pins that choice."""
    import inspect
    src = inspect.getsource(worker)
    assert "not_pinned" not in src
