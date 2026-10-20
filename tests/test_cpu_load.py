"""Load-adaptive threads (docs/DESIGN_LOAD_AWARE_NODES_2026-10-14.md (1)).

187's case: 18 vCPU with a load average of 23-24 from the host's own work -- the node must
take a couple of threads, not 9 for generation and 18 for the prompt.
"""
import os
import sys
import threading
import types
from collections import namedtuple

import pytest

from meshembed_node import cpu_load

CT = namedtuple("CT", "user nice system idle iowait irq softirq steal guest guest_nice")
PT = namedtuple("PT", "user system children_user children_system")


@pytest.mark.parametrize("idle,cap,phys,want", [
    (None, None, 8, None),      # no sample yet: keep the load-time setting
    (16.0, None, 8, 8),         # idle host: physical cores
    (16.0, 4, 8, 4),            # never above the owner's cap
    (3.0, None, 9, 2),          # busy host: 80 % of what is idle
    (0.4, None, 8, 1),          # saturated host: one thread, never zero
])
def test_choose_threads(idle, cap, phys, want):
    assert cpu_load.choose_threads(idle, cap, phys) == want


def test_sampler_separates_the_host_from_ourselves():
    clock = iter([0.0, 2.0, 4.0])
    # 18 logical cores; over 2 s the host is busy 14 cores-worth, of which we used 2.
    t0 = CT(user=0, nice=0, system=0, idle=0, iowait=0, irq=0, softirq=0, steal=0, guest=0, guest_nice=0)
    t1 = CT(user=24, nice=0, system=4, idle=8, iowait=0, irq=0, softirq=0, steal=0, guest=0, guest_nice=0)
    o0, o1 = PT(0, 0, 0, 0), PT(3.5, 0.5, 0, 0)
    times, own = iter([t0, t1]), iter([o0, o1])
    s = cpu_load.Sampler(times=lambda: next(times), own_times=lambda: next(own), logical=18,
                         clock=lambda: next(clock))
    s.tick()
    assert s.idle_cores is None
    s.tick()
    # busy = 28 cpu-s / 2 s = 14 cores; ours = 4 / 2 = 2; others = 12; idle = 18 - 12 = 6
    assert s.others_cores == pytest.approx(12.0)
    assert s.idle_cores == pytest.approx(6.0)


def test_sampler_smooths(monkeypatch):
    s = cpu_load.Sampler(times=lambda: None, own_times=lambda: None, logical=8, clock=lambda: 0.0)
    s.idle_cores, s.others_cores = 8.0, 0.0
    s._prev = (0.0, CT(0, 0, 0, 0, 0, 0, 0, 0, 0, 0), PT(0, 0, 0, 0))
    s._clock = lambda: 2.0
    s._times = lambda: CT(16, 0, 0, 0, 0, 0, 0, 0, 0, 0)    # every core busy, none of it ours
    s._own = lambda: PT(0, 0, 0, 0)
    s.tick()
    assert s.idle_cores == pytest.approx(0.8 * 8.0 + 0.2 * 0.0)


def _fake_runtime(monkeypatch, calls):
    mod = types.ModuleType("llama_cpp")
    mod.llama_set_n_threads = lambda ctx, n, nb: calls.append((ctx, n, nb))
    monkeypatch.setitem(sys.modules, "llama_cpp", mod)


@pytest.fixture
def _switched_on(monkeypatch):
    monkeypatch.delenv("MESHEMBED_LLM_ADAPTIVE_THREADS", raising=False)
    monkeypatch.setattr(cpu_load, "_BACKEND_ON", True)


def test_apply_sets_generation_and_prompt_threads(monkeypatch, _switched_on):
    calls = []
    _fake_runtime(monkeypatch, calls)
    monkeypatch.setattr(cpu_load, "idle_cores", lambda: 6.0)
    monkeypatch.setattr(cpu_load, "physical_cores", lambda: 9)
    model = types.SimpleNamespace(_ctx=types.SimpleNamespace(ctx="CTX"))
    assert cpu_load.apply_to_model(model, cap=None) == 4
    assert calls == [("CTX", 4, 4)]


def test_apply_respects_the_switch_and_missing_samples(monkeypatch, _switched_on):
    calls = []
    _fake_runtime(monkeypatch, calls)
    model = types.SimpleNamespace(_ctx=types.SimpleNamespace(ctx="CTX"))
    monkeypatch.setattr(cpu_load, "idle_cores", lambda: None)
    assert cpu_load.apply_to_model(model, cap=None) is None
    monkeypatch.setattr(cpu_load, "idle_cores", lambda: 6.0)
    monkeypatch.setenv("MESHEMBED_LLM_ADAPTIVE_THREADS", "0")
    assert cpu_load.apply_to_model(model, cap=None) is None
    assert calls == []


def test_apply_never_raises(monkeypatch, _switched_on):
    mod = types.ModuleType("llama_cpp")
    def boom(*a):
        raise RuntimeError("runtime too old")
    mod.llama_set_n_threads = boom
    monkeypatch.setitem(sys.modules, "llama_cpp", mod)
    monkeypatch.setattr(cpu_load, "idle_cores", lambda: 6.0)
    model = types.SimpleNamespace(_ctx=types.SimpleNamespace(ctx="CTX"))
    assert cpu_load.apply_to_model(model, cap=None) is None


@pytest.mark.skipif(os.name == "nt", reason="per-thread nice is POSIX")
def test_priority_is_lowered_on_the_calling_thread_only():
    main_before = os.getpriority(os.PRIO_PROCESS, 0)
    seen = {}

    def worker():
        seen["ok"] = cpu_load.lower_thread_priority()
        seen["nice"] = os.getpriority(os.PRIO_PROCESS, 0)
    t = threading.Thread(target=worker)
    t.start()
    t.join()
    assert seen["ok"] and seen["nice"] >= 10
    if sys.platform.startswith("linux"):
        assert os.getpriority(os.PRIO_PROCESS, 0) == main_before    # this thread untouched


# ── ships inert (release train, operator 2026-10-16) ─────────────────────────
@pytest.mark.parametrize("env,backend,want", [
    (None, None, False),     # nothing decided: OFF -- the release changes no behaviour by itself
    (None, False, False),
    (None, True, True),      # the platform switches it on
    ("0", True, False),      # the owner's off always wins
    ("1", None, True),       # the owner's own opt-in on one machine
    ("1", False, True),
])
def test_adaptive_threads_are_off_until_switched_on(monkeypatch, env, backend, want):
    if env is None:
        monkeypatch.delenv("MESHEMBED_LLM_ADAPTIVE_THREADS", raising=False)
    else:
        monkeypatch.setenv("MESHEMBED_LLM_ADAPTIVE_THREADS", env)
    monkeypatch.setattr(cpu_load, "_BACKEND_ON", None)
    cpu_load.set_backend_flag(backend)
    assert cpu_load.enabled() is want


def test_off_means_no_threads_change(monkeypatch):
    calls = []
    _fake_runtime(monkeypatch, calls)
    monkeypatch.delenv("MESHEMBED_LLM_ADAPTIVE_THREADS", raising=False)
    monkeypatch.setattr(cpu_load, "_BACKEND_ON", None)
    monkeypatch.setattr(cpu_load, "idle_cores", lambda: 6.0)
    model = types.SimpleNamespace(_ctx=types.SimpleNamespace(ctx="CTX"))
    assert cpu_load.apply_to_model(model, cap=None) is None and calls == []


def test_the_sampler_still_measures_while_off(monkeypatch):
    """Only a measurement: the backend reads its idle-cores hint either way; =0 stops it too."""
    monkeypatch.delenv("MESHEMBED_LLM_ADAPTIVE_THREADS", raising=False)
    assert cpu_load.sampling_allowed()
    monkeypatch.setenv("MESHEMBED_LLM_ADAPTIVE_THREADS", "0")
    assert not cpu_load.sampling_allowed()


def test_the_poll_flag_and_the_priority_are_wired():
    from pathlib import Path
    root = Path(cpu_load.__file__).parent
    worker = (root / "worker.py").read_text()
    assert '"llm_adaptive_threads" in resp' in worker and "set_backend_flag(" in worker
    llm_src = (root / "llm.py").read_text()
    i = llm_src.index("cpu_load.lower_thread_priority()")
    assert "if cpu_load.enabled():" in llm_src[i - 120:i], "the owner-first priority follows the same switch"


@pytest.mark.parametrize("gpu_offload,env,want", [
    (False, {}, {"offload": "none", "gpu_layers": 0}),
    (True, {}, {"offload": "gpu", "gpu_layers": -1}),
    (True, {"MESHEMBED_LLM_GPU_LAYERS": "0"}, {"offload": "none", "gpu_layers": 0}),
    (True, {"MESHEMBED_LLM_GPU_LAYERS": "20"}, {"offload": "gpu", "gpu_layers": 20}),
])
def test_offload_reports_what_is_used_not_what_the_build_can(monkeypatch, gpu_offload, env, want):
    from meshembed_node import llm
    monkeypatch.delenv("MESHEMBED_LLM_GPU_LAYERS", raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    assert llm._offload_facts({"gpu_offload": gpu_offload}) == want
