"""Load-adaptive threads: use the CPU the owner's own work leaves free, item by item.

docs/DESIGN_LOAD_AWARE_NODES_2026-10-14.md (1). On 187 (load average 23-24 from Frigate/ffmpeg)
the 0.5B ran at 5.75 tok/s against ~30 on an idle host of the same class: with no owner cap,
llama-cpp-python uses cpu_count // 2 threads for generation and every core for the prompt, at
normal priority, and fights the host's own work.

A background sampler measures the CPU the host's OTHER processes use (total busy minus this
process), smoothed over ~10 s. Before each item the generation and prompt thread counts are set
from what is idle -- never above the owner's cap or the physical core count -- without reloading
the model (`llama_set_n_threads`). Between items only, never mid-item.

Ships INERT (release train, operator 2026-10-16): OFF unless the backend pushes
`llm_adaptive_threads: true` on the poll. Locally, MESHEMBED_LLM_ADAPTIVE_THREADS=0 forces it off
and =1 is the owner's own opt-in on one machine. The sampler itself always runs (unless =0): it is
only a measurement, and the backend reads its idle-cores hint.
"""
from __future__ import annotations

import logging
import math
import os
import threading
import time
from typing import Any, Callable, Optional

log = logging.getLogger(__name__)

SAMPLE_S = 2.0
ALPHA = 0.2              # EWMA weight of a new sample (~10 s memory at 2 s)
USE_FRACTION = 0.8       # leave a fifth of the idle cores to the owner


_BACKEND_ON: Optional[bool] = None     # the platform's switch, from the last poll


def set_backend_flag(value: Any) -> None:
    """The poll's `llm_adaptive_threads`; None (absent) means the platform has not decided."""
    global _BACKEND_ON
    _BACKEND_ON = None if value is None else bool(value)


def _env() -> str:
    return os.environ.get("MESHEMBED_LLM_ADAPTIVE_THREADS", "").strip()


def enabled() -> bool:
    """Adaptive threads + owner-first priority: the owner's =0/=1 wins, else the platform's flag."""
    if _env() == "0":
        return False
    if _env() == "1":
        return True
    return bool(_BACKEND_ON)


def sampling_allowed() -> bool:
    return _env() != "0"


def physical_cores() -> int:
    try:
        import psutil
        return int(psutil.cpu_count(logical=False) or psutil.cpu_count() or os.cpu_count() or 1)
    except Exception:
        return int(os.cpu_count() or 1)


def choose_threads(idle_cores: Optional[float], cap: Optional[int], physical: int) -> Optional[int]:
    """Threads for the next item; None = no measurement yet (keep the load-time setting)."""
    if idle_cores is None:
        return None
    ceiling = max(1, min(int(cap), physical) if cap else physical)
    return max(1, min(ceiling, int(math.floor(idle_cores * USE_FRACTION))))


class Sampler:
    """Idle cores left by the host's other work, smoothed. Thread-safe reads."""

    def __init__(self, times: Optional[Callable[[], Any]] = None,
                 own_times: Optional[Callable[[], Any]] = None,
                 logical: Optional[int] = None, clock: Callable[[], float] = time.monotonic):
        import psutil
        self._times = times or psutil.cpu_times
        self._own = own_times or psutil.Process().cpu_times
        self._logical = int(logical or psutil.cpu_count() or os.cpu_count() or 1)
        self._clock = clock
        self._prev = None
        self.idle_cores: Optional[float] = None
        self.others_cores: Optional[float] = None

    @staticmethod
    def _busy(t) -> float:
        idle = getattr(t, "idle", 0.0) + getattr(t, "iowait", 0.0)
        total = sum(v for k, v in t._asdict().items() if k not in ("guest", "guest_nice"))
        return total - idle

    @staticmethod
    def _own_s(o) -> float:
        return (o.user + o.system + getattr(o, "children_user", 0.0) + getattr(o, "children_system", 0.0))

    def tick(self) -> None:
        now, t, o = self._clock(), self._times(), self._own()
        if self._prev is not None:
            p_now, p_t, p_o = self._prev
            dt = now - p_now
            if dt > 0:
                busy = (self._busy(t) - self._busy(p_t)) / dt
                own = (self._own_s(o) - self._own_s(p_o)) / dt
                others = max(0.0, busy - own)
                idle = max(0.0, self._logical - others)
                if self.idle_cores is None:
                    self.others_cores, self.idle_cores = others, idle
                else:
                    self.others_cores = ALPHA * others + (1 - ALPHA) * self.others_cores
                    self.idle_cores = ALPHA * idle + (1 - ALPHA) * self.idle_cores
        self._prev = (now, t, o)


_SAMPLER: Optional[Sampler] = None
_START_LOCK = threading.Lock()


def start() -> Optional[Sampler]:
    """Start the background sampler once (no-op when disabled or psutil is missing)."""
    global _SAMPLER
    if not sampling_allowed():
        return None
    with _START_LOCK:
        if _SAMPLER is not None:
            return _SAMPLER
        try:
            s = Sampler()
        except Exception as exc:                       # pragma: no cover - no psutil
            log.info("cpu load sampler unavailable (%s): fixed threads", exc)
            return None

        def loop():
            while True:
                try:
                    s.tick()
                except Exception:                      # pragma: no cover - defensive
                    pass
                time.sleep(SAMPLE_S)
        threading.Thread(target=loop, name="meshembed-cpu-load", daemon=True).start()
        _SAMPLER = s
        return s


def idle_cores() -> Optional[float]:
    return None if _SAMPLER is None else _SAMPLER.idle_cores


def apply_to_model(model, cap: Optional[int]) -> Optional[int]:
    """Set the model's generation + prompt threads for the next item. Returns the count, or None."""
    if not enabled():
        return None
    n = choose_threads(idle_cores(), cap, physical_cores())
    if n is None:
        return None
    try:
        import llama_cpp
        ctx = getattr(getattr(model, "_ctx", None), "ctx", None)
        if ctx is None:
            return None
        llama_cpp.llama_set_n_threads(ctx, n, n)
        return n
    except Exception as exc:                           # never cost an item for it
        log.debug("adaptive threads not applied (%s)", exc)
        return None


_PRIO = threading.local()


def lower_thread_priority() -> bool:
    """Owner first, with or without a cap: the GENERATING thread runs at nice 10 (Windows:
    below-normal), before llama.cpp creates its compute threads, which inherit it. On Linux
    niceness is per thread, so renicing the process from the poll loop never reached them.
    Once per thread; never fatal."""
    if getattr(_PRIO, "done", False):
        return True
    _PRIO.done = True
    try:
        if os.name == "nt":
            import psutil
            psutil.Process().nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
        else:
            cur = os.getpriority(os.PRIO_PROCESS, 0)
            if cur < 10:
                os.setpriority(os.PRIO_PROCESS, 0, 10)     # 0 = the calling thread on Linux
        return True
    except Exception as exc:                               # pragma: no cover - defensive
        log.debug("could not lower the generation thread's priority (%s)", exc)
        return False
