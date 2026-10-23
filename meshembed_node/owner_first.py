"""MVP 1 (2026-10-21, design 2.4 section 4): may this machine serve right now, owner first?

decide() is a pure function of the signals and the owner's policy, so every rule is testable. In order, each able
to stop serving (the daemon then STOPS meshembed-serve: an unloaded model cannot hurt the owner):
  1. power      -- AC only by default (resources.power_block_reason: on_battery / battery_low); allow_battery opts in
  2. thermal    -- resources.too_hot (max_temp_c, default 85)
  3. duty       -- busy at most duty_cap of each duty_window_s (default 50 % of 10 min), so fans never run for an hour
  4. owner      -- input within owner_idle_s (default 60 s), or a call in progress, means YIELD. Unknown input idle
                   (a Linux system service with no display; a Windows S4U task in session 0) follows
                   unknown_owner: "cpu" (default: rely on the host's own CPU load, below) or "yield" (never serve)
  5. memory     -- memory pressure (PSI some avg10 >= psi_mem_pct, Linux) or available memory under the model's
                   need + headroom: unload, never swap
  6. cpu        -- the host's OWN work (not ours) uses more than owner_cpu_frac of the cores
Defaults are the proposed operator decisions (design 2.4 section 10) until he answers.
"""
from __future__ import annotations

import time
from collections import deque
from typing import Any, Dict, Optional, Tuple

DEFAULTS = {
    "allow_battery": False,
    "duty_cap": 0.5,
    "duty_window_s": 600,
    "owner_idle_s": 60,
    "unknown_owner": "cpu",
    "psi_mem_pct": 10.0,
    "mem_headroom_mb": 1024,
    "owner_cpu_frac": 0.5,
}


def policy(owner: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    p = dict(DEFAULTS)
    for k, v in (owner or {}).items():
        if k in DEFAULTS:
            p[k] = v
    return p


def decide(sig: Dict[str, Any], owner: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
    """(serve?, reason). sig keys (None = unknown): power_block (str|None), too_hot (float|None), duty_busy_frac,
    human_idle_s, call_active, psi_mem_some_avg10, mem_available_mb, model_need_mb, other_cpu_frac."""
    p = policy(owner)
    pb = sig.get("power_block")
    if pb and not (pb == "on_battery" and p["allow_battery"]):
        return False, f"power:{pb}"
    if sig.get("too_hot") is not None:
        return False, "thermal"
    if (sig.get("duty_busy_frac") or 0.0) >= float(p["duty_cap"]):
        return False, "duty_cap"
    if sig.get("call_active"):
        return False, "owner:call"
    idle = sig.get("human_idle_s")
    if idle is None:
        # "cpu" relies on a CPU measurement: with NEITHER signal there is no owner evidence at all, and unknown is
        # never treated as away (auditor F3)
        if p["unknown_owner"] == "yield" or sig.get("other_cpu_frac") is None:
            return False, "owner:unknown"
    elif idle < float(p["owner_idle_s"]):
        return False, "owner:active"
    psi = sig.get("psi_mem_some_avg10")
    if psi is not None and psi >= float(p["psi_mem_pct"]):
        return False, "memory:pressure"
    avail, need = sig.get("mem_available_mb"), sig.get("model_need_mb")
    if avail is not None and need is not None and avail < need + int(p["mem_headroom_mb"]):
        return False, "memory:low"
    if (sig.get("other_cpu_frac") or 0.0) > float(p["owner_cpu_frac"]):
        return False, "owner:cpu"
    return True, "ok"


class DutyMeter:
    """Busy seconds within a sliding window: mark(busy_s) after each item; frac() for decide()."""

    def __init__(self, window_s: float = 600.0, clock=time.monotonic):
        self.window_s, self.clock, self.ev = float(window_s), clock, deque()

    def mark(self, busy_s: float) -> None:
        self.ev.append((self.clock(), float(busy_s)))

    def frac(self) -> float:
        now = self.clock()
        while self.ev and now - self.ev[0][0] > self.window_s:
            self.ev.popleft()
        return min(1.0, sum(b for _, b in self.ev) / self.window_s)


def signals(limits: Optional[Dict[str, Any]], duty: DutyMeter, *, model_need_mb: Optional[int] = None,
            other_cpu_frac: Optional[float] = None) -> Dict[str, Any]:
    """The live signals on this machine (each None when the OS cannot tell)."""
    from . import membudget as M
    from . import resources as R
    try:
        avail = M.host_available_mb()           # host-wide: the server runs in its own cgroup, not the daemon's
    except Exception:
        avail = None
    psi = M.pressure("memory")
    return {
        "power_block": R.power_block_reason(limits),
        "too_hot": R.too_hot(limits),
        "duty_busy_frac": duty.frac(),
        "human_idle_s": R.human_idle_seconds(),
        "call_active": None,                    # per-OS detection is a later step (design 2.4); unknown = not a call
        "psi_mem_some_avg10": (psi or {}).get("some_avg10"),
        "mem_available_mb": avail,
        "model_need_mb": model_need_mb,
        "other_cpu_frac": other_cpu_frac,
    }
