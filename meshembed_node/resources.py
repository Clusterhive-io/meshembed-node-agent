"""The lend envelope, enforced on the machine rather than promised.

docs/NODE_RESOURCE_CAP.md. Until now `resource_limits` was two things: a
reactive back-off (`pause_when_busy`, stop pulling while the owner is busy)
and an in-flight cap. Neither bounds how much of the machine a single encode
takes: a 16-core laptop lending "20%" would still put every core to work for
the duration of a chunk, which is what an office user notices and what makes
a lend schedule a promise rather than a control.

This module applies the ceiling the owner set:

- **CPU**: the process is confined to N cores. N comes from `max_cpu_pct` or
  `max_cpu_cores`, whichever the owner set (percentage first). It is applied
  three ways, because one alone is not enough:
    * thread pools (`OMP_NUM_THREADS`, `MKL_NUM_THREADS`, `torch.set_num_threads`)
      so the maths libraries do not spawn a thread per core;
    * CPU affinity where the platform has it (Linux, Windows), so even
      threads we do not control cannot spill onto the owner's cores;
    * process priority, so the owner's work always preempts ours.
- **RAM**: a ceiling that DEGRADES rather than kills. When the process is at
  or above `max_ram_gb`, the daemon stops pulling new work and says so. A
  hard `RLIMIT_AS` is deliberately not used: it would abort the process
  mid-chunk, losing a customer's work to protect a limit that a pause
  satisfies just as well.

Everything here is best-effort by design. A machine that cannot report its
own CPU count, or a platform without affinity, must not stop the node from
working -- it simply gets the weaker forms of the same cap, and says which.
"""
from __future__ import annotations

import logging
import math
import os
from typing import Any, Dict, Optional, Tuple

log = logging.getLogger("meshembed.resources")

# Set once, before torch is imported, and re-applied when the cap changes.
_APPLIED: Optional[Tuple] = None


def cores_allowed(limits: Optional[Dict[str, Any]], total_cores: int) -> Optional[int]:
    """How many cores this node may use, or None for "no ceiling set".

    `max_cpu_pct` wins over `max_cpu_cores` because a percentage is what a
    fleet-wide policy can express; both are clamped to at least one core, as
    zero would mean a node that can never work but still polls.
    """
    if not limits:
        return None
    pct = limits.get("max_cpu_pct")
    if pct is not None:
        try:
            pct = float(pct)
        except (TypeError, ValueError):
            return None
        if pct <= 0 or pct >= 100:
            return None                       # 100% or nonsense: no ceiling
        return max(1, int(math.floor(total_cores * pct / 100.0)))
    n = limits.get("max_cpu_cores")
    if n is None:
        return None
    try:
        n = int(n)
    except (TypeError, ValueError):
        return None
    return max(1, min(n, total_cores)) if n > 0 else None


def apply_cpu_cap(limits: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Confine this process to the owner's share of the CPU. Returns what was
    actually applied, so the caller can log the truth rather than the wish."""
    global _APPLIED
    try:
        import psutil
        total = psutil.cpu_count() or os.cpu_count() or 1
    except Exception:
        psutil = None                          # type: ignore
        total = os.cpu_count() or 1

    n = cores_allowed(limits, total)
    applied: Dict[str, Any] = {"total_cores": total, "cores": n, "threads": False,
                               "affinity": False, "priority": False}
    if n is None or n >= total:
        _APPLIED = None
        return applied

    # 1. Thread pools. Must be set before torch/numpy build theirs; on a change
    #    at runtime torch.set_num_threads still takes effect for later work.
    for var in ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS",
                "NUMEXPR_NUM_THREADS", "TOKENIZERS_PARALLELISM"):
        os.environ[var] = "false" if var == "TOKENIZERS_PARALLELISM" else str(n)
    applied["threads"] = True
    try:
        import torch
        torch.set_num_threads(n)
        try:
            torch.set_num_interop_threads(1)   # raises once threads are started
        except Exception:
            pass
    except Exception:
        pass                                   # torch not loaded yet: env vars carry it

    # 2. Affinity: the only form that binds threads we did not spawn.
    if psutil is not None:
        try:
            proc = psutil.Process()
            proc.cpu_affinity(list(range(n)))
            applied["affinity"] = True
        except (AttributeError, NotImplementedError, OSError):
            pass                               # macOS has no affinity; not a failure
        # 3. Priority: the owner's work preempts ours whatever the core count.
        try:
            proc.nice(10 if os.name != "nt" else psutil.BELOW_NORMAL_PRIORITY_CLASS)
            applied["priority"] = True
        except Exception:
            pass

    if _APPLIED != (n, applied["affinity"]):
        log.info(
            "CPU cap applied: %d of %d cores (threads=%s affinity=%s priority=%s)",
            n, total, applied["threads"], applied["affinity"], applied["priority"],
        )
        _APPLIED = (n, applied["affinity"])
    return applied


# ── power: the guard that keeps a laptop fleet installed ───────────────────
#
# A laptop is not a small desktop. Four cores at 100% draw two to three times
# idle, so an unnoticed hour of inference is a visibly flat battery, and the
# fan makes it audible. Neither is a policy problem; both are the reason a
# node gets uninstalled, and an uninstalled node is worth less than a slow
# one.
#
# `_is_laptop()` already existed in worker.py and was only ever filed as
# hardware inventory. This acts on it.
#
# The rule is deliberately blunt: on battery, do not take work. Not "reduce
# the cap" -- a laptop's owner does not care that we were only using two
# cores while their battery emptied. Plugged in, a laptop is an ordinary
# node and the usual envelope applies.

DEFAULT_MIN_BATTERY_PCT = 20.0


def _battery():
    try:
        import psutil
        return psutil.sensors_battery()
    except Exception:                              # no battery, no psutil, VM
        return None


def power_block_reason(limits: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """Why this machine should not take work right now, on power grounds.

    Returns None when it is fine to work. A desktop (no battery) is always
    fine -- the check costs one syscall and answers None immediately.

    Two states block:
      * `on_battery`  -- unplugged. Never work on battery, at any cap.
      * `battery_low` -- plugged in but still under the floor, so the machine
        is charging from flat. Taking cores from a laptop that is trying to
        recover is the same insult more slowly.

    The floor is `min_battery_pct` in the operator's limits, else 20%.
    Opt out entirely with `ignore_battery: true` -- a docked machine that
    reports a battery it never runs on.
    """
    if limits and limits.get("ignore_battery"):
        return None
    b = _battery()
    if b is None:
        return None                                # desktop / server / VM
    try:
        if not b.power_plugged:
            return "on_battery"
        floor = float((limits or {}).get("min_battery_pct", DEFAULT_MIN_BATTERY_PCT))
        if b.percent is not None and float(b.percent) < floor:
            return "battery_low"
    except Exception:
        return None                                # never block on a bad reading
    return None


def over_ram_cap(limits: Optional[Dict[str, Any]]) -> Optional[float]:
    """This process's RSS in GB when it is at or over `max_ram_gb`, else None.

    Degrading, not killing: the caller stops pulling work. A hard RLIMIT_AS
    would abort mid-chunk and lose a customer's work to enforce a ceiling
    that a pause already enforces.
    """
    if not limits:
        return None
    cap = limits.get("max_ram_gb")
    if cap is None:
        return None
    try:
        cap = float(cap)
        if cap <= 0:
            return None
        import psutil
        rss_gb = psutil.Process().memory_info().rss / 1024 ** 3
    except Exception:
        return None
    return rss_gb if rss_gb >= cap else None
