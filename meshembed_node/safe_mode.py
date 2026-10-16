"""Crash-loop guard: a node that keeps dying before its first poll comes back with
only the essentials, and says why.

docs/DESIGN_CPU_FEATURE_GUARD_2026-10-14.md (C). The Z400 crash-looped for two
days without one poll reaching the backend: embeddings lost, nothing visible.
cpu_guard stops that particular cause; this stops the CLASS -- any optional
subsystem that kills the process at start.

A breadcrumb counts starts that never reached a successful poll. The 3rd such
start runs in SAFE MODE: no LLM runtime, no power meter -- embeddings and the
poll only -- and the poll reports `safe_mode` so the dashboard shows it. The
first successful poll removes the breadcrumb, so the next clean restart is a
normal one. Fail-safe, never fail-open: it only switches OPTIONAL things off.
"""
from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional

log = logging.getLogger(__name__)

FAILED_STARTS_FOR_SAFE_MODE = 3

_ACTIVE: Optional[Dict[str, Any]] = None
_HEALTHY = False


def _path() -> Path:
    return Path.home() / ".meshembed" / "start_guard.json"


def record_start(now: Optional[float] = None) -> Dict[str, Any]:
    """Call once, first thing at daemon start. Returns the breadcrumb."""
    global _ACTIVE
    now = time.time() if now is None else now
    p = _path()
    try:
        rec = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(rec, dict):
            rec = {}
    except Exception:
        rec = {}
    starts = int(rec.get("starts") or 0) + 1
    rec = {"starts": starts, "first": rec.get("first") or now, "last": now}
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(rec), encoding="utf-8")
    except Exception:                          # a read-only home cannot crash-loop-guard
        pass
    if os.environ.get("MESHEMBED_SAFE_MODE") == "1":
        _ACTIVE = {"reason": "operator", "starts": starts}
    elif starts >= FAILED_STARTS_FOR_SAFE_MODE:
        _ACTIVE = {"reason": "crash_loop", "starts": starts}
    if _ACTIVE:
        log.warning("SAFE MODE (%s, %d starts without a poll): LLM runtime and power meter off, "
                    "embeddings only", _ACTIVE["reason"], starts)
    return rec


def mark_healthy() -> None:
    """After a successful poll: this start did not crash-loop. Cheap after the first call."""
    global _HEALTHY
    if _HEALTHY:
        return
    _HEALTHY = True
    try:
        _path().unlink()
    except FileNotFoundError:
        pass
    except Exception as exc:                   # pragma: no cover - defensive
        log.debug("start guard: could not clear the breadcrumb (%s)", exc)


def active() -> bool:
    return _ACTIVE is not None or os.environ.get("MESHEMBED_SAFE_MODE") == "1"


def report() -> Optional[Dict[str, Any]]:
    """For the poll payload; None when not in safe mode."""
    if _ACTIVE is not None:
        return dict(_ACTIVE)
    if os.environ.get("MESHEMBED_SAFE_MODE") == "1":
        return {"reason": "operator", "starts": None}
    return None
