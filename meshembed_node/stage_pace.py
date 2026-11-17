"""SP-CAP (auditor DESIGN GO 2026-11-09T16:46:37Z, PROD-STALL-2): a write-rate cap for the two FULL copies a serve
start makes of a model's weights -- the daemon's staging copy (serve_duty.stage_from_catalogue) and the root launcher's
hash+copy into /srv/mesh-di/models (serve_launch.place_model). On a node whose disk shares a pool with other VMs, an
uncapped multi-GB copy stalls its neighbours (2026-11-09 16:16Z: VM 120 -> prod's database).

The cap is paced in the process that does the I/O, so it works (unlike an ionice on a client whose server does the I/O).
MESHEMBED_STAGE_MBPS: unset = DEFAULT_MBPS; 0 (or less) = no cap; any other value is raised to FLOOR_MBPS, which is
the rate the backend's plan load deadline assumes (backend serve_warmset STAGE_MIN_MBPS): a slower cap would make a
plan miss its deadline and be re-issued, the very loop this is meant to calm. MB = 2**20 bytes, as size_mb there.
Stdlib only: the root launcher imports it.
"""
from __future__ import annotations

import os
import time
from typing import Callable, Mapping, Optional

ENV = "MESHEMBED_STAGE_MBPS"
DEFAULT_MBPS = 20.0
FLOOR_MBPS = 15.0
MB = 1 << 20
CHUNK = 8 << 20


def mbps(env: Optional[Mapping[str, str]] = None) -> float:
    """The cap in MB/s; 0.0 = no cap."""
    raw = ((env if env is not None else os.environ).get(ENV) or "").strip()
    if not raw:
        return DEFAULT_MBPS
    try:
        v = float(raw)
    except ValueError:
        return DEFAULT_MBPS
    if v != v:                                  # NaN
        return DEFAULT_MBPS
    if v <= 0:
        return 0.0
    return max(FLOOR_MBPS, v)


class Pacer:
    """Sleeps so that the bytes accounted so far never run ahead of rate_mbps since the pacer started."""

    def __init__(self, rate_mbps: float, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep):
        self.rate = float(rate_mbps) * MB if rate_mbps and rate_mbps > 0 else 0.0
        self.clock, self.sleep = clock, sleep
        self.start = clock()
        self.done = 0

    def account(self, nbytes: int) -> None:
        if not self.rate or nbytes <= 0:
            return
        self.done += nbytes
        wait = self.start + self.done / self.rate - self.clock()
        if wait > 0:
            self.sleep(wait)


def copy_paced(src: str, dst: str, rate_mbps: float, *, chunk: int = CHUNK, pacer: Optional[Pacer] = None) -> int:
    """Copy src to dst (created / truncated) at no more than rate_mbps; returns the bytes copied."""
    p = pacer or Pacer(rate_mbps)
    n = 0
    with open(src, "rb") as f, open(dst, "wb") as out:
        for block in iter(lambda: f.read(chunk), b""):
            out.write(block)
            n += len(block)
            p.account(len(block))
    return n
