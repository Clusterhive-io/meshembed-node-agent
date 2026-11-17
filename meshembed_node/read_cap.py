"""DISK-AWARE NODE item (4): a per-node read-rate cap for the daemon's own cold reads, proven before it is relied on.

Design: for-docs/DESIGN_NOTE_DISK_AWARE_NODE_2026-11-14.md Rev 1 (auditor design GO 2026-11-14T12:14:36Z, D-3): an IN-PROCESS
rate-limited reader (stdlib only, so linux, mac and windows alike; no cgroup, no unit file, no root) does the throttling, and a
measured-rate probe proves the cap holds BEFORE the cold read starts. A probe that shows the cap not holding, or whose result is
unparsable (not finite, not positive), FAILS CLOSED: the read does not start, and nothing falls back to an unthrottled read.
A quiet-disk check (own read rate over a short window, via psutil when present) makes a busy node defer instead of stacking.

What it covers, stated plainly: the daemon's OWN reads of a model file (the per-block verification pass). It does not throttle
llama.cpp's later memory-mapping of the file; that read is served from the page cache the verification pass just filled, when the
machine has the RAM for it. The cap is a number in the owner's limits (`max_model_read_mb_s`) or DEFAULT_CAP_BPS.
"""
from __future__ import annotations

import math
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional

DEFAULT_CAP_BPS = 32 * 1024 * 1024
PROBE_BYTES = 4 * 1024 * 1024
PROBE_CHUNK = 1024 * 1024
TOLERANCE = 1.10                       # the probe's achieved rate may exceed the cap by at most 10 %
IDLE_FRACTION = 0.5                    # a node already reading at more than half the cap is not idle
IDLE_WINDOW_S = 0.5
IDLE_WAIT_S = 120.0


class ReadCapError(Exception):
    """The cap could not be proven, or the disk is not idle: the cold read must not start."""


def cap_from_limits(limits: Optional[Dict[str, Any]]) -> int:
    """Bytes per second: the owner's `max_model_read_mb_s` when it is a sane positive number, else the default."""
    v = (limits or {}).get("max_model_read_mb_s")
    if isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) and 0 < v <= 100_000:
        return int(v * 1024 * 1024)
    return DEFAULT_CAP_BPS


MAX_LAG_S = 1.0                      # the most credit a stall can bank, in seconds of reading


class RateLimiter:
    """Pace reads to `bps` bytes per second on average: after n bytes are read, wait() sleeps until n / bps seconds have
    passed since the first byte. Credit is bounded: if the reader fell more than MAX_LAG_S behind the schedule (a stall, a
    pause), the schedule restarts from now, so a stall never banks a burst (auditor 21:20Z: 1920 MB after a 60 s stall)."""

    def __init__(self, bps: int, clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep) -> None:
        if not (isinstance(bps, int) and bps > 0):
            raise ReadCapError("cap is not a positive integer")
        self.bps, self._clock, self._sleep = bps, clock, sleep
        self._t0: Optional[float] = None
        self._bytes = 0

    def wait(self, n: int) -> None:
        now = self._clock()
        if self._t0 is None:
            self._t0 = now
        if now - (self._t0 + self._bytes / self.bps) > MAX_LAG_S:      # behind schedule by more than the bound: no banked credit
            self._t0, self._bytes = now, 0
        self._bytes += n
        due = self._t0 + self._bytes / self.bps
        if due > now:
            self._sleep(due - now)


def probe(path: Path, bps: int, *, nbytes: int = PROBE_BYTES, clock: Callable[[], float] = time.monotonic,
          sleep: Callable[[float], None] = time.sleep) -> float:
    """A SELF-TEST of the limiter, not a measurement of the disk: read up to `nbytes` of `path` through a fresh limiter and return the achieved bytes/s. Raises ReadCapError when the
    cap does not hold (achieved > cap * TOLERANCE), when the file cannot be read, or when the measurement is not a finite
    positive number. A file shorter than one chunk is probed as far as it goes; an empty one cannot prove anything: fail."""
    lim = RateLimiter(bps, clock, sleep)
    total = 0
    t0 = clock()
    try:
        with Path(path).open("rb") as fh:
            while total < nbytes:
                buf = fh.read(min(PROBE_CHUNK, nbytes - total))
                if not buf:
                    break
                lim.wait(len(buf))
                total += len(buf)
    except OSError as exc:
        raise ReadCapError(f"probe could not read the file: {exc.__class__.__name__}") from exc
    elapsed = clock() - t0
    if total <= 0 or not isinstance(elapsed, (int, float)) or not math.isfinite(elapsed) or elapsed <= 0:
        raise ReadCapError("probe result unparsable (no bytes, or elapsed time not a finite positive number)")
    rate = total / elapsed
    if not math.isfinite(rate) or rate <= 0:
        raise ReadCapError("probe result unparsable (rate not finite and positive)")
    if rate > bps * TOLERANCE:
        raise ReadCapError(f"the cap is not holding: probe read {int(rate)} B/s against a cap of {bps} B/s")
    return rate


def own_read_rate(window_s: float = IDLE_WINDOW_S, sleep: Callable[[float], None] = time.sleep) -> Optional[float]:
    """This machine's disk read rate (bytes/s) over a short window, or None when it cannot be measured here."""
    try:
        import psutil
        a = psutil.disk_io_counters()
        if a is None:
            return None
        sleep(window_s)
        b = psutil.disk_io_counters()
        return max(0.0, (b.read_bytes - a.read_bytes) / window_s)
    except Exception:
        return None


def wait_until_idle(bps: int, *, rate_fn: Callable[[], Optional[float]] = own_read_rate, max_wait_s: float = IDLE_WAIT_S,
                    clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep) -> None:
    """Return when the disk's own read rate is below IDLE_FRACTION of the cap; raise ReadCapError (a deferral) when it stays
    busy for max_wait_s. A rate that cannot be measured does not block: the in-process cap is the control, this is a courtesy."""
    deadline = clock() + max_wait_s
    while True:
        r = rate_fn()
        if r is None or r < bps * IDLE_FRACTION:
            return
        if clock() >= deadline:
            raise ReadCapError(f"disk busy ({int(r)} B/s own read rate) for {int(max_wait_s)} s: cold read deferred")
        sleep(min(5.0, max(0.0, deadline - clock())))
