"""Measured power for cost reporting (docs/COST_PER_1000_2026-09-28.md).

The cost of our work on a machine that is already switched on is the EXTRA draw
while it runs (operator, 2026-09-28): working watts minus the machine's idle
baseline. This module measures both, where the host lets us:

  * CPU package energy from RAPL (Linux, Intel and AMD Zen): the cumulative
    counters in /sys/class/powercap/intel-rapl:<n>/energy_uj, one per package.
    Often readable only by root (the daemon's service runs as root on Linux).
  * GPU draw from `nvidia-smi --query-gpu=power.draw` (summed over GPUs).

Anything we cannot read is simply absent: no guess is ever reported as a
measurement. Readings are self-reported like the RAM figures. The backend never
routes on them, but its daily rollups floor earnings at electricity cost, so
they do reach money (auditor P1, 2026-09-29). Never chmod RAPL energy_uj to
make it readable: world-readable RAPL is the PLATYPUS power side channel.
"""
from __future__ import annotations

import glob
import os
import shutil
import subprocess
import threading
import time
from typing import Dict, List, Optional

RAPL_GLOB = "/sys/class/powercap/intel-rapl:[0-9]*"   # packages only, not sub-zones
IDLE_SAMPLE_S = float(os.environ.get("MESHEMBED_POWER_IDLE_SAMPLE_S", "30"))
IDLE_REFRESH_S = float(os.environ.get("MESHEMBED_POWER_IDLE_REFRESH_S", "3600"))
GPU_SAMPLE_EVERY_S = 1.0
MAX_W = 5000.0                                          # anything above is a bad read


def _rapl_zones() -> List[str]:
    zones = []
    for z in sorted(glob.glob(RAPL_GLOB)):
        if os.path.isfile(os.path.join(z, "energy_uj")):
            zones.append(z)
    return zones


def _read_int(path: str) -> Optional[int]:
    try:
        with open(path) as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


class RaplCounter:
    """Cumulative package energy across zones, handling counter wrap."""

    def __init__(self, zones: Optional[List[str]] = None):
        self.zones = [z for z in (zones if zones is not None else _rapl_zones())
                      if _read_int(os.path.join(z, "energy_uj")) is not None]
        self._max = {z: (_read_int(os.path.join(z, "max_energy_range_uj")) or 0) for z in self.zones}

    @property
    def available(self) -> bool:
        return bool(self.zones)

    def read(self) -> Dict[str, int]:
        return {z: _read_int(os.path.join(z, "energy_uj")) or 0 for z in self.zones}

    def joules_between(self, a: Dict[str, int], b: Dict[str, int]) -> float:
        total = 0
        for z in self.zones:
            d = b.get(z, 0) - a.get(z, 0)
            if d < 0 and self._max.get(z):          # the counter wrapped
                d += self._max[z]
            total += max(d, 0)
        return total / 1e6


def gpu_watts_now() -> Optional[float]:
    """Summed nvidia-smi power.draw, or None when there is no readable NVIDIA GPU."""
    if not shutil.which("nvidia-smi"):
        return None
    try:
        out = subprocess.run(["nvidia-smi", "--query-gpu=power.draw", "--format=csv,noheader,nounits"],
                             capture_output=True, text=True, timeout=5).stdout
        vals = [float(x) for x in out.split() if x.replace(".", "", 1).isdigit()]
        return sum(vals) if vals else None
    except Exception:
        return None


def _clamp(w: Optional[float]) -> Optional[float]:
    if w is None or w != w or w < 0 or w > MAX_W:
        return None
    return round(w, 1)


class _GpuSampler:
    """Background samples of GPU draw between start() and stop()."""

    def __init__(self):
        self._samples: List[float] = []
        self._stop = threading.Event()
        self._t: Optional[threading.Thread] = None

    def start(self) -> None:
        self._stop.clear()
        self._samples = []

        def run():
            while not self._stop.is_set():
                w = gpu_watts_now()
                if w is not None:
                    self._samples.append(w)
                self._stop.wait(GPU_SAMPLE_EVERY_S)
        self._t = threading.Thread(target=run, name="meshembed-gpu-power", daemon=True)
        self._t.start()

    def stop(self) -> Optional[float]:
        self._stop.set()
        if self._t is not None:
            self._t.join(timeout=GPU_SAMPLE_EVERY_S + 6)
        return sum(self._samples) / len(self._samples) if self._samples else None


class PowerMeter:
    """Idle baseline + per-item measurement. One per daemon; thread-safe enough
    for one worker per item (items overlap only on multi-worker nodes, where
    the package counter measures the whole machine anyway)."""

    def __init__(self, rapl: Optional[RaplCounter] = None, gpu: bool = True):
        self.rapl = rapl if rapl is not None else RaplCounter()
        self.gpu = gpu and gpu_watts_now() is not None
        self.cpu_idle_w: Optional[float] = None
        self.gpu_idle_w: Optional[float] = None
        self.idle_at: float = 0.0
        self._lock = threading.Lock()

    @property
    def available(self) -> bool:
        return self.rapl.available or self.gpu

    def source(self) -> str:
        parts = (["rapl"] if self.rapl.available else []) + (["nvidia-smi"] if self.gpu else [])
        return "+".join(parts) or "none"

    def sample_idle(self, seconds: float = IDLE_SAMPLE_S, sleep=time.sleep) -> None:
        """Measure the baseline. Call only while the node holds no work."""
        if not self.available:
            return
        g = _GpuSampler() if self.gpu else None
        if g:
            g.start()
        a, t0 = (self.rapl.read() if self.rapl.available else {}), time.monotonic()
        sleep(seconds)
        b, t1 = (self.rapl.read() if self.rapl.available else {}), time.monotonic()
        with self._lock:
            if self.rapl.available and t1 > t0:
                self.cpu_idle_w = _clamp(self.rapl.joules_between(a, b) / (t1 - t0))
            if g:
                self.gpu_idle_w = _clamp(g.stop())
            self.idle_at = time.monotonic()

    def idle_is_stale(self) -> bool:
        return self.available and (self.idle_at == 0.0 or time.monotonic() - self.idle_at > IDLE_REFRESH_S)

    def begin(self) -> Optional[dict]:
        if not self.available:
            return None
        g = _GpuSampler() if self.gpu else None
        if g:
            g.start()
        return {"rapl": self.rapl.read() if self.rapl.available else {}, "t": time.monotonic(), "gpu": g}

    def end(self, token: Optional[dict]) -> Optional[dict]:
        """The `power` object reported with a result, or None when nothing was measured."""
        if not token:
            return None
        t1 = time.monotonic()
        out: Dict[str, object] = {"source": self.source()}
        if self.rapl.available and t1 > token["t"]:
            out["cpu_w"] = _clamp(self.rapl.joules_between(token["rapl"], self.rapl.read()) / (t1 - token["t"]))
            out["cpu_idle_w"] = self.cpu_idle_w
        if token.get("gpu") is not None:
            out["gpu_w"] = _clamp(token["gpu"].stop())
            out["gpu_idle_w"] = self.gpu_idle_w
        out = {k: v for k, v in out.items() if v is not None}
        return out if any(k in out for k in ("cpu_w", "gpu_w")) else None


_METER: Optional[PowerMeter] = None


def meter() -> PowerMeter:
    global _METER
    if _METER is None:
        _METER = PowerMeter()
    return _METER
