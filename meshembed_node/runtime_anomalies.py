"""Self-instrumentation for the MeshEmbed daemon.

The daemon can observe a handful of signals from its own host that
indicate someone is inspecting it (gdb/strace/gcore) or has
modified its runtime environment. These signals are sent to the
backend on every poll as `runtime_anomalies: [..]`. The backend
treats any non-empty list as a `runtime_inspection_detected` event
and triggers the standard detect-and-eject pipeline.

This is detection, not prevention. A sophisticated attacker can
bypass each individual check (patch /proc lookups, use eBPF probes
that don't set TracerPid, etc.). The point is to raise the floor of
"how careful does the attacker have to be" -- casual inspection
gets caught immediately; only operators with real skill avoid
detection. Combined with the bond/insurance/honey-tripwire layers,
that's a meaningful deterrent.

What's documented as detectable:

- ptrace attached (gdb / strace / lldb) -- via /proc/self/status:TracerPid
- gcore artifact on disk -- looks like the host has done a memory dump of us
- encode wall-clock anomaly -- last encode call took 3x baseline; suggests
  the process was paused (debugger break, scheduler-disabled, etc.)
- /proc/self/maps shows debugger / instrumentation libs loaded

What's NOT detectable from userspace:

- Kernel module reading our memory directly
- eBPF uprobes (most attach silently)
- /proc/<pid>/mem reads from outside our process

For those, only TEE attestation closes the gap. See
docs/TEE_ATTESTATION_DESIGN.md.
"""
from __future__ import annotations

import logging
import os
import platform
import time
from pathlib import Path
from typing import List, Optional

log = logging.getLogger(__name__)


# Encode-time anomaly: if a single encode call takes more than
# `_ENCODE_ANOMALY_MULTIPLIER` times the baseline, we flag it. The
# baseline is established from the first N successful encode calls.
_ENCODE_BASELINE_SAMPLE = 5
_ENCODE_ANOMALY_MULTIPLIER = 3.0


class _EncodeTimingTracker:
    """Maintains a running baseline of encode call durations and flags
    anomalies. Thread-unsafe but the daemon's encode path is
    single-threaded so that's fine."""

    def __init__(self) -> None:
        self._samples: list[float] = []
        self._baseline: Optional[float] = None
        self._last_anomaly: bool = False

    def record(self, duration_s: float) -> bool:
        """Record an encode duration; returns True iff anomalous.

        Once we have N samples we lock in the baseline. After that,
        any duration > baseline * 3 flags an anomaly. We also clamp
        durations <= 0 (clock jumps).
        """
        if duration_s <= 0:
            self._last_anomaly = False
            return False
        if self._baseline is None:
            self._samples.append(duration_s)
            if len(self._samples) >= _ENCODE_BASELINE_SAMPLE:
                # Baseline = median of samples (robust to outliers).
                sorted_s = sorted(self._samples)
                mid = len(sorted_s) // 2
                self._baseline = sorted_s[mid]
                log.info(
                    "runtime_anomalies.baseline_established encode_p50=%.3fs samples=%d",
                    self._baseline, len(sorted_s),
                )
            self._last_anomaly = False
            return False
        # We have a baseline; check.
        threshold = self._baseline * _ENCODE_ANOMALY_MULTIPLIER
        if duration_s > threshold:
            self._last_anomaly = True
            log.warning(
                "runtime_anomalies.encode_too_slow duration=%.3fs baseline=%.3fs threshold=%.3fs",
                duration_s, self._baseline, threshold,
            )
            return True
        self._last_anomaly = False
        return False

    @property
    def has_baseline(self) -> bool:
        return self._baseline is not None


# Module-level tracker shared between worker.run() and the encode loop.
_tracker = _EncodeTimingTracker()


def record_encode_duration(duration_s: float) -> bool:
    """Public hook for the worker loop. Returns True iff this encode
    was anomalously slow."""
    return _tracker.record(duration_s)


def _check_ptrace_attached() -> bool:
    """True iff TracerPid != 0 in /proc/self/status (Linux + Android).
    On macOS/Windows /proc/self doesn't exist; we return False (no
    cheap userspace check on those platforms)."""
    if platform.system() != "Linux":
        return False
    try:
        with open("/proc/self/status", "r") as f:
            for line in f:
                if line.startswith("TracerPid:"):
                    pid = int(line.split(":", 1)[1].strip())
                    return pid != 0
    except Exception:
        pass
    return False


def _check_gcore_artifact() -> bool:
    """True iff there's evidence that someone ran gcore on us recently.

    Looks for `core.<our-pid>` or `gcore.*` in common dump locations.
    Doesn't catch in-flight dumps (no kernel notify) but catches the
    artifact left on disk afterwards.
    """
    candidates = [
        Path("/var/crash"),
        Path("/tmp"),
        Path(os.environ.get("HOME", "/root")),
        Path.cwd(),
    ]
    our_pid = os.getpid()
    patterns = [f"core.{our_pid}", f"gcore.{our_pid}", "meshembed-node.core"]
    for d in candidates:
        try:
            if not d.is_dir():
                continue
            for p in d.iterdir():
                name = p.name
                if any(name.startswith(pat) for pat in patterns):
                    log.warning(
                        "runtime_anomalies.gcore_artifact found at %s", p,
                    )
                    return True
        except (PermissionError, FileNotFoundError, OSError):
            continue
    return False


def _check_suspicious_maps() -> bool:
    """True iff /proc/self/maps contains entries indicating that
    debugger or instrumentation libs are mapped into our process.

    Caveat: the daemon has Python + cryptography + sentence-
    transformers in its maps already; many "instrumentation" patterns
    appear there legitimately. We look only for VERY specific
    debugger artifacts (libthread_db, gdb, frida, ptrace-related).
    Returns False on non-Linux."""
    if platform.system() != "Linux":
        return False
    triggers = ("libthread_db", "libfrida", "frida-agent", "gdb-tools")
    try:
        with open("/proc/self/maps", "r") as f:
            content = f.read()
        for t in triggers:
            if t in content:
                log.warning(
                    "runtime_anomalies.suspicious_map found marker=%s",
                    t,
                )
                return True
    except Exception:
        pass
    return False


def collect() -> List[str]:
    """Return the list of anomalies detected RIGHT NOW.

    Called once per /get_job poll. The result is sent verbatim to the
    backend; an empty list means no anomalies. The backend treats a
    HARD anomaly here as a runtime_inspection_detected security event.

    Only hard, concrete signals are reported. The encode-duration
    heuristic (a single encode > 3x the rolling baseline) is deliberately
    NOT reported: it false-positives on cold model loads, CPU contention,
    thermal throttle, large batches and laptop sleep/resume, and a
    permanent eject on a timing guess is not defensible. record_encode_duration()
    still logs slow encodes locally (runtime_anomalies.encode_too_slow) for
    telemetry, but they no longer ban the node.
    """
    anomalies: List[str] = []
    if _check_ptrace_attached():
        anomalies.append("ptrace_attached")
    if _check_gcore_artifact():
        anomalies.append("gcore_artifact")
    if _check_suspicious_maps():
        anomalies.append("debugger_lib_loaded")
    return anomalies
