"""The memory this daemon may really use, not the memory the host has.

N-23711 (2026-10-11, docs/INCIDENT_2026-10-11_N23711_LLM_CANARY_THRASH.md): a 16 GB
host whose daemon unit carried MemoryHigh=6G. Every figure we reported and checked
was host-wide MemAvailable, so a 7B "fit" and then swapped for 15-26 minutes per
load. On Linux with cgroup v2 the binding number is the tightest memory.high /
memory.max on the way from this process's cgroup to the root, minus what the
cgroup already holds that cannot be reclaimed. Everywhere else (macOS, Windows,
cgroup v1, no permission) it is host MemAvailable, exactly as before.

Every probe is best-effort and never raises: a node that cannot read a file keeps
the host figure rather than refusing to poll.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Optional

CGROUP_ROOT = Path("/sys/fs/cgroup")
PROC_SELF_CGROUP = Path("/proc/self/cgroup")
PRESSURE_DIR = Path("/proc/pressure")

_MB = 1024 * 1024


def _read(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="ascii").strip()
    except Exception:
        return None


def _limit_bytes(path: Path) -> Optional[int]:
    """A cgroup v2 memory limit file: an integer, or 'max' (no limit) -> None."""
    raw = _read(path)
    if not raw or raw == "max":
        return None
    try:
        v = int(raw)
        return v if v > 0 else None
    except ValueError:
        return None


def own_cgroup_dir(proc_cgroup: Path = PROC_SELF_CGROUP, root: Path = CGROUP_ROOT) -> Optional[Path]:
    """This process's cgroup v2 directory, or None (v1, not Linux, unreadable)."""
    raw = _read(proc_cgroup)
    if not raw:
        return None
    for line in raw.splitlines():
        if line.startswith("0::"):
            rel = line[3:].strip().lstrip("/")
            d = root / rel if rel else root
            return d if d.is_dir() else None
    return None


def cgroup_memory(proc_cgroup: Path = PROC_SELF_CGROUP, root: Path = CGROUP_ROOT) -> Dict[str, Optional[int]]:
    """{'limit', 'high', 'max', 'current', 'inactive_file'} in bytes (None = unknown).

    `limit` is the tightest of memory.high and memory.max over this cgroup and its
    ancestors: a slice's limit binds the services under it.
    """
    out: Dict[str, Optional[int]] = {"limit": None, "high": None, "max": None,
                                     "current": None, "inactive_file": None}
    d = own_cgroup_dir(proc_cgroup, root)
    if d is None:
        return out
    try:
        out["current"] = int(_read(d / "memory.current") or "")
    except ValueError:
        pass
    stat = _read(d / "memory.stat") or ""
    for line in stat.splitlines():
        k, _, v = line.partition(" ")
        if k == "inactive_file":
            try:
                out["inactive_file"] = int(v)
            except ValueError:
                pass
    high = mx = None
    cur = d
    root_r = root.resolve()
    while True:
        h = _limit_bytes(cur / "memory.high")
        m = _limit_bytes(cur / "memory.max")
        if h is not None:
            high = h if high is None else min(high, h)
        if m is not None:
            mx = m if mx is None else min(mx, m)
        if cur.resolve() == root_r or cur.parent == cur:
            break
        cur = cur.parent
    out["high"], out["max"] = high, mx
    limits = [x for x in (high, mx) if x is not None]
    out["limit"] = min(limits) if limits else None
    return out


def host_available_mb() -> int:
    try:
        import psutil
        return int(psutil.virtual_memory().available / _MB)
    except Exception:
        return 0


def available_mb(host_mb: Optional[int] = None,
                 cg: Optional[Dict[str, Optional[int]]] = None) -> int:
    """What a new allocation by this daemon can count on, in MB.

    min(host MemAvailable, cgroup limit - (current - inactive_file)). Inactive file
    pages are what the kernel reclaims first, so they count as available, the same
    way MemAvailable counts cache. Swap never counts.
    """
    host = host_available_mb() if host_mb is None else int(host_mb)
    cg = cgroup_memory() if cg is None else cg
    limit, current = cg.get("limit"), cg.get("current")
    if limit is None or current is None:
        return host
    used = max(0, current - int(cg.get("inactive_file") or 0))
    return max(0, min(host, int((limit - used) / _MB)))


def cpu_quota_cores(proc_cgroup: Path = PROC_SELF_CGROUP, root: Path = CGROUP_ROOT) -> Optional[float]:
    """cpu.max as cores ('400000 100000' -> 4.0); None when unlimited or unknown."""
    d = own_cgroup_dir(proc_cgroup, root)
    raw = _read(d / "cpu.max") if d is not None else None
    if not raw:
        return None
    parts = raw.split()
    if len(parts) != 2 or parts[0] == "max":
        return None
    try:
        return round(int(parts[0]) / int(parts[1]), 2)
    except (ValueError, ZeroDivisionError):
        return None


def pressure(kind: str, pressure_dir: Path = PRESSURE_DIR) -> Optional[Dict[str, float]]:
    """/proc/pressure/<kind> as {'some_avg10', 'some_avg60', 'full_avg10', 'full_avg60'}."""
    raw = _read(pressure_dir / kind)
    if not raw:
        return None
    out: Dict[str, float] = {}
    for line in raw.splitlines():
        fields = line.split()
        if not fields or fields[0] not in ("some", "full"):
            continue
        for f in fields[1:]:
            k, _, v = f.partition("=")
            if k in ("avg10", "avg60"):
                try:
                    out[f"{fields[0]}_{k}"] = float(v)
                except ValueError:
                    pass
    return out or None


def rotational(path: Path, sys_dev_block: Path = Path("/sys/dev/block")) -> Optional[bool]:
    """Whether the block device under `path` is a spinning disk; None when unknown
    (ZFS, overlay, network filesystems, not Linux). A device TYPE, not usage."""
    try:
        st = os.stat(path)
        dev = f"{os.major(st.st_dev)}:{os.minor(st.st_dev)}"
    except Exception:
        return None
    base = sys_dev_block / dev
    for cand in (base / "queue" / "rotational", base / ".." / "queue" / "rotational"):
        raw = _read(cand)
        if raw in ("0", "1"):
            return raw == "1"
    return None


def report(cache_dir: Optional[Path] = None) -> Dict[str, Any]:
    """The memory picture sent inside the poll's `hardware` blob (MB / cores / %)."""
    out: Dict[str, Any] = {}
    try:
        cg = cgroup_memory()
        host = host_available_mb()
        out["host_available_mb"] = host
        out["available_mb"] = available_mb(host, cg)
        for k in ("limit", "high", "max", "current"):
            if cg.get(k) is not None:
                out[f"cgroup_{k}_mb"] = int(cg[k] / _MB)
    except Exception:
        pass
    try:
        import psutil
        sw = psutil.swap_memory()
        out["swap_total_mb"] = int(sw.total / _MB)
        out["swap_used_mb"] = int(sw.used / _MB)
        out["swap_in_mb_total"] = int(getattr(sw, "sin", 0) / _MB)
        out["swap_out_mb_total"] = int(getattr(sw, "sout", 0) / _MB)
    except Exception:
        pass
    q = cpu_quota_cores()
    if q is not None:
        out["cgroup_cpu_cores"] = q
    for kind in ("memory", "io", "cpu"):         # cpu: the admission hint (DESIGN_LOAD_AWARE_NODES (2))
        p = pressure(kind)
        if p is not None:
            out[f"psi_{kind}"] = p
    if cache_dir is not None:
        r = rotational(cache_dir)
        if r is not None:
            out["model_disk_rotational"] = r
    return out
