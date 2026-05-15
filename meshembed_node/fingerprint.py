"""Hardware fingerprint for anti-Sybil enforcement.

Collects hardware identifiers (CPU model, RAM size, primary MAC, root
disk UUID, motherboard serial, GPU UUID) and SHA-256 hashes them.

The daemon sends two values:
- `machine_fingerprint`: hex sha256 (64 chars), stable across reboots
  on the same physical machine.
- `gpu_uuid`: NVIDIA GPU UUID when a CUDA GPU is present; None on
  CPU / MPS.

Design notes:
- Best-effort. If a value can't be read (permissions, old kernel,
  etc.) it falls back to `"unknown"` instead of failing. The backend
  accepts a NULL fingerprint for legacy / test nodes.
- Cross-platform: Linux (/proc, /sys, sysfs), macOS (sysctl, ioreg),
  Windows (WMIC, registry).
- Filtering: virtual interfaces (docker0, veth, vbox, etc.) are
  skipped so the fingerprint doesn't change every time `docker
  restart` cycles the bridge.
"""
from __future__ import annotations

import hashlib
import logging
import platform
import subprocess
from typing import Optional

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CPU
# ---------------------------------------------------------------------------


def _cpu_model() -> str:
    """Return a stable 'CPU model name + family' string."""
    sys = platform.system()
    try:
        if sys == "Linux":
            with open("/proc/cpuinfo", "r") as f:
                for line in f:
                    if line.startswith("model name"):
                        return line.split(":", 1)[1].strip()
        elif sys == "Darwin":
            out = subprocess.check_output(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                stderr=subprocess.DEVNULL, timeout=2,
            ).decode().strip()
            return out
        elif sys == "Windows":
            out = subprocess.check_output(
                ["wmic", "cpu", "get", "Name", "/value"],
                stderr=subprocess.DEVNULL, timeout=5,
            ).decode().strip()
            for line in out.splitlines():
                if line.startswith("Name="):
                    return line.split("=", 1)[1].strip()
    except Exception:
        pass
    return platform.processor() or "unknown_cpu"


def _cpu_count() -> int:
    import os
    return os.cpu_count() or 0


# ---------------------------------------------------------------------------
# RAM
# ---------------------------------------------------------------------------


def _total_ram_gb() -> int:
    """Total RAM in GB (integer). Stable across reboots."""
    try:
        import psutil
        return int(psutil.virtual_memory().total / (1024 ** 3))
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# Primary MAC (virtual interfaces filtered out)
# ---------------------------------------------------------------------------


_VIRTUAL_PREFIXES = (
    "docker", "veth", "br-", "virbr", "vbox", "tun", "tap",
    "vmnet", "vnet", "wg", "bond", "lo",
)


def _primary_mac() -> str:
    """Return the MAC of the main physical NIC. Virtual interfaces ignored."""
    try:
        import psutil
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        # Preference: interface UP, not virtual, has a MAC.
        candidates = []
        for name, addr_list in addrs.items():
            if any(name.startswith(p) for p in _VIRTUAL_PREFIXES):
                continue
            st = stats.get(name)
            if st is None or not st.isup:
                continue
            for a in addr_list:
                if a.family.name in ("AF_LINK", "AF_PACKET") and a.address:
                    if a.address not in ("00:00:00:00:00:00",):
                        candidates.append((name, a.address))
        if candidates:
            # Stable ordering: alphabetical by interface name.
            candidates.sort()
            return candidates[0][1]
    except Exception:
        pass
    return "unknown_mac"


# ---------------------------------------------------------------------------
# Disk UUID (root)
# ---------------------------------------------------------------------------


def _root_disk_uuid() -> str:
    """UUID of the root filesystem. Stable within the same install."""
    sys = platform.system()
    try:
        if sys == "Linux":
            # findmnt root → device → UUID
            out = subprocess.check_output(
                ["findmnt", "-no", "UUID", "/"],
                stderr=subprocess.DEVNULL, timeout=2,
            ).decode().strip()
            if out:
                return out
        elif sys == "Darwin":
            out = subprocess.check_output(
                ["diskutil", "info", "/"],
                stderr=subprocess.DEVNULL, timeout=2,
            ).decode()
            for line in out.splitlines():
                if "Volume UUID:" in line:
                    return line.split(":", 1)[1].strip()
        elif sys == "Windows":
            out = subprocess.check_output(
                ["wmic", "csproduct", "get", "UUID", "/value"],
                stderr=subprocess.DEVNULL, timeout=5,
            ).decode().strip()
            for line in out.splitlines():
                if line.startswith("UUID="):
                    return line.split("=", 1)[1].strip()
    except Exception:
        pass
    return "unknown_disk"


# ---------------------------------------------------------------------------
# Motherboard serial
# ---------------------------------------------------------------------------


def _board_serial() -> str:
    sys = platform.system()
    try:
        if sys == "Linux":
            with open("/sys/class/dmi/id/board_serial", "r") as f:
                v = f.read().strip()
                if v and v not in ("None", "Default string", "0"):
                    return v
            with open("/sys/class/dmi/id/product_uuid", "r") as f:
                return f.read().strip()
        elif sys == "Darwin":
            out = subprocess.check_output(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                stderr=subprocess.DEVNULL, timeout=2,
            ).decode()
            for line in out.splitlines():
                if "IOPlatformSerialNumber" in line:
                    return line.split('"')[-2]
        elif sys == "Windows":
            out = subprocess.check_output(
                ["wmic", "baseboard", "get", "SerialNumber", "/value"],
                stderr=subprocess.DEVNULL, timeout=5,
            ).decode().strip()
            for line in out.splitlines():
                if line.startswith("SerialNumber="):
                    return line.split("=", 1)[1].strip()
    except Exception:
        pass
    return "unknown_board"


# ---------------------------------------------------------------------------
# GPU UUID (NVIDIA)
# ---------------------------------------------------------------------------


def _gpu_uuid() -> Optional[str]:
    """NVIDIA GPU UUID when available. None when not NVIDIA or pynvml fails."""
    try:
        import pynvml
        pynvml.nvmlInit()
        handle = pynvml.nvmlDeviceGetHandleByIndex(0)
        uuid = pynvml.nvmlDeviceGetUUID(handle)
        if isinstance(uuid, bytes):
            uuid = uuid.decode()
        return uuid
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Final fingerprint
# ---------------------------------------------------------------------------


def collect_fingerprint() -> tuple[str, Optional[str]]:
    """Return (machine_fingerprint sha256-hex, gpu_uuid or None).

    Deterministic: same machine ⇒ same fingerprint every run.
    Component values are logged at DEBUG for troubleshooting.
    """
    parts = {
        "cpu_model": _cpu_model(),
        "cpu_count": str(_cpu_count()),
        "ram_gb": str(_total_ram_gb()),
        "mac": _primary_mac(),
        "disk": _root_disk_uuid(),
        "board": _board_serial(),
    }
    log.debug("fingerprint.parts %s", parts)

    serialized = "|".join(f"{k}={v}" for k, v in sorted(parts.items()))
    fp = hashlib.sha256(serialized.encode()).hexdigest()

    gpu = _gpu_uuid()
    if gpu:
        log.info("hardware fingerprint=%s... gpu_uuid=%s", fp[:16], gpu)
    else:
        log.info("hardware fingerprint=%s... gpu_uuid=none", fp[:16])
    return fp, gpu
