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


_GENERIC_DMI_VALUES = {
    "", "None", "Default string", "Not Specified", "Not Available",
    "0", "00000000-0000-0000-0000-000000000000", "To Be Filled By O.E.M.",
    "System Serial Number", "System manufacturer", "System Product Name",
}


def _is_vm() -> bool:
    """Detect virtualization. Linux: systemd-detect-virt or DMI vendor.
    macOS + Windows: VMs are rare for our use case; return False (we
    treat them as bare metal). Returns True iff confident the host is a
    VM; False otherwise.
    """
    sys = platform.system()
    if sys != "Linux":
        return False
    try:
        out = subprocess.check_output(
            ["systemd-detect-virt"], stderr=subprocess.DEVNULL, timeout=2,
        ).decode().strip()
        if out and out != "none":
            return True
    except Exception:
        pass
    try:
        with open("/sys/class/dmi/id/sys_vendor", "r") as f:
            v = f.read().strip().lower()
            if any(s in v for s in ("qemu", "vmware", "kvm", "xen", "innotek", "microsoft corporation", "amazon ec2", "google", "oracle")):
                return True
    except Exception:
        pass
    return False


def _persistent_instance_id() -> str:
    """A daemon-generated UUID stored under ~/.meshembed/instance_id.

    Persists across daemon restarts. Survives package upgrades. Gets
    rotated only when the operator explicitly resets the daemon
    directory (which the backend already treats as a re-enrollment).

    Used as the strong identifier on VMs where DMI fields lie or are
    shared across clones. Bare-metal hosts also get one (cheap, no
    downside, gives a stable identity even if hardware swaps a NIC).
    """
    import os
    import pathlib
    import uuid
    p = pathlib.Path.home() / ".meshembed" / "instance_id"
    if p.is_file():
        existing = p.read_text(encoding="utf-8").strip()
        if existing:
            return existing
    new_id = uuid.uuid4().hex
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(new_id, encoding="utf-8")
        # 0600 -- only the daemon user can read/replace.
        os.chmod(p, 0o600)
    except Exception:
        # Fall back to ephemeral if we can't persist (read-only FS,
        # permission issue). The fingerprint then changes on next boot,
        # which the backend logs as a re-enrollment.
        pass
    return new_id


def _board_serial() -> str:
    """Returns the most stable, most unique identifier available.

    Order of preference:
      1. On Linux: DMI product_uuid (per-VM unique on most hypervisors).
      2. Fall back to DMI board_serial.
      3. On macOS: IOPlatformSerialNumber.
      4. On Windows: wmic baseboard SerialNumber.

    Generic / hypervisor-default values (e.g. "Default string") are
    filtered. The mixing with `_persistent_instance_id()` upstream in
    `collect_fingerprint()` is what actually guarantees uniqueness on
    cloned VMs -- this function alone is unreliable on VMs.
    """
    sys = platform.system()
    try:
        if sys == "Linux":
            # Try product_uuid FIRST -- it's more reliable on VMs.
            try:
                with open("/sys/class/dmi/id/product_uuid", "r") as f:
                    v = f.read().strip()
                    if v and v not in _GENERIC_DMI_VALUES:
                        return v
            except Exception:
                pass
            with open("/sys/class/dmi/id/board_serial", "r") as f:
                v = f.read().strip()
                if v and v not in _GENERIC_DMI_VALUES:
                    return v
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


def collect_fingerprint() -> tuple[str, Optional[str], bool]:
    """Return (machine_fingerprint sha256-hex, gpu_uuid or None, is_vm).

    Deterministic on a given host: same machine -> same fingerprint
    every run. The persistent instance_id (~/.meshembed/instance_id)
    is the strongest component on VMs and clones, because DMI fields
    are unreliable in those environments. Bare-metal hosts also get
    one -- cheap, gives a stable identity even when hardware swaps
    out a NIC or disk.

    The `is_vm` boolean tells the backend that this fingerprint is
    drawn from a VM, so policy can adapt (e.g., require mTLS for VMs,
    or refuse to grant premium-tier nodes that are VMs).

    Updated 2026-05-22 (was 2-tuple before; backend now reads 3-tuple).
    Callers that still expect the 2-tuple shape get a `tuple` and
    unpack the first two -- Python tolerates this if they use
    `fp, gpu, *_ = collect_fingerprint()` or two-target unpacking
    via `fp, gpu = collect_fingerprint()[:2]`. The main call site
    (config.py) has been updated to read all three.
    """
    is_vm = _is_vm()
    parts = {
        "cpu_model": _cpu_model(),
        "cpu_count": str(_cpu_count()),
        "ram_gb": str(_total_ram_gb()),
        "mac": _primary_mac(),
        "disk": _root_disk_uuid(),
        "board": _board_serial(),
        "instance_id": _persistent_instance_id(),
        "is_vm": "1" if is_vm else "0",
    }
    log.debug("fingerprint.parts %s", parts)

    serialized = "|".join(f"{k}={v}" for k, v in sorted(parts.items()))
    fp = hashlib.sha256(serialized.encode()).hexdigest()

    gpu = _gpu_uuid()
    if gpu:
        log.info(
            "hardware fingerprint=%s... gpu_uuid=%s is_vm=%s",
            fp[:16], gpu, is_vm,
        )
    else:
        log.info(
            "hardware fingerprint=%s... gpu_uuid=none is_vm=%s",
            fp[:16], is_vm,
        )
    return fp, gpu, is_vm
