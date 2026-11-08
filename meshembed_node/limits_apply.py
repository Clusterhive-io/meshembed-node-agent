"""IO-CAP (docs/DESIGN_IO_CAP_2026-10-31.md; auditor DESIGN GO 2026-10-31 17:35Z, IC-1..IC-7; early read 18:56Z,
IOA-1..IOA-6 + N1..N5): the ROOT limits applier.

Same privilege split as serve_launch: the unprivileged daemon only REQUESTS, by writing the effective IO/cgroup keys it
received to `$SVC_HOME/.meshembed/limits-request`; systemd (meshembed-limits-apply.path, plus a 30 s safety timer)
runs this module as root with a fixed argv. Nothing the daemon wrote is trusted:

  {"limits": {"io_read_mbps": 50, "io_class": "idle", "memory_max_gb": 8, ...}}   -- the closed IO-CAP keys only

- IC-4: the request is read like serve_launch's (O_NOFOLLOW, regular file, owner uid, size cap, truncated on read);
  every key is re-validated against the COMPILED-IN floors (auditor Q1: the only floors used here).
- IC-5: the disk to cap is resolved ONLY from two compiled-in paths (the request file in the owner's data dir from
  passwd, and /srv/mesh-di/models), st_dev -> /sys/dev/block, a partition -> its disk. Unresolvable =
  "device_unresolved", never a fallback device.
- IC-1: per unit and key, the value written is the TIGHTER of the request, every other source of that unit and
  /etc/meshembed-node/limits.local. The sources are the files systemd ITSELF lists for the unit (FragmentPath +
  DropInPaths: prefix and type drop-ins included, IOA-3), minus this applier's own drop-in and the runtime layer. A
  value it cannot compare, or a legacy key of a managed family (MemoryLimit=, BlockIO*=), = that key is not set
  ("existing_unreadable"). Per-device keys keep every other device's entries (IOA-1).
- IC-2: it writes its own 99-limits.conf FIRST (O_EXCL|O_NOFOLLOW temp + rename; it sorts LAST, and holds the tighter
  of every source, so nothing read after it can loosen it: N3), then `systemctl set-property --runtime` with the
  values in force, then reads them back (`systemctl show`; a mismatch = "overridden"). Never plain set-property, never
  `systemctl revert`, never another file. A drop-in change by anyone triggers a reconcile (the installer's second
  .path unit), so a later tighter source is honoured at once.
- IC-3: memory_max AND memory_high (IOA-2) are refused below the unit's host floor (a serve unit: its model files in
  /srv/mesh-di/models + 1 GiB; meshembed-node: a compiled-in minimum), and below memory.current + 512 MiB while the
  unit runs.
- io_class sets IOWeight, which only acts under BFQ or blk-iocost: on any other disk it is refused "not_effective",
  never reported in force (IOA-6).
- Loosening asked by the REQUEST is rate-limited root-side (one per 60 s); tightening never is, and neither is a
  reconcile after a root-side source changed (N2). An untrusted or unreadable limits.local blocks every loosening,
  never a tightening ("limits_local_invalid", Q2/IOA-5).
- IC-7: the result (keys in force, keys refused with closed codes) goes to a 0644 result.json the daemon reports in
  its heartbeat as `limits_applied`. It names the request it answers (IOB-3: `request_sha256` of the canonical
  request, the same bytes the daemon wrote) and the sources it read (IOB-1a: `sources`, unit -> path -> sha256), so
  the daemon reports only its own request and the serve launcher can prove a pass read its new 20-owner.conf.
- IOB-4 / IOA-N7: run() and reconcile() (two units that systemd may run at once; the installer and the serve
  launcher start the reconcile unit, never this module in-process) hold one flock on the state dir's lock file, so
  their read-modify-writes of applied.json and the drop-ins never interleave.
- IOA-N6: a hand cap on a managed unit belongs in a drop-in (honoured as a source); a hand
  `systemctl set-property --runtime` on it is overwritten by this applier's own runtime values and not seen.
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import math
import os
import pwd
import re
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .serve_launch import MAX_ROUNDS, _read_json, _write_nf
from .split_launch import _ENV, ROOT_UID, Refused, read_request

UNITS_MANAGED = ("meshembed-node", "meshembed-serve", "meshembed-serve-nodraft")
SERVE_UNITS = ("meshembed-serve", "meshembed-serve-nodraft")
DROPIN = "99-limits.conf"
UNITS_DIR = Path("/etc/systemd/system")                   # where this applier's own drop-in lives
RUNTIME_CONTROL = Path("/run/systemd/system.control")     # the --runtime layer this applier sets (IC-2)
LOCAL_CEILING = Path("/etc/meshembed-node/limits.local")
STATE_DIR = Path("/var/lib/meshembed-limits-apply")
MODELS = Path("/srv/mesh-di/models")
SERVE_ENV = Path("/etc/mesh-di/serve.env")
CGROUP_ROOT = Path("/sys/fs/cgroup")
SYS_BLOCK = Path("/sys/dev/block")

# The compiled-in ABSOLUTE floors (auditor Q1; the backend's fixed floors, backend/app/node_limits.py).
FLOOR = {"io_read_mbps": 20, "io_read_iops": 200, "io_write_mbps": 10, "io_write_iops": 100, "cpu_quota_pct": 25}
MAX = {"io_read_mbps": 100_000, "io_write_mbps": 100_000, "io_read_iops": 10_000_000, "io_write_iops": 10_000_000,
       "cpu_quota_pct": 25_600}
MAX_GB = 4096.0
IO_CLASSES = ("normal", "low", "idle")
IO_WEIGHT = {"low": 50, "idle": 10}              # cgroup IOWeight (live); "normal" sets nothing
KEYS = ("io_read_mbps", "io_write_mbps", "io_read_iops", "io_write_iops", "io_class",
        "memory_high_gb", "memory_max_gb", "cpu_quota_pct")
NODE_MEMORY_MIN_MB = 2048                        # IC-3: meshembed-node (the daemon + an embedding model)
MODEL_HEADROOM_MB = 1024
LIVE_HEADROOM_MB = 512
LOOSEN_MIN_INTERVAL_S = 60
LOCK_WAIT_S = 60                                 # < the units' TimeoutStartSec=120
MiB = 1 << 20

# key -> (systemd property, kind). "dev" properties are per device ("<dev> <value>"), the others single-valued.
PROPS = {
    "io_read_mbps": ("IOReadBandwidthMax", "dev"),
    "io_write_mbps": ("IOWriteBandwidthMax", "dev"),
    "io_read_iops": ("IOReadIOPSMax", "dev"),
    "io_write_iops": ("IOWriteIOPSMax", "dev"),
    "io_class": ("IOWeight", "single"),
    "memory_high_gb": ("MemoryHigh", "single"),
    "memory_max_gb": ("MemoryMax", "single"),
    "cpu_quota_pct": ("CPUQuota", "single"),
}
PROPS_KIND = {p: k for p, k in PROPS.values()}
KEY_OF = {p: k for k, (p, _) in PROPS.items()}
# IOA-3: legacy keys systemd drops once the new key of the family is set; seeing one = that family is unreadable.
LEGACY = {"MemoryLimit": "MemoryMax", "BlockIOReadBandwidth": "IOReadBandwidthMax",
          "BlockIOWriteBandwidth": "IOWriteBandwidthMax", "BlockIOWeight": "IOWeight"}


# --- the request (IC-4) ---------------------------------------------------------------------------------------------
def canonical(obj: Any) -> bytes:
    """IOB-3: the ONE byte form of a request, written by the daemon (limits_client) and hashed here."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def request_sha256(obj: Any) -> str:
    return hashlib.sha256(canonical(obj)).hexdigest()


def _int(v: Any) -> Optional[int]:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    if isinstance(v, float) and (not math.isfinite(v) or not v.is_integer()):
        return None
    return int(v)


def parse_request(req: Any) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """(the valid wanted values in canonical units, refused key -> code). A malformed envelope is Refused whole.
    Canonical: bandwidth in bytes/s, IOPS as is, io_class as IOWeight, memory in MiB, CPU in %."""
    if not isinstance(req, dict) or set(req) != {"limits"} or not isinstance(req["limits"], dict):
        raise Refused("request_keys")
    lim = req["limits"]
    if not set(lim) <= set(KEYS):
        raise Refused("request_unknown_key")
    want: Dict[str, Any] = {}
    refused: Dict[str, str] = {}
    for k, v in lim.items():
        if v is None:
            continue
        if k == "io_class":
            if v not in IO_CLASSES:
                refused[k] = "invalid"
            elif v != "normal":
                want[k] = IO_WEIGHT[v]
            continue
        if k.startswith("memory_"):
            f = None if isinstance(v, bool) or not isinstance(v, (int, float)) else float(v)
            if f is None or not math.isfinite(f) or f <= 0 or f > MAX_GB:
                refused[k] = "invalid"
            else:
                want[k] = int(f * 1024)
            continue
        n = _int(v)
        if n is None or n > MAX[k]:
            refused[k] = "invalid"
        elif n < FLOOR[k]:
            refused[k] = "below_floor"
        else:
            want[k] = n * MiB if k.endswith("_mbps") else n
    if "memory_high_gb" in want and "memory_max_gb" in want and want["memory_high_gb"] > want["memory_max_gb"]:
        refused["memory_high_gb"] = "above_memory_max"
        want.pop("memory_high_gb")
    return want, refused


# --- what every other source sets (IC-1, IOA-3) ----------------------------------------------------------------------
_SIZE = re.compile(r"^(\d+(?:\.\d+)?)([KMGT]?)$")
_UNIT = {"": 1, "K": 1 << 10, "M": 1 << 20, "G": 1 << 30, "T": 1 << 40}
# IOP-2 (IO-CAP proof 2026-11-01, P4): systemd reads IO*BandwidthMax and IO*IOPSMax suffixes to the base of 1000
# (systemd.resource-control); only the Memory* sizes are base 1024. An operator's "7M" bandwidth is 7000000.
_UNIT_1000 = {"": 1, "K": 10 ** 3, "M": 10 ** 6, "G": 10 ** 9, "T": 10 ** 12}


class Unreadable(Exception):
    pass


def _bytes(s: str, units: Dict[str, int] = _UNIT) -> int:
    m = _SIZE.match(s.strip())
    if not m:
        raise Unreadable(s)
    return int(float(m.group(1)) * units[m.group(2)])


def parse_value(prop: str, raw: str, dev_of: Callable[[str], Optional[str]]) -> Any:
    """A systemd value in canonical units, or None for "no limit" (infinity / empty); Unreadable when it cannot be
    compared safely (a percentage of RAM, an unknown unit, a device that cannot be resolved)."""
    raw = raw.strip()
    if prop in ("MemoryMax", "MemoryHigh"):
        if raw in ("", "infinity"):
            return None
        return _bytes(raw) // MiB
    if prop == "CPUQuota":
        if raw == "":
            return None
        if not raw.endswith("%"):
            raise Unreadable(raw)
        return int(float(raw[:-1]))
    if prop == "IOWeight":
        if raw == "":
            return None
        if not raw.isdigit():
            raise Unreadable(raw)
        return int(raw)
    parts = raw.split()                                       # per device: "<path> <value>"
    if len(parts) != 2:
        raise Unreadable(raw)
    dev = dev_of(parts[0])
    if dev is None:
        raise Unreadable(raw)
    if parts[1] == "infinity":
        return (dev, None)
    # IOP-2 / IOP-3: bandwidth AND IOPS take base-1000 suffixes ("7K" IOPS is valid systemd and used to raise
    # ValueError here, which crashed the whole pass and lost the request)
    return (dev, _bytes(parts[1], _UNIT_1000))


def systemctl_show(unit: str, props: List[str]) -> Optional[Dict[str, List[str]]]:
    """prop -> its value lines (a per-device property prints one line per entry), or None if systemctl failed."""
    try:
        out = subprocess.run(["systemctl", "show", f"{unit}.service", *(f"--property={p}" for p in props)],
                             env=_ENV, timeout=30, check=True, capture_output=True, encoding="utf-8").stdout
    except (OSError, subprocess.SubprocessError):
        return None
    d: Dict[str, List[str]] = {}
    for line in out.splitlines():
        k, sep, v = line.partition("=")
        if sep:
            d.setdefault(k, []).append(v)
    return d


def unit_sources(unit: str, show: Callable, units_dir: Path = UNITS_DIR) -> Optional[List[Path]]:
    """IOA-3: the files systemd applies to the unit, in its order (FragmentPath, then DropInPaths), minus this
    applier's own drop-in and the runtime layer it sets. None when systemd cannot say (fail closed)."""
    d = show(unit, ["FragmentPath", "DropInPaths"])
    if d is None:
        return None
    ours = units_dir / f"{unit}.service.d" / DROPIN
    paths = [p for p in ((d.get("FragmentPath") or [""])[0].split() + " ".join(d.get("DropInPaths") or []).split()) if p]
    return [Path(p) for p in paths
            if Path(p) != ours and not str(p).startswith(str(RUNTIME_CONTROL) + "/")]


def sources_digest(files: Optional[List[Path]]) -> Dict[str, str]:
    """IOB-1a: path -> sha256 of every source as read in this pass (an unreadable one is left out)."""
    out: Dict[str, str] = {}
    for f in files or []:
        try:
            out[str(f)] = hashlib.sha256(f.read_bytes()).hexdigest()
        except OSError:
            continue
    return out


def others_in_force(files: Optional[List[Path]], dev_of: Callable[[str], Optional[str]]) -> Dict[str, Any]:
    """prop -> the value set by every source but this applier: single props a value or None; device props a
    {dev: value} dict. A prop whose existing value cannot be read -> an Unreadable as its value."""
    out: Dict[str, Any] = {}
    if files is None:
        return {prop: Unreadable("sources_unknown") for prop in PROPS_KIND}
    for f in files:
        try:
            text = f.read_text(encoding="utf-8")
        except OSError:
            return {prop: Unreadable(str(f)) for prop in PROPS_KIND}
        section = None
        for line in text.splitlines():
            s = line.strip()
            if not s or s[0] in "#;":
                continue
            if s.startswith("["):
                section = s
                continue
            if section != "[Service]" or "=" not in s:
                continue
            key, raw = (x.strip() for x in s.split("=", 1))
            if key in LEGACY:
                out[LEGACY[key]] = Unreadable(key)
                continue
            kind = PROPS_KIND.get(key)
            if kind is None or isinstance(out.get(key), Unreadable):
                continue
            try:
                v = parse_value(key, raw, dev_of)
            except Unreadable as e:
                out[key] = e
                continue
            except Exception:                                 # IOP-3: ANY other parse error = that key unreadable
                out[key] = Unreadable(raw)
                continue
            if kind == "single":
                out[key] = v
            elif raw == "":
                out[key] = {}                                   # an empty assignment resets the list
            else:
                d = dict(out.get(key) or {})
                d[v[0]] = v[1]
                out[key] = d
    return out


def read_local_ceiling(path: Path = LOCAL_CEILING) -> Tuple[Dict[str, Any], Optional[str]]:
    """(the owner's ceilings, None) or ({}, "limits_local_invalid"). limits.local is optional (auditor Q2); it is
    trusted only when root-owned and not group/world writable. An invalid one blocks every loosening (the caller),
    never a tightening (IOA-5)."""
    try:
        st = os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        return {}, None
    if not stat.S_ISREG(st.st_mode) or st.st_uid != ROOT_UID or st.st_mode & 0o022:
        return {}, "limits_local_invalid"
    try:
        want, refused = parse_request({"limits": json.loads(path.read_text(encoding="utf-8"))})
    except (OSError, ValueError, Refused):
        return {}, "limits_local_invalid"
    return want, ("limits_local_invalid" if refused else None)


def tighter(a: Optional[int], b: Optional[int]) -> Optional[int]:
    """The tighter of two caps; None = no cap. For IOWeight, too, lower is tighter."""
    if a is None:
        return b
    if b is None:
        return a
    return min(a, b)


# --- devices (IC-5, IOA-6) ------------------------------------------------------------------------------------------
def _whole_disk(mm: str, sys_block: Path) -> Optional[str]:
    try:
        real = (sys_block / mm).resolve(strict=True)
    except OSError:
        return None
    if (real / "partition").exists():
        try:
            return (real.parent / "dev").read_text(encoding="ascii").strip()
        except OSError:
            return None
    return mm


def disk_of(path: Path, sys_block: Path = SYS_BLOCK) -> Optional[str]:
    """'MAJ:MIN' of the whole disk holding `path`, or None (a virtual or unknown device)."""
    try:
        dev = os.stat(path).st_dev
    except OSError:
        return None
    if os.major(dev) == 0:
        return None                                          # tmpfs, overlay, btrfs subvolume: no block device
    return _whole_disk(f"{os.major(dev)}:{os.minor(dev)}", sys_block)


def device_path_to_disk(p: str, sys_block: Path = SYS_BLOCK) -> Optional[str]:
    """For a device named in ANOTHER drop-in: its 'MAJ:MIN' (partitions mapped to the disk), or None."""
    try:
        st = os.stat(p)
    except OSError:
        return None
    if not stat.S_ISBLK(st.st_mode):
        return None
    return _whole_disk(f"{os.major(st.st_rdev)}:{os.minor(st.st_rdev)}", sys_block)


def weight_effective(disks: List[str], sys_block: Path = SYS_BLOCK, cgroup_root: Path = CGROUP_ROOT) -> bool:
    """IOA-6: IOWeight acts only under BFQ or with blk-iocost enabled; every resolved disk must have one of them."""
    if not disks:
        return False
    try:
        qos = (cgroup_root / "io.cost.qos").read_text(encoding="ascii")
    except OSError:
        qos = ""
    on = {ln.split()[0] for ln in qos.splitlines() if " enable=1" in f" {ln}"}
    for d in disks:
        try:
            sched = (sys_block / d / "queue" / "scheduler").read_text(encoding="ascii")
        except OSError:
            sched = ""
        if "[bfq]" not in sched and d not in on:
            return False
    return True


# --- the host floors (IC-3) -------------------------------------------------------------------------------------------
def serve_floor_mb(env: Path = SERVE_ENV, models: Path = MODELS) -> Optional[int]:
    """The serve plan in force: its model files (root-owned, under /srv/mesh-di/models) + 1 GiB, or None when it
    cannot be read (then memory caps are refused for the serve units: "floor_unknown")."""
    try:
        text = env.read_text(encoding="utf-8")
    except OSError:
        return None
    total = 0
    for line in text.splitlines():
        k, _, v = line.partition("=")
        if k not in ("MODEL", "DRAFT_MODEL"):
            continue
        p = Path(v.strip())
        if p.parent != models:
            return None
        try:
            st = os.stat(p, follow_symlinks=False)
        except OSError:
            return None
        if not stat.S_ISREG(st.st_mode) or st.st_uid != ROOT_UID:
            return None
        total += st.st_size
    return (total // MiB + MODEL_HEADROOM_MB) if total else None


def memory_current_mb(unit: str, cgroup_root: Path = CGROUP_ROOT) -> Optional[int]:
    try:
        return int((cgroup_root / "system.slice" / f"{unit}.service" / "memory.current").read_text(encoding="ascii").strip()) // MiB
    except (OSError, ValueError):
        return None


# --- the plan for one unit -------------------------------------------------------------------------------------------
def plan_unit(want: Dict[str, Any], local: Dict[str, Any], others: Dict[str, Any], disks: List[str], *,
              memory_floor_mb: Optional[int], memory_now_mb: Optional[int],
              weight_ok: bool) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """(prop -> value to write: single props an int, device props {disk: value}; refused key -> code)."""
    out: Dict[str, Any] = {}
    refused: Dict[str, str] = {}
    for key, value in want.items():
        prop, kind = PROPS[key]
        other = others.get(prop)
        if isinstance(other, Unreadable):
            refused[key] = "existing_unreadable"
            continue
        if key in ("memory_max_gb", "memory_high_gb"):          # IOA-2: both memory caps take the host floors
            if memory_floor_mb is None:
                refused[key] = "floor_unknown"
                continue
            if value < memory_floor_mb:
                refused[key] = "below_floor"
                continue
            if memory_now_mb is not None and value < memory_now_mb + LIVE_HEADROOM_MB:
                refused[key] = "below_current_usage"
                continue
        if key == "io_class" and not weight_ok:
            refused[key] = "not_effective"
            continue
        v = tighter(value, local.get(key))
        if kind == "single":
            out[prop] = tighter(v, other)
            continue
        if not disks:
            refused[key] = "device_unresolved"
            continue
        merged = dict(other or {})                              # IOA-1: every other device's entry stays
        merged.update({d: tighter(v, (other or {}).get(d)) for d in disks})
        out[prop] = merged
    return out, refused


def dropin_text(props: Dict[str, Any]) -> str:
    lines = ["# IO-CAP limits (written by meshembed_node.limits_apply; the tighter of the request, every other",
             "# source of this unit and limits.local -- edit those, not this file)", "[Service]"]
    for prop in sorted(props):
        lines += _assignments(prop, props[prop])
    return "\n".join(lines) + "\n"


def _assignments(prop: str, v: Any) -> List[str]:
    if isinstance(v, dict):
        return [f"{prop}=/dev/block/{d} {_fmt(prop, x)}" for d, x in sorted(v.items())]
    return [f"{prop}={_fmt(prop, v)}"]


def _fmt(prop: str, v: Optional[int]) -> str:
    if v is None:
        return "infinity" if prop in ("MemoryMax", "MemoryHigh") or prop.endswith("Max") else ""
    if prop in ("MemoryMax", "MemoryHigh"):
        return f"{v}M"
    if prop == "CPUQuota":
        return f"{v}%"
    return str(v)


def runtime_args(managed: Dict[str, Any], others: Dict[str, Any], props_before: List[str]) -> List[str]:
    """IC-2: the --runtime assignments. A prop this applier sets gets its written value (device lists already carry
    every other device's entry, IOA-1); a prop it set before and no longer does gets the value now in force from the
    other sources (never a bare reset that would hide them). The caller never passes an Unreadable here (IOA-4)."""
    args: List[str] = []
    for prop in sorted(set(managed) | set(props_before)):
        v = managed[prop] if prop in managed else others.get(prop)
        if PROPS_KIND[prop] == "dev":
            args.append(f"{prop}=")                           # reset the runtime list, then every entry in force
            args += _assignments(prop, v or {})
        else:
            args.append(f"{prop}={_fmt(prop, v)}" if v is not None else f"{prop}=")
    return args


# --- the readback (N3) ------------------------------------------------------------------------------------------------
_SPAN = {"us": 1, "ms": 1000, "s": 1_000_000, "min": 60_000_000}


def _usec(s: str) -> Optional[int]:
    if s in ("", "infinity"):
        return None
    total = 0
    for num, unit in re.findall(r"(\d+(?:\.\d+)?)(us|ms|min|s)", s):
        total += int(float(num) * _SPAN[unit])
    return total


def readback_mismatch(props: Dict[str, Any], shown: Optional[Dict[str, List[str]]]) -> List[str]:
    """The props whose value in force (systemctl show) is not what this applier set; all of them when unknown."""
    if shown is None:
        return sorted(props)
    bad = []
    for prop, v in props.items():
        if prop == "CPUQuota":
            got = _usec((shown.get("CPUQuotaPerSecUSec") or [""])[0])
            ok = got == v * 10_000
        elif prop in ("MemoryMax", "MemoryHigh"):
            raw = (shown.get(prop) or [""])[0]
            ok = raw.isdigit() and int(raw) == v * MiB
        elif prop == "IOWeight":
            ok = (shown.get(prop) or [""])[0] == str(v)
        else:
            entries = {}
            for line in shown.get(prop) or []:
                parts = line.split()
                if len(parts) == 2 and parts[0].startswith("/dev/block/"):
                    entries[parts[0][len("/dev/block/"):]] = parts[1]
            ok = all(entries.get(d) == str(x) for d, x in v.items() if x is not None)
        if not ok:
            bad.append(prop)
    return bad


# --- one pass ---------------------------------------------------------------------------------------------------------
def _looser(prop: str, new: Any, old: Any) -> bool:
    """True when `new` lets the unit use more than `old` (a removed cap is looser than any cap)."""
    if isinstance(old, dict) or isinstance(new, dict):
        o, n = old or {}, new or {}
        return any(_looser(prop, n.get(d), o.get(d)) for d in set(o) | set(n))
    if old is None:
        return False
    return new is None or new > old


def _refuse(refused: Dict[str, str], in_force: set, key: str, code: str,
            per_unit: Optional[Dict[str, str]] = None) -> None:
    """The top-level result: a key is in_force only if it is in force on EVERY managed unit, and refused if it is
    refused on ANY (first code wins). IOP-1: per_unit keeps the unit's own view, reported under result["units"]."""
    refused.setdefault(key, code)
    in_force.discard(key)
    if per_unit is not None:
        per_unit.setdefault(key, code)


def run_once(request: Path, owner: str, *, state: Path = STATE_DIR, now: Optional[float] = None,
             units_dir: Path = UNITS_DIR, systemctl: Optional[Callable] = None, show: Callable = systemctl_show,
             local_path: Path = LOCAL_CEILING, models: Path = MODELS, serve_env: Path = SERVE_ENV,
             cgroup_root: Path = CGROUP_ROOT, disk_of_fn: Callable[[Path], Optional[str]] = disk_of,
             dev_of: Callable[[str], Optional[str]] = device_path_to_disk,
             weight_ok_fn: Callable[[List[str]], bool] = weight_effective,
             req_obj: Optional[Dict[str, Any]] = None, rate_limit: bool = True,
             loosen_interval_s: int = LOOSEN_MIN_INTERVAL_S) -> str:
    now = time.time() if now is None else now
    systemctl = systemctl or (lambda *a: subprocess.run(["systemctl", *a], env=_ENV, timeout=120,
                                                        check=True, capture_output=True))
    pw = pwd.getpwnam(owner)
    state.mkdir(mode=0o755, parents=True, exist_ok=True)
    prev = _read_json(state / "applied.json")                 # what this applier set last time, per unit
    req: Any = None
    sources: Dict[str, Dict[str, str]] = {}
    try:
        req = read_request(request, pw.pw_uid) if req_obj is None else req_obj
        if req is None:
            return "no_request"
        want, refused = parse_request(req)
        local, local_bad = read_local_ceiling(local_path)
        # IC-5: the data dir is the request's own directory (argv, fixed by the installer from passwd); the unit's
        # ProtectHome=yes hides everything of /home but the bind-mounted request file, so it is stat'ed by that file.
        data = request if req_obj is None else Path(pw.pw_dir) / ".meshembed" / "limits-request"
        disks = sorted({d for d in (disk_of_fn(data), disk_of_fn(models)) if d})
        weight_ok = weight_ok_fn(disks)
        applied: Dict[str, Any] = {}
        runtime: Dict[str, List[str]] = {}
        in_force: set = set(want)
        unit_refused: Dict[str, Dict[str, str]] = {}           # IOP-1: per unit, beside the aggregated view
        parked = False
        for unit in UNITS_MANAGED:
            files = unit_sources(unit, show, units_dir)
            if files is not None and not files:
                continue                                      # systemd knows no such unit here
            sources[unit] = sources_digest(files)
            others = others_in_force(files, dev_of)
            floor = serve_floor_mb(serve_env, models) if unit in SERVE_UNITS else NODE_MEMORY_MIN_MB
            props, ref = plan_unit(want, local, others, disks, memory_floor_mb=floor,
                                   memory_now_mb=memory_current_mb(unit, cgroup_root), weight_ok=weight_ok)
            per = unit_refused.setdefault(unit, {})
            for k, code in ref.items():
                _refuse(refused, in_force, k, code, per)
            before = dict((prev.get("units") or {}).get(unit) or {})
            # IOA-4: a prop set before whose other sources are now unreadable keeps this applier's previous value
            for p in [p for p in before if p not in props and isinstance(others.get(p), Unreadable)]:
                props[p] = before[p]
                _refuse(refused, in_force, KEY_OF[p], "existing_unreadable", per)
            for p in [p for p in props if isinstance(props[p], dict)]:
                props[p] = {d: x for d, x in props[p].items()}
            loosens = [p for p in set(props) | set(before) if _looser(p, props.get(p), before.get(p))]
            if loosens and local_bad:                         # IOA-5: a bad limits.local blocks loosening only
                for p in loosens:
                    if p in before:
                        props[p] = before[p]
                    _refuse(refused, in_force, KEY_OF[p], local_bad, per)
                loosens = []
            if loosens and rate_limit and 0 <= now - float(prev.get("last_loosen") or 0) < loosen_interval_s:
                for p in loosens:                             # keep the old (tighter) value for now; retry later
                    if p in before:
                        props[p] = before[p]
                    # IOB-6: the old cap is still in force, so the result names it (a parked clear included)
                    _refuse(refused, in_force, KEY_OF[p], "loosen_parked", per)
                parked = True
            d = units_dir / f"{unit}.service.d"
            d.mkdir(mode=0o755, exist_ok=True)
            text = dropin_text(props)
            try:
                same = (d / DROPIN).read_text(encoding="utf-8") == text
            except OSError:
                same = False
            if not same:                                      # IC-2: the drop-in FIRST; untouched when unchanged
                _write_nf(d / DROPIN, text, 0o644)
                systemctl("daemon-reload")
            # IOP-2: also every prop this applier set at RUNTIME before (it may have copied another source's entries
            # there); re-deriving it from the sources now resets a copy whose source is gone. A prop whose other
            # sources are unreadable is left as it is (IOA-4: never a bad arg).
            rt_before = {a.partition("=")[0] for a in ((prev.get("runtime") or {}).get(unit) or [])}
            rt_before = {q for q in rt_before if q in PROPS_KIND and q not in props
                         and not isinstance(others.get(q), Unreadable)}
            args = runtime_args(props, others, sorted(set(before) | rt_before))
            if args and (not same or (prev.get("runtime") or {}).get(unit) != args):
                systemctl("set-property", "--runtime", f"{unit}.service", *args)
            runtime[unit] = args
            for p in readback_mismatch({p: v for p, v in props.items() if v is not None},
                                       show(unit, [*(q for q in props if q != "CPUQuota"), "CPUQuotaPerSecUSec"])
                                       if props else {}):
                _refuse(refused, in_force, KEY_OF[p], "overridden", per)
            applied[unit] = props
        if not applied:                                       # no managed unit on this host: nothing is in force
            for k in list(in_force):
                _refuse(refused, in_force, k, "no_unit")
        loosened = any(_looser(p, applied.get(u, {}).get(p), ((prev.get("units") or {}).get(u) or {}).get(p))
                       for u in applied for p in set(applied[u]) | set(((prev.get("units") or {}).get(u) or {})))
        _write_nf(state / "applied.json", json.dumps({
            "units": applied, "runtime": runtime,
            "last_loosen": now if (loosened and rate_limit) else prev.get("last_loosen", 0),
            # N2: reconcile replays the last request APPLIED in full, never a parked loosening
            "request": prev.get("request") if parked else req,
        }, sort_keys=True), 0o600)
        if parked:
            _write_nf(state / "pending.json", json.dumps(req, sort_keys=True), 0o600)
        elif req_obj is None or rate_limit:
            try:
                os.unlink(state / "pending.json")
            except FileNotFoundError:
                pass
        code = "parked:loosen_rate_limited" if parked else "applied"
        result = {"in_force": sorted(in_force), "refused": refused, "at": int(now), "result": code,
                  # IOP-1: what is in force / refused on EACH unit (the top level aggregates: in force on every
                  # managed unit / refused on any)
                  # IOP-1b: in force on a unit = written there (props) AND not refused by the same read-back
                  # ("overridden") or any other code; requested-and-not-refused alone is not enough
                  "units": {u: {"in_force": sorted(k for k in want if k not in r and PROPS[k][0] in applied[u]),
                                "refused": r}
                            for u, r in unit_refused.items() if u in applied}}
    except Refused as exc:
        code = f"refused:{exc}"
        result = {"in_force": [], "refused": {}, "at": int(now), "result": code}
    except subprocess.SubprocessError:                       # CalledProcessError, TimeoutExpired
        code = "systemctl_failed"
        result = {"in_force": [], "refused": {}, "at": int(now), "result": code}
    except OSError:                                           # IOB-1: a closed code, never a traceback
        code = "refused:io_error"
        result = {"in_force": [], "refused": {}, "at": int(now), "result": code}
    except Exception as exc:                                  # IOP-3: an unknown error never loses a request
        import traceback
        traceback.print_exc()                                 # to the unit's journal (caps and paths, no secrets)
        code = f"error:{type(exc).__name__}"
        # IOP-3b: the caps of the last good pass are still in force; never report [] (= "nothing capped") after a
        # failure. Carry the last result's view, marked stale; with no previous state, in force is unknown (null).
        last = _read_json(state / "result.json")
        if isinstance(last.get("in_force"), list) and not str(last.get("result", "")).startswith("error:"):
            result = {"in_force": last["in_force"], "refused": last.get("refused") or {},
                      "units": last.get("units") or {}, "at": int(now), "result": code, "stale": True}
        elif last.get("stale") is True:
            result = {**last, "at": int(now), "result": code}
        else:
            result = {"in_force": None, "refused": {}, "at": int(now), "result": code, "stale": True}
        if req is not None and req_obj is None:               # read (and truncated) by this pass: keep it root-side
            try:                                              # for the next pass, as a rate-limited one is kept
                _write_nf(state / "pending.json", json.dumps(req, sort_keys=True), 0o600)
            except OSError:
                pass
    result["request_sha256"] = request_sha256(req) if req is not None else None
    result["sources"] = sources
    _write_result(state, result)
    return code


def _write_result(state: Path, result: Dict[str, Any]) -> None:
    try:
        _write_nf(state / "result.json", json.dumps(result, sort_keys=True), 0o644)
    except OSError:
        pass                                                  # the daemon then reports nothing in force (IC-7)


@contextlib.contextmanager
def _locked(state: Path, wait_s: float = LOCK_WAIT_S):
    """IOB-4 / IOA-N7: one pass at a time across the apply unit and the reconcile unit (and a hand --reconcile).
    Yields False when the lock was not got within wait_s (the caller then changes nothing)."""
    state.mkdir(mode=0o755, parents=True, exist_ok=True)
    fd = os.open(str(state / "lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        start = time.monotonic()
        deadline = start + wait_s
        waited = False
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if not waited:                                # P9 (IO-CAP proof): the serialization is visible
                    print("limits_apply: lock busy, waiting", file=sys.stderr, flush=True)
                    waited = True
                if time.monotonic() >= deadline:
                    yield False
                    return
                time.sleep(0.2)
        if waited:
            print(f"limits_apply: lock acquired after {time.monotonic() - start:.1f}s", file=sys.stderr, flush=True)
        yield True
    finally:
        os.close(fd)                                          # closing the fd releases the lock


def reconcile(owner: str, *, state: Path = STATE_DIR, systemctl: Optional[Callable] = None, **kw) -> str:
    """Re-apply the last request applied in full against the sources as they are NOW (N2: not rate-limited; the
    change came from a root-side source). Run in its OWN unit, meshembed-limits-reconcile.service (IOB-1: never
    in-process in another unit's sandbox): started by the serve launcher after it rewrites a serve unit's
    20-owner.conf and before it restarts the unit, by any drop-in change (the installer's reconcile .path), and by
    the installer after it rewrote the units. A daemon-reload first, so systemd lists a drop-in written since the
    last one. Every pass that got the lock writes result.json, including "no_request" (with its sources, IOB-1a)."""
    systemctl = systemctl or (lambda *a: subprocess.run(["systemctl", *a], env=_ENV, timeout=120,
                                                        check=True, capture_output=True))
    with _locked(state, kw.pop("lock_wait_s", LOCK_WAIT_S)) as got:
        if not got:
            return "refused:lock_busy"
        now = kw.pop("now", None)
        now = time.time() if now is None else now
        try:
            systemctl("daemon-reload")
        except (subprocess.SubprocessError, OSError):
            _write_result(state, {"in_force": [], "refused": {}, "at": int(now), "result": "systemctl_failed",
                                  "request_sha256": None, "sources": {}})
            return "systemctl_failed"
        last = _read_json(state / "applied.json").get("request")
        if not isinstance(last, dict):
            # IOB-1a: even with nothing to re-apply, say which sources this pass saw (the serve launcher checks its
            # new 20-owner.conf against them)
            show = kw.get("show", systemctl_show)
            units_dir = kw.get("units_dir", UNITS_DIR)
            _write_result(state, {"in_force": [], "refused": {}, "at": int(now), "result": "no_request",
                                  "request_sha256": None,
                                  "sources": {u: sources_digest(f) for u in UNITS_MANAGED
                                              for f in [unit_sources(u, show, units_dir)] if f}})
            return "no_request"
        return run_once(Path("/nonexistent"), owner, state=state, req_obj=last, rate_limit=False,
                        systemctl=systemctl, now=now, **kw)


def run(request: Path, owner: str, *, state: Path = STATE_DIR, max_rounds: int = MAX_ROUNDS, **kw) -> str:
    """F-3 pattern: handle requests until the file is empty, then a parked (rate-limited) request."""
    with _locked(state, kw.pop("lock_wait_s", LOCK_WAIT_S)) as got:
        if not got:
            return "refused:lock_busy"                        # the request stays in its file for the next run
        last = "no_request"
        for _ in range(max_rounds):
            code = run_once(request, owner, state=state, **kw)
            if code == "no_request":
                parked = _read_json(state / "pending.json")
                if parked:
                    last = run_once(request, owner, state=state, req_obj=parked, **kw)
                break
            last = code
        return last


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="meshembed_node.limits_apply")
    ap.add_argument("--request", required=True)
    ap.add_argument("--owner", required=True)
    ap.add_argument("--reconcile", action="store_true", help="re-apply the last request (installer, serve launcher)")
    a = ap.parse_args(argv)
    if os.geteuid() != 0:
        print("limits_apply: must run as root (meshembed-limits-apply.service)")
        return 2
    from .path_heal import drift
    bad = drift()                    # HT-5 at start (auditor 2026-11-03 14:06:46Z): the fourth root entry point (v0.3.82)
    if bad:
        print(f"limits_apply: refused venv_drift {bad}")
        return 3
    code = reconcile(a.owner) if a.reconcile else run(Path(a.request), a.owner)
    print(f"limits_apply: {code}")
    return 1 if code.startswith("error:") else 0                  # IOP-3: a failed pass fails its unit, visibly


if __name__ == "__main__":
    raise SystemExit(main())
