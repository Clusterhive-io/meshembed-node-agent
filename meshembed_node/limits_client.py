"""IO-CAP, the daemon's half (docs/DESIGN_IO_CAP_2026-10-31.md): hand the effective IO/cgroup keys to whatever this OS
can apply them with, and say what is in force.

- Linux with the root applier installed (/var/lib/meshembed-limits-apply exists): the keys are written to
  ~/.meshembed/limits-request (0600, ours) ONLY when they change, and the applier's result.json is reported. The
  daemon applies nothing itself there.
- Windows and macOS: io_class by the process's own IO priority (Windows PROCESS_MODE_BACKGROUND_BEGIN, macOS
  setiopolicy_np); every other key is reported "not_supported", never silently ignored.
- Linux without the applier (a user install): every key is "applier_not_installed".

report() is the heartbeat's `limits_applied` (closed key names and codes), or None when no IO-CAP key is set. Only a
result for THIS request is reported: the applier names the sha256 of the canonical request it processed, and it must
equal the sha256 of the bytes written here (IOB-3; IC-7: a dead applier, or a result for another request, must not
look in force).
- IOB-2: what was handed over lives in memory, so after a restart the first sync on Linux writes the current want
  once, even empty, whenever the applier's last result names a request other than the empty one (a cap cleared
  while the daemon was down is cleared, not left in force unreported).
- IOB-6: a clear is a loosening, so it can be parked or refused while the old caps stay in force. report() then
  still reports: it returns None only before anything was handed over, and it passes on the applier's own lists
  (a held cap comes back refused "loosen_parked" / "limits_local_invalid"). A whole refusal names every key that may
  still be in force (_held), not only the ones requested. A clear that IS applied reports empty lists, so the
  backend's stored report is replaced, never left saying "held".
- IOB-4: sync() and report() run under one lock (the primary poll and the heartbeat thread both call sync(); both
  pass the backend's one effective_limits(), IC-6).
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import stat
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

log = logging.getLogger("meshembed_node.limits")

KEYS = ("io_read_mbps", "io_write_mbps", "io_read_iops", "io_write_iops", "io_class",
        "memory_high_gb", "memory_max_gb", "cpu_quota_pct")
REQUEST = Path.home() / ".meshembed" / "limits-request"
APPLIER_STATE = Path("/var/lib/meshembed-limits-apply")
RESULT_MAX_BYTES = 16 * 1024
_CODE = re.compile(r"^[a-z_]{1,40}$")

_last_sent: Optional[Dict[str, Any]] = None     # what this process last handed over
_sent_sha = ""                                   # IOB-3: sha256 of the bytes written for it
_local: Dict[str, Any] = {}                      # Windows/macOS: the in-process outcome
_first_sync_done = False                         # IOB-2
_held: set = set()                               # IOB-6: keys the applier last said were (or stayed) in force
HELD_CODES = ("loosen_parked", "limits_local_invalid")
_lock = threading.Lock()                         # IOB-4


def canonical(obj: Any) -> bytes:
    """IOB-3: the ONE byte form of a request (limits_apply.canonical hashes the same form)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


CLEAR_SHA = hashlib.sha256(canonical({"limits": {}})).hexdigest()


def _io(limits: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    return {k: v for k, v in (limits or {}).items() if k in KEYS and v is not None}


def _platform() -> str:
    if sys.platform.startswith("linux"):
        return "linux" if APPLIER_STATE.is_dir() else "linux_no_applier"
    if sys.platform == "win32":
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "other"


def sync(limits: Optional[Dict[str, Any]], *, request: Path = REQUEST, platform: Optional[str] = None,
         result: Optional[Path] = None) -> None:
    """Called with the effective limits on every poll/heartbeat; acts only when the IO-CAP keys changed."""
    global _last_sent, _sent_sha, _local, _first_sync_done, _held
    with _lock:
        want = _io(limits)
        p = platform or _platform()
        first, _first_sync_done = not _first_sync_done, True
        if want == (_last_sent or {}) and _last_sent is not None:
            return
        if not want and _last_sent is None:
            prior = _prior_result(result) if first and p == "linux" else None
            if prior is None:
                return                            # nothing set, nothing in force: today's behaviour, no request
            _held = prior                         # IOB-2/IOB-6: what the last result left in force
        if p == "linux":
            data = canonical({"limits": want})
            request.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            fd = os.open(str(request), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            try:
                os.write(fd, data)
            finally:
                os.close(fd)
            _sent_sha = hashlib.sha256(data).hexdigest()
        elif p in ("windows", "macos"):
            _local = _apply_in_process(want, p)
        else:
            _local = {"in_force": [], "refused": {k: "applier_not_installed" if p == "linux_no_applier"
                                                  else "not_supported" for k in want}}
        _last_sent = want


def _prior_result(result: Optional[Path]) -> Optional[set]:
    """IOB-2: None when nothing needs clearing; else the keys the applier's last result names (in force, or held),
    when it answers a request other than the empty one (or, from an applier without request_sha256, shows something
    in force)."""
    r = _read_result(result or APPLIER_STATE / "result.json")
    if r is None:
        return None
    keys = {k for k in r.get("in_force") or [] if k in KEYS} | \
        {k for k, v in (r.get("refused") or {}).items() if k in KEYS and v in HELD_CODES}
    sha = r.get("request_sha256")
    if isinstance(sha, str):
        return keys if sha != CLEAR_SHA else None
    return keys or None


def report(*, platform: Optional[str] = None, result: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    with _lock:
        return _report(platform, result)


def _report(platform: Optional[str], result: Optional[Path]) -> Optional[Dict[str, Any]]:
    global _held
    if _last_sent is None:
        return None                               # nothing handed over since start (IOB-6: {} is a clear, reported)
    p = platform or _platform()
    if p != "linux":
        return {k: v for k, v in _local.items() if k in ("in_force", "refused")} or None
    r = _read_result(result or APPLIER_STATE / "result.json")
    if r is None or r.get("request_sha256") != _sent_sha:
        return None                               # not (yet) applied, or another request's: "not applied"
    whole = str(r.get("result") or "")
    if whole.startswith("refused:") or whole == "systemctl_failed":    # the whole request: every key refused
        code = whole.split(":", 1)[-1]
        code = code if _CODE.match(code) else "refused"
        return {"in_force": [], "refused": {k: code for k in sorted(set(_last_sent) | _held)[:16]}}
    in_force = [k for k in r.get("in_force") or [] if k in KEYS]
    refused = {k: v for k, v in (r.get("refused") or {}).items() if k in KEYS and isinstance(v, str) and _CODE.match(v)}
    _held = set(in_force) | {k for k, v in refused.items() if v in HELD_CODES}
    # a clear applied reports empty lists (not None), so the backend replaces a stored "still held" report
    return {"in_force": sorted(in_force)[:16], "refused": dict(sorted(refused.items())[:16])}


def _read_result(path: Path) -> Optional[Dict[str, Any]]:
    """The applier's 0644 root-owned result, or None (absent, not regular, too large, not JSON)."""
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > RESULT_MAX_BYTES:
            return None
        data = os.read(fd, RESULT_MAX_BYTES + 1)
    finally:
        os.close(fd)
    try:
        r = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(r, dict) or not isinstance(r.get("at"), int) or isinstance(r.get("at"), bool):
        return None
    return r


# --- Windows / macOS: io_class only, by the process's own IO priority -------------------------------------------------
def _apply_in_process(want: Dict[str, Any], p: str) -> Dict[str, Any]:
    refused = {k: "not_supported" for k in want if k != "io_class"}
    in_force = []
    if "io_class" in want or _local.get("io_class_set"):
        cls = want.get("io_class", "normal")
        try:
            (_win_background if p == "windows" else _mac_iopolicy)(cls)
            if "io_class" in want:
                in_force.append("io_class")
        except Exception as exc:                                  # never let a cap stop the node
            log.warning("io_class not applied: %s", type(exc).__name__)
            if "io_class" in want:
                refused["io_class"] = "apply_failed"
    out: Dict[str, Any] = {"in_force": in_force, "refused": refused}
    if "io_class" in want:
        out["io_class_set"] = True
    return out


def _win_background(cls: str) -> None:
    import ctypes
    k32 = ctypes.windll.kernel32                                  # type: ignore[attr-defined]
    mode = 0x00100000 if cls in ("low", "idle") else 0x00200000   # PROCESS_MODE_BACKGROUND_BEGIN / _END
    if not k32.SetPriorityClass(k32.GetCurrentProcess(), mode):
        err = k32.GetLastError()
        if not (mode == 0x00200000 and err == 402):               # END when not in background mode: nothing to undo
            raise OSError(err)


def _mac_iopolicy(cls: str) -> None:
    import ctypes
    import ctypes.util
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    # IOPOL_TYPE_DISK 0, IOPOL_SCOPE_PROCESS 0; IOPOL_DEFAULT 0, IOPOL_THROTTLE 3, IOPOL_UTILITY 4
    policy = {"idle": 3, "low": 4}.get(cls, 0)
    if libc.setiopolicy_np(0, 0, policy) != 0:
        raise OSError(ctypes.get_errno())
