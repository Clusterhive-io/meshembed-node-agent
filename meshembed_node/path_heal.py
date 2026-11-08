"""The .path self-heal (PATH-LIMIT, auditor 2026-11-03 12:55:28Z; the heal timer ruled 13:38:41Z with HT-1..HT-4).

A burst of writes to a launcher's watched file trips systemd's start limit on the launcher SERVICE, and the .path unit
then fails for good: nothing restarts it (the sandbox bed 2026-11-03: meshembed-split-launch.path dead on both nodes;
under real systemd a 4/s burst kills all three .path units). This root oneshot, run by meshembed-path-heal.timer, heals
them:
- HT-1: a FIXED unit list (the three launchers' .path units; since v0.3.82 also the limits applier's two, CD-4), a
  fixed argv, no input from the daemon. It acts only on a unit that is FAILED:
  reset-failed + start, and a journal line "path_unit_healed <unit>".
- HT-2: node-update.path at most once per hour (its updater reinstalls; never 6 attempts every 10 min), and ANY unit
  healed 3 times in 24 h is no longer healed and is reported ("path_unit_heal_stopped <unit>") for a human.
- HT-3: per-unit counts in the root state, plus a world-readable summary the daemon reports (hw.path_heal).
Standard library only."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

UNITS = ("meshembed-split-launch.path", "meshembed-serve-launch.path", "meshembed-node-update.path",
         # CD-4 (auditor 2026-11-03 14:55:22Z): IO-CAP's two .path units; a dead one = an owner's LOWERED cap
         # never applied. The same failed-only rule and 3-in-24-h stop; the hourly bound stays node-update's only
         "meshembed-limits-apply.path", "meshembed-limits-reconcile.path")
STATE_DIR = Path("/var/lib/meshembed-path-heal")
MIN_GAP_S = {"meshembed-node-update.path": 3600}     # HT-2
WINDOW_S = 24 * 3600
MAX_IN_WINDOW = 3                                    # HT-2: the third heal in 24 h is the last; then stop + report
_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}


def _real_is_failed(unit: str) -> bool:
    return subprocess.run(["systemctl", "is-failed", "--quiet", unit], env=_ENV, timeout=30,
                          check=False).returncode == 0


def _real_systemctl(*args: str) -> None:
    subprocess.run(["systemctl", *args], env=_ENV, timeout=60, check=False)


def _load(state: Path) -> Dict[str, Any]:
    try:
        d = json.loads((state / "heals.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return d if isinstance(d, dict) else {}


def _write(path: Path, doc: Dict[str, Any], mode: int) -> None:
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(doc, f, sort_keys=True)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def run(state: Path = STATE_DIR, now: Optional[float] = None, *, is_failed: Callable[[str], bool] = _real_is_failed,
        systemctl: Callable[..., None] = _real_systemctl, units=UNITS) -> List[str]:
    """One pass. Returns the journal lines it printed (for tests)."""
    now = time.time() if now is None else now
    state.mkdir(mode=0o755, parents=True, exist_ok=True)
    doc = _load(state)
    lines: List[str] = []
    for unit in units:
        rec = doc.get(unit) if isinstance(doc.get(unit), dict) else {}
        heals = [t for t in rec.get("heals", []) if isinstance(t, (int, float)) and now - t < WINDOW_S]
        stopped = bool(rec.get("stopped"))
        if not is_failed(unit):
            doc[unit] = {"heals": heals, "stopped": stopped}
            continue
        if stopped or len(heals) >= MAX_IN_WINDOW:
            doc[unit] = {"heals": heals, "stopped": True}
            lines.append(f"path_unit_heal_stopped {unit} heals_24h {len(heals)}")
            continue
        gap = MIN_GAP_S.get(unit)
        if gap and heals and now - max(heals) < gap:
            doc[unit] = {"heals": heals, "stopped": False}
            lines.append(f"path_unit_heal_deferred {unit}")
            continue
        systemctl("reset-failed", unit)
        systemctl("start", unit)
        heals.append(int(now))
        doc[unit] = {"heals": heals, "stopped": False}  # the NEXT failure after the third heal stops it
        lines.append(f"path_unit_healed {unit} heals_24h {len(heals)}")
    _write(state / "heals.json", doc, 0o600)
    summary = {u: {"heals_24h": len(doc[u]["heals"]), "stopped": doc[u]["stopped"]} for u in units if u in doc}
    _write(state / "summary.json", summary, 0o644)       # HT-3: the daemon reads this (counts + flags only)
    for line in lines:
        print(line)
    return lines


def drift(paths=None) -> Optional[str]:
    """HT-5 at START (auditor 2026-11-03 14:01:53Z, optional, taken): the install-time guard re-checked cheaply before
    running as root: the interpreter's real target, this module's file and every parent of both up to / are root-owned
    and not group/other-writable. Returns the first offending path, or None."""
    import stat as _st
    paths = paths or [os.path.realpath(sys.executable), os.path.realpath(__file__)]
    seen = set()
    for p in paths:
        while True:
            if p not in seen:
                seen.add(p)
                try:
                    st = os.lstat(p)
                except OSError:
                    return p
                if st.st_uid != 0 or st.st_mode & (_st.S_IWGRP | _st.S_IWOTH) and not _st.S_ISLNK(st.st_mode):
                    return p
            parent = os.path.dirname(p)
            if parent == p:
                break
            p = parent
    return None


def main(argv=None) -> int:
    if os.geteuid() != 0:
        print("path_heal: must run as root (meshembed-path-heal.service)")
        return 2
    bad = drift()
    if bad:
        print(f"path_heal: refused venv_drift {bad}")      # never run root code the daemon user could have edited
        return 3
    run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
