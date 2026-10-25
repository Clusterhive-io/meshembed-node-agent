"""The node's REAL pause (DESIGN_H1 "Blocker 0.1 in detail"; auditor design GO 2026-10-23 14:38Z with P-a..P-c).

An ELEVATED pause tool (meshembed-node-pause[.ps1]) stops the node, disables its relaunch (the Windows task with its
2-min watchdog; the systemd unit; the launchd job) AND writes a marker at a root/SYSTEM path. This module is the
daemon's half: while the marker exists the node does not run at all.

  - P-c: PRESENCE alone = paused. os.path.lexists(marker), checked FIRST in run() (before any network call, model load,
    update check or heartbeat) and before every poll. The content is never parsed to decide: an empty, unreadable,
    malformed or symlinked marker (even a dangling symlink) still pauses.
  - P-a: EVERY marker pauses. Ownership only decides who can remove it; a marker that is not root/SYSTEM-owned is
    honoured AND logged as a warning (the tool's -Status reports it), never ignored: ignoring it would fail OPEN.
  - P-b: nothing in the daemon ever removes or rewrites the marker. Only the elevated tool's resume does.
The process then exits with PAUSED_EXIT (Linux: 75, which the unit's RestartPreventExitStatus= keeps systemd from
restarting; elsewhere 0), holding no work: it is drained.
"""
from __future__ import annotations

import logging
import os
import sys
from typing import Optional

log = logging.getLogger("meshembed.pause")

MARKERS = {
    "linux": "/etc/meshembed-node/paused",
    "darwin": "/Library/Application Support/MeshEmbed/paused",
    "win32": os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "MeshEmbed", "node-paused"),
}
PAUSED_EXIT_LINUX = 75                                  # EX_TEMPFAIL; the unit sets RestartPreventExitStatus=75


def marker_path(platform: str = sys.platform) -> Optional[str]:
    for key, path in MARKERS.items():
        if platform.startswith(key):
            return path
    return None


def paused(platform: str = sys.platform, path: Optional[str] = None) -> bool:
    """P-c: presence alone, lexists (a symlink, even a dangling one, counts). Never reads the content."""
    p = path or marker_path(platform)
    return bool(p) and os.path.lexists(p)


def admin_owned(path: str, platform: str = sys.platform) -> Optional[bool]:
    """True / False on POSIX (owned by root, no group/world write); None where the daemon cannot tell (Windows: the
    tool's -Status checks the ACL)."""
    if platform.startswith("win"):
        return None
    try:
        st = os.lstat(path)
    except OSError:
        return False
    return st.st_uid == 0 and not (st.st_mode & 0o022)


def paused_exit_code(platform: str = sys.platform) -> int:
    return PAUSED_EXIT_LINUX if platform.startswith("linux") else 0


def enforce(where: str, platform: str = sys.platform, path: Optional[str] = None, _exit=os._exit) -> None:
    """If paused: one log line (closed words only) and exit at once. Otherwise return."""
    p = path or marker_path(platform)
    if not paused(platform, p):
        return
    owned = admin_owned(p, platform)
    if owned is False:
        log.warning("node paused by marker (%s) -- the marker is NOT admin-owned: honoured anyway (P-a); "
                    "fix it with the elevated pause tool", where)
    else:
        log.warning("node paused by marker (%s): not running", where)
    _exit(paused_exit_code(platform))
