"""D-4 / PB-V (v0.3.80; auditor 2026-10-30 06:31Z + 06:45Z): the installers' self-check of the INSTALLED package.

    <the daemon's python> -I -m meshembed_node selfcheck

Every installer runs it after pip, before registering or (re)starting the node, and fails the install when it fails:
v0.3.79 printed "INSTALLATION VERIFIED" on a Windows node that could not start (agent_daemon imported grp at its top).

What it does: imports every module of the package (except the commented Linux-only-by-design launchers below), then
evaluates the start path's guards (the agent host, the serve duty) exactly as the daemon's start does. What it never
does: build Config (no key is read), touch the network, write a file, or leave a thread running. Output: one line,
closed codes only.
"""
from __future__ import annotations

import importlib
import os
import pkgutil
import sys
from typing import List, Tuple

# Run only as root launchers ("python -m", from their systemd units); no module on the worker or installer path imports
# them. They need grp/pwd at their top and are Linux-only by design (auditor D-3 list, 2026-10-30 06:57Z).
LINUX_ONLY_BY_DESIGN = {
    "serve_launch": "the root serve launcher (meshembed-serve-launch.service, python -m)",
    "split_launch": "imported only by serve_launch; the root split launcher",
}


def check() -> Tuple[bool, List[str]]:
    """(ok, problems). A problem is "<module>:<ExceptionType>" or "<guard>:<ExceptionType>"; never a message text."""
    import meshembed_node
    problems: List[str] = []
    names = sorted(m.name for m in pkgutil.iter_modules(meshembed_node.__path__))
    for name in names:
        if name in LINUX_ONLY_BY_DESIGN:
            continue                                   # on no start path, on any OS; never imported here
        try:
            importlib.import_module(f"meshembed_node.{name}")
        except Exception as exc:                       # any failure fails the install
            problems.append(f"{name}:{type(exc).__name__}")
    try:
        from . import worker
        env = dict(os.environ)
        if worker.agent_host_skip(env) is None:        # the flag is set on Linux: its module must import too
            from . import agent_daemon  # noqa: F401
        from . import serve_duty
        serve_duty.why_off(env)
    except Exception as exc:
        problems.append(f"start_guards:{type(exc).__name__}")
    return (not problems), problems


def _quiet_check() -> Tuple[bool, List[str]]:
    """SC-1 (auditor 2026-10-30 07:53Z): the self-check's ONLY output is its one stdout line. install.ps1 runs under
    $ErrorActionPreference = "Stop", and in Windows PowerShell 5.1 a native command's stderr line can become a
    terminating error, which would fail the install of a node that CAN start. So while the package imports: warnings
    are ignored, logging is disabled, and file descriptor 2 itself points at the null device (a native library writes
    there directly, past any Python filter). Everything is restored afterwards."""
    import logging
    import warnings
    sys.stderr.flush()
    saved_fd, saved_stream = os.dup(2), sys.stderr
    null = os.open(os.devnull, os.O_WRONLY)
    os.dup2(null, 2)
    os.close(null)
    sys.stderr = open(os.devnull, "w")                  # the Python stream too: it need not be fd 2
    logging.disable(logging.CRITICAL)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return check()
    finally:
        logging.disable(logging.NOTSET)
        sys.stderr.close()
        sys.stderr = saved_stream
        os.dup2(saved_fd, 2)
        os.close(saved_fd)


def main() -> int:
    ok, problems = _quiet_check()
    if ok:
        print("meshembed-node selfcheck ok")
        return 0
    print("meshembed-node selfcheck FAILED: " + ", ".join(problems[:20]))
    return 1
