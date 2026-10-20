"""Warn when the node API key sits inline in the systemd unit (Linux).

A unit is world-readable, and `systemctl show -p Environment` hands its Environment= lines to every local uid. The
installers keep credentials in the 0600 ~/.meshembed/.env, but an older layout put them in the unit, and until
v0.3.76 an upgrade run through passwordless sudo did not move them (187, found by verify-coloc 2026-10-17). The
daemon says so at start -- never the value -- so the owner can re-run the installer as root.
"""
from __future__ import annotations

import logging
import platform
import shutil
import subprocess
from typing import Callable

log = logging.getLogger(__name__)
UNIT = "meshembed-node.service"


def key_in_unit(run: Callable = subprocess.run) -> bool:
    if platform.system() != "Linux" or not shutil.which("systemctl"):
        return False
    try:
        out = run(["systemctl", "show", "-p", "Environment", "--value", UNIT],
                  capture_output=True, text=True, timeout=5)
    except Exception:
        return False
    return "MESHEMBED_NODE_API_KEY=" in (getattr(out, "stdout", "") or "")


def warn_if_key_in_unit(run: Callable = subprocess.run) -> bool:
    if key_in_unit(run):
        log.warning("node API key is inline in %s (world-readable through `systemctl show`): re-run the installer "
                    "as root to move it into ~/.meshembed/.env (0600)", UNIT)
        return True
    return False
