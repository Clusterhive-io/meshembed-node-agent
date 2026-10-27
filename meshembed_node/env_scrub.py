"""EV-2 (auditor 2026-10-23 17:45Z): variables that make a library load INTO this daemon (which holds the node key) or
into its children, removed from the environment at the very start of the daemon, before llama_cpp is imported.

  - GGML_BACKEND_PATH: ggml's registry (bundled in llama-cpp-python) getenv()s it and loads that library in-process;
  - LD_PRELOAD / LD_AUDIT (Linux), DYLD_INSERT_LIBRARIES (macOS): already applied by the loader to THIS process at exec
    (nothing to undo here), but they must not reach the children we start (the CPU probe, installers).
The daemon's own .env never sets them either (config._load_dotenv skips these names). Only the NAMES are logged.
"""
from __future__ import annotations

import logging
import os
from typing import List, MutableMapping, Optional

log = logging.getLogger("meshembed.env_scrub")

SCRUBBED = ("GGML_BACKEND_PATH", "LD_PRELOAD", "LD_AUDIT", "DYLD_INSERT_LIBRARIES")


def scrub(env: Optional[MutableMapping[str, str]] = None) -> List[str]:
    """Remove every SCRUBBED name from env (default os.environ, which also unsets it for getenv). -> names removed."""
    env = os.environ if env is None else env
    gone = [k for k in SCRUBBED if k in env]
    for k in gone:
        del env[k]
    if gone:
        log.warning("env_scrub: removed %s from the daemon's environment (EV-2)", ",".join(gone))
    return gone
