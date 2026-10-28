"""AR1 G9: the G0 check of the agent unit (auditor 13:19Z S4/S6; the G0 rule): runs as ExecStartPre, BEFORE the loop.

Refuses to start (exit 1, one closed code on stderr) when the process environment carries anything that could steer
the interpreter, the dynamic loader, a model runtime or a tool, or when the credentials directory holds anything but
the expected names. The unit has no EnvironmentFile and no Environment; this check makes that a property of the
running process, not only of the file.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# what systemd itself sets for a service; nothing else may be present
ALLOWED_ENV = frozenset({"PATH", "LANG", "LC_ALL", "HOME", "LOGNAME", "USER", "SHELL", "INVOCATION_ID",
                         "JOURNAL_STREAM", "SYSTEMD_EXEC_PID", "CREDENTIALS_DIRECTORY", "STATE_DIRECTORY",
                         "RUNTIME_DIRECTORY", "TERM", "NOTIFY_SOCKET", "MAINPID", "PIDFILE", "MEMORY_PRESSURE_WATCH",
                         "MEMORY_PRESSURE_WRITE"})
FORBIDDEN_PREFIXES = ("LLAMA_", "GGML_", "PYTHON", "LD_", "MESHEMBED_", "CUDA_", "OMP_", "HF_", "TRANSFORMERS_")
ALLOWED_CREDENTIALS = frozenset({"state-key"})


def check(env=None, creds_dir=None) -> str:
    env = dict(os.environ if env is None else env)
    for k in env:
        if k.upper().startswith(FORBIDDEN_PREFIXES):
            return "g0_forbidden_env"
        if k not in ALLOWED_ENV:
            return "g0_unexpected_env"
    cd = creds_dir if creds_dir is not None else env.get("CREDENTIALS_DIRECTORY")
    if cd:
        names = {p.name for p in Path(cd).iterdir()}
        if not names <= ALLOWED_CREDENTIALS:
            return "g0_unexpected_credential"          # e.g. a lane key: S1 says only the daemon holds it
    return "ok"


def main() -> int:
    code = check()
    if code != "ok":
        print(code, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
