"""EV-2 (auditor 2026-10-23 17:45Z): loader variables never reach the daemon's ggml or its children."""
import os
import re
import subprocess
import sys
from pathlib import Path

from meshembed_node import env_scrub as S

ROOT = Path(__file__).resolve().parents[1]


def test_scrub_removes_exactly_the_named_variables():
    env = {"GGML_BACKEND_PATH": "/tmp/evil.so", "LD_PRELOAD": "x.so", "LD_AUDIT": "a.so",
           "DYLD_INSERT_LIBRARIES": "d.dylib", "LD_LIBRARY_PATH": "/opt/cuda/lib64", "PATH": "/usr/bin"}
    assert sorted(S.scrub(env)) == sorted(S.SCRUBBED)
    assert env == {"LD_LIBRARY_PATH": "/opt/cuda/lib64", "PATH": "/usr/bin"}      # nothing else touched


def test_the_daemon_entry_scrubs_before_importing_anything_else():
    src = (ROOT / "meshembed_node" / "__main__.py").read_text()
    # since v0.3.78 (P2-F4) config and worker are imported lazily, after the pause check: every import still follows
    first = src.index("_env_scrub.scrub()")
    imports = [m.start() for m in re.finditer(r"from \.(config|worker) import", src)]
    assert imports and all(first < i for i in imports)


def test_dotenv_never_sets_them(tmp_path, monkeypatch):
    home = tmp_path / "h"
    (home / ".meshembed").mkdir(parents=True)
    (home / ".meshembed" / ".env").write_text("GGML_BACKEND_PATH=/tmp/evil.so\nLD_PRELOAD=/tmp/x.so\n"
                                              "MESHEMBED_POLL_MIN_S=2\n")
    monkeypatch.setenv("HOME", str(home))
    for k in S.SCRUBBED + ("MESHEMBED_POLL_MIN_S",):
        monkeypatch.delenv(k, raising=False)               # restored after the test (no leak into others)
    from meshembed_node.config import Config
    try:
        Config._load_dotenv(Config.__new__(Config))
    except Exception:
        pass
    assert "GGML_BACKEND_PATH" not in os.environ and "LD_PRELOAD" not in os.environ
    assert os.environ.get("MESHEMBED_POLL_MIN_S") == "2"


def test_a_child_of_the_daemon_never_sees_them():
    env = dict(os.environ, GGML_BACKEND_PATH="/tmp/evil.so", PYTHONPATH=str(ROOT))
    code = ("import os, meshembed_node.__main__ as m; import subprocess, sys; "
            "print(subprocess.run([sys.executable, '-c', 'import os; print(os.environ.get(\"GGML_BACKEND_PATH\"))'],"
            " capture_output=True, text=True).stdout.strip())")
    out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, cwd=str(ROOT))
    assert out.stdout.strip().splitlines()[-1] == "None", out.stderr[-500:]
