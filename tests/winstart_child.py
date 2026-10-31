"""PB-I child (v0.3.80; auditor D-2, corrected to (a') at 2026-10-30 07:21Z): the node's start AS ON WINDOWS, in a
fresh interpreter.

    python winstart_child.py <node-agent dir> <stub backend url> <home dir>

(a'): the POSIX-only modules are refused ONLY when the importer is a meshembed_node module (a builtins.__import__
wrapper that checks the caller's __name__). The stdlib and third-party packages import as they really do on this host,
so nothing fails for a reason Windows would never hit (a global sys.modules block broke shutil, psutil and subprocess).
sys.platform becomes "win32" only AFTER all imports, around the start call. Then: every meshembed_node module is
imported (except the Linux-only launchers; WINSTART_SKIP_WALK=1 skips the walk to prove the run() path alone), and
worker.run() is started with BOTH optional duties requested (MESHEMBED_AGENT_HOST=1, MESHEMBED_SERVE=1, the worst
case). The parent test passes when the stub backend sees the first /get_job.
"""
import builtins
import os
import sys

node_agent, backend, home = sys.argv[1], sys.argv[2], sys.argv[3]

BLOCKED = {"grp", "pwd", "fcntl", "resource", "termios", "pty", "tty", "posix", "crypt", "spwd", "syslog"}
_real_import = builtins.__import__


def _windows_like_import(name, globals=None, locals=None, fromlist=(), level=0):
    importer = (globals or {}).get("__name__", "") or ""
    if level == 0 and name.split(".")[0] in BLOCKED and importer.startswith("meshembed_node"):
        raise ModuleNotFoundError(f"No module named '{name}' (as on Windows; imported by {importer})", name=name)
    return _real_import(name, globals, locals, fromlist, level)


builtins.__import__ = _windows_like_import
os.environ.update(HOME=home, USERPROFILE=home, ProgramData=os.path.join(home, "ProgramData"),
                  MESHEMBED_BACKEND=backend, MESHEMBED_NODE_API_KEY="test-node-key", MESHEMBED_NODE_ID="node-winsim",
                  MESHEMBED_AGENT_HOST="1", MESHEMBED_SERVE="1", MESHEMBED_WORKERS="1")
sys.path.insert(0, node_agent)

import importlib  # noqa: E402
import pkgutil  # noqa: E402

import meshembed_node  # noqa: E402

LINUX_ONLY_BY_DESIGN = {"serve_launch", "split_launch"}     # root launchers, "python -m" only (D-3 list)
if os.environ.get("WINSTART_SKIP_WALK") != "1":               # the walk; skipped only to prove (c) on its own
    for m in sorted(pkgutil.iter_modules(meshembed_node.__path__), key=lambda m: m.name):
        if m.name in LINUX_ONLY_BY_DESIGN:
            continue
        importlib.import_module(f"meshembed_node.{m.name}")  # any failure ends the child: the parent shows it
    print("WINSTART walk ok", flush=True)

from meshembed_node import worker  # noqa: E402
from meshembed_node.config import Config  # noqa: E402


class FakeEncoder:                                            # no model download in a test
    def __init__(self, *a, **k):
        pass

    def ensure_default_loaded(self):
        return None

    def installed_models(self):
        return []

    def __getattr__(self, name):                              # anything else the loop asks of it: harmless no-ops
        return lambda *a, **k: None


worker.Encoder = FakeEncoder
worker._llm_warm = lambda *a, **k: None
worker._power_idle_loop = lambda *a, **k: None
cfg = Config()
sys.platform = "win32"                                        # only now, around the start call (a')
print("WINSTART run", flush=True)
worker.run(cfg)
