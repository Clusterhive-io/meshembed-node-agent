"""PB-I (v0.3.80; auditor 2026-10-30 06:31Z + D-2 06:45Z): the node starts AS ON WINDOWS, up to its first poll.

v0.3.79 crashed every Windows node at start: worker._start_agent_host imported agent_daemon (grp/pwd at its top)
before any flag or platform check. The node suite ran on Linux only, so nothing saw it. This test runs the real start
in a fresh interpreter with the POSIX-only modules blocked and sys.platform "win32" (tests/winstart_child.py), against
a stub backend, and passes only when the stub receives the first /get_job. Run on 7b4d99d (v0.3.79) it fails with
ModuleNotFoundError: the negative control.
"""
from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit
NODE_AGENT = Path(__file__).resolve().parents[1]
CHILD = Path(__file__).resolve().with_name("winstart_child.py")


class _Stub(BaseHTTPRequestHandler):
    seen: list = []

    def _reply(self, code=200, body=b"{}"):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):                                      # noqa: N802
        n = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(n)
        self.seen.append(self.path)
        if self.path.startswith("/get_job"):
            self.send_response(204)
            self.end_headers()
            return
        self._reply(200, json.dumps({"node_number": 1, "ok": True}).encode())

    def do_GET(self):                                       # noqa: N802
        self.seen.append(self.path)
        self._reply(404, b"{}")

    def log_message(self, *a):                              # quiet
        pass


def start_as_windows(node_agent: Path, home: Path, timeout_s: float = 120.0, walk: bool = True):
    """(reached_first_poll, child_output). The child is always stopped. walk=False skips the module walk, so only
    worker.run()'s own path is exercised (D-2 (c): the v0.3.79 crash was a function-local import on that path)."""
    import os
    env = dict(os.environ, WINSTART_SKIP_WALK="0" if walk else "1")
    _Stub.seen = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Stub)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}"
    p = subprocess.Popen([sys.executable, str(CHILD), str(node_agent), url, str(home)],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding="utf-8", errors="replace",
                         env=env)                         # RC-a: a failure message is never lost to a cp1252 decode
    try:
        t0 = time.time()
        while time.time() - t0 < timeout_s:
            if any(s.startswith("/get_job") for s in _Stub.seen):
                return True, ""
            if p.poll() is not None:                        # the child ended before its first poll
                return False, p.stdout.read()
            time.sleep(0.2)
        return False, "timeout"
    finally:
        if p.poll() is None:
            p.kill()
            p.wait(timeout=10)
        srv.shutdown()


@pytest.mark.parametrize("walk", [True, False])
def test_the_node_starts_as_on_windows_up_to_its_first_poll(tmp_path, walk):
    ok, out = start_as_windows(NODE_AGENT, tmp_path, walk=walk)
    assert ok, out[-3000:]


# --- PB-I (a'), the static half (auditor 2026-10-30 07:21Z): POSIX-only ATTRIBUTES are never touched at import ------
# The import hook above covers POSIX-only MODULES. Attributes such as os.getuid or signal.SIGHUP exist on Linux, so no
# hook can refuse them; a reference that runs at import time (module level, a class body, a default argument or a
# decorator) would crash a Windows node at start. Function bodies run later and are guarded where needed.
POSIX_ONLY_ATTRS = {
    "os": {"getuid", "geteuid", "getgid", "getegid", "getgroups", "setuid", "setgid", "seteuid", "setegid", "fork",
           "forkpty", "setsid", "getsid", "setpgid", "getpgid", "killpg", "chown", "fchown", "lchown", "WNOHANG",
           "O_NOFOLLOW", "O_NONBLOCK", "O_DIRECTORY", "mkfifo", "statvfs", "fstatvfs", "sync", "getloadavg",
           "sched_getaffinity", "nice", "uname"},
    "signal": {"SIGHUP", "SIGKILL", "SIGUSR1", "SIGUSR2", "SIGALRM", "SIGCHLD", "SIGQUIT", "SIGPIPE", "SIGSTOP",
               "SIGCONT", "SIGTSTP", "setitimer", "alarm", "pause"},
    "socket": {"AF_UNIX", "SO_PEERCRED", "SCM_RIGHTS"},
}
LINUX_ONLY_BY_DESIGN = {"serve_launch", "split_launch"}


def _import_time_nodes(tree):
    """The AST nodes that execute at import: module-level statements, class bodies, default args and decorators."""
    import ast
    out = []

    def visit_body(stmts):
        for st in stmts:
            if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
                out.extend(st.decorator_list)
                out.extend(st.args.defaults)
                out.extend(d for d in st.args.kw_defaults if d is not None)
            elif isinstance(st, ast.ClassDef):
                out.extend(st.decorator_list)
                out.extend(st.bases)
                visit_body(st.body)
            else:
                out.append(st)
    visit_body(tree.body)
    return out


def test_no_posix_only_attribute_is_touched_at_import():
    import ast
    found = []
    for f in sorted((NODE_AGENT / "meshembed_node").glob("*.py")):
        if f.stem in LINUX_ONLY_BY_DESIGN:
            continue
        for node in _import_time_nodes(ast.parse(f.read_text(encoding="utf-8"), str(f))):
            for n in ast.walk(node):
                if (isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)
                        and n.attr in POSIX_ONLY_ATTRS.get(n.value.id, ())):
                    found.append(f"{f.name}:{n.lineno} {n.value.id}.{n.attr}")
    assert found == [], found


def test_the_static_check_catches_what_it_is_for():
    """Positive control: an import-time use is found, a use inside a function body is not."""
    import ast
    src = ("import os, signal\nUID = os.getuid()\n"
           "def f(sig=signal.SIGHUP):\n    return os.geteuid()\n"
           "class C:\n    MODE = os.O_NOFOLLOW\n")
    hits = sorted(f"{n.value.id}.{n.attr}" for node in _import_time_nodes(ast.parse(src)) for n in ast.walk(node)
                  if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)
                  and n.attr in POSIX_ONLY_ATTRS.get(n.value.id, ()))
    assert hits == ["os.O_NOFOLLOW", "os.getuid", "signal.SIGHUP"]          # never os.geteuid (a function body)
