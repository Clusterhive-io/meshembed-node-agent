"""MVP 1/2 (2026-10-21): the daemon's serve loop -- pull a request from the router, run it on the local
meshembed-serve llama-server (Unix socket), return the completion. Owner first: before every poll the owner-first
decision runs; when it says no, the daemon asks the ROOT launcher to STOP the server (serve_launch "stop", which
needs no plan) and does not poll. Nothing is written to disk but that request.

INERT: nothing in the worker calls serve_once() yet; the wiring comes with the backend serve plans.
"""
from __future__ import annotations

import http.client
import json
import os
import socket
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import serve_tools

SOCKET = Path("/run/mesh-serve/serve.sock")
STOP_REQUEST = Path.home() / ".meshembed" / "serve-request"


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float):
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self._path)
        self.sock = s


def forward(body: Dict[str, Any], *, sock: Path = SOCKET, timeout: float = 110.0) -> Tuple[bool, Any]:
    """(True, completion) or (False, closed code): engine_down / engine_error / bad_request."""
    c = _UnixHTTPConnection(str(sock), timeout)
    try:
        try:
            c.request("POST", "/v1/chat/completions", body=json.dumps(body).encode(),
                      headers={"Content-Type": "application/json"})
            r = c.getresponse()
            data = r.read()
        except (OSError, http.client.HTTPException):
            return False, "engine_down"
        if r.status >= 500:
            return False, "engine_error"
        if r.status != 200:
            return False, "bad_request"
        try:
            return True, json.loads(data)
        except ValueError:
            return False, "engine_error"
    finally:
        c.close()


# Post-start speculation check (auditor 19:22Z (c); M1 2026-10-21: --spec-type defaults to none, and a missing
# timings.draft_n means NO speculation). Synthetic text only; the result is a closed code, nothing else.
PROBE_BODY = {"messages": [{"role": "user", "content": "Count from 1 to 30, separated by commas."}],
              "max_tokens": 64, "temperature": 0, "chat_template_kwargs": {"enable_thinking": False}}


def speculation_probe(*, sock: Path = SOCKET, timeout: float = 120.0) -> str:
    """"spec_active" when the server drafted tokens for the synthetic probe, "spec_inactive" when it did not,
    "engine_down" when it did not answer. Run once after a plan WITH a draft started."""
    ok, out = forward(dict(PROBE_BODY), sock=sock, timeout=timeout)
    if not ok:
        return "engine_down"
    t = out.get("timings") if isinstance(out, dict) else None
    n = t.get("draft_n") if isinstance(t, dict) else None
    return "spec_active" if isinstance(n, int) and not isinstance(n, bool) and n > 0 else "spec_inactive"


def request_stop(reason: str, path: Path = STOP_REQUEST) -> None:
    """Ask the root launcher to stop the server. 0600, owned by us (serve_launch checks both)."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, json.dumps({"action": "stop", "reason": reason}).encode())
    finally:
        os.close(fd)


def serve_once(post: Callable[[str, Dict[str, Any], float], Tuple[int, Any]], node_id: str, models: List[str], *,
               decide: Callable[[], Tuple[bool, str]], sock: Path = SOCKET, stop_path: Path = STOP_REQUEST,
               serving: Optional[Dict[str, Any]] = None, wait_s: float = 20.0,
               duty_mark: Optional[Callable[[float], None]] = None) -> str:
    """One cycle. `post(path, json, timeout) -> (status, json)` is the daemon's authenticated backend call.
    Returns what happened: yield:<reason> | idle | served | failed:<code>."""
    serving = serving if serving is not None else {}
    ok, reason = decide()
    if not ok:
        if serving.get("running", True):
            request_stop(reason, stop_path)
            serving["running"] = False
        return f"yield:{reason}"
    status, job = post("/nodes/serve/next", {"node_id": node_id, "models": models, "wait_s": wait_s}, wait_s + 10)
    if status == 204 or not job:
        return "idle"
    t0 = time.monotonic()
    spec = job.get("tools")
    # M8: True = our three tools; a list = only those names (AR1 T-a: an agent definition's subset); anything else = none
    allowed = None if spec is True else (spec if isinstance(spec, list) and spec
                                         and all(isinstance(t, str) for t in spec) else False)
    if allowed is not False and serve_tools.available():
        # the router marked the request (catalogue supports_tools + the caller's builtin_tools): evaluated here;
        # nothing of the tool step leaves the node (T9)
        rep: Dict[str, int] = {}
        good, out = serve_tools.run_with_tools(job["body"], lambda b, t: forward(b, sock=sock, timeout=t),
                                               report=rep, tools=allowed)
    else:
        rep = None
        good, out = forward(job["body"], sock=sock)
    dur = time.monotonic() - t0
    if duty_mark:
        duty_mark(dur)
    result = {"node_id": node_id, "req_id": job["req_id"], "ok": good, "duration_s": round(dur, 3)}
    result.update({"completion": out} if good else {"code": out})
    if good and rep is not None:
        result["tool_rounds"] = int(rep.get("rounds", 0))      # counts only: the backend clamps usage to rounds + 1
        result["tool_calls"] = int(rep.get("calls", 0))        # counts only: an agent run's tool budget (AR1 T-b)
    post("/nodes/serve/result", result, 30.0)
    return "served" if good else f"failed:{out}"
