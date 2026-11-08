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
import queue
import socket
import threading
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


# --- EP1 (docs/DESIGN_EP1_POOL_ENDPOINT_STREAMING_2026-10-30.md): the answer as frame batches ------------------------
STREAM_ADVERT = 1                 # hw.serve.stream: this daemon answers a job marked "stream" through /nodes/serve/frames
STREAM_FLUSH_S = 0.25             # a frame post at most every 250 ms while tokens come
STREAM_KEEPALIVE_S = 1.0          # and at least one a second while none do (the backend's watchdog is 4 s)
STREAM_BATCH_MAX = 256            # pieces per post (the backend takes <= 512)
STREAM_STALL_S = 15.0             # once tokens flow, this long without one = a hung engine: keepalives must not hide it
FINISH_REASONS = ("stop", "length", "tool_calls")


def _sse_reader(resp, q: "queue.Queue") -> None:
    """Thread: the engine's SSE lines -> ("piece", text) / ("finish", reason) / ("usage", dict) / ("eof", None) /
    ("error", code). Text goes only into the queue, never into a log."""
    try:
        while True:
            line = resp.readline()
            if not line:
                q.put(("eof", None))
                return
            line = line.strip()
            if not line.startswith(b"data:"):
                continue
            data = line[5:].strip()
            if data == b"[DONE]":
                q.put(("eof", None))
                return
            try:
                ev = json.loads(data)
            except ValueError:
                q.put(("error", "engine_error"))
                return
            for c in ev.get("choices") or []:
                t = (c.get("delta") or {}).get("content")
                if isinstance(t, str) and t:
                    q.put(("piece", t))
                if c.get("finish_reason") in FINISH_REASONS:
                    q.put(("finish", c["finish_reason"]))
            if isinstance(ev.get("usage"), dict):
                q.put(("usage", ev["usage"]))
    except (OSError, ValueError, http.client.HTTPException):
        q.put(("error", "engine_down"))


class _Frames:
    """The frame posts of one job. send() is False when the backend no longer wants the answer (dropped, refused,
    unreachable): the caller then stops the engine."""

    def __init__(self, post, node_id: str, req_id: str, clock: Callable[[], float] = time.monotonic):
        self.post, self.node_id, self.req_id, self.clock = post, node_id, req_id, clock
        self.seq, self.last = 0, clock()

    def send(self, pieces: List[str], **final: Any) -> bool:
        body = {"node_id": self.node_id, "req_id": self.req_id, "seq": self.seq, "frames": pieces, **final}
        for _ in range(2):                                  # one transport retry: the same seq is a harmless duplicate
            try:
                status, resp = self.post("/nodes/serve/frames", body, 15.0)
            except Exception:
                continue
            self.last = self.clock()
            if status == 200:
                self.seq += 1
                return bool((resp or {}).get("accepted"))
            return False                                    # 409 / 413 / 429 / 404 ...: the attempt is over
        return False

    def due(self, pending: List[str]) -> bool:
        idle = self.clock() - self.last
        return (bool(pending) and idle >= STREAM_FLUSH_S) or len(pending) >= STREAM_BATCH_MAX \
            or idle >= STREAM_KEEPALIVE_S


def stream_job(post, node_id: str, job: Dict[str, Any], *, sock: Path = SOCKET, timeout: float = 110.0,
               clock: Callable[[], float] = time.monotonic) -> Tuple[bool, str]:
    """EP1: run one job on the local engine with stream=true and post its pieces as frame batches, keepalives
    while none come, then a final post with the usage. (True, "served") or (False, closed code)."""
    fr = _Frames(post, node_id, job["req_id"], clock)
    t0 = clock()
    body = dict(job["body"], stream=True, stream_options={"include_usage": True})
    c = _UnixHTTPConnection(str(sock), timeout)
    raw: Optional[socket.socket] = None
    r = None
    try:
        try:
            c.request("POST", "/v1/chat/completions", body=json.dumps(body).encode(),
                      headers={"Content-Type": "application/json"})
            raw = c.sock
            r = c.getresponse()
        except (OSError, http.client.HTTPException):
            fr.send([], done=True, ok=False, code="engine_down")
            return False, "engine_down"
        if r.status != 200:
            code = "engine_error" if r.status >= 500 else "bad_request"
            fr.send([], done=True, ok=False, code=code)
            return False, code
        q: "queue.Queue" = queue.Queue()
        threading.Thread(target=_sse_reader, args=(r, q), name="meshembed-serve-sse", daemon=True).start()
        pending: List[str] = []
        finish, usage = None, {}
        last_piece: Optional[float] = None                  # None until the first token (prompt reading may be long)
        while True:
            try:
                kind, v = q.get(timeout=STREAM_FLUSH_S)
            except queue.Empty:
                kind, v = None, None
            if kind == "piece":
                pending.append(v)
                last_piece = clock()
            elif kind == "finish":
                finish = v
            elif kind == "usage":
                usage = v
            elif kind == "eof":
                break
            elif kind == "error":
                fr.send(pending, done=True, ok=False, code=v)
                return False, v
            if last_piece is not None and clock() - last_piece > STREAM_STALL_S:
                fr.send(pending, done=True, ok=False, code="engine_stalled")
                return False, "engine_stalled"
            if fr.due(pending):
                if not fr.send(pending):
                    return False, "dropped"                 # the backend let the attempt go: stop generating
                pending = []
        def _n(k):
            x = usage.get(k)
            return x if isinstance(x, int) and not isinstance(x, bool) and x >= 0 else None
        fr.send(pending, done=True, ok=True, finish_reason=finish or "stop", prompt_tokens=_n("prompt_tokens"),
                completion_tokens=_n("completion_tokens"), duration_s=round(clock() - t0, 3))
        return True, "served"
    finally:
        # an unfinished stream: llama-server stops when its client goes away. close() alone is not enough: the
        # response's file object keeps the socket open, so shut it down (this also ends the reader thread)
        if raw is not None:
            try:
                raw.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        if r is not None:
            r.close()
        c.close()


def _with_keepalives(fn: Callable[[], Tuple[bool, Any]], fr: "_Frames") -> Tuple[bool, Any]:
    """EP1: a non-streaming step (the tools rounds) of a streamed job, with keepalives so the backend's watchdog
    sees the node alive. A refused keepalive does not stop the step; its answer is then simply dropped."""
    box: Dict[str, Any] = {}
    th = threading.Thread(target=lambda: box.update(out=fn()), name="meshembed-serve-tools", daemon=True)
    th.start()
    while th.is_alive():
        th.join(STREAM_KEEPALIVE_S)
        if th.is_alive():
            fr.send([])
    return box.get("out", (False, "engine_error"))


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
    streamed = job.get("stream") is True                   # EP1: the backend marked this attempt for frame batches
    # M8: True = our three tools; a list = only those names (AR1 T-a: an agent definition's subset); anything else = none
    allowed = None if spec is True else (spec if isinstance(spec, list) and spec
                                         and all(isinstance(t, str) for t in spec) else False)
    if streamed and (allowed is False or not serve_tools.available()):
        good, code = stream_job(post, node_id, job, sock=sock)
        if duty_mark:
            duty_mark(time.monotonic() - t0)
        return "served" if good else f"failed:{code}"
    if allowed is not False and serve_tools.available():
        # the router marked the request (catalogue supports_tools + the caller's builtin_tools): evaluated here;
        # nothing of the tool step leaves the node (T9)
        rep: Dict[str, int] = {}
        run = lambda: serve_tools.run_with_tools(job["body"], lambda b, t: forward(b, sock=sock, timeout=t),
                                                 report=rep, tools=allowed)
        if streamed:                                         # EP1: the rounds under keepalives, the answer as frames
            fr = _Frames(post, node_id, job["req_id"])
            good, out = _with_keepalives(run, fr)
            if duty_mark:
                duty_mark(time.monotonic() - t0)
            if not good:
                fr.send([], done=True, ok=False, code=out if isinstance(out, str) else "engine_error")
                return f"failed:{out}"
            msg = ((out.get("choices") or [{}])[0].get("message") or {}) if isinstance(out, dict) else {}
            u = out.get("usage") if isinstance(out, dict) and isinstance(out.get("usage"), dict) else {}
            text = msg.get("content") if isinstance(msg.get("content"), str) else ""
            fr.send([text] if text else [], done=True, ok=True, finish_reason="stop",
                    prompt_tokens=u.get("prompt_tokens") if isinstance(u.get("prompt_tokens"), int) else None,
                    completion_tokens=u.get("completion_tokens") if isinstance(u.get("completion_tokens"), int) else None,
                    duration_s=round(time.monotonic() - t0, 3), tool_rounds=int(rep.get("rounds", 0)),
                    tool_calls=int(rep.get("calls", 0)))
            return "served"
        good, out = run()
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
