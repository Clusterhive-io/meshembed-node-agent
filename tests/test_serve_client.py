"""MVP 1/2 serve loop (2026-10-21): owner first, then pull, forward to the local server's Unix socket, answer."""
from __future__ import annotations

import json
import os
import socketserver
import threading
from http.server import BaseHTTPRequestHandler

import pytest

from meshembed_node import serve_client as SC

pytestmark = pytest.mark.unit
DONE = {"choices": [{"message": {"content": "ok"}}], "usage": {"completion_tokens": 7}}


class _Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


@pytest.fixture
def engine(tmp_path):
    seen = []

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            seen.append((self.path, body))
            code, out = (500, b"{}") if body.get("boom") else (200, json.dumps(DONE).encode())
            self.send_response(code); self.send_header("Content-Length", str(len(out))); self.end_headers()
            self.wfile.write(out)

        def log_message(self, *a):
            pass

        def address_string(self):
            return "unix"

    path = str(tmp_path / "serve.sock")
    srv = _Server(path, H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield tmp_path / "serve.sock", seen
    srv.shutdown()


def backend(job=None):
    calls = []

    def post(path, body, timeout):
        calls.append((path, body))
        if path == "/nodes/serve/next":
            return (200, job) if job else (204, None)
        return 200, {"accepted": True}
    return post, calls


def test_owner_needs_the_machine_stop_once_and_do_not_poll(tmp_path):
    post, calls = backend()
    st, stop = {}, tmp_path / "serve-request"
    assert SC.serve_once(post, "n1", ["m"], decide=lambda: (False, "owner:active"), stop_path=stop,
                         serving=st) == "yield:owner:active"
    assert json.loads(stop.read_text()) == {"action": "stop", "reason": "owner:active"}
    assert oct(os.stat(stop).st_mode & 0o777) == "0o600" and calls == []
    stop.write_text("")
    SC.serve_once(post, "n1", ["m"], decide=lambda: (False, "owner:active"), stop_path=stop, serving=st)
    assert stop.read_text() == ""                                  # asked once, not every cycle


def test_nothing_waiting_is_idle(engine, tmp_path):
    post, calls = backend()
    sock, _ = engine
    assert SC.serve_once(post, "n1", ["m"], decide=lambda: (True, "ok"), sock=sock) == "idle"
    assert calls[0][1] == {"node_id": "n1", "models": ["m"], "wait_s": 20.0}


def test_a_request_is_forwarded_and_answered(engine):
    sock, seen = engine
    post, calls = backend({"req_id": "r" * 32, "model": "m", "body": {"messages": [{"role": "user", "content": "x"}]}})
    marks = []
    assert SC.serve_once(post, "n1", ["m"], decide=lambda: (True, "ok"), sock=sock, duty_mark=marks.append) == "served"
    assert seen[0][0] == "/v1/chat/completions" and seen[0][1]["messages"][0]["content"] == "x"
    path, res = calls[-1]
    assert path == "/nodes/serve/result" and res["ok"] is True and res["completion"] == DONE and res["req_id"] == "r" * 32
    assert len(marks) == 1 and marks[0] >= 0


def test_an_engine_error_is_returned_as_a_code(engine):
    sock, _ = engine
    post, calls = backend({"req_id": "r" * 32, "model": "m", "body": {"boom": True}})
    assert SC.serve_once(post, "n1", ["m"], decide=lambda: (True, "ok"), sock=sock) == "failed:engine_error"
    assert calls[-1][1] == {"node_id": "n1", "req_id": "r" * 32, "ok": False, "code": "engine_error",
                            "duration_s": calls[-1][1]["duration_s"]}


def test_no_server_is_engine_down(tmp_path):
    post, calls = backend({"req_id": "r" * 32, "model": "m", "body": {}})
    assert SC.serve_once(post, "n1", ["m"], decide=lambda: (True, "ok"), sock=tmp_path / "none.sock") == "failed:engine_down"
    assert calls[-1][1]["code"] == "engine_down"


# --- post-start speculation probe (auditor 19:22Z (c)) ---------------------------------------------------------

def _fake_server(tmp_path, payload):
    import socketserver, threading, http.server
    sock = tmp_path / "s.sock"

    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            seen.append(json.loads(self.rfile.read(n)))
            body = json.dumps(payload).encode()
            self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    class S(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
        daemon_threads = True

        def get_request(self):
            req, _ = super().get_request()
            return req, ("local", 0)
    seen = []
    srv = S(str(sock), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, sock, seen


@pytest.mark.parametrize("timings, want", [
    ({"draft_n": 40, "draft_n_accepted": 37}, "spec_active"),
    ({"predicted_n": 64}, "spec_inactive"),                # the field absent = no speculation
    ({"draft_n": 0}, "spec_inactive"),
])
def test_speculation_probe_reports_a_closed_code(tmp_path, timings, want):
    srv, sock, seen = _fake_server(tmp_path, {"choices": [], "timings": timings})
    try:
        assert SC.speculation_probe(sock=sock, timeout=5) == want
        assert seen[0]["messages"][0]["content"].startswith("Count from 1 to 30")      # synthetic text only
    finally:
        srv.shutdown(); srv.server_close()


def test_speculation_probe_engine_down(tmp_path):
    assert SC.speculation_probe(sock=tmp_path / "missing.sock", timeout=1) == "engine_down"
