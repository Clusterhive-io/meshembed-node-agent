"""EP1 (docs/DESIGN_EP1_POOL_ENDPOINT_STREAMING_2026-10-30.md): a job the backend marked "stream" runs on the local
engine with stream=true; its pieces go to /nodes/serve/frames in order, keepalives while none come, then a final
post with the usage; a backend that lets the attempt go stops the engine; an unmarked job keeps /serve/result."""
from __future__ import annotations

import json
import socketserver
import threading
import time
from http.server import BaseHTTPRequestHandler

import pytest

from meshembed_node import serve_client as SC

pytestmark = pytest.mark.unit
JOB = {"req_id": "r" * 32, "model": "m", "stream": True, "body": {"messages": [{"role": "user", "content": "x"}]}}


class _Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


@pytest.fixture
def engine(tmp_path):
    """A llama-server stand-in: SSE pieces, optional delay before the first, optional 500."""
    cfg = {"pieces": ["Hel", "lo", "!"], "delay": 0.0, "gap": 0.0, "status": 200, "seen": [], "broken": [],
           "hang_after": None}

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            cfg["seen"].append(body)
            if cfg["status"] != 200:
                self.send_response(cfg["status"]); self.send_header("Content-Length", "2"); self.end_headers()
                self.wfile.write(b"{}")
                return
            self.send_response(200); self.send_header("Content-Type", "text/event-stream"); self.end_headers()
            time.sleep(cfg["delay"])
            try:
                for i, p in enumerate(cfg["pieces"]):
                    if cfg["hang_after"] is not None and i >= cfg["hang_after"]:
                        time.sleep(5)
                        return
                    ev = {"choices": [{"index": 0, "delta": {"content": p}, "finish_reason": None}]}
                    self.wfile.write(f"data: {json.dumps(ev)}\n\n".encode()); self.wfile.flush()
                    time.sleep(cfg["gap"])
                last = {"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}
                use = {"choices": [], "usage": {"prompt_tokens": 9, "completion_tokens": len(cfg["pieces"])}}
                self.wfile.write(f"data: {json.dumps(last)}\n\ndata: {json.dumps(use)}\n\ndata: [DONE]\n\n".encode())
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                cfg["broken"].append(True)

        def log_message(self, *a):
            pass

        def address_string(self):
            return "unix"

    path = str(tmp_path / "serve.sock")
    srv = _Server(path, H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield tmp_path / "serve.sock", cfg
    srv.shutdown()


def backend(job=JOB, accept=lambda body: True, fail_first=False):
    calls, state = [], {"failed": False}

    def post(path, body, timeout):
        if path == "/nodes/serve/next":
            return 200, job
        if fail_first and not state["failed"] and path == "/nodes/serve/frames":
            state["failed"] = True
            raise ConnectionError("lost")
        calls.append((path, json.loads(json.dumps(body))))
        return 200, {"accepted": accept(body)}
    return post, calls


def frames(calls):
    return [b for p, b in calls if p == "/nodes/serve/frames"]


def test_the_pieces_go_out_in_order_then_one_final_post_with_the_usage(engine):
    sock, cfg = engine
    post, calls = backend()
    assert SC.serve_once(post, "n1", ["m"], decide=lambda: (True, "ok"), sock=sock) == "served"
    fs = frames(calls)
    assert "".join(p for f in fs for p in f["frames"]) == "Hello!"
    assert [f["seq"] for f in fs] == list(range(len(fs)))
    last = fs[-1]
    assert last["done"] is True and last["ok"] is True and last["finish_reason"] == "stop"
    assert last["prompt_tokens"] == 9 and last["completion_tokens"] == 3
    assert not [p for p, _ in calls if p == "/nodes/serve/result"]          # never the whole-result route
    sent = cfg["seen"][0]
    assert sent["stream"] is True and sent["stream_options"] == {"include_usage": True}


def test_keepalives_go_out_while_the_engine_reads_the_prompt(engine):
    sock, cfg = engine
    cfg["delay"] = 2.3                                                       # > 2 keepalive periods, no token yet
    post, calls = backend()
    assert SC.serve_once(post, "n1", ["m"], decide=lambda: (True, "ok"), sock=sock) == "served"
    fs = frames(calls)
    first_piece = next(i for i, f in enumerate(fs) if f["frames"])
    assert first_piece >= 2 and all(f["frames"] == [] and not f.get("done") for f in fs[:first_piece])


def test_a_backend_that_lets_the_attempt_go_stops_the_engine(engine):
    sock, cfg = engine
    cfg["pieces"], cfg["gap"] = ["a"] * 40, 0.05
    post, calls = backend(accept=lambda body: body["seq"] < 1)               # the second post is "dropped"
    assert SC.serve_once(post, "n1", ["m"], decide=lambda: (True, "ok"), sock=sock) == "failed:dropped"
    assert len(frames(calls)) == 2 and not any(f.get("done") for f in frames(calls))
    t_end = time.monotonic() + 3
    while not cfg["broken"] and time.monotonic() < t_end:                   # the engine saw the connection close
        time.sleep(0.05)
    assert cfg["broken"] == [True]


def test_an_engine_error_is_a_final_post_with_its_code(engine):
    sock, cfg = engine
    cfg["status"] = 500
    post, calls = backend()
    assert SC.serve_once(post, "n1", ["m"], decide=lambda: (True, "ok"), sock=sock) == "failed:engine_error"
    assert frames(calls) == [{"node_id": "n1", "req_id": "r" * 32, "seq": 0, "frames": [], "done": True,
                              "ok": False, "code": "engine_error"}]


def test_no_engine_is_engine_down(tmp_path):
    post, calls = backend()
    assert SC.serve_once(post, "n1", ["m"], decide=lambda: (True, "ok"), sock=tmp_path / "none.sock") == \
        "failed:engine_down"
    assert frames(calls)[-1]["code"] == "engine_down"


def test_a_lost_post_is_resent_once_with_the_same_seq(engine):
    sock, _ = engine
    post, calls = backend(fail_first=True)
    assert SC.serve_once(post, "n1", ["m"], decide=lambda: (True, "ok"), sock=sock) == "served"
    fs = frames(calls)
    assert fs[0]["seq"] == 0 and [f["seq"] for f in fs] == list(range(len(fs)))


def test_an_unmarked_job_keeps_the_whole_result_route(engine):
    sock, cfg = engine
    post, calls = backend(job={k: v for k, v in JOB.items() if k != "stream"})
    cfg["status"] = 500                                                      # whatever happens, it is /serve/result
    SC.serve_once(post, "n1", ["m"], decide=lambda: (True, "ok"), sock=sock)
    assert [p for p, _ in calls] == ["/nodes/serve/result"]


def test_a_streamed_tools_job_sends_keepalives_during_the_rounds_and_the_answer_as_frames(monkeypatch):
    def rounds(body, fwd, report, tools):
        time.sleep(2.3)
        report.update(rounds=2, calls=3)
        return True, {"choices": [{"message": {"content": "42"}}], "usage": {"prompt_tokens": 50, "completion_tokens": 4}}
    monkeypatch.setattr(SC.serve_tools, "available", lambda: True)
    monkeypatch.setattr(SC.serve_tools, "run_with_tools", rounds)
    post, calls = backend(job=dict(JOB, tools=True))
    assert SC.serve_once(post, "n1", ["m"], decide=lambda: (True, "ok")) == "served"
    fs = frames(calls)
    assert len(fs) >= 3 and all(f["frames"] == [] for f in fs[:-1])
    assert fs[-1]["frames"] == ["42"] and fs[-1]["done"] is True and fs[-1]["tool_rounds"] == 2
    assert fs[-1]["tool_calls"] == 3 and fs[-1]["completion_tokens"] == 4


def test_the_hardware_report_adverts_streaming_only_with_a_serve_duty(monkeypatch):
    from meshembed_node import worker as W

    class Duty:
        def status(self):
            return {"ready": True, "reason": "ok"}
    monkeypatch.setattr(W, "_SERVE_DUTY", Duty())
    # node-rel-next: CANARY-HOLD (b) adds unload: 1 beside EP1's stream: 1
    assert W._hardware_info()["serve"] == {"ready": True, "reason": "ok", "stream": 1, "unload": 1}
    monkeypatch.setattr(W, "_SERVE_DUTY", None)
    assert "stream" not in W._hardware_info()["serve"]


def test_a_hung_engine_after_the_first_token_is_not_hidden_by_keepalives(engine, monkeypatch):
    sock, cfg = engine
    cfg["hang_after"] = 1
    monkeypatch.setattr(SC, "STREAM_STALL_S", 1.5)
    post, calls = backend()
    t0 = time.monotonic()
    assert SC.serve_once(post, "n1", ["m"], decide=lambda: (True, "ok"), sock=sock) == "failed:engine_stalled"
    assert time.monotonic() - t0 < 4
    last = frames(calls)[-1]
    assert last["done"] is True and last["ok"] is False and last["code"] == "engine_stalled"
