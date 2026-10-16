"""M2 build #5b, daemon side: items of a split plan go to the plan's engine over a UNIX socket,
with the same constraints the single-node runner applies; the engine counts as ready only for
the plan the ROOT launcher started it for, unexpired, and answering /health."""
from __future__ import annotations

import json
import socketserver
import threading
import time
from http.server import BaseHTTPRequestHandler

import pytest

from meshembed_node import split_engine as E

pytestmark = pytest.mark.unit


class _H(BaseHTTPRequestHandler):
    seen: list = []
    mode = "ok"

    def address_string(self):
        return "unix"

    def log_message(self, *a):
        pass

    def _send(self, obj, code=200):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self._send({"status": "ok"} if self.path == "/health" else {}, 200 if self.path == "/health" else 404)

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        _H.seen.append((self.path, body))
        if _H.mode == "500":
            self._send({"error": {"message": "rpc stage said something long"}}, 500)
        elif _H.mode == "400":
            self._send({"error": {"message": "bad grammar"}}, 400)
        elif self.path == "/v1/chat/completions":
            fr = None if _H.mode == "cut" else "stop"
            self._send({"choices": [{"message": {"content": '{"title": "X"}'}, "finish_reason": fr}],
                        "usage": {"prompt_tokens": 40, "completion_tokens": 7}})
        elif self.path == "/completion":
            self._send({"content": "yes", "stop": _H.mode != "cut", "timings": {"prompt_n": 12, "predicted_n": 1}})
        else:
            self._send({}, 404)


class _UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


@pytest.fixture
def engine(tmp_path):
    sock = tmp_path / "engine.sock"
    srv = _UnixServer(str(sock), _H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    _H.seen = []
    _H.mode = "ok"
    yield sock
    srv.shutdown()
    srv.server_close()


def test_chat_items_keep_their_json_constraint_and_report_tokens(engine):
    g = E.generate({"messages": [{"role": "user", "content": "q"}]},
                   {"response_format": {"type": "json_object"}, "max_tokens": 32, "seed": 7}, "ab" * 32, sock=engine,
                   prompt_cache=True)
    assert (g.text, g.input_tokens, g.output_tokens, g.model_sha, g.confidence) == ('{"title": "X"}', 40, 7, "ab" * 32, None)
    path, body = _H.seen[0]
    assert path == "/v1/chat/completions" and body["json_schema"] == {"type": "object"}
    assert body["max_tokens"] == 32 and body["seed"] == 7 and body["temperature"] == 0.0 and body["cache_prompt"] is True


def test_prompt_items_with_labels_are_constrained_to_the_labels(engine):
    g = E.generate({"prompt": "Is it?"}, {"response_format": {"type": "labels", "labels": ["yes", "no"]}}, "cd" * 32,
                   sock=engine)
    assert (g.text, g.input_tokens, g.output_tokens) == ("yes", 12, 1)
    path, body = _H.seen[0]
    assert path == "/completion" and body["grammar"] == 'root ::= "yes" | "no"' and body["n_predict"] == 512


def test_a_schema_is_passed_as_a_schema_never_as_a_runtime_object():
    schema = {"type": "object", "properties": {"isbn": {"type": "string"}}, "required": ["isbn"]}
    _, body = E.request_body({"prompt": "p"}, {"response_format": {"type": "json_schema", "schema": schema},
                                               "repeat_penalty": 1.1})
    assert body["json_schema"] == schema and body["repeat_penalty"] == 1.1
    json.dumps(body)                                                      # serialisable end to end


def test_a_malformed_item_or_empty_labels_fail_loudly():
    with pytest.raises(RuntimeError, match="split_engine_bad_item"):
        E.request_body({"nothing": 1}, {})
    with pytest.raises(RuntimeError, match="labels_empty"):
        E.request_body({"prompt": "p"}, {"response_format": {"type": "labels", "labels": []}})


def test_the_engine_is_ready_only_for_the_launchers_unexpired_plan(engine, tmp_path):
    lr = tmp_path / "engine.json"
    assert E.status(last_result=lr, sock=engine) == {"plan_id": None, "ready": False}           # nothing started
    lr.write_text(json.dumps({"plan_id": "sp-1", "role": "coordinator", "result": "ok", "code": "engine_started",
                              "expires_at": int(time.time()) + 600}))
    assert E.status(last_result=lr, sock=engine) == {"plan_id": "sp-1", "ready": True}
    assert E.status(last_result=lr, sock=engine, now=time.time() + 700)["ready"] is False      # expired
    assert E.status(last_result=lr, sock=tmp_path / "absent.sock")["ready"] is False           # not answering
    lr.write_text(json.dumps({"plan_id": "sp-1", "role": "stage", "result": "ok", "code": "stage_started",
                              "expires_at": int(time.time()) + 600}))
    assert E.status(last_result=lr, sock=engine)["ready"] is False                              # not a coordinator


def test_the_prompt_cache_is_used_only_when_the_backend_flags_a_production_item():
    assert E.request_body({"prompt": "p"}, {}, prompt_cache=True)[1]["cache_prompt"] is True
    assert E.request_body({"prompt": "p"}, {}, prompt_cache=False)[1]["cache_prompt"] is False   # verification
    assert E.request_body({"prompt": "p"}, {})[1]["cache_prompt"] is False                       # unflagged -> cold


# ---- M3 A2/A3: chain faults are a closed code, never engine text, never a partial answer ----

CHAT = ({"messages": [{"role": "user", "content": "q"}]}, {})
PROMPT = ({"prompt": "p"}, {})


@pytest.mark.parametrize("item", [CHAT, PROMPT])
def test_an_engine_5xx_is_a_chain_fault_with_the_bare_code(engine, item):
    _H.mode = "500"
    with pytest.raises(E.SplitInfraError) as e:
        E.generate(item[0], item[1], "ab" * 32, sock=engine)
    assert e.value.code == "split_engine_error" and str(e.value) == "split_engine_error"


@pytest.mark.parametrize("item", [CHAT, PROMPT])
def test_a_cut_short_generation_is_never_a_result(engine, item):
    _H.mode = "cut"
    with pytest.raises(E.SplitInfraError) as e:
        E.generate(item[0], item[1], "ab" * 32, sock=engine)
    assert e.value.code == "split_engine_error"


def test_a_4xx_is_the_items_own_fault_not_the_chains(engine):
    _H.mode = "400"
    with pytest.raises(RuntimeError) as e:
        E.generate(*CHAT, "ab" * 32, sock=engine)
    assert not isinstance(e.value, E.SplitInfraError) and str(e.value) == "split_engine_http_400"


def test_a_missing_socket_is_engine_down(tmp_path):
    with pytest.raises(E.SplitInfraError) as e:
        E.generate(*CHAT, "ab" * 32, sock=tmp_path / "gone.sock", timeout=2)
    assert e.value.code == "split_engine_down"


def test_only_the_closed_codes_exist():
    with pytest.raises(AssertionError):
        E.SplitInfraError("split_engine_said_hello")


def test_the_worker_reports_a_chain_fault_as_the_bare_code():
    """The generate path forwards ONLY the closed code (the backend's infra rule keys on it)."""
    import inspect
    from meshembed_node import worker
    src = inspect.getsource(worker)
    assert 'raise _se.SplitInfraError("split_engine_down")' in src
    assert 'if _code in ("split_stage_unreachable", "split_engine_down", "split_engine_error"):' in src
    assert "error = _code" in src
    assert tuple(E.INFRA_CODES) == ("split_stage_unreachable", "split_engine_down", "split_engine_error")
