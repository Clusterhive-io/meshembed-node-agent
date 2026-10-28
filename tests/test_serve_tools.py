"""M8 tool loop in the serve path (auditor A8: T5, T7, T9, K1, K5, K6)."""
import json
import logging

import pytest

from meshembed_node import serve_client, serve_tools as S, tools_eval as E

SECRET = "Customer Smith owes 1234.56"


def completion(content=None, tool_calls=None, p=10, c=5):
    msg = {"role": "assistant", "content": content}
    if tool_calls is not None:
        msg["tool_calls"] = tool_calls
    return {"id": "x", "choices": [{"index": 0, "message": msg, "finish_reason": "tool_calls" if tool_calls else "stop"}],
            "usage": {"prompt_tokens": p, "completion_tokens": c, "total_tokens": p + c}}


def call(name, args, cid="c1"):
    return {"id": cid, "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}


class Engine:
    """A fake llama-server: returns the scripted completions in order and records what it was sent."""

    def __init__(self, *outs):
        self.outs, self.sent = list(outs), []

    def __call__(self, body, timeout):
        self.sent.append(json.loads(json.dumps(body)))
        return True, self.outs.pop(0)


def body(content="What is 2*21?"):
    return {"model": "m", "messages": [{"role": "user", "content": content}], "max_tokens": 64}


def test_one_round_real_child():
    eng = Engine(completion(tool_calls=[call("calc", {"expression": "2*21"})]), completion("42"))
    ok, out = S.run_with_tools(body(), eng)
    assert ok and out["choices"][0]["message"]["content"] == "42"
    assert eng.sent[0]["tools"] == S.TOOL_DEFS and eng.sent[0]["tool_choice"] == "auto"
    tool_msg = eng.sent[1]["messages"][-1]
    assert tool_msg == {"role": "tool", "tool_call_id": "c1", "content": json.dumps({"result": "42"})}
    assert eng.sent[1]["messages"][-2]["tool_calls"][0]["function"]["name"] == "calc"
    assert out["usage"] == {"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 30}   # summed rounds


def test_rounds_capped_then_one_call_without_tools():
    loops = [completion(tool_calls=[call("calc", {"expression": "1"})]) for _ in range(S.MAX_ROUNDS)]
    eng = Engine(*loops, completion("done", tool_calls=[call("calc", {"expression": "1"})]))
    ok, out = S.run_with_tools(body(), eng, child=lambda *a: {"result": "1"})
    assert ok and len(eng.sent) == S.MAX_ROUNDS + 1
    assert "tools" not in eng.sent[-1] and "tool_choice" not in eng.sent[-1]
    assert "tool_calls" not in out["choices"][0]["message"]                 # never handed to the customer


def test_calls_per_round_capped():
    many = [call("calc", {"expression": "1"}, f"c{i}") for i in range(S.MAX_CALLS_PER_ROUND + 2)]
    eng = Engine(completion(tool_calls=many), completion("ok"))
    ran = []
    ok, _ = S.run_with_tools(body(), eng, child=lambda *a: ran.append(1) or {"result": "1"})
    tools = [m for m in eng.sent[1]["messages"] if m["role"] == "tool"]
    assert len(ran) == S.MAX_CALLS_PER_ROUND and len(tools) == len(many)
    assert [json.loads(t["content"]) for t in tools[-2:]] == [{"error": "too_many_calls"}] * 2


def test_tool_budget_shared_across_calls():
    t = [0.0]
    clock = lambda: t[0]

    def slow_child(*a):
        t[0] += 6.0
        return {"result": "1"}
    eng = Engine(completion(tool_calls=[call("calc", {"expression": "1"}, f"c{i}") for i in range(3)]),
                 completion("ok"))
    S.run_with_tools(body(), eng, child=slow_child, clock=clock)
    res = [json.loads(m["content"]) for m in eng.sent[1]["messages"] if m["role"] == "tool"]
    assert res == [{"result": "1"}, {"result": "1"}, {"error": "tool_timeout"}]     # 10 s budget


def test_deadline_ends_the_loop():
    t = [0.0]
    eng = Engine(completion(tool_calls=[call("calc", {"expression": "1"})]), completion("ok"))

    def fwd(b, timeout):
        t[0] += 200.0
        return eng(b, timeout)
    assert S.run_with_tools(body(), fwd, child=lambda *a: {"result": "1"}, clock=lambda: t[0]) == \
        (False, "engine_error")


def test_hostile_calls_get_closed_codes():
    calls = [{"id": "a", "type": "function", "function": {"name": "os.system", "arguments": "{}"}},
             {"id": "b", "type": "function", "function": {"name": "calc", "arguments": "{\"expression\": \"__import__\"}"}},
             {"id": "c", "type": "function", "function": {"name": "calc", "arguments": "not json"}},
             {"id": "../../etc", "type": "function", "function": {"name": "table", "arguments": "{\"op\": \"sum\"}"}}]
    eng = Engine(completion(tool_calls=calls), completion("ok"))
    S.run_with_tools(body(), eng)
    msgs = eng.sent[1]["messages"]
    res = [json.loads(m["content"]) for m in msgs if m["role"] == "tool"]
    assert res == [{"error": "unknown_tool"}, {"error": "bad_expression"}, {"error": "bad_arguments"},
                   {"error": "no_table"}]
    echoed = msgs[-5]["tool_calls"]
    assert echoed[2]["function"]["arguments"] == "{}"                     # invalid JSON never echoed to the template
    assert echoed[3]["id"] == "call_3"                                    # an id outside the pattern is replaced


def test_table_comes_only_from_a_fenced_csv_block():
    text = "Totals please.\n```csv\nitem,amount\nA,2.50\nB,4\n```\nand 9,9,9 in prose is not a table"
    eng = Engine(completion(tool_calls=[call("table", {"op": "sum", "column": "amount"}),
                                        call("table", {"op": "sum", "column": "amount", "table": 2}, "c2")]),
                 completion("6.50"))
    S.run_with_tools(body(text), eng)
    res = [json.loads(m["content"]) for m in eng.sent[1]["messages"] if m["role"] == "tool"]
    assert res == [{"result": "6.50"}, {"error": "no_table"}]


def test_extract_tables_bounds():
    big = "```csv\na\n" + "1\n" * (E.TABLE_MAX_BYTES // 2 + 10) + "```"
    msgs = [{"role": "assistant", "content": "```csv\nx\n1\n```"},              # not from the caller: ignored
            {"role": "user", "content": big},
            {"role": "user", "content": "".join(f"```csv\nc\n{i}\n```\n" for i in range(12))}]
    t = S.extract_tables(msgs)
    assert len(t) == E.TABLE_MAX_BLOCKS and t[0] is None and t[1] == "c\n0\n"
    eng = Engine(completion(tool_calls=[call("table", {"op": "sum", "column": "a"})]), completion("x"))
    S.run_with_tools({"messages": msgs}, eng)
    assert json.loads(eng.sent[1]["messages"][-1]["content"]) == {"error": "table_too_large"}


def test_request_with_its_own_tools_runs_as_given():
    b = dict(body(), tools=[{"type": "function", "function": {"name": "x"}}])
    eng = Engine(completion("plain"))
    ok, out = S.run_with_tools(b, eng)
    assert eng.sent == [b] and out["choices"][0]["message"]["content"] == "plain"
    b2 = {"messages": [{"role": "tool", "content": "x", "tool_call_id": "1"}]}
    eng2 = Engine(completion("plain"))
    S.run_with_tools(b2, eng2)
    assert eng2.sent == [b2]


def test_no_tool_call_is_one_plain_round():
    eng = Engine(completion("hello"))
    ok, out = S.run_with_tools(body(), eng)
    assert ok and len(eng.sent) == 1 and out["usage"]["total_tokens"] == 15


def test_engine_failure_passes_through():
    assert S.run_with_tools(body(), lambda b, t: (False, "engine_down")) == (False, "engine_down")
    assert S.run_with_tools(body(), lambda b, t: (True, {"choices": []})) == (False, "engine_error")


def test_logs_are_content_free(caplog):
    caplog.set_level(logging.DEBUG)
    text = f"{SECRET}\n```csv\nname,owed\nSmith,1234.56\n```"
    eng = Engine(completion(tool_calls=[call("table", {"op": "argmax", "column": "owed", "label": "name"}),
                                        call("calc", {"expression": "1234.56 * 2"}, "c2"),
                                        call("table", {"op": "sum", "column": "Smith"}, "c3")]),
                 completion("Smith owes most"))
    S.run_with_tools(body(text), eng)
    logged = " ".join(r.getMessage() for r in caplog.records)
    assert "serve.tool table ok" in logged and "serve.tool calc ok" in logged and "unknown_column" in logged
    for leak in ("Smith", "1234", "owed", "2469", SECRET):
        assert leak not in logged


def test_real_child_timeout_is_a_closed_code(monkeypatch):
    monkeypatch.setattr(S, "EVAL_SCRIPT", "/bin/does-not-exist.py")
    assert S.run_child("calc", {"expression": "1"}, None, 2.0) == {"error": "tool_failed"}
    assert S.run_child("calc", {"expression": "1"}, None, 0.0001)["error"] in ("tool_timeout", "tool_failed")


def test_child_output_is_revalidated(monkeypatch):
    class P:
        returncode = 0
        stdout = json.dumps({"result": "x" * (E.RESULT_MAX_CHARS + 1)}).encode()
    monkeypatch.setattr(S.subprocess, "run", lambda *a, **k: P())
    assert S.run_child("calc", {"expression": "1"}, None, 1.0) == {"error": "tool_failed"}
    P.stdout = json.dumps({"error": "a stack trace with Smith"}).encode()
    assert S.run_child("calc", {"expression": "1"}, None, 1.0) == {"error": "tool_failed"}


def test_tool_defs_match_the_evaluator_schema():
    for d in S.TOOL_DEFS:
        f = d["function"]
        assert set(f["parameters"]["properties"]) == set(E.SCHEMAS[f["name"]])
        assert set(f["parameters"]["required"]) <= set(E.SCHEMAS[f["name"]])
        assert f["parameters"]["additionalProperties"] is False
    assert [d["function"]["name"] for d in S.TOOL_DEFS] == list(E.TOOLS)


def test_serve_once_uses_tools_only_when_the_router_marks_it(monkeypatch, tmp_path):
    seen = {}
    def fake_tools(b, f, report=None, tools=None):
        seen.setdefault("tools", True)
        seen["allowed"] = tools
        report["rounds"], report["calls"] = 2, 3
        return True, completion("t")
    monkeypatch.setattr(S, "run_with_tools", fake_tools)
    monkeypatch.setattr(serve_client, "forward", lambda b, sock, timeout=110.0: (True, completion("plain")))
    posts = []

    def post(path, js, timeout):
        posts.append((path, js))
        if path == "/nodes/serve/next":
            return 200, {"req_id": "a" * 32, "model": "m", "body": body(), "tools": marker}
        return 200, {}
    for marker, want in ((True, "t"), (False, "plain"), ("yes", "plain"), (None, "plain")):
        seen.clear()
        serve_client.serve_once(post, "n1", ["m"], decide=lambda: (True, ""), sock=tmp_path / "s",
                                stop_path=tmp_path / "r")
        assert posts[-1][1]["completion"]["choices"][0]["message"]["content"] == want
        assert ("tools" in seen) == (marker is True)
        assert posts[-1][1].get("tool_rounds") == (2 if marker is True else None)   # counts, only for tools jobs
        assert posts[-1][1].get("tool_calls") == (3 if marker is True else None)


def test_fence_scan_is_linear():
    """auditor 07:30Z FIX 1: the daemon scans request text outside the child; 1 MiB of unclosed fences < 0.5 s."""
    import time
    hostile = "```csv\n" * (1024 * 1024 // 7)
    t0 = time.monotonic()
    assert S.extract_tables([{"role": "user", "content": hostile}]) == []
    assert time.monotonic() - t0 < 0.5
    t0 = time.monotonic()
    S.extract_tables([{"role": "user", "content": "```csv\n" + "a,b\n" * 300_000 + "```"}] * 50)
    assert time.monotonic() - t0 < 2.0                         # SCAN_CHARS + SCAN_MESSAGES bound the work


def test_fence_rules():
    c = ("```csv\na\n1\n```\n"            # a table
         "  ```csv\nb\n2\n```\n"           # not at column 0: not an opening fence
         "```CSV \r\nc\r\n3\r\n```  \r\n"  # case, trailing blanks and CRLF are fine
         "```csv\nd\n4\n")                 # unclosed: not a table
    assert S.extract_tables([{"role": "user", "content": c}]) == ["a\n1\n", "c\r\n3\r\n"]
    assert S.extract_tables([{"role": "user", "content": "x"}] * (S.SCAN_MESSAGES + 1)
                            + [{"role": "user", "content": "```csv\na\n1\n```"}]) == []


def test_the_table_example_in_the_description_is_valid():
    """auditor 08:28Z note 3: steer the model with an example; the example itself must pass the closed schema."""
    d = [t for t in S.TOOL_DEFS if t["function"]["name"] == "table"][0]["function"]["description"]
    ex = json.loads(d.split("Example: ", 1)[1])
    assert E.parse_arguments("table", json.dumps(ex)) == ex
    assert E.evaluate("table", ex, "item,units,unit_price,region\nA,2,1.50,north\nB,3,2,south\n") == {"result": "3.00"}
    # what Granite wrote on its own in W4 stays refused (closed codes back to the model)
    assert E.evaluate("table", {"op": "sum", "column": "units*unit_price"},
                      "units,unit_price\n1,2\n") == {"error": "unknown_column"}
    with pytest.raises(E.ToolError) as ei:
        E.parse_arguments("table", json.dumps({"op": "sum", "column": "units", "where": "region=north"}))
    assert ei.value.code == "bad_argument_type"


def test_the_round_count_is_reported_beside_the_completion():
    rep = {}
    eng = Engine(completion(tool_calls=[call("calc", {"expression": "1"})]),
                 completion(tool_calls=[call("calc", {"expression": "2"})]), completion("done"))
    ok, out = S.run_with_tools(body(), eng, child=lambda *a: {"result": "1"}, report=rep)
    assert ok and rep == {"rounds": 2, "calls": 2} and "rounds" not in json.dumps(out)   # never in the completion
    rep = {}
    S.run_with_tools(body(), Engine(completion("plain")), report=rep)
    assert rep == {"rounds": 0, "calls": 0}
    rep = {}
    assert S.run_with_tools(body(), lambda b, t: (False, "engine_down"), report=rep) == (False, "engine_down")
    assert rep == {}


def test_t_a_only_the_definitions_tools_are_offered_and_callable():
    """AR1 T-a: a calc-only definition: only calc is offered, and a table call gets unknown_tool."""
    eng = Engine(completion(tool_calls=[call("table", {"op": "count"}), call("calc", {"expression": "2"}, "c2")]),
                 completion("ok"))
    rep = {}
    S.run_with_tools(body(), eng, child=lambda *a: {"result": "2"}, report=rep, tools=["calc"])
    assert [d["function"]["name"] for d in eng.sent[0]["tools"]] == ["calc"]
    res = [json.loads(m["content"]) for m in eng.sent[1]["messages"] if m["role"] == "tool"]
    assert res == [{"error": "unknown_tool"}, {"result": "2"}] and rep == {"rounds": 1, "calls": 2}
    eng2 = Engine(completion("plain"))                                       # an empty / foreign list: no tools
    S.run_with_tools(body(), eng2, tools=["shell"])
    assert "tools" not in eng2.sent[0]


def test_serve_once_passes_a_tool_subset(monkeypatch, tmp_path):
    seen = {}

    def fake_tools(b, f, report=None, tools=None):
        seen["allowed"] = tools
        report["rounds"], report["calls"] = 0, 0
        return True, completion("t")
    monkeypatch.setattr(S, "run_with_tools", fake_tools)
    monkeypatch.setattr(serve_client, "forward", lambda b, sock, timeout=110.0: (True, completion("plain")))
    for spec, want in ((["calc"], ["calc"]), (True, None)):
        serve_client.serve_once(lambda p, j, t: (200, {"req_id": "a" * 32, "model": "m", "body": body(),
                                                         "tools": spec}) if p.endswith("next") else (200, {}),
                                "n1", ["m"], decide=lambda: (True, ""), sock=tmp_path / "s", stop_path=tmp_path / "r")
        assert seen["allowed"] == want
    seen.clear()
    serve_client.serve_once(lambda p, j, t: (200, {"req_id": "a" * 32, "model": "m", "body": body(),
                                                     "tools": [1, 2]}) if p.endswith("next") else (200, {}),
                            "n1", ["m"], decide=lambda: (True, ""), sock=tmp_path / "s", stop_path=tmp_path / "r")
    assert "allowed" not in seen                                              # malformed spec: no tools at all
