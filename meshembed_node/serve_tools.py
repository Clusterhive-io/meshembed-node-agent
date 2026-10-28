"""M8 (auditor A8 design GO 2026-10-23 05:43Z, T1-T9 + K1-K8): built-in tools in the serve loop.

When the router marks a request "tools" (the catalogue says the pinned model supports tools: K8, a reviewed field,
never a node claim; and the caller asked for builtin_tools), the node offers the model exactly three tools -- calc,
table, dates -- through llama-server's native tool calling. The model returns tool_calls; OUR evaluator computes them
(tools_eval.py, in a child process with rlimits); the results go back as tool messages; the model writes the answer.

Bounds (T5, K5, K6):
  - at most MAX_ROUNDS tool rounds, then one last call WITHOUT tools, so the model must answer;
  - at most MAX_CALLS_PER_ROUND calls a round (the rest get "too_many_calls");
  - every call: CALL_TIMEOUT_S wall clock in a child with RLIMIT_CPU/AS/FSIZE/NPROC/NOFILE/CORE;
  - all calls together: TOOL_BUDGET_S; the whole request: the caller's deadline;
  - results <= tools_eval.RESULT_MAX_CHARS before they enter the context.
Tables (K3): ONLY fenced ```csv blocks of the request's own messages (an explicit data block, never a scan of free
text), at most TABLE_MAX_BLOCKS; the call names one by number (1 = the first).
Content-free (T7, T9): the log line is the tool name, the closed code and the duration. No argument, result, table or
column name is logged or sent to the backend; the backend gets the usual completion + usage.

Linux only for now (the serve unit is): elsewhere available() is False and the request runs without tools.
"""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import tools_eval as E

log = logging.getLogger("meshembed.serve_tools")

MAX_ROUNDS = 4
MAX_CALLS_PER_ROUND = 4
CALL_TIMEOUT_S = 3.0
TOOL_BUDGET_S = 10.0
EVAL_SCRIPT = Path(E.__file__).resolve()
# Scan caps (auditor 07:30Z FIX 1): the daemon parses request text OUTSIDE the child, so the scan is linear and
# bounded: at most SCAN_MESSAGES messages, SCAN_CHARS characters of each.
SCAN_MESSAGES = 200
SCAN_CHARS = E.TABLE_MAX_BLOCKS * E.TABLE_MAX_BYTES + 64 * 1024
_CALL_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")

# K1: what the model is offered -- the same closed set tools_eval.SCHEMAS enforces
TOOL_DEFS: List[Dict[str, Any]] = [
    {"type": "function", "function": {
        "name": "calc",
        "description": "Exact decimal arithmetic. Operators + - * / and parentheses, postfix % (15% = 0.15), "
                       "functions round(x, n) (half-up, n 0..10), min, max, sum, avg, abs. No powers. "
                       "Example: round((1250.40 * 3 - 10%) * 1.21, 2)",
        "parameters": {"type": "object", "properties": {"expression": {"type": "string"}},
                       "required": ["expression"], "additionalProperties": False}}},
    {"type": "function", "function": {
        "name": "table",
        "description": "Aggregate a CSV table given in the conversation as a fenced ```csv block (table 1 = the "
                       "first block). column, column2 and label must be EXACT header names; no expressions. ops: "
                       "sum, avg, count, min, max, argmin, argmax (needs label = the column to report), sum_product "
                       "(column * column2 per row, summed: use it for units x price). where: a LIST of up to 4 "
                       "objects {column, cmp (= != < <= > >=), value}, never a text condition. Numbers use '.' "
                       "unless decimal=','. Example: {\"op\": \"sum_product\", \"column\": \"units\", "
                       "\"column2\": \"unit_price\", \"where\": [{\"column\": \"region\", \"cmp\": \"=\", "
                       "\"value\": \"north\"}]}",
        "parameters": {"type": "object", "properties": {
            "op": {"type": "string", "enum": list(E.TABLE_OPS)},
            "column": {"type": "string"}, "column2": {"type": "string"}, "label": {"type": "string"},
            "where": {"type": "array", "maxItems": E.TABLE_MAX_WHERE, "items": {
                "type": "object", "properties": {"column": {"type": "string"},
                                                 "cmp": {"type": "string", "enum": list(E.TABLE_CMPS)},
                                                 "value": {"type": ["string", "number"]}},
                "required": ["column", "cmp", "value"], "additionalProperties": False}},
            "table": {"type": "integer", "minimum": 1, "maximum": E.TABLE_MAX_BLOCKS},
            "delimiter": {"type": "string", "enum": list(E.DELIMITERS)},
            "decimal": {"type": "string", "enum": list(E.DECIMALS)}},
            "required": ["op"], "additionalProperties": False}}},
    {"type": "function", "function": {
        "name": "dates",
        "description": "Calendar arithmetic on ISO dates (YYYY-MM-DD). ops: add_days, add_business_days "
                       "(Mon-Fri, skipping the given holidays), days_between, business_days_between, weekday.",
        "parameters": {"type": "object", "properties": {
            "op": {"type": "string", "enum": list(E.DATES_OPS)},
            "date": {"type": "string"}, "date2": {"type": "string"},
            "n": {"type": "integer", "minimum": -E.DATES_MAX_N, "maximum": E.DATES_MAX_N},
            "holidays": {"type": "array", "maxItems": E.DATES_MAX_HOLIDAYS, "items": {"type": "string"}}},
            "required": ["op", "date"], "additionalProperties": False}}},
]


def available() -> bool:
    return sys.platform.startswith("linux")


def _fence_open(line: str) -> bool:
    return line.startswith("```") and line[3:].strip(" \t").lower() == "csv"


def _fence_close(line: str) -> bool:
    return line.startswith("```") and not line[3:].strip(" \t")


def extract_tables(messages: List[Dict[str, Any]]) -> List[Optional[str]]:
    """The request's explicit data blocks, in order: fenced ```csv blocks of system/user messages (the opening line is
    exactly ```csv, the closing line exactly ```, both at column 0). ONE linear pass over each message's lines; a
    block over the byte cap is kept as None (a call on it gets table_too_large); an unclosed block is not a table;
    at most TABLE_MAX_BLOCKS blocks, SCAN_MESSAGES messages, SCAN_CHARS characters a message."""
    out: List[Optional[str]] = []
    scanned = 0
    for m in messages:
        if not isinstance(m, dict) or m.get("role") not in ("system", "user"):
            continue
        scanned += 1
        if scanned > SCAN_MESSAGES:
            break
        c = m.get("content")
        if not isinstance(c, str) or "```" not in c:
            continue
        block: Optional[List[str]] = None
        size = 0
        for line in c[:SCAN_CHARS].split("\n"):
            bare = line[:-1] if line.endswith("\r") else line
            if block is None:
                if _fence_open(bare):
                    block, size = [], 0
                continue
            if _fence_close(bare):
                out.append("".join(block) if size <= E.TABLE_MAX_BYTES else None)
                block = None
                if len(out) >= E.TABLE_MAX_BLOCKS:
                    return out
                continue
            size += len(line.encode("utf-8", "surrogatepass")) + 1
            if size <= E.TABLE_MAX_BYTES:
                block.append(line + "\n")
    return out


def run_child(name: str, args: Dict[str, Any], block: Optional[str], timeout: float) -> Dict[str, str]:
    """One evaluation in a fresh `python -I` child (rlimits set by the child before it reads input). Never raises.
    stdin and stdout MUST be pipes (capture_output): the child's seccomp filter allows write on fds 1-2 only as plain
    writes, and a file-backed stdout makes a system call outside the list, so the child is killed (auditor 07:42Z)."""
    payload = json.dumps({"tool": name, "args": args, "block": block}, ensure_ascii=False).encode("utf-8",
                                                                                                  "surrogatepass")
    try:
        p = subprocess.run([sys.executable, "-I", str(EVAL_SCRIPT)], input=payload, capture_output=True,
                           timeout=max(0.1, timeout), env={"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8"},
                           cwd="/", close_fds=True)
    except subprocess.TimeoutExpired:
        return {"error": "tool_timeout"}
    except OSError:
        return {"error": "tool_failed"}
    if p.returncode != 0:
        return {"error": "tool_timeout" if p.returncode in (-9, -24, 152) else "tool_failed"}
    try:
        out = json.loads(p.stdout[:E.RESULT_MAX_CHARS * 4 + 256])
    except ValueError:
        return {"error": "tool_failed"}
    if isinstance(out, dict) and set(out) == {"error"} and out["error"] in E.CODES:
        return {"error": out["error"]}
    if isinstance(out, dict) and set(out) == {"result"} and isinstance(out["result"], str) \
            and len(out["result"]) <= E.RESULT_MAX_CHARS:
        return {"result": out["result"]}
    return {"error": "tool_failed"}


def call_tool(fn: Any, tables: List[Optional[str]], timeout: float,
              child: Callable[..., Dict[str, str]] = run_child,
              allowed: Optional[frozenset] = None) -> Tuple[str, Dict[str, str]]:
    """(tool name for the log, result dict). fn = the tool call's "function" object as the model wrote it.
    `allowed`: the tools this request may use (AR1 T-a: a definition's subset); any other name is unknown_tool."""
    name = fn.get("name") if isinstance(fn, dict) else None
    if allowed is not None and name not in allowed:
        return "unknown", {"error": "unknown_tool"}
    shown = name if name in E.SCHEMAS else "unknown"
    try:
        args = E.parse_arguments(name, fn.get("arguments") if isinstance(fn, dict) else None)
    except E.ToolError as e:
        return shown, {"error": e.code}
    block = None
    if name == "table":
        k = args.get("table", 1)
        if not 1 <= k <= E.TABLE_MAX_BLOCKS or k > len(tables):
            return shown, {"error": "no_table"}
        block = tables[k - 1]
        if block is None:
            return shown, {"error": "table_too_large"}
    return shown, child(name, args, block, timeout)


def _clean_calls(calls: Any) -> List[Dict[str, Any]]:
    """The assistant's tool_calls as we echo them back into the conversation: our shape, bounded."""
    out = []
    for i, c in enumerate(calls if isinstance(calls, list) else []):
        fn = c.get("function") if isinstance(c, dict) else None
        fn = fn if isinstance(fn, dict) else {}
        cid = c.get("id") if isinstance(c, dict) else None
        name = fn.get("name") if isinstance(fn.get("name"), str) else ""
        args = fn.get("arguments")
        args = args if isinstance(args, str) else json.dumps(args if isinstance(args, dict) else {})
        try:                                     # invalid JSON would fail the template on the next round
            ok = len(args) <= E.MAX_ARGS_BYTES and isinstance(json.loads(args), dict)
        except (ValueError, RecursionError):
            ok = False
        args = args if ok else "{}"
        out.append({"id": cid if isinstance(cid, str) and _CALL_ID.match(cid) else f"call_{i}",
                    "type": "function",
                    "function": {"name": name[:32], "arguments": args}})
    return out


def _usage_add(total: Dict[str, int], out: Any) -> None:
    u = out.get("usage") if isinstance(out, dict) else None
    if not isinstance(u, dict):
        return
    for k in ("prompt_tokens", "completion_tokens"):
        v = u.get(k)
        if isinstance(v, int) and not isinstance(v, bool) and v >= 0:
            total[k] = total.get(k, 0) + v


def run_with_tools(body: Dict[str, Any], forward: Callable[[Dict[str, Any], float], Tuple[bool, Any]], *,
                   deadline_s: float = 110.0, child: Callable[..., Dict[str, str]] = run_child,
                   clock: Callable[[], float] = time.monotonic,
                   report: Optional[Dict[str, int]] = None,
                   tools: Optional[Any] = None) -> Tuple[bool, Any]:
    """(True, completion) / (False, closed code), as serve_client.forward. `forward(body, timeout)`.
    A request that already carries tools, a tool_choice or tool messages is run as given (no tools of ours mixed in;
    the router refuses such requests anyway). `report`, when given, receives {"rounds": n}: the tool rounds that
    ran (0..MAX_ROUNDS) and {"calls": n}, sent to the backend beside the completion: usage is clamped to rounds + 1
    model calls (auditor 2026-10-23 07:42Z residual) and an agent run counts its tool calls (AR1 T-b). Never part of
    the completion. `tools`: the tool names this request may use (AR1 T-a: an agent definition's subset); None = all
    three. Only those are offered, and any other name the model calls gets unknown_tool."""
    msgs = body.get("messages") if isinstance(body.get("messages"), list) else []
    if any(k in body for k in ("tools", "tool_choice", "functions")) or \
            any(isinstance(m, dict) and (m.get("role") == "tool" or "tool_calls" in m) for m in msgs):
        return forward(body, deadline_s)
    allowed = frozenset(E.TOOLS) if tools is None else frozenset(t for t in tools if t in E.TOOLS)
    if not allowed:
        return forward(body, deadline_s)
    offered = [d for d in TOOL_DEFS if d["function"]["name"] in allowed]
    t_end = clock() + deadline_s
    tool_left = TOOL_BUDGET_S
    tables = extract_tables(msgs)
    convo = list(msgs)
    usage: Dict[str, int] = {}
    stats = {"calls": 0, "errors": 0, "rounds": 0}
    for rnd in range(MAX_ROUNDS + 1):
        req = dict(body)
        req["messages"] = convo
        req["stream"] = False
        if rnd < MAX_ROUNDS:
            req["tools"] = offered
            req["tool_choice"] = "auto"
        remaining = t_end - clock()
        if remaining <= 1.0:
            return False, "engine_error"
        ok, out = forward(req, remaining)
        if not ok:
            return ok, out
        _usage_add(usage, out)
        try:
            choice = out["choices"][0]
            msg = choice["message"]
        except (KeyError, IndexError, TypeError):
            return False, "engine_error"
        calls = msg.get("tool_calls") if isinstance(msg, dict) else None
        if rnd == MAX_ROUNDS or not calls:
            if report is not None:
                report["rounds"] = stats["rounds"]
                report["calls"] = stats["calls"]
            final = dict(out)
            if isinstance(msg, dict) and "tool_calls" in msg:
                m2 = {k: v for k, v in msg.items() if k != "tool_calls"}
                final["choices"] = [dict(choice, message=m2)] + list(out["choices"][1:])
            if usage:
                u = dict(final.get("usage") or {})
                u.update(prompt_tokens=usage.get("prompt_tokens", 0),
                         completion_tokens=usage.get("completion_tokens", 0))
                u["total_tokens"] = u["prompt_tokens"] + u["completion_tokens"]
                final["usage"] = u
            if stats["calls"]:
                log.info("serve.tools rounds=%d calls=%d errors=%d", stats["rounds"], stats["calls"],
                         stats["errors"])
            return True, final
        stats["rounds"] += 1
        echoed = _clean_calls(calls)
        raw = [c.get("function") if isinstance(c, dict) else None for c in calls] if isinstance(calls, list) else []
        convo = convo + [{"role": "assistant", "content": msg.get("content") or "", "tool_calls": echoed}]
        for i, c in enumerate(echoed):
            if i >= MAX_CALLS_PER_ROUND:
                res, shown = {"error": "too_many_calls"}, "skipped"
            elif tool_left <= 0.1:
                res, shown = {"error": "tool_timeout"}, "skipped"
            else:
                t0 = clock()
                shown, res = call_tool(raw[i], tables, min(CALL_TIMEOUT_S, tool_left,
                                                                   max(0.1, t_end - clock() - 2.0)), child, allowed)
                dt = clock() - t0
                tool_left -= dt
                log.info("serve.tool %s %s %dms", shown, res.get("error", "ok"), int(dt * 1000))   # T7: no content
            stats["calls"] += 1
            stats["errors"] += "error" in res
            convo.append({"role": "tool", "tool_call_id": c["id"], "content": json.dumps(res, ensure_ascii=False)})
    return False, "engine_error"                                   # not reached: the last round has no tools
