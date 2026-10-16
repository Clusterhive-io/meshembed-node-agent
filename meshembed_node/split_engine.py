"""M2 build #5b, daemon side: run an item of a split plan on that plan's ENGINE.

The engine is the Build-B llama-server the ROOT launcher started for the plan (unit
meshembed-di-engine) on a UNIX socket (/run/mesh-di-engine/engine.sock, group mesh-di-sock,
which the daemon's user is in). There is no TCP listener; the daemon talks HTTP over the socket.

- status(): {"plan_id", "ready"} for hardware_info.split.engine -- ready only when the root
  launcher's last-result says THIS node's engine was started for that plan, the plan has not
  expired, and the socket answers /health. The backend routes a split job's items here only
  then (store.split_jobs_for_coordinator).
- generate(): one item -> Generation (same shape the single-node runner returns), with the
  plan's model sha. `messages` -> chat endpoint, `prompt` -> completion endpoint; the same
  parameters the single-node runner honours, in llama-server's own terms: json_object -> an
  object schema, json_schema -> that schema, labels -> a GBNF alternation of the labels (the
  answer is constrained exactly as before). Confidence is None on this path (not computed).
- The per-job prompt cache (E3a) is used only for items the BACKEND flags as production
  (assignment.prompt_cache); verification items and unflagged items run cold (orchestrator Q2).
  The engine lives for one plan = one job, so the cache never spans jobs or clients (auditor).
"""
from __future__ import annotations

import http.client
import json
import socket
import time
from pathlib import Path
from typing import Any, Dict, Optional

SOCKET = Path("/run/mesh-di-engine/engine.sock")
INFRA_CODES = ("split_stage_unreachable", "split_engine_down", "split_engine_error")


class SplitInfraError(RuntimeError):
    """M3 A2: the CHAIN failed, not the item. `code` is one of INFRA_CODES and is all that is
    reported (never the engine's own text); the backend re-queues the item without burning its
    retry and loses the plan after K of these in a row."""

    def __init__(self, code: str):
        assert code in INFRA_CODES
        super().__init__(code)
        self.code = code
LAST_RESULT = Path("/var/lib/meshembed-split-launch/engine.json")      # written by the ROOT launcher


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float):
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self._path)
        self.sock = s


def _request(method: str, path: str, body: Optional[dict], *, sock: Path, timeout: float) -> Dict[str, Any]:
    c = _UnixHTTPConnection(str(sock), timeout)
    try:
        payload = json.dumps(body).encode() if body is not None else None
        try:
            c.request(method, path, body=payload, headers={"Content-Type": "application/json"} if payload else {})
            r = c.getresponse()
            data = r.read()
        except (OSError, http.client.HTTPException):
            # socket gone / refused / reset / timed out: the engine (or, through its rpc client
            # aborting, a stage) is down -- a chain fault (M3 A2)
            raise SplitInfraError("split_engine_down")
        if r.status >= 500:
            raise SplitInfraError("split_engine_error")
        if r.status != 200:
            raise RuntimeError(f"split_engine_http_{r.status}")       # 4xx: the item's own fault
        try:
            return json.loads(data or b"{}")
        except ValueError:
            raise SplitInfraError("split_engine_error")
    finally:
        c.close()


def status(*, last_result: Path = LAST_RESULT, sock: Path = SOCKET, now: Optional[float] = None) -> Dict[str, Any]:
    now = time.time() if now is None else now
    try:
        lr = json.loads(last_result.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"plan_id": None, "ready": False}
    if lr.get("role") != "coordinator" or lr.get("code") != "engine_started" or lr.get("result") != "ok":
        return {"plan_id": None, "ready": False}
    pid = lr.get("plan_id") if isinstance(lr.get("plan_id"), str) else None
    if not pid or int(lr.get("expires_at") or 0) <= now:
        return {"plan_id": pid, "ready": False}
    try:
        h = _request("GET", "/health", None, sock=sock, timeout=3)
        ok = h.get("status") == "ok"
    except Exception:
        ok = False
    return {"plan_id": pid, "ready": ok}


def _labels_gbnf(labels) -> str:
    if not labels:
        raise RuntimeError("labels_empty")
    def q(l):
        return '"' + str(l).replace('\\', '\\\\').replace('"', '\\"') + '"'
    return "root ::= " + " | ".join(q(l) for l in labels)


def request_body(item: Dict[str, Any], params: Dict[str, Any], *, prompt_cache: bool = False) -> tuple:
    """(endpoint, body) for one item -- the same parameters the single-node runner honours,
    expressed in llama-server's own terms (schemas / GBNF strings, no runtime objects)."""
    params = params or {}
    fmt = params.get("response_format") or {}
    kind = fmt.get("type")
    # Q2 (orchestrator 12:59Z): the per-job prompt cache only when the BACKEND says this is a
    # production item; verification items (canaries, twins) and anything unflagged run cold.
    common: Dict[str, Any] = {"temperature": float(params.get("temperature", 0.0)),
                              "cache_prompt": prompt_cache is True}
    if "top_p" in params:
        common["top_p"] = float(params["top_p"])
    if params.get("stop"):
        common["stop"] = list(params["stop"])
    if params.get("seed") is not None:
        common["seed"] = int(params["seed"])
    for key in ("repeat_penalty", "frequency_penalty", "presence_penalty"):
        if params.get(key) is not None:
            common[key] = float(params[key])
    if kind == "json_object":
        common["json_schema"] = {"type": "object"}
    elif kind == "json_schema":
        common["json_schema"] = fmt.get("schema") or {}
    elif kind == "labels":
        common["grammar"] = _labels_gbnf(list(fmt.get("labels") or []))
    max_tokens = int(params.get("max_tokens", 512))
    if item.get("messages"):
        return "/v1/chat/completions", dict(common, messages=item["messages"], max_tokens=max_tokens)
    if isinstance(item.get("prompt"), str):
        return "/completion", dict(common, prompt=item["prompt"], n_predict=max_tokens)
    raise RuntimeError("split_engine_bad_item")


def generate(item: Dict[str, Any], params: Dict[str, Any], model_sha: str, *, sock: Path = SOCKET,
             timeout: float = 900, prompt_cache: bool = False) -> "Any":
    from .llm import Generation
    endpoint, body = request_body(item, params, prompt_cache=prompt_cache)
    t0 = time.perf_counter()
    r = _request("POST", endpoint, body, sock=sock, timeout=timeout)
    # M3 A3: only a COMPLETE generation is ever reported as a result; anything cut short is a
    # chain fault, never a partial answer.
    if endpoint == "/v1/chat/completions":
        try:
            ch = r["choices"][0]
            text = (ch["message"].get("content") or "")
        except (KeyError, IndexError, TypeError, AttributeError):
            raise SplitInfraError("split_engine_error")
        if ch.get("finish_reason") not in ("stop", "length"):
            raise SplitInfraError("split_engine_error")
        usage = r.get("usage") or {}
        tin, tout = int(usage.get("prompt_tokens") or 0), int(usage.get("completion_tokens") or 0)
    else:
        if r.get("stop") is not True or not isinstance(r.get("content"), str):
            raise SplitInfraError("split_engine_error")
        text = r.get("content") or ""
        tm = r.get("timings") or {}
        tin = int(tm.get("prompt_n") or r.get("tokens_evaluated") or 0)
        tout = int(tm.get("predicted_n") or r.get("tokens_predicted") or 0)
    return Generation(text=text, input_tokens=tin, output_tokens=tout, seconds=time.perf_counter() - t0,
                      model_sha=model_sha, confidence=None)
