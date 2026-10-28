"""AR1 G9, daemon side: the ONLY door between the agent unit and the world (DESIGN_AR1 section 12; auditor G9 design
GO 2026-10-23 13:19Z, A1 = the socket, S1, S2).

The node DAEMON keeps everything that decides (P3): it takes run tickets from the backend, verifies them
(run_ticket_verify), keeps the revocation snapshot fresh, holds the per-agent-host lane key, and talks to the backend.
The agent unit (uid mesh-agent, PrivateNetwork, AF_UNIX only: S1) runs the loop on hostile content and reaches
nothing but this socket.

The socket (S2) is HOSTILE input to the daemon:
  - a closed message set, one JSON object per line, at most MAX_MSG bytes:
      {"op": "next_run"}
      {"op": "step",   "ticket_id", "request"}       -> forwarded to the backend with the lane key the agent never sees
      {"op": "result", "ticket_id", "answer"}        -> forwarded; the run is then forgotten
      {"op": "state",  "ticket_id", "code"}          -> "stopped" + a closed code; forgotten
      {"op": "resume", "ticket_id", "run_id"}        -> back through verify_ticket (G3)
  - every reply is {"ok": ...} or {"code": <closed code>}: never a path, node or store data, nothing about other runs;
  - step / result / state only for a ticket THIS bridge handed to the agent and still holds live;
  - the peer must be the agent uid (SO_PEERCRED); the socket directory is the daemon's, 0750 group mesh-agent, the
    socket 0660.
The task text lives only in this process's memory (and the agent's): never in a file (A1).
INERT: nothing in the worker starts a bridge yet; the wiring comes with the agent-host unit's node release.
"""
from __future__ import annotations

import json
import os
import re
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

from . import run_ticket_verify as V

MAX_MSG = 512 * 1024
MAX_ANSWER_CHARS = 64 * 1024
OPS = ("next_run", "step", "result", "state", "resume")
_TICKET = re.compile(r"^rt-[0-9a-f]{24}$")
_RUN = re.compile(r"^run-[0-9a-f]{24}$")
_CODE = re.compile(r"^[a-z_]{1,40}$")
LANE_HEADER = "X-Agent-Host-Key"

# post(path, json, headers, timeout) -> (status, json-or-None): the daemon's backend call, injected
Post = Callable[[str, Dict[str, Any], Dict[str, str], float], Tuple[int, Any]]


@dataclass
class _Run:
    ticket: Dict[str, Any]           # the envelope as verified (kept for a resume)
    definition: Dict[str, Any]       # the signed definition envelope
    policy: Dict[str, Any]
    task: str
    run_id: str
    body: Dict[str, Any]             # the verified ticket body
    handed: bool = False
    started_at: float = field(default_factory=time.monotonic)


def read_lane_key(path: Path) -> Optional[str]:
    """The per-agent-host lane key, held by the DAEMON only (S1). 0600, owned by us, one line; else None."""
    try:
        st = path.stat()
        if st.st_uid != os.getuid() or st.st_mode & 0o077:
            return None
        k = path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError):
        return None
    return k if re.fullmatch(r"meah_[A-Za-z0-9_-]{20,100}", k) else None


class AgentBridge:
    def __init__(self, *, node_id: str, tenant: str, agent_uid: int, post: Post, lane_key: Callable[[], Optional[str]],
                 verify_ctx: Dict[str, Any], clock: Callable[[], float] = time.time):
        """verify_ctx: the keyword arguments of run_ticket_verify.verify_ticket other than the per-run ones
        (admin_keys, revocations, nonces, policy_versions, and in tests trusted / plan_keys)."""
        self.node_id, self.tenant, self.agent_uid = node_id, tenant, agent_uid
        self.post, self.lane_key, self.ctx, self.clock = post, lane_key, verify_ctx, clock
        self.runs: Dict[str, _Run] = {}
        self.lock = threading.Lock()

    # --- intake from the backend (the daemon's poll loop) ----------------------------------------------------------
    def offer(self, item: Any) -> str:
        """An item from /nodes/agent/next. Verified here (START); "accepted" or the closed rejection code, which is
        also reported to the backend as the run's stop code."""
        try:
            env = item["ticket"]
            out = V.verify_ticket(env, node_id=self.node_id, tenant=self.tenant, task_text=item["task"],
                                  definition=item["definition"], policy=item["policy"], now=self.clock(), **self.ctx)
        except V.TicketRejected as e:
            self._report(item, "stopped", str(e))
            return str(e)
        except (KeyError, TypeError):
            return "bad_item"
        t = out["ticket"]
        if self._report(item, "started", None) != 200:
            return "start_not_recorded"
        with self.lock:
            self.runs[t["ticket_id"]] = _Run(env, item["definition"], item["policy"], item["task"], out["run_id"], t)
        return "accepted"

    def _report(self, item: Any, state: str, code: Optional[str]) -> int:
        try:
            tid = item["ticket"]["ticket"]["ticket_id"]
        except (KeyError, TypeError):
            return 0
        if not (isinstance(tid, str) and _TICKET.fullmatch(tid)):
            return 0
        body = {"state": state} if code is None else {"state": state, "code": code[:40]}
        return self._backend(f"/agent/v1/runs/{tid}/state", body)[0]

    def _backend(self, path: str, body: Dict[str, Any], timeout: float = 130.0) -> Tuple[int, Any]:
        key = self.lane_key()
        if not key:
            return 0, None
        try:
            return self.post(path, body, {LANE_HEADER: key}, timeout)
        except Exception:
            return 0, None

    # --- the socket ------------------------------------------------------------------------------------------------
    def handle(self, raw: bytes) -> Dict[str, Any]:
        """One message from the agent -> one reply. Never raises."""
        if len(raw) > MAX_MSG:
            return {"code": "message_too_large"}
        try:
            m = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, RecursionError):
            return {"code": "bad_message"}
        if not isinstance(m, dict) or m.get("op") not in OPS:
            return {"code": "bad_message"}
        op = m["op"]
        keys = {"next_run": {"op"}, "step": {"op", "ticket_id", "request"}, "result": {"op", "ticket_id", "answer"},
                "state": {"op", "ticket_id", "code"}, "resume": {"op", "ticket_id", "run_id"}}[op]
        if set(m) != keys:
            return {"code": "bad_message"}
        try:
            return getattr(self, "_op_" + op)(m)
        except Exception:
            return {"code": "bridge_error"}

    def _live(self, tid: Any) -> Optional[_Run]:
        if not (isinstance(tid, str) and _TICKET.fullmatch(tid)):
            return None
        with self.lock:
            r = self.runs.get(tid)
        if r is None or not r.handed or r.body["expires_at"] <= self.clock():
            return None
        return r

    def _forget(self, tid: str) -> None:
        with self.lock:
            self.runs.pop(tid, None)

    @staticmethod
    def _info(tid: str, r: _Run) -> Dict[str, Any]:
        d = r.definition["definition"]
        return {"ticket_id": tid, "run_id": r.run_id, "user_id": r.body["user_id"], "task": r.task,
                "class_ceiling": r.body["class_ceiling"], "models": list(d["models"]), "tools": list(d["tools"]),
                "budgets": dict(d["budgets"]), "expires_at": r.body["expires_at"]}

    def _op_next_run(self, m) -> Dict[str, Any]:
        with self.lock:
            for tid, r in self.runs.items():
                if not r.handed:
                    r.handed = True
                    return {"ok": self._info(tid, r)}
        return {"code": "no_run"}

    def _op_step(self, m) -> Dict[str, Any]:
        r = self._live(m["ticket_id"])
        if r is None:
            return {"code": "ticket_not_held"}
        if not isinstance(m["request"], dict):
            return {"code": "bad_message"}
        status, out = self._backend("/agent/v1/steps/chat", {"ticket_id": m["ticket_id"], "request": m["request"]})
        if status == 200 and isinstance(out, dict):
            return {"ok": out}
        detail = out.get("detail") if isinstance(out, dict) else None
        return {"code": detail if isinstance(detail, str) and _CODE.fullmatch(detail) else "step_failed"}

    def _op_result(self, m) -> Dict[str, Any]:
        r = self._live(m["ticket_id"])
        if r is None:
            return {"code": "ticket_not_held"}
        if not isinstance(m["answer"], str) or len(m["answer"]) > MAX_ANSWER_CHARS:
            return {"code": "answer_too_large"}
        status, _ = self._backend(f"/agent/v1/runs/{m['ticket_id']}/result", {"answer": m["answer"]})
        self._forget(m["ticket_id"])                      # the text leaves this process's memory either way
        return {"ok": "delivered"} if status == 200 else {"code": "result_not_delivered"}

    def _op_state(self, m) -> Dict[str, Any]:
        r = self._live(m["ticket_id"])
        if r is None:
            return {"code": "ticket_not_held"}
        if not (isinstance(m["code"], str) and _CODE.fullmatch(m["code"])):
            return {"code": "bad_message"}
        self._backend(f"/agent/v1/runs/{m['ticket_id']}/state", {"state": "stopped", "code": m["code"]})
        self._forget(m["ticket_id"])
        return {"ok": "stopped"}

    def _op_resume(self, m) -> Dict[str, Any]:
        tid, run_id = m["ticket_id"], m["run_id"]
        if not (isinstance(tid, str) and _TICKET.fullmatch(tid) and isinstance(run_id, str) and _RUN.fullmatch(run_id)):
            return {"code": "bad_message"}
        with self.lock:
            r = self.runs.get(tid)
        if r is None or r.run_id != run_id:
            return {"code": "ticket_not_held"}
        try:
            V.verify_ticket(r.ticket, node_id=self.node_id, tenant=self.tenant, task_text=r.task,
                            definition=r.definition, policy=r.policy, resume_run_id=run_id, now=self.clock(),
                            **self.ctx)
        except V.TicketRejected as e:
            self._forget(tid)
            return {"code": str(e)}
        r.handed = True
        return {"ok": self._info(tid, r)}

    # --- serving ---------------------------------------------------------------------------------------------------
    @staticmethod
    def peer_uid(conn: socket.socket) -> int:
        creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        return struct.unpack("3i", creds)[1]

    def serve_connection(self, conn: socket.socket) -> None:
        """One agent connection: line-delimited JSON; a wrong peer uid is closed at once."""
        with conn:
            if self.peer_uid(conn) != self.agent_uid:
                return
            buf = b""
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    return
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    conn.sendall(json.dumps(self.handle(line)).encode() + b"\n")
                if len(buf) > MAX_MSG:
                    conn.sendall(json.dumps({"code": "message_too_large"}).encode() + b"\n")
                    return

    def listen(self, path: Path, group_gid: Optional[int] = None) -> socket.socket:
        """The socket at path: its directory must be ours and not world-accessible; the socket 0660."""
        d = path.parent
        st = d.stat()
        if st.st_uid != os.getuid() or st.st_mode & 0o007:
            raise PermissionError("agent socket directory must be the daemon's, no world access")
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old = os.umask(0o117)
        try:
            s.bind(str(path))
        finally:
            os.umask(old)
        os.chmod(path, 0o660)
        if group_gid is not None:
            os.chown(path, -1, group_gid)
        s.listen(4)
        return s
