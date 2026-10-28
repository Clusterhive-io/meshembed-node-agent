"""AR1 G9, agent side: the plan / act / check loop, run as uid mesh-agent in meshembed-agent.service
(DESIGN_AR1 sections 9-12; auditor G9 design GO 2026-10-23 13:19Z, S1-S5).

The agent has NO network (S1): its only channel is the daemon's socket (agent_bridge). It never holds the lane key, the
node key or any store. It asks the bridge for a verified run, then loops:
  act    one model step through the bridge (the request asks for the built-in tools when the signed definition names
         any; in phase 0 they are evaluated by the M8 path on the serving node, so no tool code runs in this unit);
  check  OUR code checks the answer: not empty, within the size cap, and no remote URL that the task did not contain
         (G5: rendering is an exfiltration channel);
  plan   a failed check goes back to the model with the closed reason as the next message.
Budgets (G8) are enforced here AND by the backend: steps, wall time (the run's budgets), the run's expiry.
Checkpoints (G6, S3): after each step, the conversation is written AES-GCM-encrypted with a fresh 96-bit nonce under a
per-USER key HKDF(host state key, user_id), AAD = ticket_id | run_id | user_id | step. The per-user keys are
separation hygiene, not a boundary against this process or root (S3); the boundary is the signed host policy (P1) and
the personal-host rule. The unit does not start without the sealed state key (no FDE report -> no agent host,
auditor 14:15Z); the "no key -> RAM only" path below is for tests and fails closed.
Nothing is logged but closed codes and counts.
"""
from __future__ import annotations

import json
import os
import re
import socket
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

MAX_ANSWER_CHARS = 64 * 1024
_URL = re.compile(r"https?://[^\s)>\]\"']+", re.I)
CHECK_RETRY_TEXT = ("Your previous answer failed a check ({code}). Answer again, fixing only that, without links that "
                    "were not in the task.")


class BridgeClient:
    """One line of JSON per message over the daemon's Unix socket."""

    def __init__(self, path: str, timeout: float = 180.0):
        self.path, self.timeout = path, timeout

    def call(self, op: str, **kw) -> Dict[str, Any]:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            s.connect(self.path)
            s.sendall(json.dumps(dict(op=op, **kw)).encode() + b"\n")
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
        except OSError:
            return {"code": "bridge_unreachable"}
        finally:
            s.close()
        try:
            out = json.loads(buf)
        except ValueError:
            return {"code": "bridge_error"}
        return out if isinstance(out, dict) else {"code": "bridge_error"}


def check_answer(answer: Any, task: str) -> Optional[str]:
    """None when the answer passes; else a closed code."""
    if not isinstance(answer, str) or not answer.strip():
        return "empty_answer"
    if len(answer) > MAX_ANSWER_CHARS:
        return "answer_too_long"
    allowed = set(_URL.findall(task))
    if any(u not in allowed for u in _URL.findall(answer)):
        return "remote_url_not_in_task"                       # G5
    return None


# --- checkpoints (S3) -------------------------------------------------------------------------------------------------
def user_key(host_key: bytes, user_id: str) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"meshembed-agent-checkpoint-v1|" + user_id.encode()).derive(host_key)


def _aad(ticket_id: str, run_id: str, user_id: str, step: int) -> bytes:
    return f"{ticket_id}|{run_id}|{user_id}|{step}".encode()


def save_checkpoint(state_dir: Path, host_key: bytes, run: Dict[str, Any], step: int, messages: List[Any]) -> None:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(12)
    ct = AESGCM(user_key(host_key, run["user_id"])).encrypt(
        nonce, json.dumps(messages).encode(), _aad(run["ticket_id"], run["run_id"], run["user_id"], step))
    # ticket / run ids in clear so a restart can ask the bridge to resume; they are in the AAD, so editing them
    # makes the checkpoint fail to decrypt
    rec = {"v": 1, "ticket_id": run["ticket_id"], "run_id": run["run_id"], "step": step, "nonce": nonce.hex(),
           "ct": ct.hex()}
    path = state_dir / f"{run['ticket_id']}.ckpt"
    tmp = path.with_suffix(".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(rec, f)
    os.replace(tmp, path)


def load_checkpoint(state_dir: Path, host_key: bytes, run: Dict[str, Any], path: Optional[Path] = None
                    ) -> Optional[Tuple[int, List[Any]]]:
    """(step, messages) or None when there is none or it does not authenticate for THIS run and user."""
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    path = path or state_dir / f"{run['ticket_id']}.ckpt"
    try:
        rec = json.loads(path.read_text())
        step = int(rec["step"])
        pt = AESGCM(user_key(host_key, run["user_id"])).decrypt(
            bytes.fromhex(rec["nonce"]), bytes.fromhex(rec["ct"]),
            _aad(run["ticket_id"], run["run_id"], run["user_id"], step))
    except (OSError, ValueError, KeyError, TypeError, InvalidTag):
        return None
    return step, json.loads(pt)


def purge_checkpoint(state_dir: Optional[Path], ticket_id: str) -> None:
    if state_dir is not None:
        try:
            (state_dir / f"{ticket_id}.ckpt").unlink()
        except FileNotFoundError:
            pass


# --- the loop ---------------------------------------------------------------------------------------------------------
def pending_resumes(state_dir: Optional[Path]) -> List[Tuple[str, str]]:
    """(ticket_id, run_id) of the checkpoints left by a restart; each goes back through the bridge (G3)."""
    out = []
    for p in sorted(state_dir.glob("*.ckpt")) if state_dir is not None else []:
        try:
            rec = json.loads(p.read_text())
            out.append((str(rec["ticket_id"]), str(rec["run_id"])))
        except (OSError, ValueError, KeyError, TypeError):
            continue
    return out


def run_once(bridge: BridgeClient, *, state_dir: Optional[Path] = None, host_key: Optional[bytes] = None,
             clock: Callable[[], float] = time.time, resume: Optional[Tuple[str, str]] = None) -> str:
    """Take one verified run (or resume one through the bridge) and work it to the end. Returns a closed code
    (no_run | done | stopped:<code>)."""
    got = bridge.call("resume", ticket_id=resume[0], run_id=resume[1]) if resume else bridge.call("next_run")
    if "ok" not in got:
        if resume:
            purge_checkpoint(state_dir, resume[0])            # refused (expired, revoked, ...): the state goes too
        return got.get("code", "no_run")
    run = got["ok"]
    tid, task, budgets = run["ticket_id"], run["task"], run["budgets"]
    model = run["models"][0]
    started, deadline = clock(), min(run["expires_at"], clock() + budgets["wall_s"])
    messages: List[Any] = [{"role": "user", "content": task}]
    step = 0
    if state_dir is not None and host_key is not None:
        ck = load_checkpoint(state_dir, host_key, run)
        if ck is not None:
            step, messages = ck
    while True:
        if step >= budgets["steps"]:
            return _stop(bridge, state_dir, tid, "steps_exhausted")
        if clock() >= deadline:
            return _stop(bridge, state_dir, tid, "wall_time_exhausted")
        req = {"model": model, "messages": messages, "temperature": 0}
        if run["tools"]:
            req["builtin_tools"] = True
        out = bridge.call("step", ticket_id=tid, request=req)
        step += 1
        if "ok" not in out:
            return _stop(bridge, state_dir, tid, out.get("code", "step_failed"))
        try:
            answer = out["ok"]["choices"][0]["message"].get("content")
        except (KeyError, IndexError, TypeError, AttributeError):
            return _stop(bridge, state_dir, tid, "bad_completion")
        code = check_answer(answer, task)
        if code is None:
            res = bridge.call("result", ticket_id=tid, answer=answer)
            purge_checkpoint(state_dir, tid)
            return "done" if "ok" in res else "stopped:" + res.get("code", "result_not_delivered")
        messages = messages + [{"role": "assistant", "content": answer if isinstance(answer, str) else ""},
                               {"role": "user", "content": CHECK_RETRY_TEXT.format(code=code)}]
        if state_dir is not None and host_key is not None:
            save_checkpoint(state_dir, host_key, run, step, messages)


def _stop(bridge: BridgeClient, state_dir: Optional[Path], tid: str, code: str) -> str:
    bridge.call("state", ticket_id=tid, code=code if re.fullmatch(r"[a-z_]{1,40}", code or "") else "stopped")
    purge_checkpoint(state_dir, tid)
    return "stopped:" + code


# --- the unit's entry point ---------------------------------------------------------------------------------------
SOCKET_PATH = "/run/meshembed/agent.sock"


def _host_key() -> Optional[bytes]:
    d = os.environ.get("CREDENTIALS_DIRECTORY")
    if not d:
        return None
    try:
        k = (Path(d) / "state-key").read_bytes()
    except OSError:
        return None
    return k if len(k) >= 32 else None


def main() -> int:
    """Resume what a restart left (each through the bridge, G3), then take runs one at a time. State on disk only
    with the sealed state key (G6); otherwise RAM only."""
    host_key = _host_key()
    state = Path(os.environ["STATE_DIRECTORY"]) if host_key and os.environ.get("STATE_DIRECTORY") else None
    bridge = BridgeClient(SOCKET_PATH)
    for pending in pending_resumes(state):
        run_once(bridge, state_dir=state, host_key=host_key, resume=pending)
    idle = 1.0
    while True:
        code = run_once(bridge, state_dir=state, host_key=host_key)
        idle = min(idle * 2, 30.0) if code in ("no_run", "bridge_unreachable") else 1.0
        time.sleep(idle)


if __name__ == "__main__":
    raise SystemExit(main())
