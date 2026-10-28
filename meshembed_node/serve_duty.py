"""S-D (docs/DESIGN_S_D_NODE_SERVE_DUTY_2026-10-27.md; auditor design GO 2026-10-27 19:53Z with SD-a..SD-d, SD-e
19:56Z): the daemon's serve duty. It wires the GO'd pieces together; it adds no new trust:

  - intake: on every SUCCESSFUL get_job response, its `serve_plans` (signed envelopes) are pre-checked with
    serve_plan.verify_serve_plan (the ROOT launcher re-verifies everything anyway). At most ONE plan is active. A
    response WITHOUT the key, or one that no longer lists the active plan, means REVOKED: stop. A failed or
    unreachable get_job changes nothing by itself; the backend hands out a request only on a live plan (s1).
  - start: the plan's model (and draft) are staged by sha in ~/.meshembed/serve-models (a copy of the daemon's
    sha-verified weights, one link), then {"action": "start", "plan": envelope} is written to the request file the
    ROOT launcher acts on (meshembed-serve-launch.path). At most one start request per START_BACKOFF_S.
  - ready (hardware_info.serve): true ONLY with an active unexpired verified plan AND the unit answering on its
    socket AND no gate reason AND not paused. Never assumed from a written request. The backend treats it as a
    claim (SD-d): it routes only on a live signed plan.
  - stop (P3-4, the unit STOPPED, not ignored): on pause, any gate reason, expiry, revoke or shutdown, a stop request
    is written (serve_client.request_stop), ready goes false and polling stops. The root side also stops the unit
    when the daemon itself stops or the pause marker exists (SD-e: BindsTo + ConditionPathExists drop-in, the
    launcher's own pause refusal).
  - after a stop, the same plan cannot start again (the launcher remembers each plan nonce until expiry); the node
    waits for its next plan. That is availability, never safety.
Logs carry codes and counts only, never a prompt, a completion or a socket payload.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import serve_client as SC
from . import serve_plan as SP

log = logging.getLogger("meshembed.serve_duty")

LAUNCH_PATH_UNIT = Path("/etc/systemd/system/meshembed-serve-launch.path")
RUNNING = Path("/var/lib/meshembed-serve-launch/running.json")   # F-3: the ROOT launcher's record of what it started
REQUEST = Path.home() / ".meshembed" / "serve-request"
STAGING = Path.home() / ".meshembed" / "serve-models"
MIN_REMAINING_S = 60          # as the launcher: a plan with less left is stopped, never started
START_BACKOFF_S = 60          # SD-a, daemon side (the launcher enforces its own)
HEALTH_TIMEOUT_S = 2.0
IDLE_SLEEP_S = 5.0
LEFTOVER_STOP_S = 30          # Q-1: with no active plan but a unit the launcher started, a STOP is re-written this often


class _NoNonces:
    """The daemon's PRE-check must not consume a nonce: the root launcher keeps the real store."""

    def seen(self, nonce: str, now: float) -> bool:
        return False

    def remember(self, nonce: str, expires_at: int, now: float) -> None:
        return None


def why_off(env: Dict[str, str], platform: str = sys.platform, unit: Path = LAUNCH_PATH_UNIT) -> Optional[str]:
    """None when the duty may start, else the reason it stays off (reported as hw.serve.reason)."""
    if not platform.startswith("linux"):
        return "serve_linux_only"
    try:
        st = unit.lstat()
        if st.st_uid != 0 or not unit.is_file() or unit.is_symlink():
            return "serve_not_installed"
    except OSError:
        return "serve_not_installed"
    if env.get("MESHEMBED_SERVE", "0") != "1":
        return "serve_off"
    return None


def _write_request(path: Path, text: str) -> None:
    """0600, owned by us, no symlink followed (as serve_client.request_stop)."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, text.encode())
    finally:
        os.close(fd)


def launcher_running_plan(path: Path = RUNNING) -> Optional[str]:
    """F-3b: the plan the root launcher last STARTED (null after a stop, or once its unit stopped by itself).
    Unreadable or malformed -> None (= not known to run: never ready on it)."""
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    pid = d.get("plan_id") if isinstance(d, dict) else None
    return pid if isinstance(pid, str) and pid else None


def _spawn(fn: Callable[[], None]) -> None:
    threading.Thread(target=fn, name="serve-stage", daemon=True).start()


def socket_ok(sock: Path = SC.SOCKET, timeout: float = HEALTH_TIMEOUT_S) -> bool:
    """The unit answers its health route on the Unix socket (llama-server GET /health -> 200)."""
    try:
        conn = SC._UnixHTTPConnection(str(sock), timeout)
        try:
            conn.request("GET", "/health")
            return conn.getresponse().status == 200
        finally:
            conn.close()
    except (OSError, Exception):
        return False


class ServeDuty:
    """One per daemon. Thread-safe: intake runs on the poll thread, the loop on its own thread."""

    def __init__(self, node_id: str, post: Callable[[str, Dict[str, Any], float], Tuple[int, Any]], *,
                 gate: Callable[[], Optional[str]], paused: Callable[[], bool],
                 stage: Callable[[str], bool], model_id_for: Callable[[str], Optional[str]],
                 request: Path = REQUEST, sock: Path = SC.SOCKET, clock: Callable[[], float] = time.time,
                 health: Optional[Callable[[], bool]] = None, trusted: Optional[Dict[str, str]] = None,
                 serve_once: Callable[..., str] = SC.serve_once,
                 running_plan: Callable[[], Optional[str]] = launcher_running_plan,
                 spawn: Callable[[Callable[[], None]], None] = _spawn):
        self.node_id, self.post = node_id, post
        self.running_plan, self.spawn = running_plan, spawn
        self.gate, self.paused, self.stage, self.model_id_for = gate, paused, stage, model_id_for
        self.request, self.sock, self.clock = request, sock, clock
        self.health = health or (lambda: socket_ok(sock))
        self.trusted, self.serve_once = trusted, serve_once
        self._lock = threading.Lock()
        self._active: Optional[Dict[str, Any]] = None      # {"plan": body, "envelope": env, "model_id": str}
        self._started_at = 0.0
        self._stopped_plan: Optional[str] = None            # a plan stopped once is never started again
        self._serving: Dict[str, Any] = {"running": False}
        self._reason = "no_plan"
        self._staging: Dict[str, str] = {}                 # F-2: sha -> "busy" | "done" | "failed"
        self._staging_plan: Optional[str] = None            # the plan whose model is being staged
        self._leftover_at: Optional[float] = None           # Q-1: when a STOP for a leftover unit was last written

    # --- staging off the poll path (F-2) ---------------------------------------------------------------------------
    def _stage_state(self, shas: List[str]) -> str:
        """Under self._lock. "done" when every sha is staged; "busy" while a background copy/download runs (one per
        sha); "failed" once, after which the next intake retries."""
        for sha in shas:
            st = self._staging.get(sha)
            if st == "done":
                continue
            if st == "busy":
                return "busy"
            if st == "failed":
                del self._staging[sha]
                return "failed"
            self._staging[sha] = "busy"

            def work(sha: str = sha) -> None:
                try:
                    ok = bool(self.stage(sha))
                except Exception:
                    ok = False
                with self._lock:
                    self._staging[sha] = "done" if ok else "failed"
            self.spawn(work)
            return "busy"
        return "done"

    # --- stopping (P3-4) -------------------------------------------------------------------------------------------
    def _stop(self, reason: str) -> None:
        SC.request_stop(reason, self.request)
        self._serving["running"] = False
        if self._active is not None:
            self._stopped_plan = self._active["plan"]["plan_id"]
        self._active = None
        self._reason = reason
        log.warning("serve_duty.stop reason=%s", reason)

    def _blocked(self) -> Optional[str]:
        try:
            if self.paused():
                return "paused"
        except Exception:
            return "paused"                                 # cannot tell = paused (fail closed)
        try:
            return self.gate()
        except Exception:
            return "gate_unknown"

    # --- intake (every successful get_job response) ----------------------------------------------------------------
    def on_get_job(self, resp: Dict[str, Any]) -> None:
        now = self.clock()
        envs = resp.get("serve_plans") if isinstance(resp, dict) else None
        verified: List[Tuple[Dict[str, Any], Any]] = []
        for env in envs if isinstance(envs, list) else []:
            try:
                body = SP.verify_serve_plan(env, self.node_id, now=now, nonces=_NoNonces(), trusted=self.trusted)
            except Exception:
                continue                                    # a forged, foreign, expired or malformed plan: ignored
            verified.append((body, env))
        with self._lock:
            ids = {b["plan_id"] for b, _ in verified}
            if self._staging_plan not in ids:
                self._staging_plan = None                   # its plan is gone: the staged file stays, the plan does not
            if self._active is not None:
                if self._active["plan"]["plan_id"] not in ids:
                    self._stop("plan_revoked")              # (b): absent = revoked, also when the key is missing
                elif self._active["plan"]["expires_at"] - now < MIN_REMAINING_S:
                    self._stop("plan_expired")
                return
            blocked = self._blocked()
            if blocked:
                self._reason = blocked
                return
            if now - self._started_at < START_BACKOFF_S:
                return
            for body, env in sorted(verified, key=lambda be: -be[0]["expires_at"]):
                if body["plan_id"] == self._stopped_plan or body["expires_at"] - now < MIN_REMAINING_S:
                    continue
                mid = self.model_id_for(body["model_sha"])
                if not mid:
                    self._reason = "model_not_in_catalogue"
                    continue
                st = self._stage_state([body["model_sha"]] + ([body["draft_sha"]] if body["draft_sha"] else []))
                if st == "busy":                            # F-2: never blocks the poll loop; the next intake checks
                    self._reason, self._staging_plan = "staging", body["plan_id"]
                    return
                if st == "failed":
                    self._reason, self._staging_plan = "model_not_staged", None
                    continue
                self._staging_plan = None
                _write_request(self.request, json.dumps({"action": "start", "plan": env}))
                self._active = {"plan": body, "envelope": env, "model_id": mid}
                self._started_at = now
                self._serving["running"] = True
                self._reason = "starting"
                log.warning("serve_duty.start plan=%s", body["plan_id"])
                return
            if not verified:
                self._reason = "no_plan"

    # --- readiness (hardware_info.serve) ---------------------------------------------------------------------------
    def status(self) -> Dict[str, Any]:
        with self._lock:
            act = self._active
            reason = self._reason
            staging_plan = self._staging_plan
        running = self.running_plan()                       # F-3c: reported so the backend need not take our word
        if act is None:
            # RD-1 (auditor 2026-10-28 15:57Z): idle, the gate reason comes first, so "no_plan" means exactly
            # "capable, idle, not gated" -- the backend gives a FIRST plan only to that state (serve_warmset.serve_capable)
            blocked = self._blocked()
            if not blocked and running is not None:
                reason = "stopping_leftover"                # Q-1: no plan of ours, yet a unit runs: being stopped
            out: Dict[str, Any] = {"ready": False, "reason": blocked or reason, "running_plan_id": running}
            if not blocked and reason == "staging" and staging_plan:
                out["plan_id"] = staging_plan               # F-2: staging the model of this plan
            return out
        pid = act["plan"]["plan_id"]
        out = {"ready": False, "plan_id": pid, "model_sha": act["plan"]["model_sha"], "running_plan_id": running}
        if act["plan"]["expires_at"] - self.clock() < MIN_REMAINING_S:
            out["reason"] = "plan_expired"
        elif self._blocked():
            out["reason"] = self._blocked()
        elif running is not None and running != pid:
            out["reason"] = "unit_plan_mismatch"            # F-3b (R3): the launcher runs ANOTHER plan
        elif running is None or not self.health():
            out["reason"] = "unit_not_answering"            # not started yet, or loading
        else:
            out["ready"], out["reason"] = True, "ok"        # ready = our plan, started by the launcher, answering
        return out

    # --- the poll loop (one thread) --------------------------------------------------------------------------------
    def tick(self) -> str:
        with self._lock:
            act = self._active
            if act is not None and act["plan"]["expires_at"] - self.clock() < MIN_REMAINING_S:
                self._stop("plan_expired")
                return "stopped:plan_expired"
            if act is not None:
                blocked = self._blocked()
                if blocked:
                    self._stop(blocked)                     # P3-4: STOP, then no poll
                    return f"stopped:{blocked}"
        if act is None:
            # Q-1 (auditor 2026-10-28 16:38Z): the launcher consumes a request when it reads it, so a STOP lost after
            # that (the launcher died mid-run, a future bug) would leave a revoked plan's unit running unnoticed.
            # Converge: while the launcher still records a running plan and we hold none, re-write a STOP each period.
            if self.running_plan() is not None:
                now = self.clock()
                if self._leftover_at is None or now - self._leftover_at >= LEFTOVER_STOP_S:
                    SC.request_stop("stopping_leftover", self.request)
                    self._leftover_at = now
                    log.warning("serve_duty.stop reason=stopping_leftover")
                return "stopping_leftover"
            self._leftover_at = None
            return "no_plan"
        running = self.running_plan()
        if running is not None and running != act["plan"]["plan_id"]:
            with self._lock:
                if self._active is act:
                    self._stop("unit_plan_mismatch")        # F-3b: never serve a plan that is not ours
            return "stopped:unit_plan_mismatch"
        if running is None or not self.health():
            return "unit_not_answering"
        def decide() -> Tuple[bool, str]:
            r = self._blocked()
            return r is None, r or "ok"

        out = self.serve_once(self.post, self.node_id, [act["model_id"]], decide=decide, sock=self.sock,
                              stop_path=self.request, serving=self._serving)
        if out.startswith("yield:"):
            with self._lock:
                if self._active is not None:
                    self._stopped_plan = self._active["plan"]["plan_id"]
                self._active = None
                self._reason = out.split(":", 1)[1]
        return out

    def stop(self) -> None:
        with self._lock:
            if self._active is not None or self._serving.get("running"):
                self._stop("shutdown")

    def run(self, stop_event: threading.Event) -> None:
        while not stop_event.is_set():
            try:
                out = self.tick()
            except Exception as exc:                        # never takes the daemon down
                log.warning("serve_duty.error %s", type(exc).__name__)
                out = "error"
            if out in ("no_plan", "unit_not_answering", "error", "idle", "stopping_leftover") or out.startswith("stopped:"):
                stop_event.wait(IDLE_SLEEP_S)
        self.stop()


def stage_from_catalogue(sha: str, *, staging: Path = STAGING) -> bool:
    """Copy the daemon's sha-verified weights for `sha` to staging/<sha>.gguf (a fresh file, one link). The root
    launcher hashes the bytes again before installing them."""
    from . import llm
    dst = staging / f"{sha}.gguf"
    try:
        st = dst.lstat()
        if st.st_nlink == 1 and not dst.is_symlink() and st.st_size > 0:
            return True
    except OSError:
        pass
    spec = next((s for s in llm.load_catalog(include_serve_only=True).values() if s.sha256 == sha), None)
    if spec is None:
        return False
    src = llm.ensure_model(spec)
    if src is None:
        return False
    staging.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = staging / f".{sha}.part"
    try:
        tmp.unlink(missing_ok=True)
        shutil.copyfile(src, tmp)
        os.chmod(tmp, 0o600)
        os.replace(tmp, dst)
        return True
    except OSError:
        tmp.unlink(missing_ok=True)
        return False


def model_id_from_catalogue(sha: str) -> Optional[str]:
    from . import llm
    return next((s.model_id for s in llm.load_catalog(include_serve_only=True).values() if s.sha256 == sha), None)
