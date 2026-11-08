"""M2 build #5a, daemon side: hand a signed split plan to the ROOT launcher (D4) and say whether
this node is split-ready (D6). The daemon gains no power: it can only write the envelope it
received to a 0600 file in its own directory; the root launcher re-verifies everything.

- ready(): MESHEMBED_ENABLE_SPLIT=1 AND the launcher's root-written ready.json says the mesh-di
  runtime set verifies and the units exist. Anything else -> not ready (fail closed).
- handoff(): for each delivered envelope, newest first: skip plan ids already handled (the poll
  re-sends live plans); verify it here too (a plan not for us, expired or forged is never even
  queued); write it ONLY when the request file is empty (the launcher truncates after reading,
  so an unprocessed request is never overwritten); one plan per poll.
"""
from __future__ import annotations

import json
import time
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import split_plan_verify as V

log = logging.getLogger(__name__)
STATE_DIR = Path("/var/lib/meshembed-split-launch")
_HANDLED: Dict[str, str] = {}


def enabled() -> bool:
    return os.environ.get("MESHEMBED_ENABLE_SPLIT", "0") == "1"


def ready(state_dir: Path = STATE_DIR, now: Optional[float] = None) -> Dict[str, Any]:
    if not enabled():
        return {"ready": False, "code": "disabled"}
    try:
        d = json.loads((state_dir / "ready.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"ready": False, "code": "launcher_absent"}
    out = {"ready": d.get("ready") is True, "code": str(d.get("code", ""))[:40]}
    # overlay automation step 3: the PUBLIC key the root launcher generated (never the private
    # half -- the daemon cannot read it); and how this host can be reached (from the address the
    # backend OBSERVED on the last poll, decided locally, a node claim that can only break its own chain)
    k = d.get("wg_pubkey")
    if isinstance(k, str) and _WGKEY.fullmatch(k):
        out["wg_pubkey"] = k
    # SPLIT-SERVE (SS-4): the digest of the runtime set the ROOT launcher verified; a claim used for PLANNING only (the
    # launcher enforces the signed runtime_set against its own verified set)
    rs = d.get("runtime_set")
    if isinstance(rs, str) and _HEX64.fullmatch(rs):
        out["runtime_set"] = rs
    rec = current_reclaimed(now=now)
    if rec:
        out["reclaimed"] = rec                           # head 5: the backend marks that plan lost (owner_reclaim)
    out.update(reachability())
    return out


_WGKEY = __import__("re").compile(r"^[A-Za-z0-9+/]{43}=$")
_HEX64 = __import__("re").compile(r"^[0-9a-f]{64}$")
_OBSERVED: Dict[str, Optional[str]] = {"ip": None}


def set_observed(ip: Any) -> None:
    """The backend's view of this poll's source address (GetJobResponse.split_observed_ip)."""
    try:
        _OBSERVED["ip"] = str(__import__("ipaddress").IPv4Address(str(ip))) if ip else None
    except ValueError:
        _OBSERVED["ip"] = None


def _local_ipv4s() -> set:
    import subprocess
    try:
        out = subprocess.run(["ip", "-4", "-o", "addr", "show"], capture_output=True, text=True,
                             timeout=5, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return set()
    ips = set()
    for line in out.splitlines():
        parts = line.split()
        if "inet" in parts:
            ips.add(parts[parts.index("inet") + 1].split("/")[0])
    return ips


def _primary_lan() -> Optional[str]:
    """The RFC1918 source address this host uses for outbound traffic (no packet is sent)."""
    import ipaddress
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))                   # TEST-NET: a route lookup only
        ip = ipaddress.IPv4Address(s.getsockname()[0])
    except OSError:
        return None
    finally:
        s.close()
    rfc1918 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
    overlay = ipaddress.ip_network("10.44.0.0/16")
    return str(ip) if any(ip in n for n in rfc1918) and ip not in overlay else None


def reachability() -> Dict[str, Any]:
    obs = _OBSERVED["ip"]
    out: Dict[str, Any] = {"public_addr": bool(obs) and obs in _local_ipv4s()}
    lan = _primary_lan()
    if lan:
        out["lan_addr"] = lan
    return out


def revoke_path() -> Path:
    return Path.home() / ".meshembed" / "split-revoke"


def relay_revocations(ids: Optional[List[str]], *, path: Optional[Path] = None, state_dir: Optional[Path] = None,
                      now: Optional[float] = None) -> Optional[str]:
    """A plan this daemon handed to the launcher was lost/revoked by the backend: relay its id.
    The launcher tears down ONLY if it equals the plan it applied (it can never bring anything up).
    Relayed ONCE per plan (bed 2026-11-03, auditor 12:13:29Z + 12:14:56Z: the backend keeps listing a lost plan until it
    expires, and every relay fires the launcher, which re-hashes the runtime set; a dead plan must not cost the owner's
    CPU every poll for hours)."""
    if not ids or not enabled():
        return None
    # SO-1 (SPLIT-ORPHAN, auditor 12:38:44Z): also the plan the ROOT launcher says it applied (applied.json), so a daemon
    # restart (an empty _HANDLED) never forgets a revocation of the plan the launcher still runs
    applied = _launcher_applied(state_dir or STATE_DIR, time.time() if now is None else now)
    mine = lambda i: (i in _HANDLED or (applied is not None and i == applied["plan_id"])) and _HANDLED.get(i) != "revoked"
    hit = next((i for i in ids if isinstance(i, str) and mine(i)), None)
    if hit is None:
        return None
    path = path or revoke_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump({"plan_id": hit}, f)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    _HANDLED[hit] = "revoked"
    log.warning("split: plan %s revoked by the backend; relayed to the root launcher", hit)
    return hit


def request_overlay(env: Dict[str, Any], *, path: Optional[Path] = None, state_dir: Path = STATE_DIR,
                    wait_s: float = 60.0) -> bool:
    """A verified PROBE plan: ask the launcher to bring meshdi0 up for it, wait until it says so."""
    import time as _t
    pid = (env.get("plan") or {}).get("plan_id")
    if not _write_request(path or request_path(), env):
        return False
    deadline = _t.time() + wait_s
    while _t.time() < deadline:
        try:
            r = json.loads((state_dir / "last-result.json").read_text(encoding="utf-8"))
            if r.get("plan_id") == pid and r.get("code") == "probe_overlay_up":
                return True
            if r.get("result") == "refused" and int(r.get("at") or 0) >= int(deadline - wait_s):
                return False
        except (OSError, ValueError):
            pass
        _t.sleep(1)
    return False


def keep_path() -> Path:
    return Path.home() / ".meshembed" / "split-keep"


KEEP_MAX_IDS = 8


def touch_keep(pid: str, now: float, *, path: Optional[Path] = None) -> bool:
    """SO-2, the LEASE (SPLIT-ORPHAN, auditor 2026-11-03 12:38:44Z): each time the backend still delivers a plan this
    daemon handed over, refresh {plan_id: time} in split-keep (the daemon user, 0600, atomic, never followed). The root
    launcher tears a plan down when its entry is stale; a fresh entry can only keep a plan up to its SIGNED expiry, never
    extend or widen it. Not a .path trigger: refreshing it never fires the launcher."""
    path = path or keep_path()
    try:
        cur = json.loads(path.read_text(encoding="utf-8")) if path.exists() and not path.is_symlink() else {}
    except (OSError, ValueError):
        cur = {}
    cur = {k: v for k, v in (cur.items() if isinstance(cur, dict) else []) if isinstance(k, str)
           and isinstance(v, (int, float)) and not isinstance(v, bool) and now - v < 3600}
    cur[pid] = int(now)
    if len(cur) > KEEP_MAX_IDS:
        cur = dict(sorted(cur.items(), key=lambda kv: kv[1])[-KEEP_MAX_IDS:])
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(cur, f)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
        return True
    except OSError:
        return False


def renew_live(ids: Optional[List[str]], *, path: Optional[Path] = None, now: Optional[float] = None) -> List[str]:
    """SO-4: the heartbeat's "split_live" ids renew the lease ONLY for plans this daemon handed over and still holds as
    queued; an id the backend calls live but this daemon never handed (or revoked) renews nothing. Returns the renewed."""
    if not ids or not enabled():
        return []
    t = time.time() if now is None else now
    done = [i for i in ids if isinstance(i, str) and _HANDLED.get(i) == "queued"]
    for i in done:
        touch_keep(i, t, path=path)
    return done


def request_path() -> Path:
    return Path.home() / ".meshembed" / "split-request"


def _write_request(path: Path, env: Dict[str, Any]) -> bool:
    try:
        if path.exists() and path.stat().st_size > 0:
            return False                                  # launcher has not consumed the last one
    except OSError:
        return False
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(env, f, separators=(",", ":"))
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    return True


# SPLIT-SERVE head 5, OWNER-RECLAIM (docs/DESIGN_SPLIT_SERVE_2026-11-02.md section 5; SD-3: live before any prod
# split-serve). When the owner-first gate says no (power, idle, thermal, metered, the RAM ceiling, a pause), every plan
# this daemon handed to the root launcher is RELEASED through the existing revocation channel (the launcher stops the
# units, tears the overlay down and purges the stage cache), a still-pending request for it is withdrawn (the launcher
# must not apply it after the release), and the release is REPORTED (hw.split.reclaimed) so the backend marks the plan
# lost (owner_reclaim) and re-plans without this machine.
_RECLAIMED: Dict[str, Any] = {}
_EXPIRES: Dict[str, int] = {}                             # plan id -> its verified expires_at (handoff)
# the daemon-side head (auditor 2026-11-02 21:13:50Z): each VERIFIED serve split body, so the serve duty can report the
# plan it coordinates (or stages); what RUNS is only ever read from the root launcher's records below
_SERVE: Dict[str, Dict[str, Any]] = {}


class _NoNonces:
    """DS-2: a re-verification that must not consume a nonce (the root launcher keeps the real store)."""

    def seen(self, nonce: str, now: float) -> bool:
        return False

    def remember(self, nonce: str, expires_at: int, now: float) -> None:
        return None


def _remember_serve(body: Dict[str, Any]) -> None:
    if body.get("kind") == "serve":
        _SERVE[body["plan_id"]] = {"plan_id": body["plan_id"], "coordinator": body["coordinator"],
                                   "members": [m["node_id"] for m in body["members"]],
                                   "model_sha": body["model_sha"], "expires_at": int(body["expires_at"])}


def serve_split_role(me: str, *, now: Optional[float] = None) -> Optional[Dict[str, Any]]:
    """The newest live serve split plan this daemon handed over (not revoked, not reclaimed) naming `me`, with its role
    ("coordinator" or "stage"), or None."""
    now = time.time() if now is None else now
    live = [p for pid, p in _SERVE.items() if _HANDLED.get(pid) == "queued" and p["expires_at"] > now
            and me in p["members"]]
    if not live:
        return None
    p = max(live, key=lambda x: x["expires_at"])
    return dict(p, role="coordinator" if p["coordinator"] == me else "stage")


def _root_record(state_dir: Path, name: str) -> Dict[str, Any]:
    try:
        d = json.loads((state_dir / name).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return d if isinstance(d, dict) else {}


def split_coord_running(*, state_dir: Optional[Path] = None, now: Optional[float] = None) -> Optional[str]:
    """F-3c for a serve split: the plan the ROOT launcher STARTED serve-coord for (its serve-coord.json), never the
    daemon's own belief. None unless the record says serve_coord_started and has not expired."""
    now = time.time() if now is None else now
    d = _root_record(state_dir or STATE_DIR, "serve-coord.json")
    pid, exp = d.get("plan_id"), d.get("expires_at")
    if d.get("code") == "serve_coord_started" and isinstance(pid, str) and isinstance(exp, int) and exp > now:
        return pid
    return None


def stage_running(plan_id: str, *, state_dir: Optional[Path] = None) -> bool:
    """A stage's report: the launcher APPLIED this plan and its last result is stage_started for it."""
    sd = state_dir or STATE_DIR
    last = _root_record(sd, "last-result.json")
    return (_root_record(sd, "applied.json").get("plan_id") == plan_id and last.get("plan_id") == plan_id
            and last.get("code") == "stage_started")


def reclaimed_path() -> Path:
    return Path.home() / ".meshembed" / "split-reclaimed.json"


def _save_reclaimed(rec: Dict[str, Any], path: Optional[Path] = None) -> None:
    """H5-2 (auditor 20:07:19Z): the report survives a daemon restart (0600, atomic, the daemon's own dir)."""
    path = path or reclaimed_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(rec, f, sort_keys=True)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def current_reclaimed(*, path: Optional[Path] = None, now: Optional[float] = None) -> Dict[str, Any]:
    """The release to report: kept in memory, re-read from disk after a restart (and that plan marked handled, so it is
    never handed over again), reported until the plan's expires_at passes, then dropped. Garbage = nothing."""
    path = path or reclaimed_path()
    now = time.time() if now is None else now
    if not _RECLAIMED:
        try:
            if not path.is_symlink():
                d = json.loads(path.read_text(encoding="utf-8"))
                if (isinstance(d, dict) and isinstance(d.get("plan_id"), str)
                        and isinstance(d.get("expires_at"), int) and isinstance(d.get("at"), int)):
                    _RECLAIMED.update(plan_id=d["plan_id"], reason=str(d.get("reason", ""))[:40], at=d["at"],
                                      expires_at=d["expires_at"])
                    _HANDLED.setdefault(d["plan_id"], "reclaimed")
        except (OSError, ValueError):
            pass
    if _RECLAIMED and _RECLAIMED["expires_at"] <= now:
        _RECLAIMED.clear()
        try:
            path.unlink()
        except OSError:
            pass
    return {k: _RECLAIMED[k] for k in ("plan_id", "reason", "at")} if _RECLAIMED else {}


def _launcher_applied(state_dir: Path, now: float) -> Optional[Dict[str, Any]]:
    """H5-1 (auditor 20:07:19Z): the plan the ROOT launcher says it runs (its applied.json, root-written 0644), when the
    daemon's memory has none (a restart while the units kept running). None when absent, garbage or expired."""
    try:
        d = json.loads((state_dir / "applied.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not (isinstance(d, dict) and isinstance(d.get("plan_id"), str) and isinstance(d.get("expires_at"), int)):
        return None
    return d if d["expires_at"] > now else None


def reclaim_for_owner(reason: Optional[str], *, path: Optional[Path] = None, request: Optional[Path] = None,
                      now: Optional[float] = None, state_dir: Optional[Path] = None,
                      record: Optional[Path] = None) -> Optional[str]:
    """Release the plan this daemon last handed to the launcher, for `reason` (None = the owner does not need the
    machine: nothing to do). After a daemon restart (memory empty) the plan is the launcher's applied one, or a
    request a previous process left pending. Returns the plan id released, or None."""
    if not reason or not enabled():
        return None
    now = time.time() if now is None else now
    current_reclaimed(path=record, now=now)               # a persisted release is known before anything is chosen
    req = request or request_path()
    pending = None
    try:
        if req.exists() and not req.is_symlink():
            d = json.loads(req.read_text(encoding="utf-8") or "{}")
            pending = (d.get("plan") or {}) if isinstance(d, dict) else None
    except (OSError, ValueError):
        pending = None
    live = [pid for pid, st in _HANDLED.items() if st == "queued"]
    expires = None
    if live:
        pid = live[-1]                                    # the launcher applies one plan at a time: the latest
        expires = _EXPIRES.get(pid)
    else:
        applied = _launcher_applied(state_dir or STATE_DIR, now)
        pend_id = pending.get("plan_id") if isinstance(pending, dict) else None
        if applied and applied["plan_id"] not in _HANDLED:     # a revoked/reclaimed one is already going
            pid, expires = applied["plan_id"], applied["expires_at"]
        elif isinstance(pend_id, str) and pend_id not in _HANDLED:
            pid = pend_id
            exp = pending.get("expires_at")
            expires = exp if isinstance(exp, int) and not isinstance(exp, bool) else None
        else:
            return None
    try:                                                  # withdraw it if the launcher has not read it yet
        if isinstance(pending, dict) and pending.get("plan_id") == pid:
            with open(req, "w", encoding="utf-8"):
                pass
    except OSError:
        pass
    path = path or revoke_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump({"plan_id": pid, "reason": "owner_reclaim"}, f)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    for p in live:
        _HANDLED[p] = "reclaimed"
    _HANDLED[pid] = "reclaimed"
    # an unknown expiry (no verified body seen) is reported for the longest a plan may live
    exp = int(expires) if isinstance(expires, int) and expires > now else int(now) + V.MAX_LIFETIME_S
    _RECLAIMED.clear()
    _RECLAIMED.update(plan_id=pid, reason=str(reason)[:40], at=int(now), expires_at=exp)
    _save_reclaimed(dict(_RECLAIMED), record)
    log.warning("split: plan %s released for the owner (%s); relayed to the root launcher", pid, reason)
    return pid


def handoff(envelopes: Optional[List[Dict[str, Any]]], my_node_id: str, *,
            path: Optional[Path] = None, nonces: Optional[V.NonceStore] = None,
            trusted=None, now: Optional[float] = None) -> Optional[str]:
    """Queue at most one new plan for the launcher. Returns its plan_id, or None."""
    if not envelopes or not enabled():
        return None
    path = path or request_path()
    t = time.time() if now is None else now
    for env in envelopes:
        pid = (env.get("plan") or {}).get("plan_id") if isinstance(env, dict) else None
        if not isinstance(pid, str):
            continue
        if pid in _HANDLED:
            if _HANDLED[pid] == "queued":
                touch_keep(pid, t, path=path.parent / "split-keep")                        # SO-2: the backend still delivers it: the lease is renewed
            continue
        applied = _launcher_applied(STATE_DIR, t)
        if applied and applied["plan_id"] == pid:
            # DS-2 (auditor 21:13:50Z): the plan the ROOT launcher already runs, re-delivered after a daemon restart:
            # verified WITHOUT consuming a nonce (signature, schema, node, expiry), remembered, never handed over again
            try:
                body = V.verify_plan(env, my_node_id, now=now, nonces=_NoNonces(), trusted=trusted)
            except V.PlanRejected as e:
                _HANDLED[pid] = f"refused:{e}"
                continue
            _HANDLED[pid] = "queued"
            _EXPIRES[pid] = int(body["expires_at"])
            _remember_serve(body)
            touch_keep(pid, t, path=path.parent / "split-keep")
            log.warning("split: plan %s already applied by the root launcher; known again, not re-handed", pid)
            continue
        try:
            body = V.verify_plan(env, my_node_id, now=now, nonces=nonces, trusted=trusted)
        except V.PlanRejected as e:
            _HANDLED[pid] = f"refused:{e}"
            log.warning("split: plan %s refused by the daemon (%s)", pid, e)
            continue
        if not _write_request(path, env):
            return None                                   # retry next poll (not marked handled)
        _HANDLED[pid] = "queued"
        _EXPIRES[pid] = int(body["expires_at"])
        _remember_serve(body)
        touch_keep(pid, t, path=path.parent / "split-keep")
        log.warning("split: plan %s handed to the root launcher", pid)
        return pid
    return None
