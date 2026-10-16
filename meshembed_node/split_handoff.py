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


def ready(state_dir: Path = STATE_DIR) -> Dict[str, Any]:
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
    out.update(reachability())
    return out


_WGKEY = __import__("re").compile(r"^[A-Za-z0-9+/]{43}=$")
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


def relay_revocations(ids: Optional[List[str]], *, path: Optional[Path] = None) -> Optional[str]:
    """A plan this daemon handed to the launcher was lost/revoked by the backend: relay its id.
    The launcher tears down ONLY if it equals the plan it applied (it can never bring anything up)."""
    if not ids or not enabled():
        return None
    hit = next((i for i in ids if isinstance(i, str) and i in _HANDLED), None)
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


def handoff(envelopes: Optional[List[Dict[str, Any]]], my_node_id: str, *,
            path: Optional[Path] = None, nonces: Optional[V.NonceStore] = None,
            trusted=None, now: Optional[float] = None) -> Optional[str]:
    """Queue at most one new plan for the launcher. Returns its plan_id, or None."""
    if not envelopes or not enabled():
        return None
    path = path or request_path()
    for env in envelopes:
        pid = (env.get("plan") or {}).get("plan_id") if isinstance(env, dict) else None
        if not isinstance(pid, str) or pid in _HANDLED:
            continue
        try:
            V.verify_plan(env, my_node_id, now=now, nonces=nonces, trusted=trusted)
        except V.PlanRejected as e:
            _HANDLED[pid] = f"refused:{e}"
            log.warning("split: plan %s refused by the daemon (%s)", pid, e)
            continue
        if not _write_request(path, env):
            return None                                   # retry next poll (not marked handled)
        _HANDLED[pid] = "queued"
        log.warning("split: plan %s handed to the root launcher", pid)
        return pid
    return None
