"""AR1 G9: the node daemon's agent-host duty -- started from the worker ONLY when every piece is in place, else a
closed reason and nothing runs (inert by default).

Needs, all of them (fail closed):
  - MESHEMBED_AGENT_HOST=1 in the daemon's environment, on Linux;
  - the mesh-agent system user (made by the root installer when the host is designated);
  - /etc/meshembed-agent/host.json, ROOT-owned (auditor 14:10Z W1), root:<daemon group> 0640 in a root directory
    with no group/world write: {"tenant": <pool>, "admin_keys": {kid: base64 ed25519 pub}, "policy": <this host's
    policy SIGNED by that admin key>} -- the G2 trust root, written by the office admin with sudo at designation; the
    backend cannot set it and a compromise of the daemon's uid cannot swap it. The policy must verify for THIS node
    and pool: an undesignated host never starts the bridge (auditor 13:58Z);
  - ~/.meshembed/agent-lane.key, 0600, ours: the per-agent-host lane key (S1: only the daemon holds it);
  - /run/meshembed, made by root (agent-unit/meshembed-agent.tmpfiles.in: d /run/meshembed 0750 <daemon user>
    mesh-agent): owned by us, group mesh-agent, no world access.
Then three daemon threads:
  - intake: long-poll /nodes/agent/next (node key) -> AgentBridge.offer (verify_ticket in this process, P3);
  - revocations: GET /nodes/agent/revocations every REVOCATIONS_EVERY_S -> Revocations.update (fresh: P2);
  - the socket: /run/meshembed/agent.sock, at most MAX_CONNECTIONS agent connections at a time (S2).
Nothing here logs content; the log lines are closed reasons and counts.
"""
from __future__ import annotations

import grp
import json
import logging
import os
import pwd
import re
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

from . import agent_bridge as B
from . import run_ticket_verify as V

log = logging.getLogger("meshembed.agent_daemon")
SOCKET_DIR = Path("/run/meshembed")
HOST_CONFIG = Path("/etc/meshembed-agent/host.json")
REVOCATIONS_EVERY_S = 120
MAX_CONNECTIONS = 4
_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def _private_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        st = path.stat()
        if st.st_uid != os.getuid() or st.st_mode & 0o077:
            return None
        d = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return d if isinstance(d, dict) else None


def _root_json(path: Path) -> Optional[Dict[str, Any]]:
    """W1: the file AND its directory owned by root and writable by nobody else; readable by us (group)."""
    try:
        for p in (path.parent, path):
            st = p.stat()
            if st.st_uid != 0 or st.st_mode & 0o022:
                return None
        d = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return d if isinstance(d, dict) else None


def load_host_config(path: Path = HOST_CONFIG) -> Optional[Dict[str, Any]]:
    """{"tenant", "admin_keys", "policy"} from the ROOT-owned file the office admin wrote, or None."""
    d = _root_json(path)
    if d is None or set(d) != {"tenant", "admin_keys", "policy"} or not (isinstance(d["tenant"], str)
                                                              and _ID.fullmatch(d["tenant"])):
        return None
    keys = d["admin_keys"]
    if not isinstance(keys, dict) or not keys or not all(
            isinstance(k, str) and _ID.fullmatch(k) and isinstance(v, str) and re.fullmatch(r"[A-Za-z0-9+/]{43}=", v)
            for k, v in keys.items()):
        return None
    return d


def preflight(env: Dict[str, str], home: Path, node_id: str, socket_dir: Path = SOCKET_DIR,
              platform: str = sys.platform, host_config: Path = HOST_CONFIG) -> Tuple[Optional[Dict[str, Any]], str]:
    """(settings, "ok") or (None, closed reason). Every piece or nothing."""
    if env.get("MESHEMBED_AGENT_HOST") != "1":
        return None, "agent_host_off"
    if not platform.startswith("linux"):
        return None, "agent_host_linux_only"
    try:
        agent_uid = pwd.getpwnam("mesh-agent").pw_uid
        agent_gid = grp.getgrnam("mesh-agent").gr_gid
    except KeyError:
        return None, "agent_user_missing"
    cfg = load_host_config(host_config)
    if cfg is None:
        return None, "agent_host_config_missing"
    try:                                               # designated = a policy signed for THIS host and pool
        V.verify_policy(cfg["policy"], cfg["admin_keys"], node_id, cfg["tenant"],
                        V.PolicyVersions(home / "agent-policy-version.json"))
    except V.TicketRejected:
        return None, "agent_host_not_designated"
    if B.read_lane_key(home / "agent-lane.key") is None:
        return None, "agent_lane_key_missing"
    try:
        st = socket_dir.stat()
    except OSError:
        return None, "agent_socket_dir_missing"
    if st.st_uid != os.getuid() or st.st_gid != agent_gid or st.st_mode & 0o027 or (st.st_mode & 0o050) != 0o050:
        return None, "agent_socket_dir_unsafe"               # ours, group mesh-agent, 0750
    return {"agent_uid": agent_uid, "tenant": cfg["tenant"], "admin_keys": cfg["admin_keys"]}, "ok"


def make_bridge(node_id: str, settings: Dict[str, Any], home: Path, lane_post: B.Post) -> B.AgentBridge:
    ctx = dict(admin_keys=settings["admin_keys"], revocations=V.Revocations(home / "agent-revocations.json"),
               nonces=V.RunNonces(home / "run-ticket-nonces.json"),
               policy_versions=V.PolicyVersions(home / "agent-policy-version.json"))
    return B.AgentBridge(node_id=node_id, tenant=settings["tenant"], agent_uid=settings["agent_uid"], post=lane_post,
                         lane_key=lambda: B.read_lane_key(home / "agent-lane.key"), verify_ctx=ctx)


def intake_once(bridge: B.AgentBridge, node_post: Callable[[str, Dict[str, Any], float], Tuple[int, Any]],
                node_id: str, wait_s: float = 20.0) -> str:
    """One long poll for a ticket. Returns idle | <the bridge's offer code> | poll_failed."""
    try:
        status, item = node_post("/nodes/agent/next", {"node_id": node_id, "wait_s": wait_s}, wait_s + 10)
    except Exception:
        return "poll_failed"
    if status == 204:
        return "idle"
    if status != 200:
        return "poll_failed"
    return bridge.offer(item) if item else "idle"


def refresh_revocations(bridge: B.AgentBridge, node_get: Callable[[str, float], Tuple[int, Any]], node_id: str,
                        now: Optional[float] = None) -> str:
    """P2: a successful fetch stamps the snapshot; a failed one leaves it to age out (runs then refuse)."""
    try:
        status, rev = node_get(f"/nodes/agent/revocations?node_id={node_id}", 30.0)
    except Exception:
        return "fetch_failed"
    if status != 200 or not isinstance(rev, dict):
        return "fetch_failed"
    defs, ticks = rev.get("definitions"), rev.get("tickets")
    if not isinstance(defs, list) or not isinstance(ticks, list) \
            or not all(isinstance(d, list) and len(d) == 2 and isinstance(d[0], str) and isinstance(d[1], int)
                       and not isinstance(d[1], bool) for d in defs) or not all(isinstance(t, str) for t in ticks):
        return "fetch_failed"
    bridge.ctx["revocations"].update([(a, v) for a, v in defs], ticks, time.time() if now is None else now)
    return "ok"


def start(node_id: str, env: Dict[str, str], home: Path, *, node_post, node_get, lane_post,
          stop: threading.Event, socket_dir: Path = SOCKET_DIR, host_config: Path = HOST_CONFIG) -> str:
    """Start the three threads when preflight passes; returns the preflight reason either way."""
    settings, reason = preflight(env, home, node_id, socket_dir, host_config=host_config)
    if settings is None:
        log.info("agent host not started: %s", reason)
        return reason
    bridge = make_bridge(node_id, settings, home, lane_post)
    sock = bridge.listen(socket_dir / "agent.sock")
    slots = threading.BoundedSemaphore(MAX_CONNECTIONS)

    def serve() -> None:
        while not stop.is_set():
            try:
                conn, _ = sock.accept()
            except OSError:
                return
            if not slots.acquire(blocking=False):
                conn.close()                                       # S2: bounded
                continue

            def one(c=conn):
                try:
                    bridge.serve_connection(c)
                except OSError:
                    pass
                finally:
                    slots.release()
            threading.Thread(target=one, name="meshembed-agent-conn", daemon=True).start()

    def intake() -> None:
        while not stop.is_set():
            code = intake_once(bridge, node_post, node_id)
            if code not in ("idle", "accepted"):
                log.info("agent intake: %s", code)
                stop.wait(10)

    def revocations() -> None:
        while not stop.is_set():
            if refresh_revocations(bridge, node_get, node_id) != "ok":
                log.info("agent revocations: fetch_failed")
            stop.wait(REVOCATIONS_EVERY_S)

    for target, name in ((serve, "serve"), (intake, "intake"), (revocations, "revocations")):
        threading.Thread(target=target, name=f"meshembed-agent-{name}", daemon=True).start()
    log.info("agent host started")
    return "ok"
