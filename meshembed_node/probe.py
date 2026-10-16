"""M2 build #4, node half: measure RTT to the members of a VERIFIED probe plan.

docs/DESIGN_DI_CHAIN_FORMATION.md section 4; auditor decisions D1-D3 (2026-10-12); this build
needs its per-build GO. Off unless MESHEMBED_ENABLE_SPLIT=1 on the node.

- The plan comes from POST /node_probe_plan and is acted on ONLY after
  split_plan_verify.verify_plan (closed schema, compiled-in key, names this node, unexpired,
  unseen nonce). Until a release compiles the split-plan key in, every plan is refused and
  nothing is measured.
- Targets are the OTHER members' overlay /32s from that verified plan, and nothing else
  (each re-checked to be a host in 10.44.0.0/16): no arbitrary host, no scan.
- RTT is measured IN-PROCESS, no exec: an unprivileged ICMP echo over a datagram socket
  (needs net.ipv4.ping_group_range to cover the service gid); if the kernel refuses that
  socket, a TCP connect to a fixed port of the peer (SYN -> SYN/ACK or RST = one round trip).
  At most PINGS packets per peer, each bounded by TIMEOUT_S. Neither method -> no number
  for that peer (it simply stays unmeasured: fail closed, it is never grouped into a site).
- No listener is opened (D3: no bandwidth). The report is numbers only:
  {"node_id", "plan_id", "results": [{"peer_node_id", "rtt_ms"}]}.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import socket
import statistics
import struct
import time
from typing import Any, Callable, Dict, List, Optional

from . import split_plan_verify as V

log = logging.getLogger(__name__)

PINGS = 5
TIMEOUT_S = 2.0
TCP_PORT = 9                 # "discard": closed on nodes, so a live peer answers with RST
INTERVAL_S = 300.0           # ask for a plan at most every 5 min


def enabled() -> bool:
    return os.environ.get("MESHEMBED_ENABLE_SPLIT", "0") == "1"


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _icmp_socket() -> Optional[socket.socket]:
    """An unprivileged ICMP datagram socket, or None when the kernel refuses it."""
    try:
        return socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    except OSError:
        return None


def _icmp_rtts(sock: socket.socket, ip: str, n: int, timeout: float) -> List[float]:
    """Echo request/reply over a ping socket (the kernel sets and checks the echo id)."""
    sock.settimeout(timeout)
    out: List[float] = []
    for seq in range(1, n + 1):
        payload = os.urandom(16)
        hdr = struct.pack("!BBHHH", 8, 0, 0, 0, seq)
        pkt = struct.pack("!BBHHH", 8, 0, _checksum(hdr + payload), 0, seq) + payload
        t0 = time.monotonic()
        try:
            sock.sendto(pkt, (ip, 0))
            while True:
                data, addr = sock.recvfrom(1024)
                if addr[0] != ip or len(data) < 8:
                    continue
                typ, _code, _ck, _id, rseq = struct.unpack("!BBHHH", data[:8])
                if typ == 0 and rseq == seq and data[8:] == payload:
                    out.append((time.monotonic() - t0) * 1000.0)
                    break
                if time.monotonic() - t0 > timeout:
                    break
        except (socket.timeout, OSError):
            continue
    return out


def _tcp_rtts(ip: str, n: int, timeout: float, port: int = TCP_PORT) -> List[float]:
    """connect() time: SYN/ACK (open) or RST (closed) both mean one round trip.
    A timeout or an unreachable error is no measurement."""
    out: List[float] = []
    for _ in range(n):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        t0 = time.monotonic()
        try:
            s.connect((ip, port))
            out.append((time.monotonic() - t0) * 1000.0)
        except ConnectionRefusedError:
            out.append((time.monotonic() - t0) * 1000.0)
        except OSError:
            pass
        finally:
            s.close()
    return out


def measure(ip: str, *, pings: int = PINGS, timeout: float = TIMEOUT_S,
            icmp_socket: Callable[[], Optional[socket.socket]] = _icmp_socket) -> Optional[float]:
    """Median RTT in ms to `ip`, or None. ICMP first; TCP only when ICMP is unavailable."""
    sock = icmp_socket()
    if sock is not None:
        try:
            rtts = _icmp_rtts(sock, ip, pings, timeout)
        finally:
            sock.close()
        method = "icmp"
    else:
        rtts = _tcp_rtts(ip, pings, timeout)
        method = "tcp"
    if not rtts:
        log.info("probe: no RTT to %s (%s)", ip, method)
        return None
    return round(max(statistics.median(rtts), 0.001), 3)


def targets(body: Dict[str, Any], my_node_id: str) -> List[Dict[str, str]]:
    """The OTHER members of a verified plan, each re-checked to be an overlay host."""
    out = []
    for m in body["members"]:
        if m["node_id"] == my_node_id:
            continue
        ip = ipaddress.ip_address(m["overlay_ip"])
        if ip.version != 4 or ip not in V.OVERLAY_NET or ip in (V.OVERLAY_NET.network_address,
                                                                  V.OVERLAY_NET.broadcast_address):
            continue
        out.append({"node_id": m["node_id"], "ip": str(ip)})
    return out


def run_once(post: Callable[[str, dict], dict], my_node_id: str, *,
             nonces: Optional[V.NonceStore] = None, trusted: Optional[Dict[str, str]] = None,
             measure_fn: Callable[[str], Optional[float]] = measure,
             overlay_up: Optional[Callable[[dict], bool]] = None) -> Optional[int]:
    """Fetch -> verify -> measure -> report. Returns pairs reported, or None if nothing
    was acted on. `post(path, payload) -> json` is the daemon's authenticated POST."""
    env = (post("/node_probe_plan", {"node_id": my_node_id}) or {}).get("plan")
    if not env:
        return None
    try:
        body = V.verify_plan(env, my_node_id, nonces=nonces, trusted=trusted)
    except V.PlanRejected as e:
        log.warning("probe: plan refused (%s)", e)
        return None
    if body["kind"] != "probe":
        log.warning("probe: plan refused (not_a_probe_plan)")
        return None
    if overlay_up is not None and not overlay_up(env):       # step 3: the ROOT launcher builds meshdi0
        log.warning("probe: the launcher did not bring the overlay up for plan %s", body["plan_id"])
        return None
    results = []
    for t in targets(body, my_node_id):
        rtt = measure_fn(t["ip"])
        if rtt is not None:
            results.append({"peer_node_id": t["node_id"], "rtt_ms": rtt})
    if not results:
        return 0
    resp = post("/node_probe_report", {"node_id": my_node_id, "plan_id": body["plan_id"], "results": results})
    return int((resp or {}).get("stored", 0))


def loop(post: Callable[[str, dict], dict], my_node_id: str, stop) -> None:
    """Daemon thread body (only started when enabled()). `stop` is a threading.Event."""
    while not stop.wait(INTERVAL_S):
        try:
            from .split_handoff import request_overlay
            run_once(post, my_node_id, overlay_up=request_overlay)
        except Exception as exc:          # 404 = backend without split; anything else: retry later
            log.debug("probe cycle failed: %s", exc)
