"""Overlay automation step 3, ROOT side (runs inside the root split launcher only).
docs/DESIGN_OVERLAY_AUTOMATION_2026-10-13.md sections 2, 6, 7; auditor design GO 2026-10-14 06:29Z.

- ensure_key(): the node's WireGuard key pair is generated HERE, as root, once: umask 077, the
  private key written O_EXCL 0600 in a 0700 root directory; the public half derived by feeding
  the private key FILE to `wg pubkey` on stdin (never argv, env or a log). Only the public value
  ever leaves (ready.json -> the daemon -> the backend), condition (d).
- configure(): builds the interface `meshdi0` (its own name: a host's wg0, like M1's, is never
  touched) from a VERIFIED plan v2 body only. OWN-KEY CHECK first: the plan's entry for this node
  must carry THIS host's public key, else Refused("own_wg_key_mismatch") (a stale plan after a
  rotation, or a plan for a key this host does not hold). Then: /32 from the plan, the private key
  by PATH (`wg set ... private-key <file>`), one peer per OTHER member with allowed-ips = its /32
  only, an endpoint only when the plan gives one, keepalive when this node dials out, and a listen
  port only when the plan names this node a listener. Fixed argv, validated values, no shell.
- firewall(): table inet mesh_di -- TCP 50052 only on meshdi0 from the members' /32s; UDP 51820
  only while this node listens, from the given sources (empty = any; auditor decision pending).
- teardown(): removes meshdi0 and the table. Idempotent.
"""
from __future__ import annotations

import ipaddress
import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence

IFACE = "meshdi0"
WG_DIR = Path("/etc/meshembed-node/wg")
WG_PORT = 51820
RPC_PORT = 50052
NFT_TABLE = "mesh_di"
HANDSHAKE_RATE = "20/second"      # WireGuard handshake initiations per listener (a plan has <= 64 members)
HANDSHAKE_BURST = 50
_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}
_WGKEY = re.compile(r"^[A-Za-z0-9+/]{43}=$")

Runner = Callable[[Sequence[str], Optional[bytes]], bytes]


class Refused(Exception):
    """A short code; nothing is configured."""


def run(argv: Sequence[str], stdin: Optional[bytes] = None) -> bytes:
    r = subprocess.run(list(argv), input=stdin, capture_output=True, env=_ENV, timeout=30, check=False)
    if r.returncode != 0:
        raise RuntimeError(f"{argv[0]} {argv[1] if len(argv) > 1 else ''} failed rc={r.returncode}")
    return r.stdout


def ensure_key(wg_dir: Path = WG_DIR, runner: Runner = run) -> str:
    """The node's own WireGuard public key, generating the pair once. Root-only files."""
    wg_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(wg_dir, 0o700)
    priv, pub = wg_dir / "private.key", wg_dir / "public.key"
    if not priv.exists():
        old = os.umask(0o077)
        try:
            key = runner(["wg", "genkey"], None)
            fd = os.open(priv, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(fd, key)
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            os.umask(old)
    st = os.stat(priv)
    if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077:
        raise Refused("wg_private_key_permissions")
    with open(priv, "rb") as f:                       # the private key goes to wg on STDIN, never argv
        public = runner(["wg", "pubkey"], f.read()).decode().strip()
    if not _WGKEY.fullmatch(public):
        raise Refused("wg_pubkey_invalid")
    tmp = pub.with_suffix(".tmp")
    tmp.write_text(public + "\n")
    os.chmod(tmp, 0o644)
    os.replace(tmp, pub)
    return public


def _own(body: Dict[str, Any], me: str) -> Dict[str, Any]:
    mine = [m for m in body["members"] if m["node_id"] == me]
    if len(mine) != 1:
        raise Refused("plan_does_not_name_this_node")
    return mine[0]


def configure(body: Dict[str, Any], me: str, own_pubkey: str, *, wg_dir: Path = WG_DIR,
              runner: Runner = run, netns: Optional[str] = None) -> Dict[str, Any]:
    """meshdi0 from a VERIFIED plan v2 body. Returns what was configured (ids/IPs only)."""
    own = _own(body, me)
    if own["wg_pubkey"] != own_pubkey:
        raise Refused("own_wg_key_mismatch")
    pre = ["ip", "netns", "exec", netns] if netns else []
    own_ip = str(ipaddress.ip_address(own["overlay_ip"]))
    listener = own.get("endpoint") is not None
    teardown(runner=runner, netns=netns)
    runner(pre + ["ip", "link", "add", IFACE, "type", "wireguard"], None)
    args = pre + ["wg", "set", IFACE, "private-key", str(wg_dir / "private.key")]
    if listener:
        args += ["listen-port", str(WG_PORT)]
    peers: List[str] = []
    for m in body["members"]:
        if m["node_id"] == me:
            continue
        ip = str(ipaddress.ip_address(m["overlay_ip"]))
        args += ["peer", m["wg_pubkey"], "allowed-ips", f"{ip}/32"]
        if m.get("endpoint"):
            args += ["endpoint", m["endpoint"]]
        if not listener:
            args += ["persistent-keepalive", "25"]
        peers.append(ip)
    runner(args, None)
    runner(pre + ["ip", "address", "add", f"{own_ip}/32", "dev", IFACE], None)
    runner(pre + ["ip", "link", "set", IFACE, "up"], None)
    for ip in peers:
        runner(pre + ["ip", "route", "add", f"{ip}/32", "dev", IFACE], None)
    return {"iface": IFACE, "own_ip": own_ip, "peers": peers, "listener": listener}


def firewall(peers: Iterable[str], *, listener: bool, udp_sources: Iterable[str] = (),
             runner: Runner = run, netns: Optional[str] = None) -> str:
    """The nft table for this plan (replaces any previous one). Returns the ruleset text applied."""
    pre = ["ip", "netns", "exec", netns] if netns else []
    peer_set = ", ".join(str(ipaddress.ip_address(p)) for p in peers) or "127.0.0.255"
    src = [str(ipaddress.ip_address(s)) for s in udp_sources]
    udp = ""
    if listener:
        # auditor 08:05Z (option ii + recommendation): any source while listening, but HANDSHAKE
        # INITIATIONS (WireGuard message type 1 = first payload byte) are rate-limited per listener;
        # data packets (type 4) are never throttled -- they carry every token's activations.
        saddr = f"ip saddr {{ {', '.join(src)} }} " if src else ""
        udp = (f"    udp dport {WG_PORT} {saddr}@th,64,8 1 limit rate {HANDSHAKE_RATE} burst {HANDSHAKE_BURST} packets accept\n"
               f"    udp dport {WG_PORT} @th,64,8 1 counter drop\n"
               f"    udp dport {WG_PORT} {saddr}accept\n")
    rules = (f"table inet {NFT_TABLE} {{\n"
             f"  chain input {{\n"
             f"    type filter hook input priority -10; policy accept;\n"
             f"    iifname \"{IFACE}\" tcp dport {RPC_PORT} ip saddr {{ {peer_set} }} accept\n"
             f"    tcp dport {RPC_PORT} drop\n"
             f"{udp}"
             f"    udp dport {WG_PORT} drop\n"
             f"  }}\n"
             f"}}\n")
    try:
        runner(pre + ["nft", "delete", "table", "inet", NFT_TABLE], None)
    except RuntimeError:
        pass
    runner(pre + ["nft", "-f", "-"], rules.encode())
    return rules


def teardown(*, runner: Runner = run, netns: Optional[str] = None) -> None:
    pre = ["ip", "netns", "exec", netns] if netns else []
    for argv in (pre + ["ip", "link", "del", IFACE], pre + ["nft", "delete", "table", "inet", NFT_TABLE]):
        try:
            runner(argv, None)
        except RuntimeError:
            pass                                      # already gone
