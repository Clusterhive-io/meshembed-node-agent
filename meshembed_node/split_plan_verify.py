"""M2 build #3, node half: act on a split/probe plan ONLY when it is genuine and for us.

docs/DESIGN_DI_CHAIN_FORMATION.md section 7, fabric F2 (auditor DESIGN GO 2026-10-12; this
build needs its per-build GO). A plan arrives on the poll as {"plan", "sig", "kid"}. It is
accepted only when ALL hold, else it is refused with a short code and ignored:
  - the body is in the CLOSED schema (the backend's split_signing.validate_body, rule for rule);
  - its ed25519 signature over the canonical body verifies against a split-plan PUBLIC key
    COMPILED INTO this daemon (rotated by node release; never delivered at enrolment);
  - it names THIS node (a member, or the coordinator);
  - it is unexpired and does not claim a lifetime over 24 h;
  - its nonce was never seen before (replays refused; nonces kept until their expiry).
The canonical body is RFC 8785 JCS; for this schema (no floats, ASCII strings, ints) that is
exactly json.dumps(sort_keys=True, separators=(",", ":")) -- proven against the backend by
the shared golden vector (shared/split_plan_golden.json).
"""
from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, Optional

# kid -> base64 raw ed25519 public key. EMPTY until the operator generates the split-plan
# key pair and a node release compiles its public half in; until then EVERY plan is refused.
_TRUSTED_SPLIT_PLAN_KEYS: Dict[str, str] = {}

PLAN_VERSION = 2          # v2 (overlay automation 2026-10-14): members carry "endpoint"; v1 is refused
WG_PORT = 51820
PLAN_TYPE = "meshembed.split_plan"
KINDS = ("primary", "twin", "probe")
OVERLAY_NET = ipaddress.ip_network("10.44.0.0/16")
MAX_LIFETIME_S = 24 * 3600
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_WGKEY = re.compile(r"^[A-Za-z0-9+/]{43}=$")
MEMBER_KEYS = {"node_id", "overlay_ip", "wg_pubkey", "layers", "endpoint"}
_RFC1918 = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def endpoint_ok(ep: Any) -> bool:
    """The SAME rule as the backend (backend/app/split_signing.endpoint_ok): None, or
    "A.B.C.D:51820" with a global unicast or RFC1918 IPv4 that is not the overlay, loopback,
    link-local, multicast, unspecified or reserved."""
    if ep is None:
        return True
    if not isinstance(ep, str) or ep.count(":") != 1:
        return False
    host, port = ep.split(":")
    if port != str(WG_PORT):
        return False
    try:
        ip = ipaddress.IPv4Address(host)
    except ValueError:
        return False
    if str(ip) != host or ip in OVERLAY_NET:
        return False
    if ip.is_multicast or ip.is_reserved or ip.is_loopback or ip.is_link_local or ip.is_unspecified:
        return False
    return ip.is_global or any(ip in n for n in _RFC1918)


class PlanRejected(Exception):
    """The plan is not acted on. str() is a short code (reported, never the plan)."""


def canonical(body: Dict[str, Any]) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def validate_body(body: Any) -> None:
    allowed = {"v", "type", "kind", "plan_id", "job_id", "model_sha", "coordinator", "members",
               "expires_at", "nonce"}
    if not isinstance(body, dict) or set(body) != allowed:
        raise PlanRejected("plan_schema_keys")
    if body["v"] != PLAN_VERSION or body["type"] != PLAN_TYPE or body["kind"] not in KINDS:
        raise PlanRejected("plan_schema_header")
    if not (isinstance(body["plan_id"], str) and _ID.fullmatch(body["plan_id"])):
        raise PlanRejected("plan_schema_plan_id")
    probe = body["kind"] == "probe"
    for k in ("job_id", "coordinator"):
        v = body[k]
        if probe and v is not None or (not probe and not (isinstance(v, str) and _ID.fullmatch(v))):
            raise PlanRejected(f"plan_schema_{k}")
    if probe and body["model_sha"] is not None or (
            not probe and not (isinstance(body["model_sha"], str) and _HEX64.fullmatch(body["model_sha"]))):
        raise PlanRejected("plan_schema_model_sha")
    if not (isinstance(body["expires_at"], int) and not isinstance(body["expires_at"], bool)):
        raise PlanRejected("plan_schema_expires_at")
    if not (isinstance(body["nonce"], str) and _HEX32.fullmatch(body["nonce"])):
        raise PlanRejected("plan_schema_nonce")
    members = body["members"]
    if not isinstance(members, list) or not (1 <= len(members) <= 64):
        raise PlanRejected("plan_schema_members")
    seen_nodes, seen_ips = set(), set()
    for m in members:
        if not isinstance(m, dict) or set(m) != MEMBER_KEYS:
            raise PlanRejected("plan_schema_member_keys")
        if not endpoint_ok(m["endpoint"]):
            raise PlanRejected("plan_schema_member_endpoint")
        if not (isinstance(m["node_id"], str) and _ID.fullmatch(m["node_id"])) or m["node_id"] in seen_nodes:
            raise PlanRejected("plan_schema_member_node")
        try:
            ip = ipaddress.ip_address(m["overlay_ip"])
        except (ValueError, TypeError):
            raise PlanRejected("plan_schema_member_ip")
        if ip not in OVERLAY_NET or str(ip) in seen_ips:
            raise PlanRejected("plan_schema_member_ip")
        if not (isinstance(m["wg_pubkey"], str) and _WGKEY.fullmatch(m["wg_pubkey"])):
            raise PlanRejected("plan_schema_member_wg")
        lay = m["layers"]
        if probe:
            if lay is not None:
                raise PlanRejected("plan_schema_member_layers")
        elif not (isinstance(lay, list) and len(lay) == 2
                  and all(isinstance(x, int) and not isinstance(x, bool) for x in lay) and 0 <= lay[0] < lay[1]):
            raise PlanRejected("plan_schema_member_layers")
        seen_nodes.add(m["node_id"])
        seen_ips.add(str(ip))


class NonceStore:
    """Nonces already accepted, kept until their plan's expiry (replays refused)."""

    def __init__(self, path: Optional[Path] = None):
        self.path = path or Path.home() / ".meshembed" / "split-plan-nonces.json"

    def _load(self, now: float) -> Dict[str, int]:
        try:
            d = json.loads(self.path.read_text(encoding="utf-8"))
            return {k: int(v) for k, v in d.items() if int(v) > now}
        except Exception:
            return {}

    def seen(self, nonce: str, now: float) -> bool:
        return nonce in self._load(now)

    def remember(self, nonce: str, expires_at: int, now: float) -> None:
        d = self._load(now)
        d[nonce] = int(expires_at)
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(d), encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)


def _verify_sig(body: Dict[str, Any], sig_b64: Any, kid: Any, trusted: Dict[str, str]) -> None:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    if not isinstance(kid, str) or kid not in trusted:
        raise PlanRejected("plan_key_not_trusted")
    try:
        sig = base64.b64decode(sig_b64, validate=True)
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(trusted[kid], validate=True))
        pub.verify(sig, canonical(body))
    except (InvalidSignature, ValueError, TypeError):
        raise PlanRejected("plan_signature_invalid")


def verify_plan(envelope: Any, my_node_id: str, *, now: Optional[float] = None,
                nonces: Optional[NonceStore] = None,
                trusted: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """The plan body when it may be acted on; raises PlanRejected otherwise. The nonce is
    remembered only after every other check passed."""
    now = time.time() if now is None else now
    trusted = _TRUSTED_SPLIT_PLAN_KEYS if trusted is None else trusted
    nonces = nonces or NonceStore()
    if not isinstance(envelope, dict) or set(envelope) != {"plan", "sig", "kid"}:
        raise PlanRejected("plan_envelope")
    body = envelope["plan"]
    validate_body(body)
    _verify_sig(body, envelope["sig"], envelope["kid"], trusted)
    if body["expires_at"] <= now:
        raise PlanRejected("plan_expired")
    if body["expires_at"] - now > MAX_LIFETIME_S:
        raise PlanRejected("plan_lifetime_too_long")
    names = {m["node_id"] for m in body["members"]} | ({body["coordinator"]} if body["coordinator"] else set())
    if my_node_id not in names:
        raise PlanRejected("plan_not_for_this_node")
    if nonces.seen(body["nonce"], now):
        raise PlanRejected("plan_replayed")
    nonces.remember(body["nonce"], body["expires_at"], now)
    return body
