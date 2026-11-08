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
from fractions import Fraction
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# kid -> base64 raw ed25519 public key. The PROD split-plan key, generated on 188 by the orchestrator on the operator's
# OK (2026-10-28 12:19:38Z; sha256 of the raw key df9a92c19cadc8016e9ebe885d965a8fd331a6c01d65a16b847666d4c6decc34;
# docs/RECORD_E3_PROD_KEYS_2026-10-28.md). A BUILD INPUT (P3-3): tests/test_release_keys.py pins this exact value and
# refuses any other key, the sandbox proof key included.
_TRUSTED_SPLIT_PLAN_KEYS: Dict[str, str] = {"v1": "bKtntmlv5wMX3zrbcMugBf/OZ6nqRlQTfUmt6+CiBRA="}

PLAN_VERSION = 3          # v3 (proposal A, auditor GO 2026-10-21): n_layer/ngl/ts signed, ranges == assign(); v1/v2 refused
WG_PORT = 51820
PLAN_TYPE = "meshembed.split_plan"
KINDS = ("primary", "twin", "probe", "serve")
OVERLAY_NET = ipaddress.ip_network("10.44.0.0/16")
MAX_LIFETIME_S = 24 * 3600
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_WGKEY = re.compile(r"^[A-Za-z0-9+/]{43}=$")
MEMBER_KEYS = {"node_id", "overlay_ip", "wg_pubkey", "layers", "endpoint"}
# SPLIT-SERVE head 2 (auditor 2026-11-02 18:22:04Z, option (A)): the closed key set is chosen BY the signed kind. The
# batch kinds keep the v3 sets byte-for-byte; kind "serve" adds the certified runtime set (SS-4/SP-2) to the body and
# each member's signed memory share (CAP-2) to its member entry, and forbids a job_id. An old verifier refuses a serve
# plan on its closed key set.
BODY_KEYS = frozenset({"v", "type", "kind", "plan_id", "job_id", "model_sha", "coordinator", "members",
                       "expires_at", "nonce", "n_layer", "ngl", "ts"})
SERVE_BODY_KEYS = BODY_KEYS | {"runtime_set"}
SERVE_MEMBER_KEYS = MEMBER_KEYS | {"memory_max_mb"}
MEMORY_MAX_MB = (512, 4 * 1024 * 1024)          # a member's signed share: 512 MB .. 4 TB
_RFC1918 = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
MAX_N_LAYER = 1024


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
    if not isinstance(body, dict):
        raise PlanRejected("plan_schema_keys")
    serve = body.get("kind") == "serve"
    if set(body) != (SERVE_BODY_KEYS if serve else BODY_KEYS):
        raise PlanRejected("plan_schema_keys")
    if body["v"] != PLAN_VERSION or body["type"] != PLAN_TYPE or body["kind"] not in KINDS:
        raise PlanRejected("plan_schema_header")
    if not (isinstance(body["plan_id"], str) and _ID.fullmatch(body["plan_id"])):
        raise PlanRejected("plan_schema_plan_id")
    probe = body["kind"] == "probe"
    for k in ("job_id", "coordinator"):
        v = body[k]
        absent = probe or (serve and k == "job_id")              # a serve plan never names a job
        if absent and v is not None or (not absent and not (isinstance(v, str) and _ID.fullmatch(v))):
            raise PlanRejected(f"plan_schema_{k}")
    if serve and not (isinstance(body["runtime_set"], str) and _HEX64.fullmatch(body["runtime_set"])):
        raise PlanRejected("plan_schema_runtime_set")
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
        if not isinstance(m, dict) or set(m) != (SERVE_MEMBER_KEYS if serve else MEMBER_KEYS):
            raise PlanRejected("plan_schema_member_keys")
        if serve and not (_int(m["memory_max_mb"]) and MEMORY_MAX_MB[0] <= m["memory_max_mb"] <= MEMORY_MAX_MB[1]):
            raise PlanRejected("plan_schema_member_memory")
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
        elif not (isinstance(lay, list) and len(lay) == 2 and all(_int(x) for x in lay) and 0 <= lay[0] <= lay[1]):
            raise PlanRejected("plan_schema_member_layers")
        seen_nodes.add(m["node_id"])
        seen_ips.add(str(ip))
    _validate_placement(body, probe)


def _int(x: Any) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


def llama_assign(n_layer: int, ngl: int, ts: List[int]) -> List[Tuple[int, int]]:
    """llama.cpp's split rule, written here INDEPENDENTLY of the backend (exact fractions, no float epsilon):
    the last `ngl` of the block ids 0..n_layer (n_layer = the output head) go to the RPC devices in --rpc order;
    block j of them (0-based) belongs to the first device whose cumulative --tensor-split share exceeds j/ngl.
    The earlier blocks stay on the coordinator: [0, n_layer + 1 - ngl)."""
    start, tot = n_layer + 1 - ngl, sum(ts)
    bounds, acc = [], 0
    for t in ts:
        acc += t
        bounds.append(Fraction(acc, tot))
    out: List[List[int]] = [[] for _ in ts]
    for j in range(ngl):
        x = Fraction(j, ngl)
        dev = next((d for d, b in enumerate(bounds) if x < b), len(ts) - 1)
        out[dev].append(start + j)
    return [(ids[0], ids[-1] + 1) if ids else (0, 0) for ids in out]


def _validate_placement(body: Dict[str, Any], probe: bool) -> None:
    """v3, rule for rule with the backend (split_signing._validate_placement), auditor A1 condition 1 + the 13:23Z
    node-side check: TS count == RPC members, entries non-negative integers (sum > 0); NGL in 0..n_layer+1; the
    coordinator is a member holding the FIRST blocks [0, n_layer+1-ngl); the others, in list order (= --rpc order),
    hold exactly llama_assign(n_layer, ngl, ts), each non-empty. Consistent-looking ranges that are not what
    llama.cpp would run are refused."""
    n, ngl, ts = body["n_layer"], body["ngl"], body["ts"]
    if probe:
        if n is not None or ngl is not None or ts is not None:
            raise PlanRejected("plan_schema_placement")
        return
    if not (_int(n) and 1 <= n <= MAX_N_LAYER):
        raise PlanRejected("plan_schema_n_layer")
    if not (_int(ngl) and 0 <= ngl <= n + 1):
        raise PlanRejected("plan_schema_ngl")
    members = body["members"]
    coord = [m for m in members if m["node_id"] == body["coordinator"]]
    if len(coord) != 1:
        raise PlanRejected("plan_coordinator_not_member")
    stages = [m for m in members if m["node_id"] != body["coordinator"]]
    if not (isinstance(ts, list) and len(ts) == len(stages) and all(_int(x) and x >= 0 for x in ts) and sum(ts) > 0):
        raise PlanRejected("plan_schema_ts")
    if list(coord[0]["layers"]) != [0, n + 1 - ngl]:
        raise PlanRejected("plan_coordinator_range")
    for m, (a, b) in zip(stages, llama_assign(n, ngl, ts)):
        if a >= b or list(m["layers"]) != [a, b]:
            raise PlanRejected("plan_ranges_not_assign")


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
    # AR1 (auditor 2026-10-23 09:50Z (a)): "rt*" names a RUN-TICKET key; a plan is never accepted under it, even if
    # a ticket key were put in this set by mistake
    if not isinstance(kid, str) or kid.startswith("rt") or kid not in trusted:
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
