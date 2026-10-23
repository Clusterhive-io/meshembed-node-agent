"""MVP 1 (2026-10-21): act on a SERVE plan only when it is genuine and for us.

A serve plan tells ONE node to serve ONE pinned model whole, with ONE pinned draft, on its own CPU
(meshembed-serve.service: Unix socket only, no network). It arrives as {"plan", "sig", "kid"} and is accepted only
when ALL hold, else it is refused with a short code:
  - the body is in the CLOSED schema below (no extra keys, typed, bounded);
  - its ed25519 signature over the canonical body verifies against a plan key COMPILED INTO this daemon (the same
    key set as split plans: empty until the operator generates the pair, so every plan is refused until then);
  - it names THIS node; it is unexpired and claims at most 24 h; its nonce was never seen.
Same canonical form, signature rule and nonce store as split_plan_verify. Stopping the server never needs a plan:
the owner (or the owner-first scheduler) may stop it at any time.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, Optional

from . import split_plan_verify as _S
from .split_plan_verify import NonceStore, PlanRejected

PLAN_TYPE = "meshembed.serve_plan"
PLAN_VERSION = 2           # v2 (M3, auditor 2026-10-21 18:38Z): draft_sha may be null (= the no-draft unit); v1 refused
MAX_LIFETIME_S = 6 * 3600 + 120     # w4: the backend caps a plan at 6 h; 2 min of clock skew
KEYS = {"type", "v", "plan_id", "node_id", "model_sha", "draft_sha", "ctx", "slots", "nonce", "issued_at",
        "expires_at"}
_SHA = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def _int(v: Any, lo: int, hi: int) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi


def validate_body(body: Any) -> None:
    # Q1: the TYPE first -- split plans are signed by the same key, so a split plan must fail here as a type
    if not isinstance(body, dict) or body.get("type") != PLAN_TYPE:
        raise PlanRejected("serve_plan_type")
    if set(body) != KEYS:
        raise PlanRejected("serve_plan_schema")
    if body["v"] != PLAN_VERSION:
        raise PlanRejected("serve_plan_version")
    for k in ("plan_id", "node_id", "nonce"):
        if not isinstance(body[k], str) or not _ID.match(body[k]):
            raise PlanRejected(f"serve_plan_{k}")
    if not isinstance(body["model_sha"], str) or not _SHA.match(body["model_sha"]):
        raise PlanRejected("serve_plan_model_sha")
    if body["draft_sha"] is not None and (not isinstance(body["draft_sha"], str) or not _SHA.match(body["draft_sha"])):
        raise PlanRejected("serve_plan_draft_sha")
    if body["model_sha"] == body["draft_sha"]:
        raise PlanRejected("serve_plan_draft_is_model")
    if not _int(body["ctx"], 512, 131072) or not _int(body["slots"], 1, 4):
        raise PlanRejected("serve_plan_bounds")
    if not _int(body["issued_at"], 0, 2**40) or not _int(body["expires_at"], 0, 2**40) \
            or not (0 < body["expires_at"] - body["issued_at"] <= MAX_LIFETIME_S):
        raise PlanRejected("serve_plan_times")


def verify_serve_plan(envelope: Any, my_node_id: str, *, now: Optional[float] = None,
                      nonces: Optional[NonceStore] = None,
                      trusted: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """The plan body when it may be acted on; raises PlanRejected otherwise. The nonce is remembered last."""
    now = time.time() if now is None else now
    trusted = _S._TRUSTED_SPLIT_PLAN_KEYS if trusted is None else trusted
    nonces = nonces or NonceStore()
    if not isinstance(envelope, dict) or set(envelope) != {"plan", "sig", "kid"}:
        raise PlanRejected("plan_envelope")
    body = envelope["plan"]
    validate_body(body)
    _S._verify_sig(body, envelope["sig"], envelope["kid"], trusted)
    if body["expires_at"] <= now:
        raise PlanRejected("plan_expired")
    if body["expires_at"] - now > MAX_LIFETIME_S:
        raise PlanRejected("plan_lifetime_too_long")
    if body["node_id"] != my_node_id:
        raise PlanRejected("plan_not_for_this_node")
    if nonces.seen(body["nonce"], now):
        raise PlanRejected("plan_replayed")
    nonces.remember(body["nonce"], body["expires_at"], now)
    return body
