"""AR1 G1, agent-host half: act on a RUN TICKET only when it is genuine, for us, for this task, for an admin-signed
definition we hold, for a user we may serve -- and never twice (auditor A10 G1-G3; plan GO 2026-10-23 09:50Z with
(a), (b), R1, R2, R4).

A ticket arrives as {"ticket", "sig", "kid"} beside the task text. Checked in this order, each failure a closed code
(str() of TicketRejected), nothing of the ticket or the task in it:
   1. the envelope keys (a plan envelope {"plan", ...} fails here);
   2. the closed schema, TYPE FIRST (the backend's run_ticket.validate_body, rule for rule);
   3. the key: a kid in the run-ticket namespace "rt*" AND in the run-ticket keys COMPILED INTO this daemon (empty
      until the operator generates the pair). Plan keys are a different set; a plan kid is refused here even when
      its signature would verify (a);
   4. the ed25519 signature over the canonical body;
   5. node_id == this agent host; tenant == this host's pool;
   6. not expired, no lifetime over 1 h; a START after start_by is refused (ticket_stale) (b);
   7. R2: sha256(task text) == task_sha256 (a ticket cannot be paired with another text);
   8. G2: the local definition verifies against the customer admin key PINNED at enrolment (never replaced by the
      backend), sha256(canonical definition) == def_hash, and it names the same tenant / agent / version; the ticket's
      class ceiling is not above the definition's;
   9. G2/G3: neither the definition (agent_id, def_version) nor the ticket is revoked (revocations only restrict);
   9b. P2: the revocation snapshot is FRESH (fetched within 10 min); a missing or stale one refuses the run;
  10. R4 + P1: the user may run here, by the host's policy SIGNED by the pinned customer admin key (personal: its
      owner; shared: the listed users), never an older version than one already accepted;
  11. R1: a START binds the nonce to a NEW run id (a second start of the nonce is a replay); a RESUME must present
      the run id the nonce is bound to. The store is persisted and fails closed when unreadable.
A resume (G3) runs the same checks 1-10 again (the ticket may have expired or been revoked meanwhile).

WHERE IT RUNS (auditor 10:11Z P3): in the NODE DAEMON, under the daemon's uid. The nonce, revocation and policy-version
stores and the pinned admin keys live in the daemon's ~/.meshembed (files 0600, directory 0700). The agent unit's uid,
which runs the model loop on hostile content, receives only the verified run and has NO write access to them (the
agent unit's sandbox test comes with that unit, G9).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import time
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple

# kid -> base64 raw ed25519 public key. The PROD run-ticket key rt1, generated on 188 by the orchestrator on the
# operator's OK (2026-10-28 12:19:38Z; sha256 of the raw key cefed6919d141e80870120b79aea45e2a727df32b65024954a7b119113f4c084;
# docs/RECORD_E3_PROD_KEYS_2026-10-28.md). Disjoint from split_plan_verify's plan keys. A BUILD INPUT (P3-3): pinned by
# tests/test_release_keys.py.
_TRUSTED_RUN_TICKET_KEYS: Dict[str, str] = {"rt1": "0i1VvFKwqZeLtMH5hl7lMOfs4uyQMlr0AGbLwUo2doY="}

TICKET_TYPE = "meshembed.run_ticket"
TICKET_VERSION = 1
DEF_TYPE = "meshembed.agent_definition"
DEF_VERSION = 1
MAX_LIFETIME_S = 3600
WALL_MARGIN_S = 600
START_WINDOW_S = 300
CLASSES = ("public", "internal")
_RANK = {"public": 0, "internal": 1}
PHASE0_TOOLS = frozenset({"calc", "table", "dates"})      # AR1 phase 0: the M8 tools only (auditor Q4)
KEYS = {"type", "v", "ticket_id", "node_id", "tenant", "user_id", "agent_id", "def_version", "def_hash",
        "task_sha256", "class_ceiling", "max_tokens", "wall_s", "nonce", "issued_at", "start_by", "expires_at"}
DEF_KEYS = {"type", "v", "tenant", "agent_id", "def_version", "class_ceiling", "models", "tools", "budgets"}
_MODEL = re.compile(r"^[A-Za-z0-9._:/-]{1,128}$")
MAX_MODELS = 8
BUDGET_LIMITS = {"steps": 100, "tool_calls": 200, "tokens": 10 ** 7, "wall_s": MAX_LIFETIME_S - WALL_MARGIN_S}
_SHA = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_HEX32 = re.compile(r"^[0-9a-f]{32}$")
TICKET_KID = re.compile(r"^rt[a-z0-9]{1,14}$")


class TicketRejected(Exception):
    """The run does not start (or resume). str() is a short closed code."""


def canonical(body: Dict[str, Any]) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _int(v: Any, lo: int, hi: int) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi


def validate_body(body: Any) -> None:
    """The backend's run_ticket.validate_body, rule for rule."""
    if not isinstance(body, dict) or body.get("type") != TICKET_TYPE:
        raise TicketRejected("ticket_type")
    if set(body) != KEYS:
        raise TicketRejected("ticket_schema")
    if body["v"] != TICKET_VERSION:
        raise TicketRejected("ticket_version")
    for k in ("ticket_id", "node_id", "tenant", "user_id", "agent_id"):
        if not isinstance(body[k], str) or not _ID.fullmatch(body[k]):
            raise TicketRejected(f"ticket_{k}")
    for k in ("def_hash", "task_sha256"):
        if not isinstance(body[k], str) or not _SHA.fullmatch(body[k]):
            raise TicketRejected(f"ticket_{k}")
    if not (isinstance(body["nonce"], str) and _HEX32.fullmatch(body["nonce"])):
        raise TicketRejected("ticket_nonce")
    if body["class_ceiling"] not in CLASSES:
        raise TicketRejected("ticket_class_ceiling")
    if not _int(body["def_version"], 1, 10 ** 6) or not _int(body["max_tokens"], 1, 10 ** 7) \
            or not _int(body["wall_s"], 1, MAX_LIFETIME_S - WALL_MARGIN_S):
        raise TicketRejected("ticket_bounds")
    i, s, e = body["issued_at"], body["start_by"], body["expires_at"]
    if not all(_int(x, 0, 2 ** 40) for x in (i, s, e)) or not (i < s <= e) \
            or s - i > START_WINDOW_S or e - i > min(MAX_LIFETIME_S, body["wall_s"] + WALL_MARGIN_S):
        raise TicketRejected("ticket_times")


def _verify(body: Dict[str, Any], sig_b64: Any, pub_b64: str, code: str) -> None:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        sig = base64.b64decode(sig_b64, validate=True)
        Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64, validate=True)).verify(sig, canonical(body))
    except (InvalidSignature, ValueError, TypeError):
        raise TicketRejected(code)


def validate_definition(d: Any) -> None:
    if not isinstance(d, dict) or d.get("type") != DEF_TYPE:
        raise TicketRejected("definition_type")
    if set(d) != DEF_KEYS or d["v"] != DEF_VERSION:
        raise TicketRejected("definition_schema")
    for k in ("tenant", "agent_id"):
        if not isinstance(d[k], str) or not _ID.fullmatch(d[k]):
            raise TicketRejected("definition_schema")
    if not _int(d["def_version"], 1, 10 ** 6) or d["class_ceiling"] not in CLASSES:
        raise TicketRejected("definition_schema")
    m = d["models"]                 # auditor 13:03Z Q3: the model ids this agent may run on, SIGNED by the admin
    if not isinstance(m, list) or not 1 <= len(m) <= MAX_MODELS or m != sorted(set(m)) \
            or not all(isinstance(x, str) and _MODEL.fullmatch(x) for x in m):
        raise TicketRejected("definition_models")
    t = d["tools"]
    if not isinstance(t, list) or t != sorted(set(t)) or not set(t) <= PHASE0_TOOLS:
        raise TicketRejected("definition_tools")
    b = d["budgets"]
    if not isinstance(b, dict) or set(b) != set(BUDGET_LIMITS) \
            or not all(_int(b[k], 1, hi) for k, hi in BUDGET_LIMITS.items()):
        raise TicketRejected("definition_budgets")


def verify_definition(envelope: Any, admin_keys: Dict[str, str]) -> Tuple[Dict[str, Any], str]:
    """(definition, def_hash) when it verifies against an admin key PINNED on this host (G2)."""
    if not isinstance(envelope, dict) or set(envelope) != {"definition", "sig", "kid"}:
        raise TicketRejected("definition_envelope")
    d = envelope["definition"]
    validate_definition(d)
    _ascii(d, "definition_schema")
    kid = envelope["kid"]
    if not isinstance(kid, str) or kid not in admin_keys:
        raise TicketRejected("definition_key_not_pinned")
    _verify(d, envelope["sig"], admin_keys[kid], "definition_signature_invalid")
    return d, hashlib.sha256(canonical(d)).hexdigest()


REVOCATIONS_MAX_AGE_S = 600


class Revocations:
    """Revoked definitions and tickets, from the host's last fetch of /nodes/agent/revocations.
    ADD only: a fetch merges into what is held, it never removes (G2: a revocation push can only restrict).
    FRESH only (auditor 10:11Z P2): a run neither starts nor resumes when the snapshot is missing, unreadable or
    older than REVOCATIONS_MAX_AGE_S -- so deleting the file or blocking the feed refuses runs instead of
    un-revoking."""

    def __init__(self, path: Optional[Path] = None):
        self.path = path or Path.home() / ".meshembed" / "agent-revocations.json"

    def _read(self) -> Optional[Dict[str, Any]]:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except Exception:
            raise TicketRejected("revocations_unreadable")          # fail closed

    def load(self, now: float) -> Dict[str, set]:
        d = self._read()
        if d is None or not isinstance(d.get("fetched_at"), (int, float)) \
                or not (0 <= now - d["fetched_at"] <= REVOCATIONS_MAX_AGE_S):
            raise TicketRejected("revocations_stale")
        return {"definitions": {tuple(x) for x in d.get("definitions", [])}, "tickets": set(d.get("tickets", []))}

    def update(self, definitions: Iterable[Tuple[str, int]], tickets: Iterable[str], now: float) -> None:
        """A successful fetch: merge (add-only) and stamp the time."""
        d = self._read() or {}
        defs = {tuple(x) for x in d.get("definitions", [])} | {(str(a), int(v)) for a, v in definitions}
        ticks = set(d.get("tickets", [])) | {str(t) for t in tickets}
        _write(self.path, {"definitions": sorted([list(x) for x in defs]), "tickets": sorted(ticks),
                           "fetched_at": now})


class RunNonces:
    """R1: nonce -> run_id, kept until the ticket's expiry. Fails closed when the file exists but cannot be read."""

    def __init__(self, path: Optional[Path] = None):
        self.path = path or Path.home() / ".meshembed" / "run-ticket-nonces.json"

    def _load(self, now: float) -> Dict[str, list]:
        try:
            d = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except Exception:
            raise TicketRejected("nonce_store_unreadable")
        return {k: v for k, v in d.items() if int(v[1]) > now}

    def start(self, nonce: str, expires_at: int, now: float) -> str:
        d = self._load(now)
        if nonce in d:
            raise TicketRejected("ticket_replayed")
        run_id = "run-" + secrets.token_hex(12)
        d[nonce] = [run_id, int(expires_at)]
        _write(self.path, d)
        return run_id

    def resume(self, nonce: str, run_id: str, now: float) -> str:
        bound = self._load(now).get(nonce)
        if bound is None or bound[0] != run_id:
            raise TicketRejected("ticket_replayed")                 # not the run this nonce started
        return run_id


def _write(path: Path, obj: Any) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(obj), encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


POLICY_TYPE = "meshembed.agent_host_policy"
POLICY_KEYS = {"type", "v", "tenant", "node_id", "mode", "owner", "users", "version"}


def _ascii(body: Dict[str, Any], code: str) -> None:
    """Signed documents are ASCII-only, so this canonical form == the backend's JCS (auditor 10:11Z nit)."""
    if not canonical(body).isascii():
        raise TicketRejected(code)


def verify_policy(envelope: Any, admin_keys: Dict[str, str], node_id: str, tenant: str,
                  versions: Optional["PolicyVersions"] = None) -> Dict[str, Any]:
    """P1 (auditor 10:11Z): the host's user policy is a document SIGNED by the customer admin key pinned here, so a
    backend cannot add a user to a host. Its version never goes back (a replayed older policy is refused)."""
    if not isinstance(envelope, dict) or set(envelope) != {"policy", "sig", "kid"}:
        raise TicketRejected("policy_envelope")
    p = envelope["policy"]
    if not isinstance(p, dict) or p.get("type") != POLICY_TYPE:
        raise TicketRejected("policy_type")
    if set(p) != POLICY_KEYS or p["v"] != 1 or not _int(p["version"], 1, 10 ** 9):
        raise TicketRejected("policy_schema")
    for k in ("tenant", "node_id"):
        if not isinstance(p[k], str) or not _ID.fullmatch(p[k]):
            raise TicketRejected("policy_schema")
    users = p["users"]
    if not isinstance(users, list) or len(users) > 500 or users != sorted(set(users)) \
            or not all(isinstance(u, str) and _ID.fullmatch(u) for u in users):
        raise TicketRejected("policy_schema")
    if p["mode"] == "personal":
        if not (isinstance(p["owner"], str) and _ID.fullmatch(p["owner"])) or users:
            raise TicketRejected("policy_schema")
    elif p["mode"] == "shared":
        if p["owner"] is not None or not users:
            raise TicketRejected("policy_schema")
    else:
        raise TicketRejected("policy_schema")
    _ascii(p, "policy_schema")
    kid = envelope["kid"]
    if not isinstance(kid, str) or kid not in admin_keys:
        raise TicketRejected("policy_key_not_pinned")
    _verify(p, envelope["sig"], admin_keys[kid], "policy_signature_invalid")
    if p["node_id"] != node_id or p["tenant"] != tenant:
        raise TicketRejected("policy_not_for_this_host")
    if versions is not None:
        versions.check(node_id, p["version"])
    return {"mode": p["mode"], "owner": p["owner"], "users": users}


class PolicyVersions:
    """The highest policy version this host has accepted (rollback guard). Fails closed when unreadable."""

    def __init__(self, path: Optional[Path] = None):
        self.path = path or Path.home() / ".meshembed" / "agent-policy-version.json"

    def check(self, node_id: str, version: int) -> None:
        try:
            d = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            d = {}
        except Exception:
            raise TicketRejected("policy_store_unreadable")
        if version < int(d.get(node_id, 0)):
            raise TicketRejected("policy_rolled_back")
        if version > int(d.get(node_id, 0)):
            d[node_id] = int(version)
            _write(self.path, d)


def user_allowed(policy: Any, user_id: str) -> bool:
    """R4: this host's copy of the pool admin's policy. {"mode": "personal", "owner": id} or
    {"mode": "shared", "users": [ids]}; anything else serves nobody."""
    if not isinstance(policy, dict):
        return False
    if policy.get("mode") == "personal":
        return isinstance(policy.get("owner"), str) and policy["owner"] == user_id
    if policy.get("mode") == "shared":
        users = policy.get("users")
        return isinstance(users, list) and user_id in users
    return False


def verify_ticket(envelope: Any, *, node_id: str, tenant: str, task_text: str, definition: Any,
                  admin_keys: Dict[str, str], policy: Any, revocations: Revocations, nonces: RunNonces,
                  resume_run_id: Optional[str] = None, now: Optional[float] = None,
                  trusted: Optional[Dict[str, str]] = None,
                  plan_keys: Optional[Dict[str, str]] = None,
                  policy_versions: PolicyVersions) -> Dict[str, Any]:
    """{"ticket", "definition", "run_id"} when the run may start (resume_run_id None) or resume; raises
    TicketRejected otherwise. The nonce is bound only after every other check passed."""
    now = time.time() if now is None else now
    trusted = _TRUSTED_RUN_TICKET_KEYS if trusted is None else trusted
    if not isinstance(envelope, dict) or set(envelope) != {"ticket", "sig", "kid"}:
        raise TicketRejected("ticket_envelope")
    t = envelope["ticket"]
    validate_body(t)
    kid = envelope["kid"]
    if not isinstance(kid, str) or not TICKET_KID.fullmatch(kid) or kid not in trusted:
        raise TicketRejected("ticket_key_not_trusted")
    from .split_plan_verify import _TRUSTED_SPLIT_PLAN_KEYS
    plan_pubs = set(_TRUSTED_SPLIT_PLAN_KEYS.values() if plan_keys is None else plan_keys.values())
    if trusted[kid] in plan_pubs:
        raise TicketRejected("ticket_key_not_trusted")           # (a): one key never serves both types
    _verify(t, envelope["sig"], trusted[kid], "ticket_signature_invalid")
    if t["node_id"] != node_id:
        raise TicketRejected("ticket_not_for_this_host")
    if t["tenant"] != tenant:
        raise TicketRejected("ticket_wrong_tenant")
    if t["expires_at"] <= now:
        raise TicketRejected("ticket_expired")
    if t["expires_at"] - now > MAX_LIFETIME_S:
        raise TicketRejected("ticket_lifetime_too_long")
    if resume_run_id is None and now > t["start_by"]:
        raise TicketRejected("ticket_stale")
    if not isinstance(task_text, str) or \
            hashlib.sha256(task_text.encode("utf-8", "surrogatepass")).hexdigest() != t["task_sha256"]:
        raise TicketRejected("ticket_task_mismatch")
    if set(admin_keys.values()) & (plan_pubs | set(trusted.values())):
        raise TicketRejected("definition_key_not_pinned")        # the admin key is the customer's own, never ours
    d, def_hash = verify_definition(definition, admin_keys)
    if def_hash != t["def_hash"] or d["tenant"] != t["tenant"] or d["agent_id"] != t["agent_id"] \
            or d["def_version"] != t["def_version"]:
        raise TicketRejected("ticket_definition_mismatch")
    if _RANK[t["class_ceiling"]] > _RANK[d["class_ceiling"]]:
        raise TicketRejected("ticket_class_above_definition")
    if d["budgets"]["wall_s"] != t["wall_s"] or d["budgets"]["tokens"] < t["max_tokens"]:
        raise TicketRejected("ticket_budget_mismatch")
    rev = revocations.load(now)
    if (t["agent_id"], t["def_version"]) in rev["definitions"]:
        raise TicketRejected("definition_revoked")
    if t["ticket_id"] in rev["tickets"]:
        raise TicketRejected("ticket_revoked")
    pol = verify_policy(policy, admin_keys, node_id, tenant, policy_versions)
    if not user_allowed(pol, t["user_id"]):
        raise TicketRejected("ticket_user_not_allowed")
    if resume_run_id is None:
        run_id = nonces.start(t["nonce"], t["expires_at"], now)
    else:
        run_id = nonces.resume(t["nonce"], resume_run_id, now)
    return {"ticket": t, "definition": d, "run_id": run_id}
