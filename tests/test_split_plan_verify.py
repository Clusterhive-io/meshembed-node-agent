"""M2 build #3, node half: a node acts only on a genuine plan that names it.
The golden vector is the backend's (shared/split_plan_golden.json, byte-identical copy here)."""
from __future__ import annotations

import base64
import copy
import json
from pathlib import Path

import pytest

from meshembed_node import split_plan_verify as V

pytestmark = pytest.mark.unit

GOLD = json.loads((Path(__file__).parent / "fixtures" / "split_plan_golden.json").read_text())
TRUST = {"v1": GOLD["public_key_b64"]}
NOW = GOLD["verify_at"]


def _store(tmp_path):
    return V.NonceStore(tmp_path / "nonces.json")


def _resign(body):
    """Sign a modified body with the golden TEST key (to reach the checks after the signature)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    k = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(GOLD["seed_hex"]))
    return {"plan": body, "sig": base64.b64encode(k.sign(V.canonical(body))).decode(), "kid": "v1"}


def test_the_backend_golden_plan_verifies_for_its_members(tmp_path):
    assert V.canonical(GOLD["envelope"]["plan"]).decode() == GOLD["canonical"]     # node bytes == backend JCS
    body = V.verify_plan(GOLD["envelope"], "node-stage", now=NOW, nonces=_store(tmp_path), trusted=TRUST)
    assert body["plan_id"] == "sp-golden000000000000000000"


def test_nothing_is_trusted_until_a_release_compiles_a_key_in(tmp_path):
    assert V._TRUSTED_SPLIT_PLAN_KEYS == {}
    with pytest.raises(V.PlanRejected, match="plan_key_not_trusted"):
        V.verify_plan(GOLD["envelope"], "node-stage", now=NOW, nonces=_store(tmp_path))


def test_a_tampered_plan_fails_the_signature(tmp_path):
    env = copy.deepcopy(GOLD["envelope"])
    env["plan"]["members"][1]["layers"] = [24, 40]
    with pytest.raises(V.PlanRejected, match="plan_signature_invalid"):
        V.verify_plan(env, "node-stage", now=NOW, nonces=_store(tmp_path), trusted=TRUST)


def test_a_plan_for_other_nodes_is_ignored(tmp_path):
    with pytest.raises(V.PlanRejected, match="plan_not_for_this_node"):
        V.verify_plan(GOLD["envelope"], "someone-else", now=NOW, nonces=_store(tmp_path), trusted=TRUST)


def test_expired_and_overlong_plans_are_refused(tmp_path):
    with pytest.raises(V.PlanRejected, match="plan_expired"):
        V.verify_plan(GOLD["envelope"], "node-stage", now=GOLD["envelope"]["plan"]["expires_at"],
                      nonces=_store(tmp_path), trusted=TRUST)
    body = dict(copy.deepcopy(GOLD["envelope"]["plan"]), expires_at=NOW + V.MAX_LIFETIME_S + 10)
    with pytest.raises(V.PlanRejected, match="plan_lifetime_too_long"):
        V.verify_plan(_resign(body), "node-stage", now=NOW, nonces=_store(tmp_path), trusted=TRUST)


def test_a_replayed_nonce_is_refused_even_across_restarts(tmp_path):
    V.verify_plan(GOLD["envelope"], "node-stage", now=NOW, nonces=_store(tmp_path), trusted=TRUST)
    with pytest.raises(V.PlanRejected, match="plan_replayed"):
        V.verify_plan(GOLD["envelope"], "node-coord", now=NOW + 5, nonces=_store(tmp_path), trusted=TRUST)


def test_a_rejected_plan_does_not_burn_its_nonce(tmp_path):
    with pytest.raises(V.PlanRejected):
        V.verify_plan(GOLD["envelope"], "someone-else", now=NOW, nonces=_store(tmp_path), trusted=TRUST)
    V.verify_plan(GOLD["envelope"], "node-stage", now=NOW, nonces=_store(tmp_path), trusted=TRUST)


@pytest.mark.parametrize("mutate", [
    lambda e: e.update(extra="x"),
    lambda e: e["plan"].update(kind="exec"),
    lambda e: e["plan"]["members"][0].update(overlay_ip="0.0.0.0"),
    lambda e: e["plan"]["members"][0].update(cmd="sh -c id"),
    lambda e: e["plan"].update(type="something.else"),
])
def test_schema_violations_are_refused_before_any_signature_work(tmp_path, mutate):
    env = copy.deepcopy(GOLD["envelope"])
    mutate(env)
    with pytest.raises(V.PlanRejected, match="plan_(envelope|schema_)"):
        V.verify_plan(env, "node-stage", now=NOW, nonces=_store(tmp_path), trusted=TRUST)


def test_nonce_file_is_private(tmp_path):
    V.verify_plan(GOLD["envelope"], "node-stage", now=NOW, nonces=_store(tmp_path), trusted=TRUST)
    assert oct((tmp_path / "nonces.json").stat().st_mode & 0o777) == "0o600"
