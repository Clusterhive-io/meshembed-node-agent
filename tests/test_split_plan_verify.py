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


def test_only_the_compiled_key_is_trusted(tmp_path):
    # the golden plan is signed with a TEST key under kid "v1"; the release compiles the PROD key under the same kid
    # (tests/test_release_keys.py), so the test signature does not verify: a plan signed by anything but the prod
    # split-plan key is refused
    assert V._TRUSTED_SPLIT_PLAN_KEYS[GOLD["envelope"]["kid"]] != GOLD["public_key_b64"]
    with pytest.raises(V.PlanRejected, match="plan_signature_invalid"):
        V.verify_plan(GOLD["envelope"], "node-stage", now=NOW, nonces=_store(tmp_path))


def test_a_tampered_plan_fails_the_signature(tmp_path):
    env = copy.deepcopy(GOLD["envelope"])
    env["plan"]["members"][1]["overlay_ip"] = "10.44.0.9"        # schema-valid, not what was signed
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


# --- plan v3 (proposal A, auditor 2026-10-21 A1 condition 1 + the 13:23Z node-side check) ---------------------

def _resign(body):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    k = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(GOLD["seed_hex"]))
    return {"plan": body, "sig": base64.b64encode(k.sign(V.canonical(body))).decode(), "kid": GOLD["envelope"]["kid"]}


@pytest.mark.parametrize("edit, code", [
    (lambda b: b.update(ts=[25, 0]), "plan_schema_ts"),                          # TS count != RPC members
    (lambda b: b.update(ts=[-1]), "plan_schema_ts"),
    (lambda b: b.update(ts=[2.5]), "plan_schema_ts"),
    (lambda b: b.update(ts=[True]), "plan_schema_ts"),
    (lambda b: b.update(ts=[0]), "plan_schema_ts"),                              # sum 0
    (lambda b: b.update(ngl=50), "plan_schema_ngl"),                             # > n_layer + 1
    (lambda b: b.update(ngl=-1), "plan_schema_ngl"),
    (lambda b: b.update(n_layer=0), "plan_schema_n_layer"),
    (lambda b: b.update(n_layer=None), "plan_schema_n_layer"),
    (lambda b: b.pop("ts"), "plan_schema_keys"),
    (lambda b: b.update(v=2), "plan_schema_header"),                             # v2 refused
    (lambda b: b.update(coordinator="nobody"), "plan_coordinator_not_member"),
])
def test_v3_placement_fields_are_checked(tmp_path, edit, code):
    body = copy.deepcopy(GOLD["envelope"]["plan"])
    edit(body)
    with pytest.raises(V.PlanRejected, match=code):
        V.verify_plan(_resign(body), "node-stage", now=NOW, nonces=_store(tmp_path), trusted=TRUST)


def test_consistent_looking_but_wrong_ranges_are_refused(tmp_path):
    # contiguous, covering, coordinator first -- but not what llama.cpp runs for ngl 25 / ts [25]
    body = copy.deepcopy(GOLD["envelope"]["plan"])
    body["members"][0]["layers"], body["members"][1]["layers"] = [0, 20], [20, 49]
    with pytest.raises(V.PlanRejected, match="plan_coordinator_range"):
        V.verify_plan(_resign(body), "node-stage", now=NOW, nonces=_store(tmp_path), trusted=TRUST)
    body["ngl"] = 29                                     # now the coordinator matches; the stage too -> accepted
    V.verify_plan(_resign(body), "node-stage", now=NOW, nonces=_store(tmp_path), trusted=TRUST)
    body = copy.deepcopy(GOLD["envelope"]["plan"])       # two stages swapped against --rpc order
    body["members"].append({"node_id": "node-s2", "overlay_ip": "10.44.0.3", "wg_pubkey": body["members"][1]["wg_pubkey"],
                            "layers": [24, 36], "endpoint": None})
    body["members"][1]["layers"] = [36, 49]
    body["ts"] = [13, 12]
    with pytest.raises(V.PlanRejected, match="plan_ranges_not_assign"):
        V.verify_plan(_resign(body), "node-stage", now=NOW, nonces=_store(tmp_path), trusted=TRUST)
    body["ts"] = [12, 13]                                # stage 1 [24,36) is 12 blocks... in list order it is 2nd
    with pytest.raises(V.PlanRejected, match="plan_ranges_not_assign"):
        V.verify_plan(_resign(body), "node-stage", now=NOW, nonces=_store(tmp_path), trusted=TRUST)


def test_assign_matches_llama_cpp_on_the_measured_splits():
    # docs/ADAPTIVE_PLACEMENT_D1_D4_2026-10-19.md, verified on 189: Qwen2.5-0.5B (24 blocks + output), -ngl 99
    # (= all 25), --tensor-split 9,9,9 -> RPC0 layers 0-8, RPC1 9-16, RPC2 17-23 + output
    assert V.llama_assign(24, 25, [9, 9, 9]) == [(0, 9), (9, 17), (17, 25)]
    # the 30B (48 blocks) planner layout -ngl 27 --ts 10,9,8: CPU 22 layers, then 10 / 9 / 7 + output
    assert V.llama_assign(48, 27, [10, 9, 8]) == [(22, 32), (32, 41), (41, 49)]
    # applied 13:42Z with TS 9,9,9: 189 (the middle stage) loaded 9 layers
    assert V.llama_assign(48, 27, [9, 9, 9])[1] == (31, 40)
    assert V.llama_assign(48, 0, [1]) == [(0, 0)]                # ngl 0: nothing offloaded

