"""SPLIT-SERVE head 2 (auditor 2026-11-02 18:22:04Z, option (A)): plan v3 kind "serve", node half. The closed key set is
chosen BY the signed kind: a serve body adds runtime_set, each serve member adds memory_max_mb, a serve plan never names
a job. The batch kinds and their golden vector stay byte-for-byte. An OLD verifier (v0.3.81rc1) refuses a serve plan."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from meshembed_node import split_plan_verify as V

FX = Path(__file__).parent / "fixtures"
GOLD = json.loads((FX / "split_plan_golden.json").read_text())
SERVE = json.loads((FX / "split_plan_serve_golden.json").read_text())
BATCH_GOLDEN_SHA256 = "4434b909d2f53b329ecf92ec4528d09a2dd34130fb1977cde58d905c7c7a33cc"           # master's batch golden file, byte-for-byte
OLD_VERIFIER_SHA256 = "0009593014aade1d1179e585dc0530dfb03723dfdb589337832f64894af53527"           # meshembed_node/split_plan_verify.py of public v0.3.81rc1 (60f7e237)


def _serve(**kw):
    b = copy.deepcopy(SERVE["envelope"]["plan"])
    b.update(kw)
    return b


def _batch(**kw):
    b = copy.deepcopy(GOLD["envelope"]["plan"])
    b.update(kw)
    return b


def test_the_batch_golden_file_is_byte_for_byte_masters():
    assert hashlib.sha256((FX / "split_plan_golden.json").read_bytes()).hexdigest() == BATCH_GOLDEN_SHA256
    V.validate_body(_batch())


def test_the_serve_golden_vector_verifies_in_full(tmp_path):
    trusted = {"v1": SERVE["public_key_b64"]}
    body = V.verify_plan(SERVE["envelope"], "node-stage", now=SERVE["verify_at"], trusted=trusted,
                         nonces=V.NonceStore(tmp_path / "nonces.json"))
    assert body["kind"] == "serve" and body["job_id"] is None and len(body["runtime_set"]) == 64
    assert [m["memory_max_mb"] for m in body["members"]] == [9216, 6144]


@pytest.mark.parametrize("edit, code", [
    # cross-kind: a batch body or member may never carry the serve fields
    (lambda: _batch(runtime_set="ab" * 32), "plan_schema_keys"),
    (lambda: (lambda b: [m.update(memory_max_mb=4096) for m in b["members"]] and b)(_batch()), "plan_schema_member_keys"),
    # a serve body must carry both
    (lambda: (lambda b: b.pop("runtime_set") and b)(_serve()), "plan_schema_keys"),
    (lambda: (lambda b: [m.pop("memory_max_mb") for m in b["members"]] and b)(_serve()), "plan_schema_member_keys"),
    # a serve plan never names a job
    (lambda: _serve(job_id="job-x"), "plan_schema_job_id"),
    (lambda: _serve(runtime_set="AB" * 32), "plan_schema_runtime_set"),
    (lambda: _serve(runtime_set=None), "plan_schema_runtime_set"),
    (lambda: (lambda b: b["members"][0].update(memory_max_mb=True) or b)(_serve()), "plan_schema_member_memory"),
    (lambda: (lambda b: b["members"][0].update(memory_max_mb=511) or b)(_serve()), "plan_schema_member_memory"),
    (lambda: (lambda b: b["members"][0].update(memory_max_mb=4 * 1024 * 1024 + 1) or b)(_serve()), "plan_schema_member_memory"),
    (lambda: (lambda b: b["members"][0].update(memory_max_mb=1024.0) or b)(_serve()), "plan_schema_member_memory"),
])
def test_the_key_set_follows_the_signed_kind(edit, code):
    with pytest.raises(V.PlanRejected, match=code):
        V.validate_body(edit())


def test_the_v0_3_81rc1_verifier_refuses_a_serve_plan():
    src = FX / "split_plan_verify_v0_3_81rc1.py"
    assert hashlib.sha256(src.read_bytes()).hexdigest() == OLD_VERIFIER_SHA256
    spec = importlib.util.spec_from_file_location("old_split_plan_verify", src)
    old = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(old)
    old.validate_body(_batch())                                     # the old node still takes batch plans
    with pytest.raises(old.PlanRejected, match="plan_schema_keys"):
        old.validate_body(_serve())
