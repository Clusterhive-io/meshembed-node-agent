"""AR1 G1, agent-host verifier (auditor 09:50Z: (a) cross-kid + cross-type vectors, (b) start_by / lifetime, R1
resume vs replay, R2 task text, R4 user policy; A10 G2 pinned admin key + revocation, G3 resume re-verifies).
The golden vectors are the backend's (shared/run_ticket_golden.json, byte-identical copy in fixtures/)."""
import copy
import hashlib
import json
from pathlib import Path

import pytest

from meshembed_node import run_ticket_verify as V
from meshembed_node import serve_plan, split_plan_verify as SPV

GOLD = json.loads((Path(__file__).parent / "fixtures" / "run_ticket_golden.json").read_text())
TICKET_KEYS = {GOLD["keys"]["ticket"]["kid"]: GOLD["keys"]["ticket"]["pub"]}
PLAN_KEYS = {GOLD["keys"]["plan"]["kid"]: GOLD["keys"]["plan"]["pub"]}
ADMIN = {GOLD["keys"]["admin"]["kid"]: GOLD["keys"]["admin"]["pub"]}
T = GOLD["valid"]["ticket"]
NOW = T["issued_at"] + 10
OWNER = GOLD["policy_personal"]                                       # P1: admin-signed


def test_fixture_is_the_backends_copy():
    shared = Path(__file__).resolve().parents[2] / "shared" / "run_ticket_golden.json"
    if shared.exists():
        assert shared.read_bytes() == (Path(__file__).parent / "fixtures" / "run_ticket_golden.json").read_bytes()
    assert hashlib.sha256(V.canonical(T)).hexdigest() == GOLD["canonical_sha256"]


@pytest.fixture
def stores(tmp_path):
    rev = V.Revocations(tmp_path / "rev.json")
    rev.update([], [], NOW)                                               # P2: a fresh snapshot
    return rev, V.RunNonces(tmp_path / "nonces.json")


def run(stores, env=None, **kw):
    rev, nonces = stores
    a = dict(node_id="agent-host-1", tenant="t-pool-1", task_text=GOLD["task_text"], definition=GOLD["definition"],
             admin_keys=ADMIN, policy=OWNER, revocations=rev, nonces=nonces, now=NOW, trusted=TICKET_KEYS,
             plan_keys=PLAN_KEYS, policy_versions=V.PolicyVersions(rev.path.with_name("polv.json")))
    a.update(kw)
    return V.verify_ticket(GOLD["valid"] if env is None else env, **a)


def test_valid_ticket_starts_a_run(stores):
    out = run(stores)
    assert out["ticket"] == T and out["definition"]["agent_id"] == "invoice-checker"
    assert out["run_id"].startswith("run-")


# --- (a) cross-type and cross-kid, both sides ----------------------------------------------------------------------
@pytest.mark.parametrize("case,code", [
    ("plan_to_ticket_verifier", "ticket_envelope"),
    ("ticket_body_in_plan_envelope", "ticket_envelope"),
    ("ticket_signed_by_plan_key_kid_v1", "ticket_key_not_trusted"),      # a plan kid, even though the sig verifies
    ("ticket_signed_by_plan_key_kid_rt1", "ticket_signature_invalid"),
])
def test_ticket_verifier_refuses_plans_and_plan_keys(stores, case, code):
    with pytest.raises(V.TicketRejected, match=f"^{code}$"):
        run(stores, GOLD[case], trusted={**TICKET_KEYS, **PLAN_KEYS})        # even with BOTH sets loaded


def test_a_plan_key_in_the_ticket_set_is_refused(stores):
    with pytest.raises(V.TicketRejected, match="^ticket_key_not_trusted$"):
        run(stores, trusted={"rt9": GOLD["keys"]["plan"]["pub"]}, plan_keys=PLAN_KEYS,
            env=dict(GOLD["ticket_signed_by_plan_key_kid_rt1"], kid="rt9"))


def test_ticket_body_is_refused_on_type_first():
    with pytest.raises(V.TicketRejected, match="^ticket_type$"):
        V.validate_body(GOLD["plan_to_ticket_verifier"]["plan"])


@pytest.mark.parametrize("case", ["plan_signed_by_ticket_key_kid_rt1", "plan_signed_by_ticket_key_kid_v1",
                                  "ticket_body_in_plan_envelope"])
def test_plan_verifiers_refuse_tickets_and_ticket_keys(tmp_path, case):
    trusted = {**PLAN_KEYS, **TICKET_KEYS}                                   # even with BOTH sets loaded
    with pytest.raises(SPV.PlanRejected):
        serve_plan.verify_serve_plan(GOLD[case], "agent-host-1", now=NOW, trusted=trusted,
                                     nonces=SPV.NonceStore(tmp_path / "n.json"))
    with pytest.raises(SPV.PlanRejected):
        SPV.verify_plan(GOLD[case], "agent-host-1", now=NOW, trusted=trusted, nonces=SPV.NonceStore(tmp_path / "m.json"))


def test_plan_verifier_refuses_an_rt_kid_even_with_the_right_key(tmp_path):
    env = GOLD["plan_signed_by_ticket_key_kid_rt1"]
    with pytest.raises(SPV.PlanRejected, match="^plan_key_not_trusted$"):
        serve_plan.verify_serve_plan(env, "agent-host-1", now=NOW, trusted=TICKET_KEYS,
                                     nonces=SPV.NonceStore(tmp_path / "n.json"))


# --- the checks in order ------------------------------------------------------------------------------------------
@pytest.mark.parametrize("kw,code", [
    (dict(node_id="other-host"), "ticket_not_for_this_host"),
    (dict(tenant="t-pool-2"), "ticket_wrong_tenant"),
    (dict(now=T["expires_at"]), "ticket_expired"),
    (dict(now=T["start_by"] + 1), "ticket_stale"),                           # (b) not started in time
    (dict(task_text=GOLD["task_text"] + " "), "ticket_task_mismatch"),       # R2
    (dict(admin_keys={"adm1": GOLD["keys"]["ticket"]["pub"]}), "definition_key_not_pinned"),   # never our key
    (dict(admin_keys={"adm2": GOLD["keys"]["admin"]["pub"]}), "definition_key_not_pinned"),
    (dict(policy=GOLD["policy_shared_without_the_user"]), "ticket_user_not_allowed"),        # R4
    (dict(policy={"mode": "personal", "owner": T["user_id"]}), "policy_envelope"),   # P1: an unsigned policy
    (dict(policy=GOLD["policy_signed_by_ticket_key"]), "policy_signature_invalid"),
    (dict(policy=dict(GOLD["policy_personal"], kid="adm9")), "policy_key_not_pinned"),
    (dict(policy=None), "policy_envelope"),
    (dict(trusted={}), "ticket_key_not_trusted"),                            # compiled set empty: all refused
])
def test_refusals(stores, kw, code):
    with pytest.raises(V.TicketRejected, match=f"^{code}$"):
        run(stores, **kw)


def test_shared_host_serves_listed_users(stores):
    assert run(stores, policy=GOLD["policy_shared"])["run_id"]


def _definition(**changes):
    d = copy.deepcopy(GOLD["definition"])
    d["definition"].update(changes)
    return d


@pytest.mark.parametrize("d,code", [
    (_definition(def_version=4), "definition_signature_invalid"),             # edited after signing
    (dict(GOLD["definition"], sig=GOLD["valid"]["sig"]), "definition_signature_invalid"),
    (_definition(tools=["calc", "fetch_url"]), "definition_tools"),          # phase 0: M8 tools only
    (_definition(tools=["table", "calc"]), "definition_tools"),
    (_definition(budgets={"steps": 20}), "definition_budgets"),
    (_definition(extra=1), "definition_schema"),
    (_definition(models=[]), "definition_models"),                           # Q3: the model is bound
    (_definition(models=["b/x", "a/y"]), "definition_models"),
    (_definition(models=["m;rm -rf"]), "definition_models"),
    (_definition(models=["m%d" % i for i in range(9)]), "definition_models"),
    ({"definition": GOLD["definition"]["definition"]}, "definition_envelope"),
])
def test_definition_must_be_the_admin_signed_one(stores, d, code):
    with pytest.raises(V.TicketRejected, match=f"^{code}$"):
        run(stores, definition=d)


def test_revocation_only_restricts(stores, tmp_path):
    rev, _ = stores
    rev.update([("invoice-checker", 3)], [], NOW)
    with pytest.raises(V.TicketRejected, match="^definition_revoked$"):
        run(stores)
    rev.update([], [T["ticket_id"]], NOW)                                    # a fetch never removes
    assert ("invoice-checker", 3) in rev.load(NOW)["definitions"]
    (tmp_path / "rev.json").write_text("{not json")
    with pytest.raises(V.TicketRejected, match="^revocations_unreadable$"):
        run(stores)


def test_revoked_ticket(stores):
    stores[0].update([], [T["ticket_id"]], NOW)
    with pytest.raises(V.TicketRejected, match="^ticket_revoked$"):
        run(stores)


# --- R1: replay vs resume; G3: resume re-verifies -----------------------------------------------------------------
def test_second_start_is_a_replay_but_resume_passes(stores):
    run_id = run(stores)["run_id"]
    with pytest.raises(V.TicketRejected, match="^ticket_replayed$"):
        run(stores)                                                          # a second START of the nonce
    later = T["start_by"] + 60                                               # past start_by: resume still allowed
    assert run(stores, resume_run_id=run_id, now=later)["run_id"] == run_id
    with pytest.raises(V.TicketRejected, match="^ticket_replayed$"):
        run(stores, resume_run_id="run-" + "0" * 24, now=later)              # another run id = replay


def test_resume_reverifies_everything(stores):
    run_id = run(stores)["run_id"]
    stores[0].update([("invoice-checker", 3)], [], NOW)
    with pytest.raises(V.TicketRejected, match="^definition_revoked$"):
        run(stores, resume_run_id=run_id)
    with pytest.raises(V.TicketRejected, match="^ticket_expired$"):
        run(stores, resume_run_id=run_id, now=T["expires_at"] + 1)


def test_nonce_store_fails_closed(stores, tmp_path):
    (tmp_path / "nonces.json").write_text("garbage")
    with pytest.raises(V.TicketRejected, match="^nonce_store_unreadable$"):
        run(stores)


def test_nothing_is_bound_when_a_check_fails(stores, tmp_path):
    with pytest.raises(V.TicketRejected):
        run(stores, task_text="other")
    assert not (tmp_path / "nonces.json").exists()
    assert run(stores)["run_id"]                                             # the real start still works


def test_codes_carry_no_content(stores):
    try:
        run(stores, task_text="SECRET CUSTOMER TEXT")
    except V.TicketRejected as e:
        assert str(e) == "ticket_task_mismatch"


# --- auditor 10:11Z P1-P3 -----------------------------------------------------------------------------------------
def test_p1_policy_for_another_host_or_older_version_is_refused(stores, tmp_path):
    with pytest.raises(V.TicketRejected, match="^policy_not_for_this_host$"):
        V.verify_policy(GOLD["policy_personal"], ADMIN, "agent-host-2", "t-pool-1")
    pv = V.PolicyVersions(tmp_path / "pv.json")
    V.verify_policy(GOLD["policy_shared"], ADMIN, "agent-host-1", "t-pool-1", pv)          # version 3 accepted
    with pytest.raises(V.TicketRejected, match="^policy_rolled_back$"):
        V.verify_policy(GOLD["policy_personal"], ADMIN, "agent-host-1", "t-pool-1", pv)    # version 2: a replay
    (tmp_path / "pv.json").write_text("garbage")
    with pytest.raises(V.TicketRejected, match="^policy_store_unreadable$"):
        V.verify_policy(GOLD["policy_shared"], ADMIN, "agent-host-1", "t-pool-1", pv)


@pytest.mark.parametrize("mut", [
    lambda p: p.update(users=["u-b", "u-a"]),                    # unsorted
    lambda p: p.update(mode="shared", owner="u-x"),               # shared with an owner
    lambda p: p.update(mode="personal", users=["u-a"]),           # personal with a list
    lambda p: p.update(extra=1),
    lambda p: p.update(owner="u-\u00e9"),                       # non-ASCII
])
def test_p1_policy_schema(mut):
    env = copy.deepcopy(GOLD["policy_personal"])
    mut(env["policy"])
    with pytest.raises(V.TicketRejected):
        V.verify_policy(env, ADMIN, "agent-host-1", "t-pool-1")


def test_p2_missing_or_stale_revocations_refuse_the_run(stores, tmp_path):
    rev, _ = stores
    (tmp_path / "rev.json").unlink()                                       # deleting the file does not un-revoke
    with pytest.raises(V.TicketRejected, match="^revocations_stale$"):
        run(stores)
    rev.update([], [], NOW - V.REVOCATIONS_MAX_AGE_S - 1)                   # blocked feed: the snapshot ages out
    with pytest.raises(V.TicketRejected, match="^revocations_stale$"):
        run(stores)
    rev.update([], [], NOW)
    run_id = run(stores)["run_id"]
    rev.update([], [], NOW - V.REVOCATIONS_MAX_AGE_S - 1)
    with pytest.raises(V.TicketRejected, match="^revocations_stale$"):     # a RESUME needs it fresh too
        run(stores, resume_run_id=run_id)


def test_p3_stores_are_private_to_the_verifier(stores, tmp_path):
    import os
    import stat
    run(stores)
    for f in ("rev.json", "nonces.json", "polv.json"):
        st = os.stat(tmp_path / f)
        assert stat.S_IMODE(st.st_mode) == 0o600 and st.st_uid == os.getuid()


def test_definition_must_be_ascii():
    d = copy.deepcopy(GOLD["definition"]["definition"])
    d["agent_id"] = "inv\u00f6ice"
    with pytest.raises(V.TicketRejected, match="^definition_schema$"):
        V.validate_definition(d) or V._ascii(d, "definition_schema")


def test_q3_the_signed_definition_names_its_models():
    assert GOLD["definition"]["definition"]["models"] == ["meshembed/qwen3-4b-q8"]
    d = copy.deepcopy(GOLD["definition"]["definition"])
    del d["models"]
    with pytest.raises(V.TicketRejected, match="^definition_schema$"):
        V.validate_definition(d)


def test_nit_policy_versions_is_required(stores):
    rev, nonces = stores
    with pytest.raises(TypeError):
        V.verify_ticket(GOLD["valid"], node_id="agent-host-1", tenant="t-pool-1", task_text=GOLD["task_text"],
                        definition=GOLD["definition"], admin_keys=ADMIN, policy=OWNER, revocations=rev,
                        nonces=nonces, now=NOW, trusted=TICKET_KEYS, plan_keys=PLAN_KEYS)
