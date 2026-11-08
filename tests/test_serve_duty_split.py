"""SPLIT-SERVE, the daemon-side head (docs/DESIGN_SPLIT_SERVE_2026-11-02.md section 4; auditor 2026-11-02 21:13:50Z,
DS-1/DS-2): with no whole plan, the serve duty reports the serve split plan split_handoff VERIFIED, in the whole-plan
shape, with running_plan_id read ONLY from the split launcher's root-written serve-coord.json (F-3c), and serves it
through the coordinator's socket without ever writing a serve-launch request; a stage reports role "stage". DS-2: a
re-delivered plan the root launcher already applied is re-verified without consuming a nonce and never re-handed."""
from __future__ import annotations

import json
import os

import pytest

from meshembed_node import split_handoff as H
from meshembed_node import split_plan_verify as V

from test_serve_duty import World
from test_serve_mvp import NOW

pytestmark = pytest.mark.unit
SP = {"plan_id": "sp-1", "coordinator": "node-a", "members": ["node-a", "node-b"], "model_sha": "ab" * 32,
      "expires_at": NOW + 3600}


@pytest.fixture
def w(tmp_path):
    return World(tmp_path)


def _duty(w, sp=SP, role="coordinator", running="sp-1", stage_up=True):
    split = dict(sp, role=role) if sp else None
    return w.duty(split_plan=lambda: split, split_running=lambda: running, stage_running=lambda pid: stage_up)


def test_no_split_plan_reports_exactly_as_before(w):
    before = w.duty().status()
    assert _duty(w, sp=None).status() == before == {"ready": False, "reason": "no_plan", "running_plan_id": None}


def test_the_coordinator_is_ready_only_when_the_split_launcher_says_it_started_this_plan(w):
    w.health = True
    assert _duty(w).status() == {"ready": True, "reason": "ok", "plan_id": "sp-1", "model_sha": "ab" * 32,
                                 "running_plan_id": "sp-1"}
    out = _duty(w, running=None).status()
    assert (out["ready"], out["reason"], out["running_plan_id"]) == (False, "unit_not_answering", None)
    out = _duty(w, running="sp-old").status()
    assert (out["ready"], out["reason"]) == (False, "unit_plan_mismatch")
    w.health = False
    assert _duty(w).status()["reason"] == "unit_not_answering"          # serve-coord still loading


def test_a_gate_or_a_pause_blocks_the_coordinator_and_nothing_is_written(w):
    w.health, w.gate = True, "owner:active"
    d = _duty(w)
    assert d.status()["reason"] == "owner:active" and d.status()["ready"] is False
    assert d.tick() == "idle" and w.polls == [] and not w.req.exists()
    w.gate, w.paused = None, True
    assert d.status()["reason"] == "paused" and d.tick() == "idle"


def test_the_coordinator_serves_its_model_and_never_writes_a_serve_launch_request(w):
    w.health = True
    d = _duty(w)
    assert d.tick() == "served" and w.polls == [["meshembed/qwen3-4b-q8"]]
    assert not w.req.exists()                                             # no START, no STOP for the serve launcher


def test_an_expiring_plan_is_reported_expired_and_not_served(w):
    w.health = True
    d = _duty(w, sp=dict(SP, expires_at=NOW + 30))
    assert d.status()["reason"] == "plan_expired" and d.tick() == "idle" and w.polls == []


def test_the_coordinator_waits_while_the_split_launcher_runs_another_or_no_plan(w):
    w.health = True
    assert _duty(w, running=None).tick() == "unit_not_answering"
    assert _duty(w, running="sp-old").tick() == "unit_not_answering" and w.polls == []


def test_a_stage_reports_its_role_and_is_never_served_from(w):
    d = _duty(w, role="stage")
    assert d.status() == {"ready": True, "plan_id": "sp-1", "role": "stage", "running_plan_id": None, "reason": "ok"}
    assert d.tick() == "idle" and w.polls == []
    assert _duty(w, role="stage", stage_up=False).status()["reason"] == "stage_not_running"
    w.gate = "thermal"
    assert _duty(w, role="stage").status() == {"ready": False, "plan_id": "sp-1", "role": "stage",
                                               "running_plan_id": None, "reason": "thermal"}


def test_a_broken_split_source_counts_as_no_split_plan(w):
    def boom():
        raise RuntimeError("x")
    d = w.duty(split_plan=boom, split_running=lambda: "sp-1", stage_running=lambda pid: True)
    assert d.status() == {"ready": False, "reason": "no_plan", "running_plan_id": None}


def test_a_whole_model_leftover_wins_over_a_split_report(w):
    w.running = "sv-left"                                                 # the SERVE launcher still runs a unit
    out = _duty(w).status()
    assert out["reason"] == "stopping_leftover" and "plan_id" not in out


# --- split_handoff: the serve body memory, the root records, DS-2 -------------------------------------------------

@pytest.fixture
def hand(tmp_path, monkeypatch):
    monkeypatch.setenv("MESHEMBED_ENABLE_SPLIT", "1")
    for name in ("_HANDLED", "_SERVE", "_EXPIRES", "_RECLAIMED"):
        monkeypatch.setattr(H, name, {})
    st = tmp_path / "launcher"
    st.mkdir()
    monkeypatch.setattr(H, "STATE_DIR", st)
    return st


def _body(pid="sp-1", kind="serve", coord="node-a", exp=NOW + 3600):
    return {"plan_id": pid, "kind": kind, "coordinator": coord, "model_sha": "ab" * 32, "expires_at": exp,
            "members": [{"node_id": "node-a"}, {"node_id": "node-b"}]}


def test_serve_split_role_follows_the_handled_state(hand):
    H._remember_serve(_body())
    H._HANDLED["sp-1"] = "queued"
    assert H.serve_split_role("node-a", now=NOW)["role"] == "coordinator"
    assert H.serve_split_role("node-b", now=NOW)["role"] == "stage"
    assert H.serve_split_role("node-z", now=NOW) is None
    for st in ("revoked", "reclaimed", "refused:x"):
        H._HANDLED["sp-1"] = st
        assert H.serve_split_role("node-a", now=NOW) is None
    H._HANDLED["sp-1"] = "queued"
    assert H.serve_split_role("node-a", now=NOW + 3600) is None           # expired
    H._remember_serve(_body(pid="sp-2", kind="primary"))
    H._HANDLED["sp-2"] = "queued"
    assert H.serve_split_role("node-a", now=NOW)["plan_id"] == "sp-1"     # a batch plan is never a serve report


@pytest.mark.parametrize("rec,want", [
    ({"plan_id": "sp-1", "code": "serve_coord_started", "expires_at": NOW + 60}, "sp-1"),
    ({"plan_id": "sp-1", "code": "serve_coord_started", "expires_at": NOW - 1}, None),
    ({"plan_id": "sp-1", "code": "refused", "expires_at": NOW + 60}, None),
    ({}, None), ("garbage", None)])
def test_split_coord_running_reads_only_a_live_started_record(hand, rec, want):
    (hand / "serve-coord.json").write_text(rec if isinstance(rec, str) else json.dumps(rec))
    assert H.split_coord_running(now=NOW) == want


def test_stage_running_needs_the_applied_plan_and_its_stage_started(hand):
    (hand / "applied.json").write_text(json.dumps({"plan_id": "sp-1", "expires_at": NOW + 60}))
    (hand / "last-result.json").write_text(json.dumps({"plan_id": "sp-1", "code": "stage_started"}))
    assert H.stage_running("sp-1") is True
    assert H.stage_running("sp-2") is False
    (hand / "last-result.json").write_text(json.dumps({"plan_id": "sp-1", "code": "refused"}))
    assert H.stage_running("sp-1") is False


def test_ds2_after_a_restart_the_applied_plan_is_known_again_without_a_nonce_and_never_re_handed(hand, tmp_path,
                                                                                                 monkeypatch):
    """The persisted daemon nonce store already holds the plan's nonce: a consuming verify would refuse it."""
    (hand / "applied.json").write_text(json.dumps({"plan_id": "sp-1", "expires_at": NOW + 3600}))
    seen_nonces = []

    def verify(env, me, *, now=None, nonces=None, trusted=None):
        if nonces is None or not isinstance(nonces, H._NoNonces):
            raise V.PlanRejected("plan_replayed")                         # the persisted store has seen it
        seen_nonces.append(type(nonces).__name__)
        return _body()
    monkeypatch.setattr(H.V, "verify_plan", verify)
    req = tmp_path / "split-request"
    assert H.handoff([{"plan": {"plan_id": "sp-1"}}], "node-a", path=req, now=NOW) is None
    assert not req.exists()                                               # never handed to the launcher again
    assert H._HANDLED["sp-1"] == "queued" and seen_nonces == ["_NoNonces"]
    assert H.serve_split_role("node-a", now=NOW)["plan_id"] == "sp-1"


def test_ds2_a_plan_the_launcher_does_not_run_takes_the_normal_consuming_path(hand, tmp_path, monkeypatch):
    calls = []

    def verify(env, me, *, now=None, nonces=None, trusted=None):
        calls.append(isinstance(nonces, H._NoNonces))
        return _body()
    monkeypatch.setattr(H.V, "verify_plan", verify)
    req = tmp_path / "split-request"
    assert H.handoff([{"plan": {"plan_id": "sp-1"}}], "node-a", path=req, now=NOW) == "sp-1"
    assert calls == [False] and json.loads(req.read_text())["plan"]["plan_id"] == "sp-1"
    assert oct(os.stat(req).st_mode & 0o777) == "0o600"
