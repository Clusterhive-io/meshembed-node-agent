"""SPLIT-SERVE head 5, OWNER-RECLAIM (docs/DESIGN_SPLIT_SERVE_2026-11-02.md section 5; SD-3): while the owner-first gate
says no, the daemon releases the plan it handed to the root launcher through the revocation channel (the launcher stops
the units, tears down, purges), withdraws a request the launcher has not read yet, hands over no new plan, and reports
the release (hw.split.reclaimed) so the backend marks the plan lost."""
from __future__ import annotations

import json
import os

import pytest

from meshembed_node import split_handoff as H
from meshembed_node import split_launch as L

pytestmark = pytest.mark.unit


@pytest.fixture
def daemon(tmp_path, monkeypatch):
    monkeypatch.setenv("MESHEMBED_ENABLE_SPLIT", "1")
    monkeypatch.setattr(H, "_HANDLED", {})
    monkeypatch.setattr(H, "_RECLAIMED", {})
    monkeypatch.setattr(H, "_EXPIRES", {})
    monkeypatch.setattr(H, "reachability", lambda: {})
    monkeypatch.setattr(H, "reclaimed_path", lambda: tmp_path / "split-reclaimed.json")
    launcher = tmp_path / "launcher-state"
    launcher.mkdir()
    monkeypatch.setattr(H, "STATE_DIR", launcher)                     # never the host's real launcher state
    return {"revoke": tmp_path / "split-revoke", "request": tmp_path / "split-request", "tmp": tmp_path,
            "record": tmp_path / "split-reclaimed.json", "launcher": launcher}


def _restart(monkeypatch):
    """A daemon restart: every in-memory dict is empty again; the files stay."""
    monkeypatch.setattr(H, "_HANDLED", {})
    monkeypatch.setattr(H, "_RECLAIMED", {})
    monkeypatch.setattr(H, "_EXPIRES", {})


def test_nothing_happens_while_the_owner_does_not_need_the_machine(daemon):
    H._HANDLED["sp-1"] = "queued"
    assert H.reclaim_for_owner(None, path=daemon["revoke"], request=daemon["request"]) is None
    assert not daemon["revoke"].exists() and H._HANDLED["sp-1"] == "queued"


def test_a_gate_releases_the_handed_plan_and_reports_it(daemon):
    H._HANDLED.update({"sp-0": "revoked", "sp-1": "queued"})
    assert H.reclaim_for_owner("owner:active", path=daemon["revoke"], request=daemon["request"], now=1000) == "sp-1"
    assert json.loads(daemon["revoke"].read_text()) == {"plan_id": "sp-1", "reason": "owner_reclaim"}
    assert oct(os.stat(daemon["revoke"]).st_mode & 0o777) == "0o600"
    assert H._HANDLED["sp-1"] == "reclaimed"
    (daemon["tmp"] / "ready.json").write_text(json.dumps({"ready": True, "code": "ok"}))
    assert H.ready(daemon["tmp"], now=1001)["reclaimed"] == {"plan_id": "sp-1", "reason": "owner:active", "at": 1000}
    assert H.reclaim_for_owner("owner:active", path=daemon["revoke"], request=daemon["request"]) is None   # once


def test_a_pending_request_for_that_plan_is_withdrawn_and_another_is_kept(daemon):
    H._HANDLED["sp-1"] = "queued"
    daemon["request"].write_text(json.dumps({"plan": {"plan_id": "sp-1"}}))
    H.reclaim_for_owner("power:on_battery", path=daemon["revoke"], request=daemon["request"])
    assert daemon["request"].read_text() == ""                        # the launcher will not apply it
    H._HANDLED["sp-2"] = "queued"
    daemon["request"].write_text(json.dumps({"plan": {"plan_id": "sp-9"}}))
    H.reclaim_for_owner("thermal", path=daemon["revoke"], request=daemon["request"])
    assert json.loads(daemon["request"].read_text()) == {"plan": {"plan_id": "sp-9"}}


def test_split_off_does_nothing(daemon, monkeypatch):
    monkeypatch.setenv("MESHEMBED_ENABLE_SPLIT", "0")
    H._HANDLED["sp-1"] = "queued"
    assert H.reclaim_for_owner("thermal", path=daemon["revoke"], request=daemon["request"]) is None


def test_the_root_launcher_tears_down_on_the_release(daemon, monkeypatch):
    """The release goes through the EXISTING launcher path: housekeeping tears down exactly the applied plan."""
    monkeypatch.setattr(L, "ROOT_UID", os.getuid())
    state = daemon["tmp"] / "state"
    state.mkdir()
    (state / "applied.json").write_text(json.dumps({"plan_id": "sp-1", "expires_at": 10 ** 10}))
    H._HANDLED["sp-1"] = "queued"
    H.reclaim_for_owner("owner:active", path=daemon["revoke"], request=daemon["request"])
    calls, log = [], []

    class Ovl:
        def teardown(self):
            log.append("teardown")
    cache = daemon["tmp"] / "cache"
    (cache / "rpc").mkdir(parents=True)
    out = L.housekeeping(state, daemon["revoke"], os.getuid(), 1000, Ovl(), systemctl=lambda *a: calls.append(a),
                         cache_root=cache)
    assert out == "revoked_torn_down" and log == ["teardown"] and not (cache / "rpc").exists()
    assert calls and all(c[0] == "stop" for c in calls)


def test_h5_1_after_a_restart_the_launchers_applied_plan_is_released(daemon, monkeypatch):
    """H5-1: memory empty (OTA, crash, a daemon unit restart) while the root-launched stage keeps running."""
    _restart(monkeypatch)
    (daemon["launcher"] / "applied.json").write_text(json.dumps({"plan_id": "sp-7", "expires_at": 5000}))
    assert H.reclaim_for_owner("owner:active", path=daemon["revoke"], request=daemon["request"], now=1000) == "sp-7"
    assert json.loads(daemon["revoke"].read_text()) == {"plan_id": "sp-7", "reason": "owner_reclaim"}
    assert H.reclaim_for_owner("owner:active", path=daemon["revoke"], request=daemon["request"], now=1001) is None


@pytest.mark.parametrize("applied", [{}, {"plan_id": "sp-7", "expires_at": 999}, {"plan_id": 7, "expires_at": 5000},
                                     "garbage"])
def test_h5_1_no_applied_plan_or_an_expired_or_garbage_one_releases_nothing(daemon, monkeypatch, applied):
    _restart(monkeypatch)
    (daemon["launcher"] / "applied.json").write_text(applied if isinstance(applied, str) else json.dumps(applied))
    assert H.reclaim_for_owner("thermal", path=daemon["revoke"], request=daemon["request"], now=1000) is None
    assert not daemon["revoke"].exists()


def test_h5_1_a_request_a_previous_process_left_pending_is_withdrawn_and_released(daemon, monkeypatch):
    _restart(monkeypatch)
    daemon["request"].write_text(json.dumps({"plan": {"plan_id": "sp-8", "expires_at": 4000}}))
    assert H.reclaim_for_owner("power:on_battery", path=daemon["revoke"], request=daemon["request"], now=1000) == "sp-8"
    assert daemon["request"].read_text() == ""
    assert json.loads(daemon["record"].read_text())["expires_at"] == 4000


def test_h5_1_a_plan_the_backend_already_revoked_is_not_released_again(daemon):
    H._HANDLED["sp-7"] = "revoked"
    (daemon["launcher"] / "applied.json").write_text(json.dumps({"plan_id": "sp-7", "expires_at": 5000}))
    assert H.reclaim_for_owner("thermal", path=daemon["revoke"], request=daemon["request"], now=1000) is None


def test_h5_2_the_report_survives_a_restart_until_the_plan_expires(daemon, monkeypatch):
    H._HANDLED["sp-1"] = "queued"
    H._EXPIRES["sp-1"] = 5000
    H.reclaim_for_owner("owner:active", path=daemon["revoke"], request=daemon["request"], now=1000)
    assert oct(os.stat(daemon["record"]).st_mode & 0o777) == "0o600"
    _restart(monkeypatch)
    (daemon["tmp"] / "ready.json").write_text(json.dumps({"ready": True, "code": "ok"}))
    assert H.current_reclaimed(now=2000) == {"plan_id": "sp-1", "reason": "owner:active", "at": 1000}
    assert H._HANDLED["sp-1"] == "reclaimed"                          # never handed over again after the restart
    assert H.ready(daemon["tmp"], now=2001)["reclaimed"]["plan_id"] == "sp-1"
    assert H.current_reclaimed(now=5000) == {} and not daemon["record"].exists()   # expired: dropped
    _restart(monkeypatch)
    assert "reclaimed" not in H.ready(daemon["tmp"], now=5001)


@pytest.mark.parametrize("body", ["garbage", json.dumps({"plan_id": "sp-1"}), json.dumps([1])])
def test_h5_2_a_garbage_record_reports_nothing(daemon, body):
    daemon["record"].write_text(body)
    assert H.current_reclaimed(now=1000) == {}


def test_h5_2_a_handed_plan_after_the_restart_is_skipped_by_handoff(daemon, monkeypatch):
    """handoff() skips any id in _HANDLED; the restored record puts the released plan there."""
    H._HANDLED["sp-1"] = "queued"
    H.reclaim_for_owner("owner:active", path=daemon["revoke"], request=daemon["request"], now=1000)
    _restart(monkeypatch)
    H.current_reclaimed(now=1001)
    assert H.handoff([{"plan": {"plan_id": "sp-1"}}], "node-x", path=daemon["request"]) is None
    assert not daemon["request"].exists()
