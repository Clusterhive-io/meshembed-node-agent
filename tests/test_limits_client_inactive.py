"""IC-3b F4 (v0.3.85; auditor 2026-11-13T05:25:11Z): when the applier's state directory exists but the applier never answers a request
(units absent / stopped / disabled), the owner's caps are NOT in force and the node used to report NOTHING (the SILENT mode: only a
missing state directory reported "applier_not_installed"). After APPLIER_SILENT_S the node now reports "applier_inactive"."""
from __future__ import annotations

import hashlib
import json
import re

import pytest

from meshembed_node import limits_client as LC

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _fresh(monkeypatch, tmp_path):
    monkeypatch.setattr(LC, "_last_sent", None)
    monkeypatch.setattr(LC, "_sent_sha", "")
    monkeypatch.setattr(LC, "_sent_at", 0.0)
    monkeypatch.setattr(LC, "_local", {})
    monkeypatch.setattr(LC, "_first_sync_done", False)
    monkeypatch.setattr(LC, "_held", set())
    monkeypatch.setattr(LC, "APPLIER_STATE", tmp_path / "state")
    (tmp_path / "state").mkdir()                                   # the state directory EXISTS: the "installed but inactive" case


def _sha(limits):
    return hashlib.sha256(LC.canonical({"limits": limits})).hexdigest()


def _write_result(path, limits, at=1000, in_force=(), refused=None, result="applied"):
    path.write_text(json.dumps({"in_force": list(in_force), "refused": refused or {}, "at": at, "result": result,
                                "request_sha256": _sha(limits)}))


def _sent(monkeypatch, tmp_path, limits, t0=10_000.0):
    monkeypatch.setattr(LC.time, "time", lambda: t0)
    LC.sync(limits, request=tmp_path / "limits-request", platform="linux")
    return t0, tmp_path / "result.json"


def test_an_unanswered_request_is_silent_until_the_grace_then_applier_inactive(monkeypatch, tmp_path):
    t0, res = _sent(monkeypatch, tmp_path, {"io_read_mbps": 50})
    assert LC._sent_at == t0 and res.exists() is False
    assert LC.report(platform="linux", result=res, now=t0 + 299) is None                         # not yet: a healthy applier is slow at most seconds
    got = LC.report(platform="linux", result=res, now=t0 + LC.APPLIER_SILENT_S)
    assert got == {"in_force": [], "refused": {"io_read_mbps": "applier_inactive"}}


def test_the_grace_is_five_minutes():
    assert LC.APPLIER_SILENT_S == 300.0


def test_an_old_result_for_another_request_does_not_hide_a_silent_applier(monkeypatch, tmp_path):
    t0, res = _sent(monkeypatch, tmp_path, {"io_read_mbps": 50})
    _write_result(res, {"io_read_mbps": 10}, at=int(t0) - 9999)                                  # an earlier request's answer
    got = LC.report(platform="linux", result=res, now=t0 + 600)
    assert got == {"in_force": [], "refused": {"io_read_mbps": "applier_inactive"}}


def test_no_false_alarm_a_healthy_applier_that_answered_is_reported_normally_however_long_ago(monkeypatch, tmp_path):
    t0, res = _sent(monkeypatch, tmp_path, {"io_read_mbps": 50})
    _write_result(res, {"io_read_mbps": 50}, at=int(t0) + 5, in_force=["io_read_mbps"])
    got = LC.report(platform="linux", result=res, now=t0 + 3600)
    assert got == {"in_force": ["io_read_mbps"], "refused": {}}


def test_the_alarm_clears_when_the_applier_comes_back(monkeypatch, tmp_path):
    t0, res = _sent(monkeypatch, tmp_path, {"io_read_mbps": 50})
    assert LC.report(platform="linux", result=res, now=t0 + 400)["refused"] == {"io_read_mbps": "applier_inactive"}
    _write_result(res, {"io_read_mbps": 50}, at=int(t0) + 401, in_force=["io_read_mbps"])       # the owner fixed the units
    assert LC.report(platform="linux", result=res, now=t0 + 420) == {"in_force": ["io_read_mbps"], "refused": {}}


def test_a_clear_request_with_nothing_held_stays_silent_but_held_keys_are_named(monkeypatch, tmp_path):
    t0, res = _sent(monkeypatch, tmp_path, {"io_read_mbps": 50})
    _write_result(res, {"io_read_mbps": 50}, at=int(t0) + 1, in_force=["io_read_mbps"])
    assert LC.report(platform="linux", result=res, now=t0 + 5)["in_force"] == ["io_read_mbps"]    # the applier answered: the cap is held
    monkeypatch.setattr(LC.time, "time", lambda: t0 + 1000)
    LC.sync({}, request=tmp_path / "limits-request", platform="linux")                            # the owner clears every cap
    assert LC._last_sent == {} and LC._held == {"io_read_mbps"}
    # the applier has stopped: the clear is never answered, so the old cap is still in force AND unseen
    assert LC.report(platform="linux", result=res, now=t0 + 1000 + 400) == {"in_force": [], "refused": {"io_read_mbps": "applier_inactive"}}
    monkeypatch.setattr(LC, "_held", set())                                                       # nothing held: nothing to alarm about
    assert LC.report(platform="linux", result=res, now=t0 + 1000 + 400) is None


def test_nothing_requested_reports_nothing(tmp_path):
    assert LC.report(platform="linux", result=tmp_path / "result.json", now=1e9) is None          # no request ever handed over


def test_other_platforms_are_unchanged(monkeypatch, tmp_path):
    monkeypatch.setattr(LC, "_last_sent", {"io_read_mbps": 50})
    monkeypatch.setattr(LC, "_sent_at", 1.0)
    monkeypatch.setattr(LC, "_local", {"in_force": [], "refused": {"io_read_mbps": "not_supported"}})
    for plat in ("windows", "macos", "linux_no_applier"):
        assert LC.report(platform=plat, result=tmp_path / "r.json", now=1e9) == {"in_force": [], "refused": {"io_read_mbps": "not_supported"}}


def test_the_reported_codes_are_the_closed_class_and_the_key_list_is_bounded(monkeypatch, tmp_path):
    many = {k: 1 for k in LC.KEYS}
    monkeypatch.setattr(LC, "_held", {f"held_key_{i}" for i in range(30)})                        # an absurd held set must still be bounded
    t0, res = _sent(monkeypatch, tmp_path, many)
    got = LC.report(platform="linux", result=res, now=t0 + 400)
    assert len(got["refused"]) <= 16 and all(re.fullmatch(r"[a-z_]{1,40}", c) for c in got["refused"].values())
    assert set(got["refused"].values()) == {"applier_inactive"}


def test_the_heartbeat_carries_the_inactive_report(monkeypatch, tmp_path):
    from meshembed_node import worker
    t0, res = _sent(monkeypatch, tmp_path, {"io_read_mbps": 50})
    monkeypatch.setattr(LC, "_platform", lambda: "linux")
    monkeypatch.setattr(LC, "APPLIER_STATE", tmp_path / "state")
    monkeypatch.setattr(LC.time, "time", lambda: t0 + 400)
    class Cfg:                                                    # the fields _heartbeat_payload reads
        node_id = "n-test"
    payload = worker._heartbeat_payload(Cfg())
    assert payload["limits_applied"] == {"in_force": [], "refused": {"io_read_mbps": "applier_inactive"}}
