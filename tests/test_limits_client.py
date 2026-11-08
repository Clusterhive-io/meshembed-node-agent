"""IO-CAP, the daemon's half: limits_client.sync / report and the heartbeat's limits_applied (IC-7)."""
from __future__ import annotations

import hashlib
import json
import os
import threading
from unittest.mock import MagicMock

import pytest

from meshembed_node import limits_client as LC
from meshembed_node import worker

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _fresh(monkeypatch, tmp_path):
    monkeypatch.setattr(LC, "_last_sent", None)
    monkeypatch.setattr(LC, "_sent_sha", "")
    monkeypatch.setattr(LC, "_local", {})
    monkeypatch.setattr(LC, "_first_sync_done", False)
    monkeypatch.setattr(LC, "APPLIER_STATE", tmp_path / "no-applier-state")   # never the host's real result.json


def _sha(limits):
    return hashlib.sha256(LC.canonical({"limits": limits})).hexdigest()


def _result(tmp_path, at, in_force=(), refused=None, result="applied", for_limits=None, sha="unset", name="result.json"):
    p = tmp_path / name
    d = {"in_force": list(in_force), "refused": refused or {}, "at": at, "result": result}
    if sha != "unset":
        d["request_sha256"] = sha
    elif for_limits is not None:
        d["request_sha256"] = _sha(for_limits)
    p.write_text(json.dumps(d))
    return p


def test_nothing_set_writes_nothing_and_reports_nothing(tmp_path):
    req = tmp_path / "limits-request"
    LC.sync({"max_cpu_pct": 50}, request=req, platform="linux")
    assert not req.exists() and LC.report(platform="linux", result=tmp_path / "none.json") is None


def test_the_request_is_written_only_when_the_io_keys_change(tmp_path):
    req = tmp_path / "limits-request"
    LC.sync({"io_read_mbps": 50, "max_cpu_pct": 50}, request=req, platform="linux")
    assert req.read_bytes() == b'{"limits":{"io_read_mbps":50}}'          # IOB-3: the canonical bytes
    assert oct(req.stat().st_mode & 0o777) == "0o600"
    req.write_text("")                                             # the applier truncated it
    LC.sync({"io_read_mbps": 50, "max_cpu_pct": 60}, request=req, platform="linux")
    assert req.read_text() == ""                                   # no IO change: no new request, no applier run
    LC.sync({}, request=req, platform="linux")
    assert json.loads(req.read_text()) == {"limits": {}}           # cleared: the applier removes its caps


def test_only_a_result_for_this_request_is_reported(tmp_path):
    LC.sync({"io_read_mbps": 50}, request=tmp_path / "r", platform="linux")
    # IOB-3: a result for ANOTHER request (the previous one replayed by a reconcile, a parked one re-run), whatever
    # its time, and one with no digest (a dead or older applier) are not reported
    assert LC.report(platform="linux", result=_result(tmp_path, 9999, ["io_read_mbps"],
                                                      for_limits={"io_read_mbps": 40})) is None
    assert LC.report(platform="linux", result=_result(tmp_path, 9999, ["io_read_mbps"])) is None
    assert LC.report(platform="linux", result=_result(tmp_path, 1, ["io_read_mbps"],
                                                      for_limits={"io_read_mbps": 50})) == {
        "in_force": ["io_read_mbps"], "refused": {}}


def test_the_client_and_the_applier_hash_the_same_bytes(tmp_path):
    from meshembed_node import limits_apply as LA
    want = {"io_class": "low", "memory_max_gb": 7.5, "io_read_mbps": 50}
    LC.sync(want, request=tmp_path / "r", platform="linux")
    parsed = json.loads((tmp_path / "r").read_text())               # what the applier's read_request returns
    assert LA.request_sha256(parsed) == LC._sent_sha == hashlib.sha256((tmp_path / "r").read_bytes()).hexdigest()


def test_a_restart_clears_caps_left_in_force(tmp_path):
    # IOB-2: the daemon restarted (OTA, reboot) after the caps were cleared on the backend; the applier's last result
    # still names the old request -> the first sync writes the empty request once
    req = tmp_path / "r"
    res = _result(tmp_path, 1, ["memory_max_gb"], for_limits={"memory_max_gb": 8})
    LC.sync({}, request=req, platform="linux", result=res)
    assert json.loads(req.read_text()) == {"limits": {}}
    req.write_text("")
    LC.sync({}, request=req, platform="linux", result=res)
    assert req.read_text() == ""                                    # once, not on every poll


@pytest.mark.parametrize("res", [None, "clear", "older_applier_nothing"])
def test_a_restart_with_nothing_in_force_writes_nothing(tmp_path, res):
    req = tmp_path / "r"
    path = {None: tmp_path / "absent.json",
            "clear": _result(tmp_path, 1, for_limits={}),
            "older_applier_nothing": _result(tmp_path, 1)}[res]
    LC.sync({}, request=req, platform="linux", result=path)
    assert not req.exists()


def test_an_older_applier_result_with_caps_in_force_is_cleared_too(tmp_path):
    req = tmp_path / "r"
    LC.sync({}, request=req, platform="linux", result=_result(tmp_path, 1, ["io_class"]))
    assert json.loads(req.read_text()) == {"limits": {}}


def test_the_restart_clear_is_linux_with_the_applier_only(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(LC, "_win_background", lambda c: calls.append(c))
    res = _result(tmp_path, 1, ["io_class"], for_limits={"io_class": "low"})
    LC.sync({}, request=tmp_path / "r", platform="windows", result=res)
    assert not (tmp_path / "r").exists() and calls == []


def test_concurrent_syncs_never_interleave_the_request(tmp_path, monkeypatch):
    # IOB-4: the poll and the heartbeat thread call sync() together; one lock, so the file is always one whole request
    req = tmp_path / "r"
    real_write = os.write
    def slow_write(fd, data):
        n = 0
        for i in range(len(data)):
            n += real_write(fd, data[i:i + 1])
        return n
    monkeypatch.setattr(LC.os, "write", slow_write)
    wants = [{"io_read_mbps": 20 + i} for i in range(40)]
    ts = [threading.Thread(target=LC.sync, args=(w,), kwargs={"request": req, "platform": "linux"}) for w in wants]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    final = json.loads(req.read_text())
    assert final == {"limits": LC._last_sent} and LC._sent_sha == _sha(LC._last_sent)


def test_a_whole_request_refusal_is_every_key_refused(tmp_path):
    LC.sync({"io_read_mbps": 50, "io_class": "low"}, request=tmp_path / "r", platform="linux")
    r = LC.report(platform="linux", result=_result(tmp_path, 1001, result="refused:limits_local_untrusted",
                                                   for_limits={"io_read_mbps": 50, "io_class": "low"}))
    assert r == {"in_force": [], "refused": {"io_class": "limits_local_untrusted", "io_read_mbps": "limits_local_untrusted"}}


def test_codes_and_keys_are_closed(tmp_path):
    LC.sync({"io_read_mbps": 50}, request=tmp_path / "r", platform="linux")
    r = LC.report(platform="linux", result=_result(tmp_path, 1001, ["io_read_mbps", "bogus"],
                                                   {"io_class": "x" * 50, "bogus": "below_floor"},
                                                   for_limits={"io_read_mbps": 50}))
    assert r == {"in_force": ["io_read_mbps"], "refused": {}}


def test_a_symlinked_result_is_not_read(tmp_path):
    LC.sync({"io_read_mbps": 50}, request=tmp_path / "r", platform="linux")
    real = _result(tmp_path, 1001, ["io_read_mbps"], for_limits={"io_read_mbps": 50})
    link = tmp_path / "link.json"; link.symlink_to(real)
    assert LC.report(platform="linux", result=link) is None


@pytest.mark.parametrize("plat", ["windows", "macos"])
def test_windows_and_macos_apply_io_class_and_say_not_supported_for_the_rest(monkeypatch, plat, tmp_path):
    calls = []
    monkeypatch.setattr(LC, "_win_background", lambda c: calls.append(c))
    monkeypatch.setattr(LC, "_mac_iopolicy", lambda c: calls.append(c))
    LC.sync({"io_class": "idle", "io_read_mbps": 50}, request=tmp_path / "r", platform=plat)
    assert calls == ["idle"] and not (tmp_path / "r").exists()
    assert LC.report(platform=plat) == {"in_force": ["io_class"], "refused": {"io_read_mbps": "not_supported"}}
    LC.sync({}, request=tmp_path / "r", platform=plat)
    assert calls == ["idle", "normal"]                              # cleared: back to normal priority


def test_a_user_install_on_linux_says_the_applier_is_missing(tmp_path):
    LC.sync({"io_read_mbps": 50}, request=tmp_path / "r", platform="linux_no_applier")
    assert LC.report(platform="linux_no_applier") == {"in_force": [], "refused": {"io_read_mbps": "applier_not_installed"}}


def test_the_heartbeat_carries_the_report_only_when_there_is_one(monkeypatch):
    cfg = MagicMock(); cfg.node_id = "n"
    monkeypatch.setattr(LC, "report", lambda: None)
    assert "limits_applied" not in worker._heartbeat_payload(cfg)
    monkeypatch.setattr(LC, "report", lambda: {"in_force": ["io_class"], "refused": {}})
    assert worker._heartbeat_payload(cfg)["limits_applied"] == {"in_force": ["io_class"], "refused": {}}
    monkeypatch.setattr(LC, "report", lambda: (_ for _ in ()).throw(OSError("x")))
    assert "limits_applied" not in worker._heartbeat_payload(cfg)    # a failing report never stops the heartbeat


# --- IOB-6: a clear that is not (yet) applied is reported, never "nothing in force" -------------------------------------
def _clear_result(tmp_path, refused=None, result="applied", in_force=()):
    return _result(tmp_path, 1, in_force, refused, result=result, for_limits={}, name="clear.json")


def test_iob6_a_parked_clear_is_reported(tmp_path):
    LC.sync({"io_read_mbps": 50, "memory_max_gb": 8}, request=tmp_path / "r", platform="linux")
    LC.sync({}, request=tmp_path / "r", platform="linux")
    r = LC.report(platform="linux", result=_clear_result(
        tmp_path, {"io_read_mbps": "loosen_parked", "memory_max_gb": "loosen_parked"}, "parked:loosen_rate_limited"))
    assert r == {"in_force": [], "refused": {"io_read_mbps": "loosen_parked", "memory_max_gb": "loosen_parked"}}


def test_iob6_a_clear_blocked_by_an_invalid_limits_local_is_reported(tmp_path):
    LC.sync({"cpu_quota_pct": 100}, request=tmp_path / "r", platform="linux")
    LC.sync({}, request=tmp_path / "r", platform="linux")
    r = LC.report(platform="linux", result=_clear_result(tmp_path, {"cpu_quota_pct": "limits_local_invalid"}))
    assert r == {"in_force": [], "refused": {"cpu_quota_pct": "limits_local_invalid"}}


def test_iob6_a_whole_refusal_of_a_clear_names_the_caps_last_in_force(tmp_path):
    LC.sync({"io_read_mbps": 50}, request=tmp_path / "r", platform="linux")
    assert LC.report(platform="linux", result=_result(tmp_path, 1, ["io_read_mbps"],
                                                      for_limits={"io_read_mbps": 50}))["in_force"] == ["io_read_mbps"]
    LC.sync({}, request=tmp_path / "r", platform="linux")
    r = LC.report(platform="linux", result=_clear_result(tmp_path, result="refused:io_error"))
    assert r == {"in_force": [], "refused": {"io_read_mbps": "io_error"}}


def test_iob6_a_clear_applied_reports_empty_lists_so_the_backend_replaces_a_held_report(tmp_path):
    LC.sync({"io_read_mbps": 50}, request=tmp_path / "r", platform="linux")
    LC.sync({}, request=tmp_path / "r", platform="linux")
    assert LC.report(platform="linux", result=_clear_result(tmp_path)) == {"in_force": [], "refused": {}}


def test_iob6_a_cap_dropped_from_a_smaller_request_and_parked_is_reported(tmp_path):
    LC.sync({"io_read_mbps": 50, "memory_max_gb": 8}, request=tmp_path / "r", platform="linux")
    LC.sync({"io_read_mbps": 50}, request=tmp_path / "r", platform="linux")
    r = LC.report(platform="linux", result=_result(tmp_path, 1, ["io_read_mbps"], {"memory_max_gb": "loosen_parked"},
                                                   result="parked:loosen_rate_limited",
                                                   for_limits={"io_read_mbps": 50}))
    assert r == {"in_force": ["io_read_mbps"], "refused": {"memory_max_gb": "loosen_parked"}}


def test_iob6_after_a_restart_the_clear_is_reported_until_applied(tmp_path):
    req = tmp_path / "r"
    old = _result(tmp_path, 1, ["memory_max_gb"], for_limits={"memory_max_gb": 8}, name="old.json")
    LC.sync({}, request=req, platform="linux", result=old)                 # IOB-2: the clear is written
    r = LC.report(platform="linux", result=_clear_result(tmp_path, result="refused:lock_busy"))
    assert r == {"in_force": [], "refused": {"memory_max_gb": "lock_busy"}}          # the old cap named, not hidden


def test_nothing_ever_handed_over_still_reports_nothing(tmp_path):
    assert LC.report(platform="linux", result=_clear_result(tmp_path, {"io_read_mbps": "loosen_parked"})) is None
