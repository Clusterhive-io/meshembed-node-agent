"""SPLIT-ORPHAN (auditor 2026-11-03 12:38:44Z, MEDIUM; SO-1, SO-2), found by the split-serve sandbox bed
(docs/RECORD_SPLIT_SERVE_BED_2026-11-03.md): a GATED daemon (no get_job, so no split_revoked) that is then RESTARTED (an
empty _HANDLED) never relayed the revocation of the plan its root launcher still ran, so the launcher started and kept
a coordinator for a LOST plan until its signed expiry.
- SO-1: the relay also matches the launcher's applied plan (applied.json), once.
- SO-2: a LEASE: the daemon renews split-keep each time the backend still delivers the plan; the launcher tears a plan
  down when its lease is stale; the lease can only shorten a plan, never extend it past the signed expiry."""
from __future__ import annotations

import json
import os

import pytest

from meshembed_node import split_handoff as H
from meshembed_node import split_launch as L

NOW = 1_800_000_000


@pytest.fixture
def daemon(tmp_path, monkeypatch):
    monkeypatch.setenv("MESHEMBED_ENABLE_SPLIT", "1")
    monkeypatch.setattr(H, "_HANDLED", {})
    monkeypatch.setattr(H, "_EXPIRES", {})
    launcher = tmp_path / "launcher-state"
    launcher.mkdir()
    monkeypatch.setattr(H, "STATE_DIR", launcher)                     # never the host's real launcher state
    return {"tmp": tmp_path, "launcher": launcher, "revoke": tmp_path / "split-revoke", "keep": tmp_path / "split-keep"}


def _applied(launcher, pid, expires_at=NOW + 3600):
    (launcher / "applied.json").write_text(json.dumps({"plan_id": pid, "expires_at": expires_at}))


# SO-1 ----------------------------------------------------------------------------------------------------------------

def test_so1_after_a_restart_the_revocation_of_the_launchers_applied_plan_is_relayed_once(daemon):
    _applied(daemon["launcher"], "sp-orphan")
    assert H._HANDLED == {}                                           # the bed chain: gated, then restarted
    assert H.relay_revocations(["sp-orphan"], path=daemon["revoke"], now=NOW) == "sp-orphan"
    assert json.loads(daemon["revoke"].read_text()) == {"plan_id": "sp-orphan"}
    daemon["revoke"].unlink()
    assert H.relay_revocations(["sp-orphan"], path=daemon["revoke"], now=NOW) is None          # once
    assert not daemon["revoke"].exists()


def test_so1_negative_controls(daemon):
    _applied(daemon["launcher"], "sp-applied")
    assert H.relay_revocations(["sp-someone-else"], path=daemon["revoke"], now=NOW) is None    # not ours, not applied
    _applied(daemon["launcher"], "sp-applied", expires_at=NOW - 1)                             # an expired applied plan
    assert H.relay_revocations(["sp-applied"], path=daemon["revoke"], now=NOW) is None
    assert not daemon["revoke"].exists()


# SO-2 ----------------------------------------------------------------------------------------------------------------

def test_so2_the_daemon_renews_the_lease_atomically_0600(daemon):
    assert H.touch_keep("sp-1", NOW, path=daemon["keep"])
    assert H.touch_keep("sp-1", NOW + 30, path=daemon["keep"])
    assert json.loads(daemon["keep"].read_text()) == {"sp-1": NOW + 30}
    assert oct(daemon["keep"].stat().st_mode & 0o777) == "0o600"
    for i in range(H.KEEP_MAX_IDS + 3):                               # bounded
        H.touch_keep(f"sp-x{i}", NOW + 40 + i, path=daemon["keep"])
    assert len(json.loads(daemon["keep"].read_text())) == H.KEEP_MAX_IDS


class _Ovl:
    def __init__(self):
        self.torn = 0

    def teardown(self):
        self.torn += 1


def _hk(daemon, now, keep=True):
    calls, ovl = [], _Ovl()
    state = daemon["tmp"] / "lstate"
    state.mkdir(exist_ok=True)
    (state / "applied.json").write_text(json.dumps({"plan_id": "sp-1", "expires_at": NOW + 3600}))
    out = L.housekeeping(state, None, os.getuid(), now, ovl, systemctl=lambda *a: calls.append(a),
                         cache_root=daemon["tmp"] / "cache", etc=daemon["tmp"] / "etc", units=daemon["tmp"] / "units",
                         keep=daemon["keep"] if keep else None)
    return out, ovl.torn, json.loads((state / "applied.json").read_text()), calls


def test_so2_a_fresh_lease_keeps_the_plan(daemon):
    H.touch_keep("sp-1", NOW, path=daemon["keep"])
    out, torn, applied, calls = _hk(daemon, NOW + L.LEASE_S - 1)
    assert out == "" and torn == 0 and applied["plan_id"] == "sp-1" and calls == []


def test_so2_a_stale_or_missing_or_untrusted_lease_tears_the_plan_down(daemon):
    H.touch_keep("sp-1", NOW, path=daemon["keep"])
    out, torn, applied, calls = _hk(daemon, NOW + L.LEASE_S + 1)                              # stale
    assert out == "lease_expired_torn_down" and torn == 1 and applied == {} and calls
    daemon["keep"].unlink()
    assert _hk(daemon, NOW)[0] == "lease_expired_torn_down"                                  # missing
    H.touch_keep("sp-other", NOW, path=daemon["keep"])
    assert _hk(daemon, NOW)[0] == "lease_expired_torn_down"                                  # another plan's lease only
    H.touch_keep("sp-1", NOW, path=daemon["keep"])
    os.chmod(daemon["keep"], 0o644)
    assert _hk(daemon, NOW)[0] == "lease_expired_torn_down"                                  # not 0600: untrusted
    os.chmod(daemon["keep"], 0o600)
    daemon["keep"].write_text(json.dumps({"sp-1": NOW + 3600}))                             # a marker from the future
    os.chmod(daemon["keep"], 0o600)
    assert _hk(daemon, NOW)[0] == "lease_expired_torn_down"


def test_so2_the_lease_never_extends_a_plan_past_its_signed_expiry(daemon):
    H.touch_keep("sp-1", NOW + 7200, path=daemon["keep"])
    state = daemon["tmp"] / "lstate2"
    state.mkdir()
    (state / "applied.json").write_text(json.dumps({"plan_id": "sp-1", "expires_at": NOW + 3600}))
    out = L.housekeeping(state, None, os.getuid(), NOW + 7200, _Ovl(), systemctl=lambda *a: None,
                         cache_root=daemon["tmp"] / "c2", etc=daemon["tmp"] / "e2", units=daemon["tmp"] / "u2",
                         keep=daemon["keep"])
    assert out == "expired_torn_down"                                # a fresh lease cannot hold an expired plan


def test_so2_no_keep_path_is_the_old_behaviour(daemon):
    assert _hk(daemon, NOW + 10 * L.LEASE_S, keep=False)[0] == ""   # callers that pass no lease path are unchanged


def test_so2_a_redelivered_handled_plan_renews_its_lease_in_handoff(daemon, monkeypatch):
    request = daemon["tmp"] / "split-request"
    H._HANDLED["sp-live"] = "queued"
    H._HANDLED["sp-dead"] = "revoked"
    H.handoff([{"plan": {"plan_id": "sp-live"}}, {"plan": {"plan_id": "sp-dead"}}], "me", path=request, now=NOW)
    keep = json.loads((daemon["tmp"] / "split-keep").read_text())
    assert keep == {"sp-live": NOW}                                  # a revoked plan is never renewed


# SO-3 / SO-4: the heartbeat (a gated or busy daemon does not call get_job) -------------------------------------------

def test_so4_a_busy_daemons_heartbeats_keep_its_live_split(daemon, monkeypatch):
    request = daemon["tmp"] / "split-request"
    H._HANDLED["sp-1"] = "queued"
    H.touch_keep("sp-1", NOW, path=daemon["keep"])                   # the last get_job, then busy for 10 min
    for t in range(NOW + 10, NOW + 601, 10):                         # heartbeats every 10 s list the plan as live
        assert H.renew_live(["sp-1"], path=daemon["keep"], now=t) == ["sp-1"]
    assert _hk(daemon, NOW + 600)[0] == ""                           # no teardown
    assert request.exists() is False                                 # the heartbeat never hands anything over


def test_so4_heartbeats_that_stop_listing_it_tear_it_down_within_the_lease(daemon):
    H._HANDLED["sp-1"] = "queued"
    H.touch_keep("sp-1", NOW, path=daemon["keep"])
    for t in range(NOW + 10, NOW + 601, 10):
        assert H.renew_live([], path=daemon["keep"], now=t) == []    # live elsewhere, not this plan
    assert _hk(daemon, NOW + L.LEASE_S + 1)[0] == "lease_expired_torn_down"


def test_so4_a_live_id_this_daemon_never_handed_renews_nothing(daemon):
    H._HANDLED["sp-revoked"] = "revoked"
    assert H.renew_live(["sp-stranger", "sp-revoked"], path=daemon["keep"], now=NOW) == []
    assert not daemon["keep"].exists()


def test_so3_the_heartbeat_relays_a_revocation_once_through_the_worker(daemon, monkeypatch):
    from meshembed_node import worker
    monkeypatch.setattr(H, "revoke_path", lambda: daemon["revoke"])
    monkeypatch.setattr(H, "keep_path", lambda: daemon["keep"])
    H._HANDLED["sp-gated"] = "queued"
    worker._split_from_heartbeat({"split_revoked": ["sp-gated"]})   # a GATED daemon: only its heartbeat runs
    assert json.loads(daemon["revoke"].read_text()) == {"plan_id": "sp-gated"}
    daemon["revoke"].unlink()
    worker._split_from_heartbeat({"split_revoked": ["sp-gated"]})
    assert not daemon["revoke"].exists()                             # once
    worker._split_from_heartbeat({"split_live": ["sp-gated"]})       # revoked: never renewed again
    assert not daemon["keep"].exists()
