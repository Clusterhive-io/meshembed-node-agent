"""PATH-TRIGGER (0.3.86; auditor PT-3 18:03:56Z): the launcher CONSUMES the split request / revoke by unlink; the daemon creates the
name only when it is ABSENT. (A rename over an existing watched file starts nothing on systemd 255 / 26.04: host tests T1 yes / T2 no.)"""
import json
import os
import threading

import pytest

from meshembed_node import split_handoff as H
from meshembed_node import split_launch as L

UID = os.getuid()


def _put(p, text, mode=0o600):
    p.write_text(text)
    os.chmod(p, mode)


# ---- launcher side: read_request_unlink ----
def test_a_request_is_read_then_the_name_is_gone(tmp_path):
    p = tmp_path / "split-request"
    _put(p, json.dumps({"plan": {"plan_id": "sp-1"}}))
    assert L.read_request_unlink(p, UID) == {"plan": {"plan_id": "sp-1"}}
    assert not p.exists()                                           # consumed: PathExists= stops firing
    assert L.read_request_unlink(p, UID) is None                    # absent = no request


def test_an_empty_leftover_of_the_old_protocol_is_removed_not_looped_on(tmp_path):
    p = tmp_path / "split-request"
    _put(p, "")
    assert L.read_request_unlink(p, UID) is None
    assert not p.exists()


@pytest.mark.parametrize("make,code", [
    (lambda p: _put(p, "{not json"), "request_not_json"),
    (lambda p: _put(p, "{}", mode=0o644), "request_mode_too_open"),
    (lambda p: _put(p, "x" * (L.MAX_REQUEST_BYTES + 5)), "request_too_large"),
])
def test_a_refused_request_is_recorded_and_removed(tmp_path, make, code):
    p = tmp_path / "split-request"
    make(p)
    with pytest.raises(L.Refused, match=code):
        L.read_request_unlink(p, UID)
    assert not p.exists()                                           # or the level-triggered unit would loop forever


def test_a_wrong_owner_is_refused_and_removed(tmp_path):
    p = tmp_path / "split-request"
    _put(p, "{}")
    with pytest.raises(L.Refused, match="request_wrong_owner"):
        L.read_request_unlink(p, UID + 1)
    assert not p.exists()


def test_a_symlink_is_never_followed_and_the_link_is_removed(tmp_path):
    target = tmp_path / "secret"
    _put(target, json.dumps({"plan": {"plan_id": "sp-x"}}))
    link = tmp_path / "split-request"
    link.symlink_to(target)
    with pytest.raises(L.Refused, match="request_unreadable"):
        L.read_request_unlink(link, UID)
    assert not link.exists() and target.exists()                    # the link went, the target was not read or touched


def test_a_hard_linked_request_is_refused(tmp_path):
    p, q = tmp_path / "split-request", tmp_path / "other"
    _put(p, "{}")
    os.link(p, q)
    with pytest.raises(L.Refused, match="request_not_regular"):
        L.read_request_unlink(p, UID)


def test_housekeeping_revoke_goes_through_the_same_consuming_read():
    import inspect
    src = inspect.getsource(L.housekeeping) + inspect.getsource(L.run_once)
    assert "read_request_unlink(revoke" in src and "read_request_unlink(request" in src


# ---- daemon side: _write_request creates the name only when it is absent ----
def test_the_daemon_creates_the_request_when_the_name_is_absent(tmp_path):
    p = tmp_path / ".meshembed" / "split-request"
    assert H._write_request(p, {"plan": {"plan_id": "sp-a"}}) is True
    assert oct(p.stat().st_mode & 0o777) == "0o600" and json.loads(p.read_text()) == {"plan": {"plan_id": "sp-a"}}
    assert not (p.parent / "split-request.tmp").exists()


def test_the_daemon_never_overwrites_a_pending_request(tmp_path):
    p = tmp_path / "split-request"
    _put(p, '{"pending": 1}')
    assert H._write_request(p, {"plan": {"plan_id": "sp-b"}}) is False
    assert p.read_text() == '{"pending": 1}'


def test_a_present_empty_leftover_is_never_touched_by_the_daemon_and_the_launcher_consumes_it(tmp_path):
    """R3 (auditor 20:09:03Z): the daemon never unlinks a present name, not even an empty leftover (it could race the launcher's
    own drop of it and delete a brand-new request); the launcher's read_request_unlink removes it, then the daemon can write."""
    p = tmp_path / "split-request"
    _put(p, "")                                                      # the old truncate protocol's leftover
    assert H._write_request(p, {"plan": {"plan_id": "sp-c"}}) is False
    assert p.exists() and p.read_text() == ""                        # untouched
    assert L.read_request_unlink(p, UID) is None and not p.exists()  # the launcher consumed it
    assert H._write_request(p, {"plan": {"plan_id": "sp-c"}}) is True
    assert json.loads(p.read_text())["plan"]["plan_id"] == "sp-c"


def test_a_symlink_at_the_request_name_is_never_written_through(tmp_path):
    target = tmp_path / "victim"
    _put(target, "keep")
    p = tmp_path / "split-request"
    p.symlink_to(target)
    assert H._write_request(p, {"plan": {"plan_id": "sp-d"}}) is False
    assert target.read_text() == "keep"


def test_two_writer_threads_create_exactly_one_request(tmp_path):
    p = tmp_path / "split-request"
    results = []

    def w(i):
        results.append(H._write_request(p, {"plan": {"plan_id": f"sp-{i}"}}))
    ts = [threading.Thread(target=w, args=(i,)) for i in range(8)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert results.count(True) == 1 and results.count(False) == 7   # one pending request, never overwritten
    assert json.loads(p.read_text())["plan"]["plan_id"].startswith("sp-")


def test_write_then_consume_round_trip(tmp_path):
    p = tmp_path / "split-request"
    assert H._write_request(p, {"plan": {"plan_id": "sp-e"}}) is True
    assert L.read_request_unlink(p, UID) == {"plan": {"plan_id": "sp-e"}}
    assert H._write_request(p, {"plan": {"plan_id": "sp-f"}}) is True   # absent again: the next one is created


# ---- R1 / R2 / R3: the revoke names are written absent-only too; the reclaim withdraw unlinks ----
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
    monkeypatch.setattr(H, "STATE_DIR", launcher)
    return {"revoke": tmp_path / "split-revoke", "request": tmp_path / "split-request", "tmp": tmp_path,
            "record": tmp_path / "split-reclaimed.json", "launcher": launcher}


def test_relay_revocations_never_overwrites_a_pending_revoke_and_retries(daemon):
    H._HANDLED.update({"sp-a": "queued", "sp-b": "queued"})
    assert H.relay_revocations(["sp-a"], path=daemon["revoke"]) == "sp-a"
    assert H._HANDLED["sp-a"] == "revoked"
    assert H.relay_revocations(["sp-b"], path=daemon["revoke"]) is None          # a revoke is pending: refused, retried next poll
    assert H._HANDLED["sp-b"] == "queued"                                         # NOT marked revoked: nothing was written
    assert json.loads(daemon["revoke"].read_text()) == {"plan_id": "sp-a"}        # the pending one is untouched
    assert L.read_request_unlink(daemon["revoke"], UID) == {"plan_id": "sp-a"}    # the launcher consumed it
    assert H.relay_revocations(["sp-b"], path=daemon["revoke"]) == "sp-b"         # now it goes through
    assert H._HANDLED["sp-b"] == "revoked"


def test_reclaim_for_owner_sets_nothing_when_the_revoke_write_is_refused_and_acts_once_it_clears(daemon):
    H._HANDLED["sp-1"] = "queued"
    _put(daemon["revoke"], json.dumps({"plan_id": "sp-other"}))                   # a revoke already pending
    assert H.reclaim_for_owner("owner:active", path=daemon["revoke"], request=daemon["request"], now=1000) is None
    assert H._HANDLED["sp-1"] == "queued" and not H._RECLAIMED and not daemon["record"].exists()
    assert json.loads(daemon["revoke"].read_text()) == {"plan_id": "sp-other"}    # untouched
    L.read_request_unlink(daemon["revoke"], UID)                                   # the launcher consumes it
    assert H.reclaim_for_owner("owner:active", path=daemon["revoke"], request=daemon["request"], now=1001) == "sp-1"
    assert json.loads(daemon["revoke"].read_text()) == {"plan_id": "sp-1", "reason": "owner_reclaim"}
    assert H._HANDLED["sp-1"] == "reclaimed"


def test_the_reclaim_withdraw_removes_the_request_name(daemon):
    H._HANDLED["sp-1"] = "queued"
    _put(daemon["request"], json.dumps({"plan": {"plan_id": "sp-1"}}))
    H.reclaim_for_owner("power:on_battery", path=daemon["revoke"], request=daemon["request"])
    assert not daemon["request"].exists()                                         # unlinked, not truncated in place
