"""RENEW-1 (2026-11-02; auditor 18:53:02Z + 18:53:23Z): a whole-model serve plan renewed with EVERY signed field equal
keeps the running unit (no restart: the 30B's cold start is about 17.5 min). The launcher pre-checks without consuming
the nonce, then verifies in full with the root nonce store, keeps MemoryMax/CPUQuota, moves RuntimeMaxSec to the new
expiry measured from the unit's activation, and switches its running record; any difference is refused and the duty
falls back to a normal START of the same plan. A renewal that does not verify still stops the unit (plan_revoked)."""
from __future__ import annotations

import json

import pytest

from meshembed_node import serve_duty as SDY
from meshembed_node import serve_launch as SL

from test_serve_duty import World
from test_serve_mvp import NOW, _plan, _request, _run, _stage, host  # noqa: F401  (the launcher fixture)

pytestmark = pytest.mark.unit
ACTIVE = dict(unit_active=lambda unit: True, active_enter=lambda unit: 1000.0, mono_now=lambda: 1000.0 + 600)


def _start(h, **over):
    m = _stage(h, b"model-bytes")
    env = _plan(model_sha=m, draft_sha=None, **over)
    assert _run(h, _request(h, {"action": "start", "plan": env})) == f"started:{env['plan']['plan_id']}"
    return m


def _running(h):
    return json.loads((h["tmp"] / "state" / "running.json").read_text())


def test_an_identical_renewal_keeps_the_unit_and_moves_only_the_runtime(host):
    m = _start(host)
    host["calls"].clear()
    ren = _plan(plan_id="sv-2", nonce="n-2", model_sha=m, draft_sha=None, expires_at=NOW + 6 * 3600)
    assert _run(host, _request(host, {"action": "renew", "plan": ren}), **ACTIVE) == "renewed:sv-2"
    assert host["calls"] == [("daemon-reload",)]                      # no stop, no restart: the PID is kept
    drop = (host["tmp"] / "units" / "meshembed-serve-nodraft.service.d" / "20-owner.conf").read_text()
    assert "MemoryMax=6000M" in drop and "CPUQuota=400%" in drop        # kept, never recomputed from free memory
    assert f"RuntimeMaxSec={6 * 3600 + 600}" in drop                    # the new expiry, from the unit's activation
    run = _running(host)
    assert run["plan_id"] == "sv-2" and run["fields"] == {"node_id": "node-a", "model_sha": m, "draft_sha": None,
                                                          "ctx": 8192, "slots": 2}


@pytest.mark.parametrize("over", [{"ctx": 4096}, {"slots": 4}, {"draft_sha": "b" * 64}])
def test_any_changed_signed_field_is_refused_and_the_nonce_is_not_consumed(host, over):
    m = _start(host)
    ren = _plan(plan_id="sv-2", nonce="n-2", model_sha=m, **dict({"draft_sha": None}, **over))
    assert _run(host, _request(host, {"action": "renew", "plan": ren}), **ACTIVE) == "refused:renewal_differs"
    assert _running(host)["plan_id"] == "sv-1"
    # the same plan still STARTS normally (the refused renewal did not consume its nonce)
    if over.get("draft_sha"):
        _stage(host, b"draft-bytes")
        ren = _plan(plan_id="sv-2", nonce="n-2", model_sha=m, draft_sha=_stage(host, b"draft-bytes"))
    code = _run(host, _request(host, {"action": "start", "plan": ren}), start_interval_s=0)
    assert code == "started:sv-2"


def test_a_renewal_needs_a_running_unit_and_a_running_record(host):
    m = _start(host)
    ren = _plan(plan_id="sv-2", nonce="n-2", model_sha=m, draft_sha=None)
    stopped = dict(ACTIVE, unit_active=lambda unit: False)
    assert _run(host, _request(host, {"action": "renew", "plan": ren}), **stopped) == "refused:renewal_unit_not_running"
    assert _run(host, _request(host, {"action": "stop", "reason": "owner:active"})) == "stopped:owner:active"
    assert _run(host, _request(host, {"action": "renew", "plan": ren}), **ACTIVE) == "refused:renewal_differs"


def test_a_renewal_is_verified_in_full_and_never_replayed(host):
    m = _start(host)
    forged = _plan(plan_id="sv-2", nonce="n-2", model_sha=m, draft_sha=None)
    forged["plan"]["expires_at"] += 1                                   # the signature no longer covers the body
    assert _run(host, _request(host, {"action": "renew", "plan": forged}), **ACTIVE).startswith("refused:")
    ren = _plan(plan_id="sv-2", nonce="n-2", model_sha=m, draft_sha=None)
    assert _run(host, _request(host, {"action": "renew", "plan": ren}), **ACTIVE) == "renewed:sv-2"
    again = _plan(plan_id="sv-3", nonce="n-2", model_sha=m, draft_sha=None)    # a reused nonce
    assert _run(host, _request(host, {"action": "renew", "plan": again}), **ACTIVE).startswith("refused:")
    assert _running(host)["plan_id"] == "sv-2"


def test_a_paused_node_never_renews(host):
    m = _start(host)
    (host["tmp"] / "paused").write_text("x")
    ren = _plan(plan_id="sv-2", nonce="n-2", model_sha=m, draft_sha=None)
    code = _run(host, _request(host, {"action": "renew", "plan": ren}), pause_marker=host["tmp"] / "paused", **ACTIVE)
    assert code == "refused:node_paused"


# --- the duty (daemon side) -----------------------------------------------------------------------------------

@pytest.fixture
def w(tmp_path):
    return World(tmp_path)


def _started(w):
    d = w.duty()
    env = _plan(draft_sha=None)
    d.on_get_job({"serve_plans": [env]})
    assert w.request()["action"] == "start"
    w.running = "sv-1"
    return d


def test_the_duty_sends_a_renewal_not_a_stop_for_an_equal_plan(w):
    d = _started(w)
    w.req.write_text("")
    ren = _plan(plan_id="sv-2", nonce="n-2", draft_sha=None, expires_at=NOW + 6 * 3600)
    d.on_get_job({"serve_plans": [ren]})
    assert w.request() == {"action": "renew", "plan": ren}
    w.running = "sv-2"                                                  # the launcher took it
    w.req.write_text("")
    w.t += 30
    d.on_get_job({"serve_plans": [ren]})
    assert w.request() is None and d._renew_at is None                  # nothing more written


def test_a_different_plan_still_stops_the_unit(w):
    d = _started(w)
    w.req.write_text("")
    d.on_get_job({"serve_plans": [_plan(plan_id="sv-2", nonce="n-2", draft_sha=None, model_sha="c" * 64)]})
    assert w.request()["action"] == "stop" and "plan_revoked" in json.dumps(w.request())


def test_an_unverifiable_renewal_still_stops_the_unit(w):
    d = _started(w)
    w.req.write_text("")
    forged = _plan(plan_id="sv-2", nonce="n-2", draft_sha=None)
    forged["plan"]["expires_at"] += 1
    d.on_get_job({"serve_plans": [forged]})
    assert w.request()["action"] == "stop"


def test_a_renewal_the_launcher_does_not_take_falls_back_to_a_normal_start(w):
    d = _started(w)
    w.req.write_text("")
    ren = _plan(plan_id="sv-2", nonce="n-2", draft_sha=None)
    d.on_get_job({"serve_plans": [ren]})
    assert w.request()["action"] == "renew"
    w.req.write_text("")
    w.t += SDY.RENEW_WAIT_S                                             # the launcher still runs sv-1
    d.on_get_job({"serve_plans": [ren]})
    assert w.request() == {"action": "start", "plan": ren}


def test_the_duty_and_the_launcher_compare_the_same_fields():
    assert SDY.RENEW_FIELDS == SL.RENEW_FIELDS


def test_rn1_a_skewed_case_never_extends_beyond_the_signed_expiry(host):
    """RN-1: activation long ago and the wall clock near the signed expiry: RuntimeMaxSec is exactly
    (signed expires_at - now) + (monotonic now - activation), so the unit ends at the signed expiry, never later."""
    m = _start(host)
    ren = _plan(plan_id="sv-2", nonce="n-2", model_sha=m, draft_sha=None, expires_at=NOW + 61)
    skew = dict(unit_active=lambda unit: True, active_enter=lambda unit: 50.0, mono_now=lambda: 50.0 + 5 * 3600)
    assert _run(host, _request(host, {"action": "renew", "plan": ren}), **skew) == "renewed:sv-2"
    drop = (host["tmp"] / "units" / "meshembed-serve-nodraft.service.d" / "20-owner.conf").read_text()
    runtime = int(next(l for l in drop.splitlines() if l.startswith("RuntimeMaxSec=")).split("=")[1])
    assert runtime == 61 + 5 * 3600 and runtime <= (NOW + 61 - NOW) + 5 * 3600


@pytest.mark.parametrize("extra", [{"expires_at": NOW + 99999}, {"memory_max_mb": 99999}, {"unit": "other"}])
def test_rn2_a_renew_request_with_any_extra_key_is_refused_and_changes_nothing(host, extra):
    m = _start(host)
    before = (host["tmp"] / "units" / "meshembed-serve-nodraft.service.d" / "20-owner.conf").read_text()
    host["calls"].clear()
    ren = _plan(plan_id="sv-2", nonce="n-2", model_sha=m, draft_sha=None)
    assert _run(host, _request(host, dict({"action": "renew", "plan": ren}, **extra)), **ACTIVE) == "refused:request_keys"
    assert host["calls"] == [] and _running(host)["plan_id"] == "sv-1"
    assert (host["tmp"] / "units" / "meshembed-serve-nodraft.service.d" / "20-owner.conf").read_text() == before
    # and the plan's nonce is untouched: the same renewal, well-formed, is still accepted
    assert _run(host, _request(host, {"action": "renew", "plan": ren}), **ACTIVE) == "renewed:sv-2"


def test_rn4_every_other_drop_in_line_survives_a_renewal_byte_for_byte(host):
    """RN-4: a cap a later head adds to the drop-in (IO-CAP, OOMScoreAdjust) is never dropped by a renewal."""
    m = _start(host)
    drop = host["tmp"] / "units" / "meshembed-serve-nodraft.service.d" / "20-owner.conf"
    drop.write_text(drop.read_text() + "OOMScoreAdjust=900\nIOReadBandwidthMax=/dev/sda 50M\n")
    before = [l for l in drop.read_text().splitlines() if l and not l.startswith("#") and not l.startswith("RuntimeMaxSec=")]
    ren = _plan(plan_id="sv-2", nonce="n-2", model_sha=m, draft_sha=None)
    assert _run(host, _request(host, {"action": "renew", "plan": ren}), **ACTIVE) == "renewed:sv-2"
    after = [l for l in drop.read_text().splitlines() if l and not l.startswith("#") and not l.startswith("RuntimeMaxSec=")]
    assert after == before and "OOMScoreAdjust=900" in after and "IOReadBandwidthMax=/dev/sda 50M" in after


def test_rn4_a_drop_in_without_its_memory_cap_is_never_renewed(host):
    m = _start(host)
    drop = host["tmp"] / "units" / "meshembed-serve-nodraft.service.d" / "20-owner.conf"
    drop.write_text("\n".join(l for l in drop.read_text().splitlines() if not l.startswith("MemoryMax=")) + "\n")
    ren = _plan(plan_id="sv-2", nonce="n-2", model_sha=m, draft_sha=None)
    assert _run(host, _request(host, {"action": "renew", "plan": ren}), **ACTIVE) == "refused:renewal_no_dropin"


def test_rn4_ic1_a_renewal_reconciles_the_limits_against_the_new_drop_in(host):
    """RN-4 x IC-1 (the v0.3.82 composition of #53 with #22): the reconcile runs after the rewrite, on the NEW text."""
    m = _start(host)
    host["calls"].clear()
    drop = host["tmp"] / "units" / "meshembed-serve-nodraft.service.d" / "20-owner.conf"
    seen = []
    ren = _plan(plan_id="sv-2", nonce="n-2", model_sha=m, draft_sha=None, expires_at=NOW + 6 * 3600)
    out = _run(host, _request(host, {"action": "renew", "plan": ren}), **ACTIVE,
               limits_reconcile=lambda: seen.append(drop.read_text()) or "applied")
    assert out == "renewed:sv-2" and len(seen) == 1 and "renewal of" in seen[0]
    assert f"RuntimeMaxSec={6 * 3600 + 600}" in seen[0] and host["calls"] == [("daemon-reload",)]


@pytest.mark.parametrize("fail", ["error:set_property", "unbound", "raise"])
def test_rn4_ic1_a_failed_reconcile_restores_the_old_drop_in_and_refuses(host, fail):
    import subprocess
    m = _start(host)
    first = _running(host)["plan_id"]
    drop = host["tmp"] / "units" / "meshembed-serve-nodraft.service.d" / "20-owner.conf"
    drop.write_text(drop.read_text() + "IOReadBandwidthMax=/dev/sda 50M\n")
    before = drop.read_bytes()
    host["calls"].clear()

    def rec():
        if fail == "raise":
            raise subprocess.TimeoutExpired("systemctl", 180)
        return fail
    ren = _plan(plan_id="sv-2", nonce="n-2", model_sha=m, draft_sha=None)
    assert _run(host, _request(host, {"action": "renew", "plan": ren}), **ACTIVE,
                limits_reconcile=rec) == "refused:renewal_limits_failed"
    assert drop.read_bytes() == before                                  # byte-for-byte: the owner's caps never loosen
    assert host["calls"] == [("daemon-reload",), ("daemon-reload",)]     # no stop, no restart either way
    assert _running(host)["plan_id"] == first                           # the old plan's record and RuntimeMaxSec stay


def test_cd1a_a_failed_renewal_reconcile_leaves_99_limits_as_before_the_renewal(host, capsys):
    """CD-1a (auditor 2026-11-03 14:55:22Z): the applier writes 99-limits.conf FIRST (IC-2), so a pass can fail after
    writing it from the NEW drop-in. Here the fake writes 99-limits from a hash of the drop-in it reads (so the new and
    the old text give DIFFERENT bytes, harsher than the real case, where RN-4 keeps every managed line), fails once,
    then passes: after the refusal 99-limits.conf equals its pre-renewal bytes."""
    import hashlib
    m = _start(host)
    d = host["tmp"] / "units" / "meshembed-serve-nodraft.service.d"
    drop, ours = d / "20-owner.conf", d / "99-limits.conf"

    def from_drop():
        ours.write_text("# from " + hashlib.sha256(drop.read_bytes()).hexdigest() + "\n[Service]\nIOWeight=50\n")
    from_drop()
    before = ours.read_bytes()
    answers = iter(["error:set_property", "applied"])

    def rec():
        from_drop()
        return next(answers)
    ren = _plan(plan_id="sv-2", nonce="n-2", model_sha=m, draft_sha=None)
    assert _run(host, _request(host, {"action": "renew", "plan": ren}), **ACTIVE,
                limits_reconcile=rec) == "refused:renewal_limits_failed"
    assert ours.read_bytes() == before and next(answers, "spent") == "spent"     # both passes ran
    assert "renewal_limits_failed error:set_property; reconcile on the restored drop-in: applied" in capsys.readouterr().out
