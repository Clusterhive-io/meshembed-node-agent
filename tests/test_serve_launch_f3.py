"""F-3 (E3a-1 finding 2026-10-28; auditor design GO 16:26Z, R1-R3 + P-1..P-3): the root serve launcher never loses a
request. Today's race on the sandbox: START #1 took 5 min in the launcher; the daemon's STOP and START #2 written during
that run were dropped, and the revoked plan's unit kept serving. These tests replay that race on run()."""
from __future__ import annotations

import json
import os

import pytest

from meshembed_node import serve_launch as SL

from test_serve_mvp import NOW, _key, _plan, _request, _stage, host  # noqa: F401  (the launcher fixture)

pytestmark = pytest.mark.unit


def _go(h, req, now=NOW, active=lambda unit: True, **kw):
    _, trust = _key()
    t = h["tmp"]
    return SL.run(req, "meshembed", state=t / "state", now=now, etc=t / "etc", models=t / "models",
                  units=t / "units", systemctl=h["systemctl"], nid="node-a", trusted=trust,
                  gid_of=lambda name: os.getgid(), unit_active=active,
                  settings={"threads": 4, "repack_flag": "--no-repack", "memory_max_mb": 6000, "cpu_quota_pct": 400},
                  **kw)


def _running(h):
    p = h["tmp"] / "state" / "running.json"
    return json.loads(p.read_text())["plan_id"] if p.exists() else "absent"


def _start(h, pid, nonce, m):
    return {"action": "start", "plan": _plan(plan_id=pid, nonce=nonce, model_sha=m, draft_sha=None)}


def _write_during_restart(h, objs):
    """systemctl hook: at the first 'restart' (the launcher is mid-run), the daemon writes each obj in turn."""
    calls, pending = h["calls"], list(objs)

    def hook(*a):
        calls.append(a)
        if a and a[0] == "restart":
            while pending:
                _request(h, pending.pop(0))
    h["systemctl"] = hook


def test_a_stop_written_mid_run_is_handled_right_after(host):
    m = _stage(host, b"model-bytes")
    req = _request(host, _start(host, "sv-A", "n-A", m))
    _write_during_restart(host, [{"action": "stop", "reason": "plan_revoked"}])
    assert _go(host, req) == "stopped:plan_revoked"
    assert _running(host) is None                                         # the revoked plan is not left running
    assert host["calls"][-2:] == [("stop", "meshembed-serve.service"), ("stop", "meshembed-serve-nodraft.service")]


def test_todays_race_start_a_then_stop_then_start_b_ends_with_b(host):
    m = _stage(host, b"model-bytes")
    req = _request(host, _start(host, "sv-A", "n-A", m))
    _write_during_restart(host, [{"action": "stop", "reason": "plan_revoked"}, _start(host, "sv-B", "n-B", m)])
    assert _go(host, req) == SL.RATE_LIMITED                              # B within 60 s of A: refused, PARKED (R1)
    assert _running(host) == "sv-A"
    assert req.read_text() == ""                                          # the request file was consumed...
    pend = host["tmp"] / "state" / "pending.json"
    assert json.loads(pend.read_text())["plan"]["plan"]["plan_id"] == "sv-B"   # ...but B is kept root-side
    assert oct(pend.stat().st_mode & 0o777) == "0o600"
    assert _go(host, req, now=NOW + 61) == "started:sv-B"                 # the timer's next run, after the 60 s
    assert _running(host) == "sv-B" and not pend.exists()
    assert ("restart", "meshembed-serve-nodraft.service") in host["calls"]


def test_a_stop_supersedes_a_parked_start(host):
    m = _stage(host, b"model-bytes")
    req = _request(host, _start(host, "sv-A", "n-A", m))
    _write_during_restart(host, [_start(host, "sv-B", "n-B", m)])
    assert _go(host, req) == SL.RATE_LIMITED and (host["tmp"] / "state" / "pending.json").exists()
    _request(host, {"action": "stop", "reason": "paused"})
    host["calls"].clear()
    assert _go(host, req, now=NOW + 61) == "stopped:paused"                # the stop wins; B is never started
    assert not (host["tmp"] / "state" / "pending.json").exists() and _running(host) is None
    assert host["calls"] == [("stop", "meshembed-serve.service"), ("stop", "meshembed-serve-nodraft.service")]


def test_an_unchanged_request_is_a_no_op(host):
    m = _stage(host, b"model-bytes")
    req = _request(host, _start(host, "sv-A", "n-A", m))
    assert _go(host, req) == "started:sv-A"
    st = host["tmp"] / "state"
    before = {f.name: f.stat().st_mtime_ns for f in st.iterdir()}
    host["calls"].clear()
    assert _go(host, req, now=NOW + 120) == "no_request"                  # P-3: the 30 s timer, nothing pending
    assert host["calls"] == []                                           # no systemctl
    assert {f.name: f.stat().st_mtime_ns for f in st.iterdir()} == before  # no write


def test_a_request_rewritten_without_end_cannot_pin_the_launcher(host):
    n = {"i": 0}

    def hook(*a):
        host["calls"].append(a)
        n["i"] += 1
        _request(host, {"action": "stop", "reason": f"r{'x' * (n['i'] % 30)}"[:40].replace("x", "a")})
    host["systemctl"] = hook
    req = _request(host, {"action": "stop", "reason": "first"})
    _go(host, req)
    assert len([c for c in host["calls"] if c == ("stop", "meshembed-serve.service")]) == SL.MAX_ROUNDS


def test_p2_a_unit_that_stopped_by_itself_is_cleared_from_running(host):
    m = _stage(host, b"model-bytes")
    req = _request(host, _start(host, "sv-A", "n-A", m))
    assert _go(host, req) == "started:sv-A" and _running(host) == "sv-A"
    host["calls"].clear()
    assert _go(host, req, now=NOW + 30, active=lambda unit: True) == "no_request" and _running(host) == "sv-A"
    assert _go(host, req, now=NOW + 60, active=lambda unit: False) == "no_request"  # RuntimeMaxSec / BindsTo
    assert _running(host) is None and host["calls"] == []


def test_running_json_is_written_only_by_a_successful_start_or_stop(host):
    m = _stage(host, b"model-bytes")
    assert _go(host, _request(host, {"action": "start", "plan": _plan(model_sha="c" * 64, draft_sha=None)})) \
        .startswith("refused:")                                          # nothing staged for that sha
    assert _running(host) == "absent"
    # a verified start attempt counts for the 60 s limit even when it fails later (SD-a), hence +61
    assert _go(host, _request(host, _start(host, "sv-A", "n-A", m)), now=NOW + 61) == "started:sv-A"
    p = host["tmp"] / "state" / "running.json"
    assert oct(p.stat().st_mode & 0o777) == "0o644"                       # the daemon reads it (P-1)
