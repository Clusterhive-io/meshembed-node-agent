"""S-D: the node serve duty (docs/DESIGN_S_D_NODE_SERVE_DUTY_2026-10-27.md; auditor design GO 2026-10-27 19:53Z with
SD-a..SD-d, SD-e 19:56Z): the daemon side (serve_duty), the root launcher's new rules (rate limit, pause, one link)
and the installer block."""
from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path

import pytest

from meshembed_node import serve_client as SC
from meshembed_node import serve_duty as SDY
from meshembed_node import serve_launch as SL

from test_serve_mvp import NOW, _key, _plan, _request, _run, _stage, host  # noqa: F401  (the launcher fixture)

pytestmark = pytest.mark.unit
ROOT = Path(__file__).resolve().parents[1]


# --- the duty (daemon side) -----------------------------------------------------------------------------------

class World:
    def __init__(self, tmp: Path):
        self.t = NOW
        self.paused = False
        self.gate = None
        self.health = False
        self.staged = []
        self.polls = []
        self.req = tmp / "serve-request"
        self.running = "auto"                               # F-3: "auto" = the launcher does what the request says
        self._last_running = None
        self.spawned = []

    def running_plan(self):
        """The root launcher's running.json, emulated: a START runs that plan, a STOP runs none."""
        if self.running != "auto":
            return self.running
        r = self.request()
        if r and r.get("action") == "start":
            self._last_running = r["plan"]["plan"]["plan_id"]
        elif r and r.get("action") == "stop":
            self._last_running = None
        return self._last_running

    def duty(self, **kw):
        _, trust = _key()

        def serve_once(post, node_id, models, *, decide, sock, stop_path, serving):
            ok, why = decide()
            if not ok:
                SC.request_stop(why, stop_path)
                serving["running"] = False
                return f"yield:{why}"
            self.polls.append(models)
            return "served"

        kw.setdefault("spawn", self.spawned.append)
        d = SDY.ServeDuty("node-a", lambda *a: (204, None), gate=lambda: self.gate, paused=lambda: self.paused,
                          stage=lambda sha: self.staged.append(sha) or True,
                          model_id_for=lambda sha: "meshembed/qwen3-4b-q8", request=self.req,
                          clock=lambda: self.t, health=lambda: self.health, trusted=trust, serve_once=serve_once,
                          running_plan=self.running_plan, **kw)
        raw = d.on_get_job

        def on_get_job(resp):
            """F-2: staging runs in the background; here it finishes before the next poll, which then starts."""
            raw(resp)
            if self.spawned:
                while self.spawned:
                    self.spawned.pop(0)()
                raw(resp)
        d.on_get_job = on_get_job
        return d

    def request(self):
        return json.loads(self.req.read_text()) if self.req.exists() and self.req.read_text() else None


@pytest.fixture
def w(tmp_path):
    return World(tmp_path)


def test_off_paths(tmp_path):
    unit = tmp_path / "meshembed-serve-launch.path"
    assert SDY.why_off({"MESHEMBED_SERVE": "1"}, platform="darwin", unit=unit) == "serve_linux_only"
    assert SDY.why_off({"MESHEMBED_SERVE": "1"}, platform="win32", unit=unit) == "serve_linux_only"
    assert SDY.why_off({"MESHEMBED_SERVE": "1"}, platform="linux", unit=unit) == "serve_not_installed"
    unit.write_text("x")                                   # present, but owned by us (not root): not installed
    if os.getuid() != 0:
        assert SDY.why_off({"MESHEMBED_SERVE": "1"}, platform="linux", unit=unit) == "serve_not_installed"
    root_unit = Path("/etc/passwd")                        # a root-owned regular file stands in for the unit
    assert SDY.why_off({}, platform="linux", unit=root_unit) == "serve_off"
    assert SDY.why_off({"MESHEMBED_SERVE": "1"}, platform="linux", unit=root_unit) is None


def test_a_valid_plan_is_staged_and_started_once(w):
    d = w.duty()
    env = _plan(draft_sha=None)
    d.on_get_job({"serve_plans": [env]})
    assert w.request() == {"action": "start", "plan": env} and w.staged == ["a" * 64]
    assert d.status() == {"ready": False, "plan_id": "sv-1", "model_sha": "a" * 64, "reason": "unit_not_answering",
                          "running_plan_id": "sv-1"}
    w.req.write_text("")
    d.on_get_job({"serve_plans": [env, _plan(plan_id="sv-2", nonce="n-2", draft_sha=None)]})
    assert w.request() is None                              # one active plan: nothing new is started


@pytest.mark.parametrize("env", [
    _plan(node_id="node-b", draft_sha=None),                 # another node's plan
    _plan(expires_at=NOW - 1, draft_sha=None),               # expired
    {"plan": {}, "sig": "x", "kid": "t1"},                    # malformed
])
def test_unusable_plans_start_nothing(w, env):
    w.duty().on_get_job({"serve_plans": [env]})
    assert w.request() is None


def test_a_forged_plan_starts_nothing(w):
    env = _plan(draft_sha=None)
    env["plan"]["slots"] = 1                                # signature no longer matches
    w.duty().on_get_job({"serve_plans": [env]})
    assert w.request() is None


def test_ready_only_with_a_live_socket_and_no_block(w):
    d = w.duty()
    d.on_get_job({"serve_plans": [_plan(draft_sha=None)]})
    w.health = True
    assert d.status()["ready"] is True
    w.health = False                                        # the unit died
    assert d.status()["ready"] is False and d.status()["reason"] == "unit_not_answering"


@pytest.mark.parametrize("block", ["paused", "on_battery", "over_ram_cap", "owner_busy", "too_hot", "metered"])
def test_pause_or_any_gate_stops_the_unit_and_never_polls(w, block):
    d = w.duty()
    d.on_get_job({"serve_plans": [_plan(draft_sha=None)]})
    w.health = True
    if block == "paused":
        w.paused = True
    else:
        w.gate = block
    assert d.tick() == f"stopped:{block}"
    assert w.request() == {"action": "stop", "reason": block} and w.polls == []
    assert d.status()["ready"] is False


def test_paused_unknown_counts_as_paused(w):
    d = w.duty(); d.on_get_job({"serve_plans": [_plan(draft_sha=None)]}); w.health = True

    def boom():
        raise RuntimeError("cannot tell")
    d.paused = boom
    assert d.tick() == "stopped:paused"


@pytest.mark.parametrize("resp", [{"serve_plans": []}, {"assignment": None}])
def test_revoked_when_absent_or_key_missing(w, resp):
    d = w.duty()
    d.on_get_job({"serve_plans": [_plan(draft_sha=None)]})
    d.on_get_job(resp)
    assert w.request() == {"action": "stop", "reason": "plan_revoked"} and d.status()["ready"] is False


def test_revoke_between_polls_means_no_further_poll(w):
    d = w.duty(); d.on_get_job({"serve_plans": [_plan(draft_sha=None)]}); w.health = True
    assert d.tick() == "served" and len(w.polls) == 1
    d.on_get_job({"serve_plans": []})                       # s1: revoked between two polls
    assert d.tick() == "no_plan" and len(w.polls) == 1


def test_expiry_stops(w):
    d = w.duty(); d.on_get_job({"serve_plans": [_plan(draft_sha=None)]}); w.health = True
    w.t = NOW + 3600 - 30                                   # under 60 s left
    assert d.tick() == "stopped:plan_expired"


def test_a_stopped_plan_never_restarts_and_starts_back_off(w):
    d = w.duty(); d.on_get_job({"serve_plans": [_plan(draft_sha=None)]})
    w.paused = True; d.tick(); w.paused = False
    w.req.write_text("")
    d.on_get_job({"serve_plans": [_plan(draft_sha=None)]})
    assert w.request() is None                              # the same plan: never again
    d.on_get_job({"serve_plans": [_plan(plan_id="sv-2", nonce="n-2", draft_sha=None)]})
    assert w.request() is None                              # a new plan inside 60 s of the last start: not yet
    w.t += SDY.START_BACKOFF_S
    d.on_get_job({"serve_plans": [_plan(plan_id="sv-2", nonce="n-2", draft_sha=None)]})
    assert w.request()["action"] == "start" and w.request()["plan"]["plan"]["plan_id"] == "sv-2"


def test_blocked_node_does_not_start(w):
    w.gate = "on_battery"
    d = w.duty(); d.on_get_job({"serve_plans": [_plan(draft_sha=None)]})
    assert w.request() is None and d.status() == {"ready": False, "reason": "on_battery", "running_plan_id": None}


def test_shutdown_stops(w):
    d = w.duty(); d.on_get_job({"serve_plans": [_plan(draft_sha=None)]})
    d.stop()
    assert w.request() == {"action": "stop", "reason": "shutdown"}


def test_logs_are_content_free(w, caplog, monkeypatch):
    caplog.set_level(logging.DEBUG)
    d = SDY.ServeDuty("node-a", lambda p, b, t: (200, {"req_id": "r1", "body": {"messages": [
        {"role": "user", "content": "CANARY-PROMPT-7741"}]}}) if p == "/nodes/serve/next" else (200, None),
        gate=lambda: None, paused=lambda: False, stage=lambda s: True, model_id_for=lambda s: "m",
        request=w.req, clock=lambda: w.t, health=lambda: True, trusted=_key()[1],
        running_plan=lambda: "sv-1", spawn=lambda fn: fn.__call__ and pending.append(fn))
    pending = []
    monkeypatch.setattr(SC, "forward", lambda body, **kw: (True, {"choices": [{"message": {
        "content": "CANARY-COMPLETION-7741"}}]}))
    d.on_get_job({"serve_plans": [_plan(draft_sha=None)]})
    pending.pop()()                                         # F-2: the background staging finishes
    d.on_get_job({"serve_plans": [_plan(draft_sha=None)]})
    assert d.tick() == "served"
    assert "CANARY" not in caplog.text


# --- the root launcher: SD-a, SD-b, SD-e3 -----------------------------------------------------------------------

def test_launcher_rate_limits_starts_but_never_stops(host):
    m = _stage(host, b"model-bytes")
    assert _run(host, _request(host, {"action": "start", "plan": _plan(model_sha=m, draft_sha=None)})) == "started:sv-1"
    env2 = _plan(model_sha=m, draft_sha=None, plan_id="sv-2", nonce="n-2")
    assert _run(host, _request(host, {"action": "start", "plan": env2})) == "refused:start_rate_limited"
    assert _run(host, _request(host, {"action": "stop", "reason": "owner:active"})) == "stopped:owner:active"
    t = host["tmp"]
    assert oct(os.stat(t / "state" / "last-start").st_mode & 0o777) == "0o600"
    assert SL.run_once(_request(host, {"action": "start", "plan": env2}), "meshembed", state=t / "state",
                       now=NOW + 61, etc=t / "etc", models=t / "models", units=t / "units",
                       systemctl=host["systemctl"], nid="node-a", trusted=_key()[1], gid_of=lambda n: os.getgid(),
                       settings={"threads": 4, "repack_flag": "--no-repack", "memory_max_mb": 6000,
                                 "cpu_quota_pct": 400}) == "started:sv-2"


def test_launcher_burst_of_starts_gives_at_most_one(host):
    m = _stage(host, b"model-bytes")
    codes = [_run(host, _request(host, {"action": "start", "plan": _plan(model_sha=m, draft_sha=None,
                                                                         plan_id=f"sv-{i}", nonce=f"n-{i}")}))
             for i in range(5)]
    assert codes.count("started:sv-0") == 1 and codes[1:] == ["refused:start_rate_limited"] * 4


@pytest.mark.parametrize("kind", ["file", "empty", "dangling_symlink"])
def test_launcher_refuses_start_while_paused_but_stops(host, kind):
    marker = host["tmp"] / "paused"
    if kind == "file":
        marker.write_text("paused by the owner")
    elif kind == "empty":
        marker.write_text("")
    else:
        marker.symlink_to(host["tmp"] / "nowhere")
    m = _stage(host, b"model-bytes")
    req = {"action": "start", "plan": _plan(model_sha=m, draft_sha=None)}
    assert _run(host, _request(host, req), pause_marker=marker) == "refused:node_paused"
    assert host["calls"] == []
    assert _run(host, _request(host, {"action": "stop", "reason": "paused"}), pause_marker=marker) == "stopped:paused"


def test_launcher_refuses_a_hard_linked_staged_model(host, tmp_path):
    m = _stage(host, b"model-bytes")
    os.link(host["home"] / ".meshembed" / "serve-models" / f"{m}.gguf", tmp_path / "second-name")
    code = _run(host, _request(host, {"action": "start", "plan": _plan(model_sha=m, draft_sha=None)}))
    assert code == "refused:model_staging_not_regular_or_not_owned"


def test_launcher_refuses_hard_linked_symlinked_or_oversize_requests(host, tmp_path):
    req = _request(host, {"action": "stop", "reason": "x"})
    os.link(req, tmp_path / "other")
    assert _run(host, req) == "refused:request_not_regular"
    os.unlink(tmp_path / "other")
    req.write_text(json.dumps({"action": "stop", "reason": "x" * 70000})); os.chmod(req, 0o600)
    assert _run(host, req) == "refused:request_too_large"
    req.unlink(); req.symlink_to(tmp_path / "target")
    (tmp_path / "target").write_text('{"action": "stop", "reason": "x"}')
    assert _run(host, req) == "refused:request_unreadable"


def test_a_start_leaves_the_sd_e_dropin_byte_identical(host):
    """CD-1: the launcher writes only 20-owner.conf in the drop-in directory; 10-node.conf is the installer's."""
    t = host["tmp"]
    d = t / "units" / "meshembed-serve-nodraft.service.d"
    d.mkdir()
    sd_e = b"[Unit]\nBindsTo=meshembed-node.service\nAfter=meshembed-node.service\nConditionPathExists=!/etc/meshembed-node/paused\n"
    (d / "10-node.conf").write_bytes(sd_e)
    m = _stage(host, b"model-bytes")
    assert _run(host, _request(host, {"action": "start", "plan": _plan(model_sha=m, draft_sha=None)})) == "started:sv-1"
    assert (d / "10-node.conf").read_bytes() == sd_e
    assert sorted(p.name for p in d.iterdir()) == ["10-node.conf", "20-owner.conf"]


def test_a_planted_symlink_at_the_temp_name_is_not_followed(host, tmp_path):
    t = host["tmp"]
    d = t / "units" / "meshembed-serve-nodraft.service.d"
    d.mkdir()
    victim = tmp_path / "victim"
    victim.write_text("untouched")
    (d / "20-owner.conf.tmp").symlink_to(victim)
    (t / "etc" / "serve.env.tmp").symlink_to(victim)
    m = _stage(host, b"model-bytes")
    assert _run(host, _request(host, {"action": "start", "plan": _plan(model_sha=m, draft_sha=None)})) == "started:sv-1"
    assert victim.read_text() == "untouched"
    assert not (d / "20-owner.conf").is_symlink() and "RuntimeMaxSec" in (d / "20-owner.conf").read_text()


# --- the installers (SD-1, SD-c, SD-e) ----------------------------------------------------------------------------

def _serve_block() -> str:
    s = (ROOT / "install.sh").read_text()
    return s[s.index("install_serve_units() {"):s.index("\n}\n", s.index("install_serve_units() {")) + 3]


def test_install_serve_block_is_opt_in_root_linux_only():
    b = _serve_block()
    first = [ln.strip() for ln in b.splitlines()[2:5]]
    assert first[0] == '[ "${MESHEMBED_ENABLE_SERVE:-0}" = "1" ] || return 0'
    assert first[1].startswith('[ "$(id -u)" -eq 0 ] && [ "$(uname -s)" = Linux ]')
    assert 'install_serve_units "$SVC_USER"' in (ROOT / "install.sh").read_text()


def test_serve_dropin_binds_to_the_daemon_and_refuses_while_paused():
    b = _serve_block()
    for line in ("BindsTo=meshembed-node.service", "After=meshembed-node.service",
                 "ConditionPathExists=!/etc/meshembed-node/paused"):
        assert line in b
    assert "for d in meshembed-serve meshembed-serve-nodraft" in b


def test_serve_launcher_unit_is_hardened_with_a_fixed_argv():
    b = _serve_block()
    unit = b[b.index("meshembed-serve-launch.service << UNIT"):b.index("meshembed-serve-launch.path << UNIT")]
    exec_lines = [ln for ln in unit.splitlines() if ln.startswith("ExecStart")]
    assert exec_lines == ["ExecStart=$v/bin/python -I -m meshembed_node.serve_launch --request "
                          "$h/.meshembed/serve-request --owner $u"]
    for line in ("StartLimitIntervalSec=300", "StartLimitBurst=30", "User=root", "NoNewPrivileges=yes",
                 "PrivateTmp=yes", "ProtectSystem=strict", "ProtectHome=yes", "SystemCallArchitectures=native",
                 "RestrictNamespaces=yes", "LockPersonality=yes"):
        assert line in unit
    assert "EnvironmentFile" not in unit and "/bin/sh" not in unit and "bash -c" not in unit
    # home stays hidden; only the request file (read-write) and the staging dir (read-only) are reachable
    assert "ReadWritePaths=" in unit and "$h/.meshembed/serve-request" in unit and "ReadWritePaths=$h/.meshembed\n" not in unit
    assert "ReadOnlyPaths=$h/.meshembed/serve-models" in unit


def test_mac_and_windows_installers_only_refuse_serve():
    for name in ("install-mac.sh", "install.ps1"):
        s = (ROOT / name).read_text()
        assert "serve: Linux root installs only (serve_linux_only)" in s
        assert "meshembed-serve-launch" not in s and "install_serve_units" not in s


# --- RD-1 (auditor 2026-10-28 15:57Z): idle, the gate reason is reported, never "no_plan" ---------------------------

# worker.GATE_REASONS (the producer: worker._gate_reason, the ServeDuty gate) + the duty's own fail-closed reason
@pytest.mark.parametrize("gate", ["on_battery", "battery_low", "too_hot", "ram_cap", "owner_active", "idle_unknown",
                                  "busy", "gate_unknown"])
def test_rd1_idle_reports_the_gate_reason_never_no_plan(w, gate):
    d = w.duty()
    idle = {"ready": False, "running_plan_id": None}
    assert d.status() == dict(idle, reason="no_plan")                     # idle and ungated: the only "no_plan"
    w.gate = gate
    assert d.status() == dict(idle, reason=gate)
    w.gate = None
    assert d.status() == dict(idle, reason="no_plan")


def test_rd1_idle_and_paused_or_unreadable_reports_paused(w):
    d = w.duty()
    w.paused = True
    assert d.status() == {"ready": False, "reason": "paused", "running_plan_id": None}

    def boom():
        raise OSError("cannot read the marker")
    d.paused = boom
    assert d.status() == {"ready": False, "reason": "paused", "running_plan_id": None}   # cannot tell = paused


def test_f3_the_safety_net_timer_reruns_the_launcher_every_30_s():
    b = _serve_block()
    timer = b[b.index("meshembed-serve-launch.timer << UNIT"):]
    timer = timer[:timer.index("\nUNIT\n")]
    for line in ("OnUnitInactiveSec=30s", "OnBootSec=60s", "Unit=meshembed-serve-launch.service",
                 "WantedBy=timers.target"):
        assert line in timer
    assert "systemctl enable --now meshembed-serve-launch.timer" in b
    # the burst must leave room for the timer's 10 starts per 300 s plus the path triggers (a tripped limit drops STOPs)
    assert "StartLimitBurst=30" in b and "StartLimitIntervalSec=300" in b


# --- F-3b (E3a-1 2026-10-28, auditor GO 16:26Z): ready only for OUR plan, started by the launcher, answering ---------

def test_f3b_todays_case_another_plan_running_is_a_mismatch_and_is_stopped(w):
    d = w.duty()
    d.on_get_job({"serve_plans": [_plan(plan_id="sv-2", nonce="n-2", draft_sha=None)]})
    w.running, w.health = "sv-1", True                     # the launcher runs plan #1; the socket answers
    st = d.status()
    assert st["ready"] is False and st["reason"] == "unit_plan_mismatch" and st["running_plan_id"] == "sv-1"
    assert d.tick() == "stopped:unit_plan_mismatch"
    assert w.request() == {"action": "stop", "reason": "unit_plan_mismatch"} and w.polls == []


def test_f3b_not_started_by_the_launcher_is_never_ready_even_if_a_socket_answers(w):
    d = w.duty()
    d.on_get_job({"serve_plans": [_plan(draft_sha=None)]})
    w.running, w.health = None, True                       # the launcher has not started it (yet)
    assert d.status()["ready"] is False and d.status()["reason"] == "unit_not_answering"
    assert d.tick() == "unit_not_answering" and w.polls == []
    w.running = "sv-1"
    assert d.status()["ready"] is True and d.tick() == "served"


def test_p2_the_unit_gone_with_running_still_naming_our_plan_is_not_ready(w):
    d = w.duty()
    d.on_get_job({"serve_plans": [_plan(draft_sha=None)]})
    w.running, w.health = "sv-1", False                    # RuntimeMaxSec / BindsTo stopped it; running.json stale
    assert d.status()["ready"] is False and d.status()["reason"] == "unit_not_answering"


def test_f3b_the_launcher_record_is_read_strictly(tmp_path):
    p = tmp_path / "running.json"
    assert SDY.launcher_running_plan(p) is None
    for bad in ("{", "[]", '{"plan_id": 7}', '{"plan_id": ""}', '{"plan_id": null}'):
        p.write_text(bad)
        assert SDY.launcher_running_plan(p) is None, bad
    p.write_text('{"plan_id": "sv-1", "unit": "meshembed-serve-nodraft", "at": 1}')
    assert SDY.launcher_running_plan(p) == "sv-1"


# --- F-2: staging never blocks the poll loop ------------------------------------------------------------------------

def _raw(w):
    pending = []
    d = w.duty(spawn=pending.append)
    return d, pending


def test_f2_intake_returns_at_once_and_reports_staging_for_the_plan(w):
    calls = []
    d, pending = _raw(w)
    d.stage = lambda sha: calls.append(sha) or True
    env = _plan(draft_sha=None)
    raw = SDY.ServeDuty.on_get_job.__get__(d)               # the duty's own intake, without the World's helper
    raw({"serve_plans": [env]})
    assert calls == [] and w.request() is None              # nothing staged on the poll thread, no START yet
    assert d.status() == {"ready": False, "reason": "staging", "plan_id": "sv-1", "running_plan_id": None}
    pending.pop()()                                         # the background copy/download finishes
    assert calls == ["a" * 64]
    raw({"serve_plans": [env]})
    assert w.request() == {"action": "start", "plan": env}


def test_f2_a_plan_revoked_during_staging_is_dropped_and_its_file_kept(w):
    d, pending = _raw(w)
    raw = SDY.ServeDuty.on_get_job.__get__(d)
    raw({"serve_plans": [_plan(draft_sha=None)]})
    raw({"serve_plans": []})                                # revoked while staging
    assert d.status() == {"ready": False, "reason": "no_plan", "running_plan_id": None}
    pending.pop()()                                         # the copy completes anyway: the file stays staged
    raw({"serve_plans": [_plan(plan_id="sv-2", nonce="n-2", draft_sha=None)]})
    assert w.request()["plan"]["plan"]["plan_id"] == "sv-2" and pending == []   # same sha: starts at once


def test_f2_a_failed_staging_reports_model_not_staged_then_retries(w):
    d, pending = _raw(w)
    d.stage = lambda sha: False
    raw = SDY.ServeDuty.on_get_job.__get__(d)
    env = _plan(draft_sha=None)
    raw({"serve_plans": [env]})
    pending.pop()()
    raw({"serve_plans": [env]})
    assert d.status()["reason"] == "model_not_staged" and w.request() is None
    raw({"serve_plans": [env]})
    assert len(pending) == 1                                # one new attempt, never a busy loop on the poll thread


# --- Q-1 (auditor 2026-10-28 16:38Z): a leftover unit is converged to stopped -------------------------------------

def test_q1_a_lost_stop_is_rewritten_each_period_until_the_launcher_records_none(w):
    d = w.duty()
    w.running = "sv-1"                                      # no active plan, yet the launcher records a running unit
    assert d.tick() == "stopping_leftover"
    assert w.request() == {"action": "stop", "reason": "stopping_leftover"} and w.polls == []
    assert d.status() == {"ready": False, "reason": "stopping_leftover", "running_plan_id": "sv-1"}
    w.req.write_text("")                                    # the launcher consumed it... and the STOP got lost again
    w.t += SDY.LEFTOVER_STOP_S - 1
    assert d.tick() == "stopping_leftover" and w.request() is None          # not before the period
    w.t += 1
    assert d.tick() == "stopping_leftover" and w.request() == {"action": "stop", "reason": "stopping_leftover"}
    w.running = None                                        # now stopped
    assert d.tick() == "no_plan" and d.status()["reason"] == "no_plan"


def test_q1_a_gate_reason_still_comes_first(w):
    d = w.duty()
    w.running, w.gate = "sv-1", "on_battery"
    assert d.status()["reason"] == "on_battery"
    assert d.tick() == "stopping_leftover"                  # and the leftover is stopped regardless
