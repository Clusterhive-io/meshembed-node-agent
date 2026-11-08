"""SPLIT-SERVE head 4-node part B (docs/DESIGN_SPLIT_SERVE_2026-11-02.md section 4; auditor 2026-11-02 20:09:04Z,
Q-B1..Q-B3, PB-1..PB-5): the ROOT launcher starts a serve split plan's coordinator in two steps. apply() writes
serve-coord.env and starts the one-shot PROBE (-lv 4, a private socket), recording the pending state in its own state
dir (PB-1). A later pass (serve_probe_step) reads the placement ONLY from that invocation's journal (PB-2) and starts
meshembed-di-serve-coord only when the placement is verified, the plan still current, the env file unchanged, the local
stage not restarted and the two units' ExecStart equal but for the verbosity and the socket; the probe is ALWAYS
stopped, and confirmed inactive, before (PB-3). Anything else: the probe stopped, the code recorded, no coordinator."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path

import pytest

from meshembed_node import serve_launch as SL
from meshembed_node import split_launch as L

pytestmark = pytest.mark.unit
FX = Path(__file__).parent / "fixtures"
SERVE = json.loads((FX / "split_plan_serve_golden.json").read_text())
NOW = SERVE["verify_at"]
MEM = {"MemTotal": 16384, "MemAvailable": 12000}
INV, INV2, STAGE_INV = "a" * 32, "b" * 32, ""
# the golden plan: n_layer 48, ngl 25, ts [25]; the coordinator holds 24 KV layers, the one stage (10.44.0.2) 24
LOAD = ["llama_kv_cache:        CPU KV buffer size =    48.00 MiB",
        "llama_kv_cache: RPC0[10.44.0.2:50052] KV buffer size =    48.00 MiB",
        "llama_kv_cache: size =   96.00 MiB (  8192 cells,  48 layers,  2/2 seqs), K (f16):   48.00 MiB"]
WRONG = [LOAD[0].replace("48.00", "52.00"), LOAD[1].replace("48.00", "44.00"), LOAD[2]]
ARGV = ("/srv/mesh-di/bin/llama-server --cache-ram 0 --model ${MODEL} --rpc ${RPC_STAGES} -ngl ${NGL} --tensor-split"
        " ${TS} --fit off{LV} -t ${THREADS} -tb ${THREADS} -c ${CTX} --parallel ${SLOTS} --no-repack --load-mode none"
        " --host {SOCK} --no-webui --no-slots --no-ui-mcp-proxy")


def _execstart(argv: str) -> str:
    """The shape of `systemctl show -p ExecStart --value` (systemd 252/257)."""
    return (f"{{ path=/srv/mesh-di/bin/llama-server ; argv[]={argv} ; ignore_errors=no ; start_time=[n/a] ;"
            " stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }")


PROBE_ES = _execstart(ARGV.replace("{LV}", " --log-verbosity 4").replace("{SOCK}", L.PROBE_SOCK))
COORD_ES = _execstart(ARGV.replace("{LV}", "").replace("{SOCK}", L.SERVE_SOCK))


class Host:
    def __init__(self, tmp: Path):
        self.tmp, self.calls = tmp, []
        self.props = {(L.SERVE_PROBE_UNIT, "InvocationID"): "", (L.SERVE_PROBE_UNIT, "ActiveState"): "inactive",
                      (L.STAGE_UNIT, "InvocationID"): STAGE_INV, (L.SERVE_PROBE_UNIT, "ExecStart"): PROBE_ES,
                      (L.SERVE_COORD_UNIT, "ExecStart"): COORD_ES}
        self.lines = {INV: list(LOAD)}
        self.stop_works = True
        self.next_inv = INV                                  # the id systemd gives the probe's next start
        for d in ("etc", "units", "state", "models"):
            (tmp / d).mkdir()
        for u in (L.SERVE_PROBE_UNIT, L.SERVE_COORD_UNIT):
            (tmp / "units" / f"{u}.service").write_text("[Service]\n")
        m = tmp / "models" / f"{SERVE['envelope']['plan']['model_sha']}.gguf"
        m.write_bytes(b"gguf")
        os.chmod(m, 0o644)

    def systemctl(self, *a):
        self.calls.append(a)
        if a[0] == "stop" and a[-1] == f"{L.SERVE_PROBE_UNIT}.service" and self.stop_works:
            self.props[(L.SERVE_PROBE_UNIT, "ActiveState")] = "inactive"
        if a[0] == "restart" and a[-1] == f"{L.SERVE_PROBE_UNIT}.service":
            assert "--no-block" in a                         # LAUNCH-1: never wait for G2's model hash
            self.props[(L.SERVE_PROBE_UNIT, "InvocationID")] = self.next_inv
            self.props[(L.SERVE_PROBE_UNIT, "ActiveState")] = "activating" if self.next_inv else "inactive"
        if a[0] == "restart" and a[-1] == f"{L.SERVE_COORD_UNIT}.service":
            assert "--no-block" in a

    def show(self, unit, prop):
        return self.props.get((unit, prop), "")

    def journal(self, inv):
        return self.lines.get(inv, [])

    @property
    def state(self):
        return self.tmp / "state"


@pytest.fixture
def host(tmp_path, monkeypatch):
    monkeypatch.setattr(L, "ROOT_UID", os.getuid())
    monkeypatch.setattr(L, "_physical_cores", lambda *a: 8)
    return Host(tmp_path)


def _params(h, **over):
    body = copy.deepcopy(SERVE["envelope"]["plan"])
    p = L.derive(body, "node-coord", {"10.44.0.1"}, h.tmp / "models", own_set=body["runtime_set"])
    p.update(over)
    return p


def _apply(h, params):
    return L.apply(params, NOW, etc=h.tmp / "etc", units=h.tmp / "units", systemctl=h.systemctl,
                   gid_of=lambda n: os.getgid(), state=h.state, meminfo=lambda: MEM, show=h.show)


def _restarted(h, unit):
    return any(a[0] == "restart" and a[-1] == f"{unit}.service" for a in h.calls)


def _started(h):
    """apply() + the launcher's applied.json for the same plan (run_once writes it before apply)."""
    params = _params(h)
    (h.state / "applied.json").write_text(json.dumps({"plan_id": params["plan_id"], "expires_at": params["expires_at"]}))
    assert _apply(h, params) == "serve_probe_started"
    return params


def _step(h, now=NOW + 60):
    return L.serve_probe_step(h.state, now, units=h.tmp / "units", etc=h.tmp / "etc", systemctl=h.systemctl,
                              show=h.show, journal=h.journal)


def _coord_started(h):
    return _restarted(h, L.SERVE_COORD_UNIT)


def test_apply_starts_only_the_probe_and_records_the_pending_state_as_root(host):
    params = _started(host)
    assert _restarted(host, L.SERVE_PROBE_UNIT) and not _coord_started(host)
    assert host.calls[0] == ("stop", f"{L.SERVE_COORD_UNIT}.service")       # a previous coordinator never overlaps
    env = (host.tmp / "etc" / "serve-coord.env").read_text()
    keys = [l.split("=", 1)[0] for l in env.splitlines()]
    assert keys == ["MODEL", "MODEL_SHA_PIN", "RPC_STAGES", "NGL", "TS", "SLOTS", "CTX", "THREADS"]   # = G0 engine
    assert "RPC_STAGES=10.44.0.2:50052\n" in env and "NGL=25\n" in env and "TS=25\n" in env
    assert f"CTX={L.SERVE_COORD_CTX}\n" in env and f"SLOTS={L.SERVE_COORD_SLOTS}\n" in env
    assert "THREADS=6\n" in env and "REPACK" not in env                 # serve_launch's threads; --no-repack in the unit
    assert oct(os.stat(host.tmp / "etc" / "serve-coord.env").st_mode & 0o777) == "0o640"
    drop = (host.tmp / "units" / f"{L.SERVE_PROBE_UNIT}.service.d" / "20-plan.conf").read_text()
    assert "IPAddressAllow=10.44.0.2/32 127.0.0.1" in drop and "MemoryMax=" in drop
    assert "RuntimeMaxSec" not in drop                                     # PB-4: the bound is a unit byte
    pend = json.loads((host.state / "serve-probe.json").read_text())
    assert pend["plan_id"] == params["plan_id"] and pend["invocation"] == INV
    assert pend["env_sha"] == hashlib.sha256(env.encode()).hexdigest()


def test_a_host_without_the_r3_units_is_refused_before_anything_starts(host):
    (host.tmp / "units" / f"{L.SERVE_COORD_UNIT}.service").unlink()
    with pytest.raises(L.Refused, match="serve_units_absent"):
        _apply(host, _params(host))
    assert host.calls == []


def test_a_probe_without_an_invocation_id_is_stopped_and_refused(host, monkeypatch):
    host.next_inv = ""
    slept = []
    monkeypatch.setattr(L.time, "sleep", slept.append)
    with pytest.raises(L.Refused, match="probe_not_started"):
        L.apply(_params(host), NOW, etc=host.tmp / "etc", units=host.tmp / "units", systemctl=host.systemctl,
                gid_of=lambda n: os.getgid(), state=host.state, meminfo=lambda: MEM, show=host.show)
    assert host.calls[-1] == ("stop", f"{L.SERVE_PROBE_UNIT}.service")
    assert not (host.state / "serve-probe.json").exists() and len(slept) == L.PROBE_INV_WAIT_S


def test_nothing_pending_is_a_no_op(host):
    assert _step(host) == "" and host.calls == []


def test_a_loading_probe_is_left_running(host):
    _started(host)
    host.lines[INV] = ["llama_model_loader: loaded meta data"]
    host.calls.clear()
    assert _step(host) == "serve_probe_loading"
    assert host.calls == [] and json.loads((host.state / "serve-probe.json").read_text())["plan_id"]


def test_a_loading_probe_kicks_the_next_pass_soon_and_at_most_three_times(host, monkeypatch):
    """SPLIT-PACE F-P2: bed run 2's probe idled until the NEXT 5-min tick; a loading probe now schedules one bounded kick."""
    kicks = []
    monkeypatch.setattr(L, "kick_runner", kicks.append)
    _started(host)
    host.lines[INV] = ["llama_model_loader: loaded meta data"]
    for _ in range(L.PASSES_PER_START + 2):
        assert _step(host) == "serve_probe_loading"
    assert len(kicks) == L.PASSES_PER_START and all(f"--unit={L.KICK_UNIT}" in k for k in kicks)
    assert json.loads((host.state / "serve-probe.json").read_text())["kicks"] == L.PASSES_PER_START


def test_a_verified_placement_stops_the_probe_first_then_starts_the_coordinator(host):
    params = _started(host)
    host.calls.clear()
    assert _step(host, now=NOW + 60) == "serve_coord_started"
    stop = host.calls.index(("stop", f"{L.SERVE_PROBE_UNIT}.service"))
    assert stop < host.calls.index(("restart", "--no-block", f"{L.SERVE_COORD_UNIT}.service"))
    drop = (host.tmp / "units" / f"{L.SERVE_COORD_UNIT}.service.d" / "20-plan.conf").read_text()
    assert f"RuntimeMaxSec={params['expires_at'] - NOW - 60}\n" in drop and "IPAddressAllow=10.44.0.2/32 127.0.0.1" in drop
    assert json.loads((host.state / "serve-probe.json").read_text()) == {}
    assert json.loads((host.state / "serve-coord.json").read_text())["code"] == "serve_coord_started"
    assert not (host.state / "engine.json").exists()                      # the batch worker never sees it
    assert _step(host) == ""                                              # once


def _break(h, how):
    if how == "revoked":                                                  # housekeeping cleared applied.json
        (h.state / "applied.json").write_text("{}")
    elif how == "superseded":
        (h.state / "applied.json").write_text(json.dumps({"plan_id": "sp-other", "expires_at": NOW + 9000}))
    elif how == "env_changed":
        with open(h.tmp / "etc" / "serve-coord.env", "a") as f:
            f.write("# x\n")
    elif how == "stage_restarted":
        h.props[(L.STAGE_UNIT, "InvocationID")] = "c" * 32
    elif how == "units_differ":
        h.props[(L.SERVE_COORD_UNIT, "ExecStart")] = COORD_ES.replace("--fit off", "--fit on")
    elif how == "mismatch":
        h.lines[INV] = WRONG
    elif how == "ended_unloaded":                                         # PB-4: RuntimeMaxSec passed, no KV lines
        h.lines[INV] = ["llama_model_loader: loaded meta data"]
        h.props[(L.SERVE_PROBE_UNIT, "ActiveState")] = "inactive"
    elif how == "other_invocation":                                       # PB-2: a later run's lines never count
        h.props[(L.SERVE_PROBE_UNIT, "InvocationID")] = INV2
        h.lines = {INV2: list(LOAD)}
    elif how == "did_not_stop":
        h.stop_works = False


@pytest.mark.parametrize("how,code", [
    ("revoked", "serve_plan_not_current"), ("superseded", "serve_plan_not_current"),
    ("env_changed", "serve_env_changed"), ("stage_restarted", "stage_restarted"),
    ("units_differ", "serve_units_differ"), ("mismatch", "placement_mismatch"),
    ("ended_unloaded", "placement_unverified"), ("other_invocation", "placement_unverified"),
    ("did_not_stop", "probe_did_not_stop")])
def test_pb3_any_failed_condition_stops_the_probe_and_never_starts_the_coordinator(host, how, code):
    _started(host)
    _break(host, how)
    host.calls.clear()
    assert _step(host) == f"refused:{code}"
    assert ("stop", f"{L.SERVE_PROBE_UNIT}.service") in host.calls and not _coord_started(host)
    assert json.loads((host.state / "serve-probe.json").read_text()) == {}
    last = json.loads((host.state / "last-result.json").read_text())
    assert (last["result"], last["code"]) == ("refused", code)


def test_pb3_too_little_plan_life_left_is_refused(host):
    params = _started(host)
    assert _step(host, now=params["expires_at"] - L.SERVE_MIN_LIFE_S + 1) == "refused:serve_plan_not_current"
    assert not _coord_started(host)


@pytest.mark.parametrize("probe,coord,ok", [
    (PROBE_ES, COORD_ES, True),
    (COORD_ES, COORD_ES, False),                                          # the probe without -lv 4
    (PROBE_ES, PROBE_ES, False),                                          # the coordinator at -lv 4
    (PROBE_ES.replace("--log-verbosity 4", "--log-verbosity 5"), COORD_ES, False),
    (PROBE_ES, COORD_ES.replace(" --no-slots", ""), False),               # any other difference
    (PROBE_ES, COORD_ES.replace("--parallel", "-v --parallel"), False),
    (PROBE_ES, COORD_ES.replace(L.SERVE_SOCK, L.PROBE_SOCK), False),      # the coordinator on the probe's socket
    (PROBE_ES.replace(L.PROBE_SOCK, L.SERVE_SOCK), COORD_ES, False),      # the probe on serve.sock
    ("", COORD_ES, False), (PROBE_ES, "garbage", False)])
def test_q_b2_the_two_execstart_lines_may_differ_only_in_the_verbosity_and_the_socket(probe, coord, ok):
    assert L.argv_pair_ok(probe, coord) is ok


def test_run_once_runs_the_step_every_pass_even_without_a_request(host):
    """The 5-minute timer pass (and every path-triggered pass) advances a pending probe."""
    import pwd
    seen = []
    out = L.run_once(host.tmp / "no-request", pwd.getpwuid(os.getuid()).pw_name, state=host.state, now=NOW,
                     ready=(False, "x"), overlay=object(),
                     probe_step=lambda st, now: seen.append(now) or "serve_probe_loading")
    assert seen == [NOW] and out == "serve_probe_loading"


def test_a_revocation_stops_the_probe_and_the_coordinator_too(host):
    calls = []
    L._stop_units(lambda *a: calls.append(a))
    assert ("stop", f"{L.SERVE_PROBE_UNIT}.service") in calls and ("stop", f"{L.SERVE_COORD_UNIT}.service") in calls


def test_the_coordinator_context_and_slots_equal_what_the_backend_sizes_the_shares_for():
    """A serve split plan signs no ctx/slots: the launcher's host constants must be the backend's SERVE_CTX/SERVE_SLOTS,
    or the coordinator would run a larger KV than its signed share (read as text: no backend import in node tests)."""
    import re
    src = (Path(__file__).resolve().parents[2] / "backend" / "app" / "serve_warmset.py").read_text()
    m = re.search(r"^SERVE_CTX, SERVE_SLOTS = (\d+), (\d+)$", src, re.M)
    assert m and (int(m.group(1)), int(m.group(2))) == (L.SERVE_COORD_CTX, L.SERVE_COORD_SLOTS)


def test_the_launcher_pass_the_backend_grace_assumes_is_the_installers_timer():
    """PB-5: the backend's serve grace adds one launcher pass (300 s): the timer the Linux installer writes."""
    src = (Path(__file__).resolve().parents[2] / "node-agent" / "install.sh").read_text()
    assert "OnUnitActiveSec=5min" in src


@pytest.mark.parametrize("cores", [1, 2, 3, 4, 8, 16, 64])
def test_the_coordinator_threads_follow_the_serve_units_rule(cores):
    assert L.serve_threads(cores) == SL.host_settings(cores, MEM)["threads"]


def test_the_physical_core_count_is_the_serve_launchers(tmp_path):
    for i, (pkg, core) in enumerate([(0, 0), (0, 0), (0, 1), (1, 0)]):
        t = tmp_path / f"cpu{i}" / "topology"
        t.mkdir(parents=True)
        (t / "physical_package_id").write_text(f"{pkg}\n")
        (t / "core_id").write_text(f"{core}\n")
    assert L._physical_cores(tmp_path) == SL.physical_cores(tmp_path) == 3


@pytest.mark.parametrize("how", ["revoked", "expired"])
def test_a_torn_down_plan_leaves_no_serve_coord_env_or_plan_drop_ins(host, how):
    """auditor 21:04:05Z LOW: defence in depth -- a stale env file can never start a coordinator later."""
    params = _started(host)
    d = host.tmp / "units" / f"{L.SERVE_COORD_UNIT}.service.d"
    d.mkdir(exist_ok=True)
    (d / "20-plan.conf").write_text("[Service]\n")
    revoke = host.tmp / "split-revoke"
    revoke.write_text(json.dumps({"plan_id": params["plan_id"]}))
    os.chmod(revoke, 0o600)

    class Ovl:
        def teardown(self):
            pass
    now = NOW if how == "revoked" else params["expires_at"] + 1
    cache = host.tmp / "cache"
    cache.mkdir()
    out = L.housekeeping(host.state, revoke, os.getuid(), now, Ovl(), systemctl=host.systemctl, cache_root=cache,
                         etc=host.tmp / "etc", units=host.tmp / "units")
    assert out == f"{how}_torn_down"
    assert not (host.tmp / "etc" / "serve-coord.env").exists()
    for u in (L.SERVE_PROBE_UNIT, L.SERVE_COORD_UNIT):
        assert not (host.tmp / "units" / f"{u}.service.d" / "20-plan.conf").exists()


def test_launch_1_the_old_invocation_id_never_counts_as_the_new_probe(host, monkeypatch):
    """A restart that did not start yet still shows the PREVIOUS run's id: it must not be recorded as this probe's."""
    host.props[(L.SERVE_PROBE_UNIT, "InvocationID")] = INV2
    host.next_inv = INV2
    monkeypatch.setattr(L.time, "sleep", lambda s: None)
    with pytest.raises(L.Refused, match="probe_not_started"):
        _apply(host, _params(host))


@pytest.mark.parametrize("unit", L.WHOLE_SERVE_UNITS)
@pytest.mark.parametrize("state", ["active", "activating"])
def test_ds1_no_probe_while_a_whole_model_plan_runs(host, unit, state):
    host.props[(unit, "ActiveState")] = state
    with pytest.raises(L.Refused, match="whole_serve_active"):
        _apply(host, _params(host))
    assert not _restarted(host, L.SERVE_PROBE_UNIT)


def test_ds1_no_coordinator_start_while_a_whole_model_plan_runs(host):
    _started(host)
    host.props[(L.WHOLE_SERVE_UNITS[1], "ActiveState")] = "active"
    host.calls.clear()
    assert _step(host) == "refused:whole_serve_active" and not _coord_started(host)


def test_a_new_probe_clears_a_stale_coordinator_record(host):
    (host.state / "serve-coord.json").write_text(json.dumps({"plan_id": "sp-old", "code": "serve_coord_started"}))
    _started(host)
    assert json.loads((host.state / "serve-coord.json").read_text()) == {}


def test_ds1_the_serve_launcher_names_the_split_units_as_split_launch_does():
    assert SL.SPLIT_SERVE_UNITS == (L.SERVE_PROBE_UNIT, L.SERVE_COORD_UNIT)
    assert L.WHOLE_SERVE_UNITS == (SL.UNIT, SL.UNIT_NODRAFT)


@pytest.mark.parametrize("unit", SL.SPLIT_SERVE_UNITS)
def test_ds1_the_serve_launcher_refuses_a_whole_start_while_a_split_unit_runs(tmp_path, unit):
    (tmp_path / f"{unit}.service").write_text("[Service]\n")
    assert SL._split_serve_active(tmp_path, lambda u: u == unit) is True
    assert SL._split_serve_active(tmp_path, lambda u: False) is False

    def broken(u):
        raise OSError("no systemctl")
    assert SL._split_serve_active(tmp_path, broken) is True               # cannot tell = active (fail closed)


def test_ds1_a_host_without_the_split_units_never_asks_systemd(tmp_path):
    def must_not_run(u):
        raise AssertionError("asked systemd about a unit that is not installed")
    assert SL._split_serve_active(tmp_path, must_not_run) is False


def test_teardown_stops_the_consumers_before_their_stage_and_logs_the_known_exit(capsys):
    # ABRT-CORE (auditor 2026-11-03 13:58:00Z item 4): llama-server aborts on SIGTERM once its RPC peer is gone, so the
    # coordinator and the probe go FIRST, the stage LAST; a status-6 exit that still happens is logged as known
    calls = []
    L._stop_units(lambda *a: calls.append(a), show=lambda u, p: "6" if u == L.SERVE_COORD_UNIT else "0")
    order = [c[1] for c in calls]
    assert order == [f"{L.SERVE_COORD_UNIT}.service", f"{L.SERVE_PROBE_UNIT}.service", f"{L.ENGINE_UNIT}.service",
                     f"{L.STAGE_UNIT}.service"]
    assert "serve_coord_exit_6_known" in capsys.readouterr().out
    L._stop_units(lambda *a: None, show=lambda u, p: "0")                 # a clean exit: no such line
    assert "serve_coord_exit_6_known" not in capsys.readouterr().out
