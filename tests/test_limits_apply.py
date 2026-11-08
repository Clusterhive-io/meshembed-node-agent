"""IO-CAP: the root limits applier (docs/DESIGN_IO_CAP_2026-10-31.md; auditor DESIGN GO 2026-10-31 17:35Z, IC-1..IC-5,
IC-7; early read 18:56Z IOA-1..IOA-6, N2, N3). Unit tests on temp dirs with a fake systemd (it lists a unit's sources
the way systemd does and answers the readback from the runtime properties it was given); the real-systemd proof
(systemctl show before and after a daemon-reload and a serve restart) is a separate container run."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import subprocess
import threading
import time
from pathlib import Path

import pytest

from meshembed_node import limits_apply as LA
from meshembed_node import split_launch

pytestmark = pytest.mark.unit

NOW = 1_800_000_000.0
MiB = 1 << 20
DEVS = {"/dev/sda": "8:0", "/dev/sdb": "8:16"}


class FakeSystemd:
    """FragmentPath + DropInPaths as systemd orders them (prefix 'meshembed-.service.d', type 'service.d' and the
    unit's own .d, merged and sorted by file name), and the --runtime properties for the readback."""

    def __init__(self, units: Path):
        self.units, self.calls, self.runtime, self.override = units, [], {}, {}

    def systemctl(self, *a):
        self.calls.append(a)
        if a[:2] == ("set-property", "--runtime"):
            unit, rt = a[2][:-len(".service")], {}
            for arg in a[3:]:
                k, _, v = arg.partition("=")
                if LA.PROPS_KIND[k] == "dev":
                    rt[k] = [] if v == "" else rt.get(k, []) + [v]
                else:
                    rt[k] = v
            self.runtime[unit] = rt

    def show(self, unit, props):
        if "FragmentPath" in props:
            frag = self.units / f"{unit}.service"
            if not frag.is_file():
                return {"FragmentPath": [""], "DropInPaths": [""]}
            drop = {}
            for d in (self.units / "meshembed-.service.d", self.units / "service.d", self.units / f"{unit}.service.d"):
                if d.is_dir():
                    for f in d.iterdir():
                        if f.suffix == ".conf":
                            drop.setdefault(f.name, f)
            return {"FragmentPath": [str(frag)], "DropInPaths": [" ".join(str(drop[n]) for n in sorted(drop))]}
        rt = dict(self.runtime.get(unit, {}), **self.override.get(unit, {}))
        out = {}
        for p in props:
            if p == "CPUQuotaPerSecUSec":
                v = rt.get("CPUQuota", "")
                out[p] = [f"{int(v[:-1]) * 10_000}us" if v else "infinity"]
            elif p in ("MemoryMax", "MemoryHigh"):
                v = rt.get(p, "")
                out[p] = [str(int(v[:-1]) * MiB) if v.endswith("M") else "infinity"]
            elif LA.PROPS_KIND.get(p) == "dev":
                out[p] = rt.get(p, [])
            else:
                out[p] = [rt.get(p, "")]
        return out


@pytest.fixture
def h(tmp_path, monkeypatch):
    import pwd
    me = pwd.getpwuid(os.getuid())
    monkeypatch.setattr(split_launch, "ROOT_UID", os.getuid())
    monkeypatch.setattr(LA, "ROOT_UID", os.getuid())
    home = tmp_path / "home"; (home / ".meshembed").mkdir(parents=True)
    monkeypatch.setattr(LA.pwd, "getpwnam", lambda n: type("P", (), {"pw_uid": me.pw_uid, "pw_dir": str(home)})())
    units = tmp_path / "units"; units.mkdir()
    for u in ("meshembed-node", "meshembed-serve"):
        (units / f"{u}.service").write_text("[Service]\nExecStart=/bin/true\n")
    for d in ("state", "models", "etc", "cg"):
        (tmp_path / d).mkdir()
    return {"tmp": tmp_path, "home": home, "units": units, "sd": FakeSystemd(units)}


def _req(h, limits):
    p = h["home"] / ".meshembed" / "limits-request"
    p.write_text(json.dumps({"limits": limits})); os.chmod(p, 0o600)
    return p


def _kw(h):
    t = h["tmp"]
    return dict(state=t / "state", units_dir=h["units"], systemctl=lambda *a: h["sd"].systemctl(*a),
                show=lambda u, p: h["sd"].show(u, p), local_path=t / "etc" / "limits.local", models=t / "models",
                serve_env=t / "etc" / "serve.env", cgroup_root=t / "cg", disk_of_fn=lambda p: "8:0",
                dev_of=DEVS.get, weight_ok_fn=lambda d: True)


def _go(h, limits=None, *, now=NOW, serve_floor=True, **kw):
    t = h["tmp"]
    if serve_floor:
        m = t / "models" / ("a" * 64 + ".gguf")
        m.write_bytes(b"x" * 1024)
        (t / "etc" / "serve.env").write_text(f"MODEL={m}\n")
    req = _req(h, limits) if limits is not None else h["home"] / ".meshembed" / "limits-request"
    return LA.run(req, "meshembed", now=now, **{**_kw(h), **kw})


def _reconcile(h, now):
    return LA.reconcile("meshembed", now=now, **_kw(h))


def _dropin(h, unit):
    return (h["units"] / f"{unit}.service.d" / LA.DROPIN).read_text()


def _result(h):
    return json.loads((h["tmp"] / "state" / "result.json").read_text())


def _runtime(h, unit):
    return [c for c in h["sd"].calls if c[:3] == ("set-property", "--runtime", f"{unit}.service")]


def _owner_dropin(h, unit="meshembed-serve", text="MemoryMax=6000M\nCPUQuota=400%\n", name="20-owner.conf"):
    d = h["units"] / f"{unit}.service.d"; d.mkdir(exist_ok=True)
    (d / name).write_text("[Service]\n" + text)
    return d / name


# --- the request (IC-4) and the floors (Q1) ----------------------------------------------------------------------------
def test_the_186_freeze_values_are_refused_twice_and_nothing_is_capped():
    want, refused = LA.parse_request({"limits": {"io_read_mbps": 1, "io_read_iops": 60}})
    assert want == {} and refused == {"io_read_mbps": "below_floor", "io_read_iops": "below_floor"}


def test_the_compiled_in_floors_are_the_backend_fixed_floors():
    assert LA.FLOOR == {"io_read_mbps": 20, "io_read_iops": 200, "io_write_mbps": 10, "io_write_iops": 100,
                        "cpu_quota_pct": 25}


@pytest.mark.parametrize("bad", [[], {"limits": {}, "x": 1}, {"limits": {"gpu_indices": [0]}}, {"limits": "x"}])
def test_a_malformed_envelope_is_refused_whole(bad):
    with pytest.raises(split_launch.Refused):
        LA.parse_request(bad)


def test_values_are_canonical_and_checked():
    want, refused = LA.parse_request({"limits": {"io_read_mbps": 50, "io_class": "idle", "memory_max_gb": 8,
                                                 "memory_high_gb": 9, "cpu_quota_pct": True, "io_write_iops": 20.5}})
    assert want == {"io_read_mbps": 50 << 20, "io_class": 10, "memory_max_gb": 8192}
    assert refused == {"memory_high_gb": "above_memory_max", "cpu_quota_pct": "invalid", "io_write_iops": "invalid"}


def test_a_symlinked_request_is_refused(h):
    target = h["tmp"] / "elsewhere"; target.write_text('{"limits": {}}')
    (h["home"] / ".meshembed" / "limits-request").symlink_to(target)
    assert _go(h) == "refused:request_unreadable"


# --- IC-1: never looser than any other source ---------------------------------------------------------------------------
def test_a_larger_memory_max_than_20_owner_keeps_the_owner_value(h):
    owner = _owner_dropin(h)
    before = owner.read_bytes()
    assert _go(h, {"memory_max_gb": 8}) == "applied"
    assert "MemoryMax=6000M" in _dropin(h, "meshembed-serve")
    assert "MemoryMax=6000M" in _runtime(h, "meshembed-serve")[-1]
    assert owner.read_bytes() == before                                  # never another file (IC-2)
    assert sorted(p.name for p in owner.parent.iterdir()) == ["20-owner.conf", LA.DROPIN]


def test_a_tighter_request_wins(h):
    _owner_dropin(h)
    _go(h, {"memory_max_gb": 4, "cpu_quota_pct": 200})
    t = _dropin(h, "meshembed-serve")
    assert "MemoryMax=4096M" in t and "CPUQuota=200%" in t


def test_a_hand_made_bandwidth_cap_is_never_loosened(h):
    _owner_dropin(h, "meshembed-node", "IOReadBandwidthMax=/dev/sda 50M\n")
    _go(h, {"io_read_mbps": 200})
    # IOP-2: systemd reads a bandwidth "50M" to the base of 1000 (50000000), not 50 MiB
    assert "IOReadBandwidthMax=/dev/block/8:0 50000000" in _dropin(h, "meshembed-node")


def test_ioa1_another_devices_hand_cap_survives_the_apply_and_the_clear(h):
    _owner_dropin(h, "meshembed-node", "IOReadBandwidthMax=/dev/sdb 50M\n", name="50-hand.conf")   # the 186 kind
    _go(h, {"io_read_mbps": 100})                                                                # data disk 8:0
    args = _runtime(h, "meshembed-node")[-1]
    assert "IOReadBandwidthMax=/dev/block/8:16 50000000" in args                     # IOP-2: base 1000
    assert f"IOReadBandwidthMax=/dev/block/8:0 {100 << 20}" in args
    _go(h, {}, now=NOW + 120)                                                                     # clear
    args = _runtime(h, "meshembed-node")[-1]
    assert "IOReadBandwidthMax=/dev/block/8:16 50000000" in args and not any("8:0 " in a for a in args)


def test_ioa3_a_tighter_prefix_drop_in_is_honoured(h):
    d = h["units"] / "meshembed-.service.d"; d.mkdir()
    (d / "10-mine.conf").write_text("[Service]\nMemoryMax=4G\n")
    _go(h, {"memory_max_gb": 8})
    assert "MemoryMax=4096M" in _dropin(h, "meshembed-node") and "MemoryMax=4096M" in _dropin(h, "meshembed-serve")


@pytest.mark.parametrize("legacy,key,value", [("MemoryLimit=4G", "memory_max_gb", 8),
                                              ("BlockIOReadBandwidth=/dev/sda 10M", "io_read_mbps", 100)])
def test_ioa3_a_legacy_key_makes_its_family_unreadable(h, legacy, key, value):
    _owner_dropin(h, "meshembed-node", legacy + "\n", name="10-old.conf")
    _go(h, {key: value})
    assert LA.PROPS[key][0] + "=" not in _dropin(h, "meshembed-node")
    assert _result(h)["refused"][key] == "existing_unreadable"


def test_an_unreadable_existing_value_is_not_set(h):
    _owner_dropin(h, "meshembed-serve", "MemoryMax=50%\n")
    _go(h, {"memory_max_gb": 4, "io_class": "low"})
    assert "MemoryMax" not in _dropin(h, "meshembed-serve")
    assert _result(h)["refused"]["memory_max_gb"] == "existing_unreadable"


def test_ioa4_a_source_turning_unreadable_keeps_the_previous_value_never_a_bad_arg(h):
    _go(h, {"cpu_quota_pct": 200})
    _owner_dropin(h, "meshembed-node", "CPUQuota=lots\n", name="30-x.conf")
    assert _go(h, {}, now=NOW + 120) == "applied"
    args = _runtime(h, "meshembed-node")[-1]
    assert "CPUQuota=200%" in args and not any("lots" in a for a in args)
    assert _result(h)["refused"]["cpu_quota_pct"] == "existing_unreadable"


def test_systemd_unable_to_list_the_sources_sets_nothing(h):
    _go(h, {"cpu_quota_pct": 200}, show=lambda unit, props: None)
    assert "CPUQuota" not in _dropin(h, "meshembed-node")
    assert _result(h)["refused"]["cpu_quota_pct"] == "existing_unreadable"


# --- limits.local (Q2, IOA-5) --------------------------------------------------------------------------------------------
def test_limits_local_bounds_the_request(h):
    loc = h["tmp"] / "etc" / "limits.local"
    loc.write_text(json.dumps({"cpu_quota_pct": 100})); os.chmod(loc, 0o644)
    _go(h, {"cpu_quota_pct": 400})
    assert "CPUQuota=100%" in _dropin(h, "meshembed-node")


def test_ioa5_a_bad_limits_local_blocks_loosening_never_tightening(h):
    _go(h, {"cpu_quota_pct": 200})
    loc = h["tmp"] / "etc" / "limits.local"
    loc.write_text(json.dumps({"cpu_quota_pct": 100})); os.chmod(loc, 0o666)      # group/world writable: invalid
    assert _go(h, {"cpu_quota_pct": 50}, now=NOW + 120) == "applied"               # an emergency tighten applies
    assert "CPUQuota=50%" in _dropin(h, "meshembed-node")
    _go(h, {"cpu_quota_pct": 400}, now=NOW + 300)                                  # a loosening is refused
    assert "CPUQuota=50%" in _dropin(h, "meshembed-node")
    assert _result(h)["refused"]["cpu_quota_pct"] == "limits_local_invalid"


# --- IC-2: clearing a key sets the value in force from the other sources -----------------------------------------------
def test_clearing_a_key_restores_the_20_owner_value_at_runtime(h):
    _owner_dropin(h)
    _go(h, {"cpu_quota_pct": 200})
    _go(h, {}, now=NOW + 120)
    assert "CPUQuota" not in _dropin(h, "meshembed-serve")
    assert "CPUQuota=400%" in _runtime(h, "meshembed-serve")[-1]     # never a bare reset hiding 20-owner.conf


def test_the_drop_in_is_written_before_the_runtime_property_and_sorts_last(h):
    seen = []
    sd = h["sd"]
    orig = sd.systemctl
    sd.systemctl = lambda *a: (seen.append((a[0], (h["units"] / "meshembed-node.service.d" / LA.DROPIN).exists())),
                               orig(*a))
    _go(h, {"cpu_quota_pct": 200})
    assert seen.index(("daemon-reload", True)) < seen.index(("set-property", True))
    assert LA.DROPIN == "99-limits.conf"


def test_n3_an_unchanged_pass_writes_nothing_and_sets_nothing(h):
    _go(h, {"cpu_quota_pct": 200})
    n = len(h["sd"].calls)
    f = h["units"] / "meshembed-node.service.d" / LA.DROPIN
    mtime = f.stat().st_mtime_ns
    _go(h, {"cpu_quota_pct": 200}, now=NOW + 120)
    assert h["sd"].calls[n:] == [] and f.stat().st_mtime_ns == mtime


def test_n3_a_value_overridden_after_the_apply_is_never_reported_in_force(h):
    h["sd"].override["meshembed-node"] = {"CPUQuota": "800%"}      # someone else's runtime property wins
    _go(h, {"cpu_quota_pct": 200})
    r = _result(h)
    assert r["refused"]["cpu_quota_pct"] == "overridden" and "cpu_quota_pct" not in r["in_force"]


# --- IC-3 / IOA-2: the memory floors ----------------------------------------------------------------------------------------
@pytest.mark.parametrize("key", ["memory_max_gb", "memory_high_gb"])
def test_memory_caps_below_the_node_minimum_or_live_usage_are_refused(h, key):
    _go(h, {key: 1})
    assert _result(h)["refused"][key] == "below_floor"
    cg = h["tmp"] / "cg" / "system.slice" / "meshembed-node.service"; cg.mkdir(parents=True)
    (cg / "memory.current").write_text(str(3800 << 20))
    _go(h, {key: 4}, now=NOW + 120)                                   # 4096 < 3800 + 512
    assert _result(h)["refused"][key] == "below_current_usage"


def test_ioa2_a_tiny_memory_high_never_reaches_a_unit(h):
    _go(h, {"memory_high_gb": 0.001})
    assert "MemoryHigh" not in _dropin(h, "meshembed-node") and "MemoryHigh" not in _dropin(h, "meshembed-serve")


def test_a_serve_memory_floor_needs_the_root_owned_model_files(h):
    _go(h, {"memory_max_gb": 4}, serve_floor=False)
    assert "MemoryMax" not in _dropin(h, "meshembed-serve")           # no serve.env: the floor is unknown
    assert _result(h)["refused"]["memory_max_gb"] == "floor_unknown"


# --- IC-5 / IOA-6: the device -------------------------------------------------------------------------------------------
def test_an_unresolvable_disk_caps_nothing(h):
    _go(h, {"io_read_mbps": 50, "io_class": "idle"}, disk_of_fn=lambda p: None, weight_ok_fn=lambda d: bool(d))
    r = _result(h)
    assert r["refused"] == {"io_read_mbps": "device_unresolved", "io_class": "not_effective"} and r["in_force"] == []


def test_ioa6_io_class_without_bfq_or_iocost_is_not_effective(h, tmp_path):
    _go(h, {"io_class": "idle"}, weight_ok_fn=lambda d: False)
    assert "IOWeight" not in _dropin(h, "meshembed-node") and _result(h)["refused"]["io_class"] == "not_effective"
    sb = tmp_path / "sb"; (sb / "8:0" / "queue").mkdir(parents=True)
    (sb / "8:0" / "queue" / "scheduler").write_text("[mq-deadline] bfq none\n")
    assert LA.weight_effective(["8:0"], sys_block=sb, cgroup_root=tmp_path / "nocg") is False
    (sb / "8:0" / "queue" / "scheduler").write_text("mq-deadline [bfq] none\n")
    assert LA.weight_effective(["8:0"], sys_block=sb, cgroup_root=tmp_path / "nocg") is True
    (sb / "8:0" / "queue" / "scheduler").write_text("[none]\n")
    cg = tmp_path / "cg2"; cg.mkdir(); (cg / "io.cost.qos").write_text("8:0 enable=1 ctrl=auto rpct=0.00\n")
    assert LA.weight_effective(["8:0"], sys_block=sb, cgroup_root=cg) is True


def test_a_virtual_filesystem_has_no_disk():
    assert LA.disk_of(Path("/proc")) is None


# --- loosening: rate-limited when the request asks, never on a reconcile (N2) ------------------------------------------
def test_a_second_loosening_within_60_s_is_parked_and_applied_later(h):
    _go(h, {"cpu_quota_pct": 100})
    assert _go(h, {"cpu_quota_pct": 200}, now=NOW + 10) == "applied"                   # one loosening per 60 s
    assert _go(h, {"cpu_quota_pct": 400}, now=NOW + 20) == "parked:loosen_rate_limited"
    assert "CPUQuota=200%" in _dropin(h, "meshembed-node")
    assert (h["tmp"] / "state" / "pending.json").exists()
    assert _go(h, {"cpu_quota_pct": 50}, now=NOW + 30) == "applied"                    # tightening: at once
    assert "CPUQuota=50%" in _dropin(h, "meshembed-node")
    _go(h, {"cpu_quota_pct": 400}, now=NOW + 200)
    assert "CPUQuota=400%" in _dropin(h, "meshembed-node")


def test_iob6_a_parked_loosening_names_the_cap_still_in_force(h):
    _go(h, {"cpu_quota_pct": 100, "memory_max_gb": 8})
    assert _go(h, {"cpu_quota_pct": 200, "memory_max_gb": 8}, now=NOW + 10) == "applied"
    # a CLEAR inside the 60 s: both caps stay; the result says so (refused loosen_parked), never "nothing in force"
    assert _go(h, {}, now=NOW + 20) == "parked:loosen_rate_limited"
    r = _result(h)
    assert r["in_force"] == [] and r["refused"] == {"cpu_quota_pct": "loosen_parked", "memory_max_gb": "loosen_parked"}
    assert r["request_sha256"] == LA.request_sha256({"limits": {}})
    assert "CPUQuota=200%" in _dropin(h, "meshembed-node") and "MemoryMax=8192M" in _dropin(h, "meshembed-node")
    _go(h, now=NOW + 200)                                                  # the timer re-runs the parked clear
    r = _result(h)
    assert r["result"] == "applied" and r["in_force"] == [] and r["refused"] == {}
    assert "CPUQuota" not in _dropin(h, "meshembed-node") and "MemoryMax" not in _dropin(h, "meshembed-node")


def test_n2_a_root_side_loosening_is_not_rate_limited_and_a_parked_one_is_never_replayed(h):
    _owner_dropin(h, text="MemoryMax=6000M\n")
    _go(h, {"memory_max_gb": 10})
    _owner_dropin(h, text="MemoryMax=8000M\n")                          # the serve launcher's next plan: looser
    assert _reconcile(h, NOW + 5) == "applied"                          # within 60 s: not rate-limited
    assert "MemoryMax=8000M" in _dropin(h, "meshembed-serve")
    assert _go(h, {"memory_max_gb": 9}, now=NOW + 10) == "applied"      # a tightening (counts no loosening)
    assert _go(h, {"memory_max_gb": 10}, now=NOW + 15) == "applied"     # the request's one loosening
    assert _go(h, {"memory_max_gb": 12}, now=NOW + 20) == "parked:loosen_rate_limited"
    _owner_dropin(h, text="MemoryMax=20000M\n")
    _reconcile(h, NOW + 25)
    assert "MemoryMax=10240M" in _dropin(h, "meshembed-serve")         # the parked 12 GB is not applied by it


# --- IC-7: the report -----------------------------------------------------------------------------------------------------
def test_the_result_is_readable_by_the_daemon_and_closed(h):
    _go(h, {"io_class": "low", "io_read_mbps": 1})
    p = h["tmp"] / "state" / "result.json"
    assert oct(p.stat().st_mode & 0o777) == "0o644"
    r = json.loads(p.read_text())
    assert r["in_force"] == ["io_class"] and r["refused"] == {"io_read_mbps": "below_floor"} and r["result"] == "applied"


def test_reconcile_reloads_first_and_reapplies_the_last_request_against_a_new_20_owner(h):
    _owner_dropin(h, text="MemoryMax=12000M\n")
    _go(h, {"memory_max_gb": 10})
    assert "MemoryMax=10240M" in _dropin(h, "meshembed-serve")
    _owner_dropin(h, text="MemoryMax=6000M\n")                         # the serve launcher's next plan
    n = len(h["sd"].calls)
    assert _reconcile(h, NOW + 5) == "applied"
    assert h["sd"].calls[n] == ("daemon-reload",)
    assert "MemoryMax=6000M" in _dropin(h, "meshembed-serve") and "MemoryMax=6000M" in _runtime(h, "meshembed-serve")[-1]


# --- the serve launcher reconciles before it restarts (IC-1: "before and after a serve restart") ------------------------
from test_serve_mvp import _key, _plan, _request, _stage, host  # noqa: E402,F401  (the launcher fixture)


def _serve(host, rec):
    from meshembed_node import serve_launch as SL
    _, trust = _key()
    t = host["tmp"]
    m = _stage(host, b"model-bytes")
    req = _request(host, {"action": "start", "plan": _plan(plan_id="sv-L", nonce="n-L", model_sha=m, draft_sha=None)})
    return SL.run_once(req, "meshembed", state=t / "state", now=NOW_SERVE, etc=t / "etc", models=t / "models",
                       units=t / "units", systemctl=host["systemctl"], nid="node-a", trusted=trust,
                       gid_of=lambda name: os.getgid(), limits_reconcile=rec,
                       settings={"threads": 4, "repack_flag": "--no-repack", "memory_max_mb": 6000,
                                 "cpu_quota_pct": 400})


from test_serve_mvp import NOW as NOW_SERVE  # noqa: E402


def test_the_serve_launcher_reconciles_after_20_owner_and_before_the_restart(host):
    seen = []

    def rec():
        owner = host["tmp"] / "units" / "meshembed-serve-nodraft.service.d" / "20-owner.conf"
        seen.append(("reconcile", owner.exists(), [c[0] for c in host["calls"]]))
        return "applied"
    assert _serve(host, rec).startswith("started:")
    assert seen and seen[0][1] is True and "restart" not in seen[0][2]           # new 20-owner, not yet restarted


def test_a_failed_reconcile_refuses_the_start_rather_than_loosen(host):
    assert _serve(host, lambda: "systemctl_failed") == "refused:limits_reconcile_failed"
    assert not any(c[0] == "restart" for c in host["calls"])


# --- IOB-1: the reconcile runs in its OWN unit, bound to this pass (IOB-1a..IOB-1c) --------------------------------------
def _sl():
    from meshembed_node import serve_launch as SL
    return SL


def _limits_result(path, unit, dropin, text, result="applied"):
    path.write_text(json.dumps({"result": result, "at": 1, "in_force": [], "refused": {},
                                "sources": {unit: {str(dropin): hashlib.sha256(text.encode()).hexdigest()}}}))


def _installed(units):
    units.mkdir(exist_ok=True)
    (units / "meshembed-limits-reconcile.service").write_text("[Service]\n")


def test_iob1_no_applier_installed_means_nothing_to_reconcile(tmp_path):
    starts = []
    code = _sl().limits_reconcile_via_unit("meshembed-serve", tmp_path / "x.conf", "t", units=tmp_path,
                                           result=tmp_path / "r.json", start=lambda: starts.append(1))
    assert code == "not_installed" and starts == []


def test_iob1a_a_pass_that_read_the_new_20_owner_is_accepted(tmp_path):
    _installed(tmp_path)
    dropin, res, starts = tmp_path / "meshembed-serve.service.d" / "20-owner.conf", tmp_path / "r.json", []

    def start():
        starts.append(1)
        _limits_result(res, "meshembed-serve", dropin, "NEW")
    assert _sl().limits_reconcile_via_unit("meshembed-serve", dropin, "NEW", units=tmp_path, result=res,
                                           start=start) == "applied"
    assert starts == [1]


def test_iob1a_a_joined_pass_that_read_the_old_drop_in_starts_once_more(tmp_path):
    _installed(tmp_path)
    dropin, res, seen = tmp_path / "meshembed-serve.service.d" / "20-owner.conf", tmp_path / "r.json", []

    def start():                                     # 1st: joined a pass that began before the write; 2nd: fresh
        seen.append(1)
        _limits_result(res, "meshembed-serve", dropin, "OLD" if len(seen) == 1 else "NEW")
    assert _sl().limits_reconcile_via_unit("meshembed-serve", dropin, "NEW", units=tmp_path, result=res,
                                           start=start) == "applied"
    assert len(seen) == 2


def test_iob1a_two_unbound_passes_refuse_the_start(host):
    t = host["tmp"]
    _installed(t / "units")
    res, starts = t / "limits-result.json", []

    def rec():
        def start():
            starts.append(1)
            _limits_result(res, "meshembed-serve-nodraft", t / "units" / "x.conf", "other")   # never our drop-in
        return _sl().limits_reconcile_via_unit("meshembed-serve-nodraft",
                                               t / "units" / "meshembed-serve-nodraft.service.d" / "20-owner.conf",
                                               "whatever", units=t / "units", result=res, start=start)
    assert _serve(host, rec) == "refused:limits_reconcile_failed" and len(starts) == 2
    assert not any(c[0] == "restart" for c in host["calls"])


@pytest.mark.parametrize("exc", [subprocess.CalledProcessError(1, ["systemctl"]),        # IOB-1c: StartLimitBurst hit
                                 subprocess.TimeoutExpired(["systemctl"], 180), OSError(30, "Read-only file system")])
def test_iob1b_every_reconcile_failure_is_a_refusal_and_the_launcher_writes_its_result(host, exc):
    def rec():
        raise exc
    assert _serve(host, rec) == "refused:limits_reconcile_failed"
    assert not any(c[0] == "restart" for c in host["calls"])
    assert json.loads((host["tmp"] / "state" / "result.json").read_text())["result"] == "refused:limits_reconcile_failed"


def test_iob1_the_launcher_starts_the_reconcile_unit_and_never_reconciles_in_process(host, monkeypatch):
    SL = _sl()
    t = host["tmp"]
    _installed(t / "units")
    res = t / "limits-result.json"
    monkeypatch.setattr(SL, "LIMITS_RESULT", res)
    monkeypatch.setattr(LA, "reconcile", lambda *a, **k: pytest.fail("reconcile ran in-process"))
    ran = []

    def fake_run(argv, **kw):                         # the reconcile unit: reads the drop-in as it is now
        ran.append((argv, kw.get("timeout")))
        f = t / "units" / "meshembed-serve-nodraft.service.d" / "20-owner.conf"
        _limits_result(res, "meshembed-serve-nodraft", f, f.read_text())
        return subprocess.CompletedProcess(argv, 0)
    monkeypatch.setattr(SL.subprocess, "run", fake_run)
    assert _serve(host, None).startswith("started:")
    assert ran == [(["systemctl", "start", "meshembed-limits-reconcile.service"], SL.LIMITS_START_TIMEOUT_S)]
    assert SL.LIMITS_START_TIMEOUT_S > 120                                   # IOB-1b: above TimeoutStartSec=120


# --- IOB-1 / IOB-3: what result.json names -----------------------------------------------------------------------------
def test_iob3_the_result_names_the_request_it_answers(h):
    _go(h, {"io_class": "low"})
    parsed = {"limits": {"io_class": "low"}}
    assert _result(h)["request_sha256"] == LA.request_sha256(parsed) == hashlib.sha256(LA.canonical(parsed)).hexdigest()


def test_iob1a_the_result_names_the_sources_this_pass_read(h):
    f = _owner_dropin(h)
    _go(h, {"io_class": "low"})
    assert _result(h)["sources"]["meshembed-serve"][str(f)] == hashlib.sha256(f.read_bytes()).hexdigest()


def test_iob1a_a_reconcile_with_nothing_to_apply_still_says_what_it_read(h):
    f = _owner_dropin(h)
    assert _reconcile(h, NOW) == "no_request"
    r = _result(h)
    assert r["result"] == "no_request" and r["request_sha256"] is None
    assert r["sources"]["meshembed-serve"][str(f)] == hashlib.sha256(f.read_bytes()).hexdigest()


def test_iob1_an_os_error_is_a_closed_refusal_not_a_traceback(h, monkeypatch):
    real = LA._write_nf
    monkeypatch.setattr(LA, "_write_nf", lambda p, *a: (_ for _ in ()).throw(OSError(30, "ro"))
                        if p.name == LA.DROPIN else real(p, *a))
    assert _go(h, {"io_class": "low"}) == "refused:io_error"
    assert _result(h)["result"] == "refused:io_error" and _result(h)["in_force"] == []


def test_a_systemctl_timeout_is_systemctl_failed(h):
    def to(*a):
        raise subprocess.TimeoutExpired(["systemctl", *a], 120)
    assert _go(h, {"io_class": "low"}, systemctl=to) == "systemctl_failed"
    assert _result(h)["result"] == "systemctl_failed"


# --- IOB-4 / IOA-N7: one pass at a time across both units and the installer --------------------------------------------
def test_iob4_a_held_lock_makes_both_entry_points_wait_and_change_nothing(h):
    state = h["tmp"] / "state"
    fd = os.open(str(state / "lock"), os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    try:
        assert _go(h, {"io_class": "low"}, lock_wait_s=0.3) == "refused:lock_busy"
        assert LA.reconcile("meshembed", now=NOW, lock_wait_s=0.3, **_kw(h)) == "refused:lock_busy"
        assert not (state / "result.json").exists() and h["sd"].calls == []
        assert (h["home"] / ".meshembed" / "limits-request").read_text() != ""    # left for the next run
    finally:
        os.close(fd)
    assert _go(h) == "applied"                                       # the same request, once the lock is free


def test_iob4_apply_and_reconcile_started_together_never_overlap(h):
    _go(h, {"io_class": "low"})
    spans, lock = [], threading.Lock()

    def slow(*a):
        t0 = time.monotonic(); time.sleep(0.05); h["sd"].systemctl(*a)
        with lock:
            spans.append((t0, time.monotonic(), threading.current_thread().name))
    kw = {**_kw(h), "systemctl": slow}
    a = threading.Thread(name="apply", target=lambda: LA.run(_req(h, {"io_class": "idle"}), "meshembed", now=NOW + 100,
                                                             **kw))
    b = threading.Thread(name="reconcile", target=lambda: LA.reconcile("meshembed", now=NOW + 100, **kw))
    a.start(); b.start(); a.join(); b.join()
    spans.sort()
    names = [n for _, _, n in spans]
    first = names[0]
    k = names.index(next(n for n in names if n != first))
    assert set(names[:k]) == {first} and first not in names[k:]          # all of one pass, then all of the other
    assert spans[k - 1][1] <= spans[k][0]


# --- the installer (install.sh install_limits_units) ------------------------------------------------------------------
ROOT = Path(__file__).resolve().parents[1]


def _limits_block() -> str:
    s = (ROOT / "install.sh").read_text()
    return s[s.index("install_limits_units() {"):s.index("\n}\n", s.index("install_limits_units() {"))]


def test_the_applier_installs_on_linux_root_installs_by_default_and_can_be_skipped():
    b = _limits_block()
    first = [ln.strip() for ln in b.splitlines()[2:4]]
    assert first[0] == '[ "${MESHEMBED_ENABLE_LIMITS:-1}" = "1" ] || return 0'
    assert first[1] == '[ "$(id -u)" -eq 0 ] && [ "$(uname -s)" = Linux ] || return 0'
    assert 'install_limits_units "$SVC_USER"' in (ROOT / "install.sh").read_text()


def test_the_applier_units_are_hardened_with_a_fixed_argv_and_write_only_their_paths():
    b = _limits_block()
    unit = b[b.index('meshembed-limits-$mode.service" << UNIT'):b.index("meshembed-limits-apply.path << UNIT")]
    assert [ln for ln in unit.splitlines() if ln.startswith("ExecStart")] == [
        "ExecStart=$v/bin/python -I -m meshembed_node.limits_apply --request $h/.meshembed/limits-request --owner $u$extra"]
    assert 'for mode in apply reconcile; do' in b and 'if [ "$mode" = reconcile ]; then extra=" --reconcile"; fi' in b
    for line in ("User=root", "NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes",
                 "ReadWritePaths=$rw"):
        assert line in unit
    rw = b[b.index('local rw="') + len('local rw="'):].split('"', 1)[0].split()
    assert rw == ["/var/lib/meshembed-limits-apply", "/etc/systemd/system/meshembed-node.service.d",
                  "/etc/systemd/system/meshembed-serve.service.d", "/etc/systemd/system/meshembed-serve-nodraft.service.d",
                  "$h/.meshembed/limits-request"]
    assert "EnvironmentFile" not in unit


def test_n3_any_drop_in_change_of_a_managed_unit_triggers_a_reconcile():
    b = _limits_block()
    path = b[b.index("meshembed-limits-reconcile.path << UNIT"):]
    for d in ("meshembed-node.service.d", "meshembed-serve.service.d", "meshembed-serve-nodraft.service.d",
              "meshembed-.service.d", "service.d"):
        assert f"PathChanged=/etc/systemd/system/{d}\n" in path
    assert "Unit=meshembed-limits-reconcile.service" in path and "enable --now meshembed-limits-reconcile.path" in b


def test_the_installer_reconciles_after_it_rewrote_the_units():
    b = _limits_block()
    # IOB-1: in the reconcile unit's own confinement, never as a bare root process
    assert b.rindex("systemctl start meshembed-limits-reconcile.service") > b.index("systemctl daemon-reload")
    assert "meshembed_node.limits_apply --request \"$h" not in b
    assert "OnUnitInactiveSec=30s" in b and "PathModified=$h/.meshembed/limits-request" in b


def test_iob5_the_request_files_are_made_as_the_user_never_by_root():
    s = (ROOT / "install.sh").read_text()
    assert "/dev/null \"$h/.meshembed/" not in s and "install -m 0600 -o" not in s
    b = _limits_block()
    assert 'make_user_request_file "$u" "$h/.meshembed/limits-request"' in b
    # IO-N1: no regular request file -> no applier units at all (they could not start), checked before any unit
    assert b.index('limits applier skipped (no regular request file') < b.index("meshembed-limits-$mode.service")
    assert 'make_user_request_file "$u" "$h/.meshembed/serve-request"' in s
    f = s[s.index("make_user_request_file() {"):s.index("\n}\n", s.index("make_user_request_file() {"))]
    assert 'if [ -L "$f" ]; then' in f and "runuser -u \"$u\" -- sh -c 'umask 077;" in f


def _run_make_user_file(tmp_path, target):
    """The installer's function, run for real in a temp dir; runuser stubbed to run the command as this user."""
    s = (ROOT / "install.sh").read_text()
    f = s[s.index("make_user_request_file() {"):s.index("\n}\n", s.index("make_user_request_file() {")) + 2]
    stub = tmp_path / "bin"; stub.mkdir(exist_ok=True)
    (stub / "runuser").write_text('#!/bin/sh\nwhile [ "$1" != "--" ]; do shift; done; shift; exec "$@"\n')
    os.chmod(stub / "runuser", 0o755)
    script = "warn() { echo \"WARN $*\"; }\n" + f + f'\nmake_user_request_file me "{target}"\n'
    return subprocess.run(["sh", "-c", script], env={"PATH": f"{stub}:/usr/bin:/bin"}, capture_output=True,
                          text=True, timeout=30)


def test_iob5_a_symlink_at_the_request_path_leaves_its_target_untouched(tmp_path):
    victim = tmp_path / "victim"; victim.write_text("precious\n"); os.chmod(victim, 0o644)
    link = tmp_path / "limits-request"; link.symlink_to(victim)
    r = _run_make_user_file(tmp_path, link)
    assert "symlink" in r.stdout and link.is_symlink()
    assert victim.read_text() == "precious\n" and oct(victim.stat().st_mode & 0o777) == "0o644"


def test_iob5_a_missing_request_file_is_created_0600_and_an_existing_one_kept(tmp_path):
    f = tmp_path / "limits-request"
    assert _run_make_user_file(tmp_path, f).returncode == 0
    assert f.read_text() == "" and oct(f.stat().st_mode & 0o777) == "0o600"
    f.write_text('{"limits":{}}'); os.chmod(f, 0o644)
    _run_make_user_file(tmp_path, f)
    assert f.read_text() == '{"limits":{}}' and oct(f.stat().st_mode & 0o777) == "0o600"


def test_mac_and_windows_installers_install_no_root_applier():
    for name in ("install-mac.sh", "install.ps1"):
        assert "limits_apply" not in (ROOT / name).read_text()


# --- IO-CAP real-systemd proof findings (2026-11-01): IOP-1 .. IOP-3 and the P9 lock line -------------------------
def test_iop2_bandwidth_and_iops_suffixes_are_base_1000_memory_stays_base_1024():
    dev = {"/dev/sdb": "8:16"}.get
    assert LA.parse_value("IOReadBandwidthMax", "/dev/sdb 7M", dev) == ("8:16", 7_000_000)
    assert LA.parse_value("IOWriteBandwidthMax", "/dev/sdb 1G", dev) == ("8:16", 1_000_000_000)
    assert LA.parse_value("IOReadIOPSMax", "/dev/sdb 7K", dev) == ("8:16", 7_000)     # used to raise ValueError
    assert LA.parse_value("MemoryMax", "4G", dev) == 4096                             # MiB, base 1024 as systemd


def test_iop3_a_garbage_value_in_another_source_is_unreadable_never_a_crash(h):
    _owner_dropin(h, "meshembed-node", "IOReadIOPSMax=/dev/sdb 7X\n", name="50-bad.conf")
    assert _go(h, {"cpu_quota_pct": 150}) == "applied"
    r = _result(h)
    assert r["result"] == "applied" and "cpu_quota_pct" in r["in_force"]


def test_iop3_a_pass_that_fails_keeps_the_request_for_the_next_pass(h, monkeypatch):
    real = LA.plan_unit
    calls = {"n": 0}

    def boom(*a, **k):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("synthetic")
        return real(*a, **k)

    monkeypatch.setattr(LA, "plan_unit", boom)
    code = _go(h, {"cpu_quota_pct": 120})
    # the run loop retries the kept request at once; the first pass's own result said error:RuntimeError
    assert code == "applied" and calls["n"] >= 2
    r = _result(h)
    assert r["request_sha256"] == LA.request_sha256({"limits": {"cpu_quota_pct": 120}}) and "cpu_quota_pct" in r["in_force"]


def test_iop3_a_pass_that_keeps_failing_says_so_and_never_drops_the_request(h, monkeypatch):
    monkeypatch.setattr(LA, "plan_unit", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("synthetic")))
    assert _go(h, {"cpu_quota_pct": 120}).startswith("error:RuntimeError")
    assert _result(h)["result"] == "error:RuntimeError"
    kept = json.loads((h["tmp"] / "state" / "pending.json").read_text())
    assert kept == {"limits": {"cpu_quota_pct": 120}}


def test_iop2_a_runtime_copy_of_another_source_is_reset_once_that_source_is_gone(h):
    hand = _owner_dropin(h, "meshembed-node", "IOReadBandwidthMax=/dev/sdb 50M\n", name="50-hand.conf")
    _go(h, {"io_read_mbps": 100})
    _go(h, {}, now=NOW + 120)                                         # clear: the hand entry is copied at runtime
    assert any("8:16 50000000" in a for a in _runtime(h, "meshembed-node")[-1])
    hand.unlink()                                                     # the operator removes his file
    _go(h, {}, now=NOW + 240)
    last = _runtime(h, "meshembed-node")[-1]
    assert "IOReadBandwidthMax=" in last and not any("8:16" in a for a in last)


def test_iop1_the_result_names_what_is_in_force_on_each_unit(h):
    _go(h, {"memory_max_gb": 4, "cpu_quota_pct": 150}, serve_floor=False)   # no serve.env: serve memory floor unknown
    r = _result(h)
    assert r["refused"].get("memory_max_gb") == "floor_unknown"            # the aggregate: refused somewhere
    assert "memory_max_gb" in r["units"]["meshembed-node"]["in_force"]     # but in force on the node
    assert r["units"]["meshembed-serve"]["refused"] == {"memory_max_gb": "floor_unknown"}
    assert "cpu_quota_pct" in r["units"]["meshembed-serve"]["in_force"]


def test_p9_a_wait_for_the_lock_is_logged(h, capsys):
    state = h["tmp"] / "state"
    fd = os.open(str(state / "lock"), os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    threading.Timer(0.5, lambda: os.close(fd)).start()
    _go(h, {"cpu_quota_pct": 150}, lock_wait_s=5)
    err = capsys.readouterr().err
    assert "limits_apply: lock busy, waiting" in err and "limits_apply: lock acquired after" in err


def test_iop3b_an_error_after_a_good_pass_reports_the_caps_still_in_force_marked_stale(h, monkeypatch):
    assert _go(h, {"cpu_quota_pct": 150}) == "applied"
    good = _result(h)
    monkeypatch.setattr(LA, "plan_unit", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("synthetic")))
    assert _go(h, {"cpu_quota_pct": 120}, now=NOW + 5).startswith("error:")
    r = _result(h)
    assert r["result"] == "error:RuntimeError" and r["stale"] is True
    assert r["in_force"] == good["in_force"] == ["cpu_quota_pct"]          # never [] while the 150 % is in force


def test_iop3b_an_error_with_no_previous_state_reports_in_force_unknown(h, monkeypatch):
    monkeypatch.setattr(LA, "plan_unit", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("synthetic")))
    _go(h, {"cpu_quota_pct": 120})
    r = _result(h)
    assert r["in_force"] is None and r["stale"] is True                    # unknown, not "nothing capped"


def test_iop1b_a_unit_whose_readback_differs_does_not_list_the_key_in_force(h):
    h["sd"].override["meshembed-serve"] = {"CPUQuota": "400%"}             # systemd shows another value there
    _go(h, {"cpu_quota_pct": 150})
    r = _result(h)
    assert "cpu_quota_pct" in r["units"]["meshembed-node"]["in_force"]
    assert "cpu_quota_pct" not in r["units"]["meshembed-serve"]["in_force"]
    assert r["units"]["meshembed-serve"]["refused"].get("cpu_quota_pct") == "overridden"
