"""SPLIT-SERVE head 4-node, part A (docs/DESIGN_SPLIT_SERVE_2026-11-02.md; auditor 19:38:48Z K4-1..K4-3): the ROOT
launcher accepts plan v3 kind serve. A serve plan's SIGNED runtime_set must equal the set this host verified (SP-2);
only the COORDINATOR needs the model file (section 3a); the stage's --cache flag is ON only for a serve plan on a
re-hashing set with a safe cache dir (K4-3), any miss = no cache, never a refusal; a coordinator or model change
purges the cache (SD-6); the stage's MemoryMax is the signed share clamped by the host floors (CAP-2). The serve
COORDINATOR (part B) is tested in test_split_launch_serve_coord.py."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path

import pytest

from meshembed_node import split_handoff as H
from meshembed_node import split_launch as L

pytestmark = pytest.mark.unit
FX = Path(__file__).parent / "fixtures"
SERVE = json.loads((FX / "split_plan_serve_golden.json").read_text())
NOW = SERVE["verify_at"]
MEM = {"MemTotal": 16384, "MemAvailable": 12000}


@pytest.fixture
def host(tmp_path, monkeypatch):
    monkeypatch.setattr(L, "ROOT_UID", os.getuid())
    srv = tmp_path / "srv"
    (srv / "bin").mkdir(parents=True)
    man = srv / "MANIFEST.runtime-set.sha256"
    man.write_text("abc  ./ggml-rpc-server\n")
    os.chmod(man, 0o644)
    lib = srv / "bin" / "libggml-rpc.so.0.26.0"
    lib.write_bytes(b"\x7fELF ... sha256t-%016lx ... cache file '%s' does not match its key: removed ...")
    cache = tmp_path / "cache"
    cache.mkdir()
    os.chmod(cache, 0o700)
    for d in ("etc", "units", "models", "state"):
        (tmp_path / d).mkdir()
    (tmp_path / "units" / f"{L.STAGE_UNIT}.service.d").mkdir()
    own = hashlib.sha256(man.read_bytes()).hexdigest()
    return {"tmp": tmp_path, "srv": srv, "lib": lib, "cache": cache, "own": own, "calls": []}


def _body(own_set):
    b = copy.deepcopy(SERVE["envelope"]["plan"])
    b["runtime_set"] = own_set
    return b


def _params(h, **over):
    p = L.derive(_body(h["own"]), "node-stage", {"10.44.0.2"}, h["tmp"] / "models", own_set=h["own"])
    p.update(over)
    return p


def _apply(h, params, **kw):
    return L.apply(params, NOW, etc=h["tmp"] / "etc", units=h["tmp"] / "units",
                   systemctl=lambda *a: h["calls"].append(a), gid_of=lambda n: os.getgid(), state=h["tmp"] / "state",
                   cache_root=h["cache"], srv=h["srv"], uid_of=kw.get("uid_of", lambda n: os.getuid()),
                   meminfo=lambda: MEM)


def _flag(h):
    env = (h["tmp"] / "etc" / "stage.env").read_text()
    return next(l for l in env.splitlines() if l.startswith("STAGE_CACHE_FLAG=")).split("=", 1)[1]


def test_own_runtime_set_is_the_manifests_sha256(host):
    assert L.own_runtime_set(host["srv"]) == host["own"]


def test_a_serve_stage_needs_no_model_file_but_the_coordinator_does(host):
    p = _params(host)                                                      # no file in models/: fine for a stage
    assert (p["role"], p["kind"], p["memory_max_mb"]) == ("stage", "serve", 6144)
    with pytest.raises(L.Refused, match="model_not_preplaced"):
        L.derive(_body(host["own"]), "node-coord", {"10.44.0.1"}, host["tmp"] / "models", own_set=host["own"])


def test_a_batch_stage_still_needs_the_file(host):
    b = _body(None)
    b.pop("runtime_set")
    b["kind"], b["job_id"] = "primary", "job-x"
    for m in b["members"]:
        m.pop("memory_max_mb")
    with pytest.raises(L.Refused, match="model_not_preplaced"):
        L.derive(b, "node-stage", {"10.44.0.2"}, host["tmp"] / "models")


@pytest.mark.parametrize("own", [None, "cd" * 32])
def test_sp2_a_serve_plan_whose_signed_set_is_not_this_hosts_is_refused(host, own):
    with pytest.raises(L.Refused, match="runtime_set_mismatch"):
        L.derive(_body(host["own"]), "node-stage", {"10.44.0.2"}, host["tmp"] / "models", own_set=own)


def test_k4_3_the_cache_is_on_only_when_every_condition_holds(host):
    assert _apply(host, _params(host)) == "stage_started"
    assert _flag(host) == "--cache"


@pytest.mark.parametrize("breaker", ["no_markers", "dir_0755", "dir_symlink", "dir_other_owner", "set_changed",
                                     "second_lib_without_markers"])
def test_k4_3_any_miss_means_no_cache_never_a_refusal(host, breaker):
    kw = {}
    if breaker == "no_markers":
        host["lib"].write_bytes(b"\x7fELF upstream ggml-rpc, no re-hash")
    elif breaker == "dir_0755":
        os.chmod(host["cache"], 0o755)
    elif breaker == "dir_symlink":
        real = host["tmp"] / "real-cache"
        real.mkdir(mode=0o700)
        host["cache"].rmdir()
        host["cache"].symlink_to(real)
    elif breaker == "dir_other_owner":
        kw["uid_of"] = lambda n: os.getuid() + 1
    elif breaker == "second_lib_without_markers":                        # one good + one upstream library: NO cache
        (host["srv"] / "bin" / "libggml-rpc.so.0.27.0").write_bytes(b"\x7fELF upstream, no re-hash")
    elif breaker == "set_changed":                                         # the host's set moved after derive
        (host["srv"] / "MANIFEST.runtime-set.sha256").write_text("other  ./x\n")
    assert _apply(host, _params(host), **kw) == "stage_started"
    assert _flag(host) == ""


def test_cap2_the_stage_memory_max_is_the_signed_share_clamped_by_the_host(host):
    _apply(host, _params(host))
    drop = (host["tmp"] / "units" / f"{L.STAGE_UNIT}.service.d" / "20-plan.conf").read_text()
    assert "MemoryMax=6144M" in drop                                      # min(6144, 12000-1024, 12288)
    assert "Restart=no\n" in drop                                         # STAGE-RESTART F-R1: never a silent restart
    assert L.stage_memory_max_mb(20000, MEM) == 10976                      # MemAvailable - 1 GiB wins
    assert L.stage_memory_max_mb(20000, {"MemTotal": 8000, "MemAvailable": 20000}) == 6000   # 3/4 MemTotal wins


def test_sd6_a_coordinator_or_model_change_purges_the_cache(host):
    rpc = host["cache"] / "rpc"
    rpc.mkdir()
    (rpc / "sha256t-0000000000000001").write_bytes(b"w")
    _apply(host, _params(host))
    assert not rpc.exists()                                                # first start: no record -> purge
    rpc.mkdir()
    (rpc / "sha256t-0000000000000002").write_bytes(b"w")
    _apply(host, _params(host))
    assert rpc.exists()                                                    # same coordinator + model: kept
    _apply(host, _params(host, model_sha="ef" * 32))
    assert not rpc.exists()                                                # another model: purged


def test_the_daemon_reports_the_launchers_verified_set_and_drops_garbage(tmp_path, monkeypatch):
    monkeypatch.setenv("MESHEMBED_ENABLE_SPLIT", "1")
    monkeypatch.setattr(H, "reachability", lambda: {})
    (tmp_path / "ready.json").write_text(json.dumps({"ready": True, "code": "ok", "runtime_set": "ab" * 32}))
    assert H.ready(tmp_path)["runtime_set"] == "ab" * 32
    (tmp_path / "ready.json").write_text(json.dumps({"ready": True, "code": "ok", "runtime_set": "nope"}))
    assert "runtime_set" not in H.ready(tmp_path)
