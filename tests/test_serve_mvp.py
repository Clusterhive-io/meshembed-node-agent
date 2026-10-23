"""MVP 1 serving node (2026-10-21): the serve plan, the owner-first decision, the root serve launcher."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

import pytest

from meshembed_node import owner_first as OF
from meshembed_node import serve_launch as SL
from meshembed_node import serve_plan as SP
from meshembed_node import split_launch
from meshembed_node.split_plan_verify import NonceStore, PlanRejected, canonical

pytestmark = pytest.mark.unit
NOW = 1_800_000_000
SEED = bytes(range(32))


def _key():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization as s
    k = Ed25519PrivateKey.from_private_bytes(SEED)
    return k, {"t1": base64.b64encode(k.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)).decode()}


def _plan(**over):
    body = {"type": SP.PLAN_TYPE, "v": 2, "plan_id": "sv-1", "node_id": "node-a", "model_sha": "a" * 64,
            "draft_sha": "b" * 64, "ctx": 8192, "slots": 2, "nonce": "n-1", "issued_at": NOW - 10,
            "expires_at": NOW + 3600}
    body.update(over)
    k, _ = _key()
    return {"plan": body, "sig": base64.b64encode(k.sign(canonical(body))).decode(), "kid": "t1"}


# --- serve plan ---------------------------------------------------------------------------------------------

def test_a_genuine_plan_for_this_node_is_accepted_once(tmp_path):
    _, trust = _key()
    store = NonceStore(tmp_path / "n.json")
    assert SP.verify_serve_plan(_plan(), "node-a", now=NOW, nonces=store, trusted=trust)["model_sha"] == "a" * 64
    with pytest.raises(PlanRejected, match="plan_replayed"):
        SP.verify_serve_plan(_plan(), "node-a", now=NOW, nonces=store, trusted=trust)


def test_nothing_is_trusted_until_a_release_compiles_a_key_in(tmp_path):
    with pytest.raises(PlanRejected, match="plan_key_not_trusted"):
        SP.verify_serve_plan(_plan(), "node-a", now=NOW, nonces=NonceStore(tmp_path / "n.json"))


@pytest.mark.parametrize("over,code", [
    ({"node_id": "node-b"}, "plan_not_for_this_node"),
    ({"expires_at": NOW - 1}, "plan_expired"),
    ({"expires_at": NOW + 25 * 3600}, "serve_plan_times"),            # w4: over 6 h (+ skew) is refused
    ({"v": 1}, "serve_plan_version"),                                 # v1 refused
    ({"draft_sha": "zz"}, "serve_plan_draft_sha"),
    ({"type": "meshembed.split_plan"}, "serve_plan_type"),            # Q1: the type first
    ({"draft_sha": "a" * 64}, "serve_plan_draft_is_model"),
    ({"slots": 5}, "serve_plan_bounds"),
    ({"ctx": 100}, "serve_plan_bounds"),
    ({"model_sha": "../etc/passwd"}, "serve_plan_model_sha"),
    ({"extra": 1}, "serve_plan_schema"),
])
def test_bad_plans_are_refused(tmp_path, over, code):
    _, trust = _key()
    with pytest.raises(PlanRejected, match=code):
        SP.verify_serve_plan(_plan(**over), "node-a", now=NOW, nonces=NonceStore(tmp_path / "n.json"), trusted=trust)


def test_a_tampered_plan_fails_the_signature(tmp_path):
    _, trust = _key()
    env = _plan()
    env["plan"]["slots"] = 3                                # in bounds: only the signature can catch it
    with pytest.raises(PlanRejected, match="plan_signature_invalid"):
        SP.verify_serve_plan(env, "node-a", now=NOW, nonces=NonceStore(tmp_path / "n.json"), trusted=trust)


# --- owner first --------------------------------------------------------------------------------------------

IDLE = {"power_block": None, "too_hot": None, "duty_busy_frac": 0.1, "human_idle_s": 900, "call_active": None,
        "psi_mem_some_avg10": 0.0, "mem_available_mb": 8000, "model_need_mb": 3500, "other_cpu_frac": 0.1}


@pytest.mark.parametrize("over,owner,want", [
    ({}, None, (True, "ok")),
    ({"power_block": "on_battery"}, None, (False, "power:on_battery")),
    ({"power_block": "on_battery"}, {"allow_battery": True}, (True, "ok")),
    ({"power_block": "battery_low"}, {"allow_battery": True}, (False, "power:battery_low")),
    ({"too_hot": 91.0}, None, (False, "thermal")),
    ({"duty_busy_frac": 0.5}, None, (False, "duty_cap")),
    ({"call_active": True}, None, (False, "owner:call")),
    ({"human_idle_s": 12}, None, (False, "owner:active")),
    ({"human_idle_s": None}, None, (True, "ok")),                       # unknown -> rely on the CPU signal
    ({"human_idle_s": None}, {"unknown_owner": "yield"}, (False, "owner:unknown")),
    ({"psi_mem_some_avg10": 25.0}, None, (False, "memory:pressure")),
    ({"mem_available_mb": 4000}, None, (False, "memory:low")),
    ({"other_cpu_frac": 0.8}, None, (False, "owner:cpu")),
])
def test_owner_first_decision(over, owner, want):
    assert OF.decide({**IDLE, **over}, owner) == want


def test_the_power_rule_comes_before_everything():
    assert OF.decide({**IDLE, "power_block": "on_battery", "human_idle_s": 1, "too_hot": 99.0})[1] == "power:on_battery"


def test_duty_meter_window():
    t = [0.0]
    m = OF.DutyMeter(600, clock=lambda: t[0])
    m.mark(200); t[0] = 100; m.mark(100)
    assert m.frac() == pytest.approx(0.5)
    t[0] = 650                                              # the first mark is out of the window
    assert m.frac() == pytest.approx(100 / 600)


# --- the root launcher ----------------------------------------------------------------------------------------

@pytest.fixture
def host(tmp_path, monkeypatch):
    import pwd
    me = pwd.getpwuid(os.getuid())
    monkeypatch.setattr(split_launch, "ROOT_UID", os.getuid())
    home = tmp_path / "home"; (home / ".meshembed" / "serve-models").mkdir(parents=True)
    monkeypatch.setattr(SL.pwd, "getpwnam", lambda n: type("P", (), {"pw_uid": me.pw_uid, "pw_dir": str(home)})())
    for d in ("etc", "models", "units", "state"):
        (tmp_path / d).mkdir()
    calls = []
    return {"tmp": tmp_path, "home": home, "calls": calls, "systemctl": lambda *a: calls.append(a)}


def _request(h, obj):
    p = h["home"] / ".meshembed" / "serve-request"
    p.write_text(json.dumps(obj)); os.chmod(p, 0o600)
    return p


def _run(h, req, **kw):
    _, trust = _key()
    t = h["tmp"]
    return SL.run_once(req, "meshembed", state=t / "state", now=NOW, etc=t / "etc", models=t / "models",
                       units=t / "units", systemctl=h["systemctl"], nid="node-a", trusted=trust,
                       gid_of=lambda name: os.getgid(),
                       settings={"threads": 4, "repack_flag": "--no-repack", "memory_max_mb": 6000,
                                 "cpu_quota_pct": 400}, **kw)


def _stage(h, data: bytes) -> str:
    sha = hashlib.sha256(data).hexdigest()
    (h["home"] / ".meshembed" / "serve-models" / f"{sha}.gguf").write_bytes(data)
    return sha


def test_stop_is_always_honoured_without_a_plan(host):
    assert _run(host, _request(host, {"action": "stop", "reason": "owner:active"})) == "stopped:owner:active"
    assert host["calls"] == [("stop", "meshembed-serve.service"), ("stop", "meshembed-serve-nodraft.service")]


def test_start_places_verified_models_and_writes_env_and_caps(host):
    m, d = _stage(host, b"model-bytes"), _stage(host, b"draft-bytes")
    env = _plan(model_sha=m, draft_sha=d)
    code = _run(host, _request(host, {"action": "start", "plan": env}))
    assert code == "started:sv-1"
    t = host["tmp"]
    e = (t / "etc" / "serve.env").read_text()
    assert f"MODEL={t / 'models' / (m + '.gguf')}" in e and f"DRAFT_SHA_PIN={d}" in e
    assert "THREADS=4" in e and "CTX=8192" in e and "SLOTS=2" in e and "REPACK_FLAG=--no-repack" in e
    st = os.stat(t / "etc" / "serve.env")
    assert oct(st.st_mode & 0o777) == "0o640" and st.st_gid == os.getgid()    # F1: G0 runs as mesh-serve, reads it
    dropin = (t / "units" / "meshembed-serve.service.d" / "20-owner.conf").read_text()
    assert "MemoryMax=6000M" in dropin and "CPUQuota=400%" in dropin and "RuntimeMaxSec=3600" in dropin
    assert (t / "models" / f"{m}.gguf").read_bytes() == b"model-bytes"
    assert host["calls"] == [("stop", "meshembed-serve-nodraft.service"), ("daemon-reload",),
                             ("restart", "meshembed-serve.service")]


def test_a_staged_model_that_does_not_hash_to_the_sha_is_refused(host):
    d = _stage(host, b"draft-bytes")
    fake = "c" * 64
    (host["home"] / ".meshembed" / "serve-models" / f"{fake}.gguf").write_bytes(b"something else")
    code = _run(host, _request(host, {"action": "start", "plan": _plan(model_sha=fake, draft_sha=d)}))
    assert code == "refused:model_sha_mismatch"
    assert not (host["tmp"] / "models" / f"{fake}.gguf").exists() and host["calls"] == []


def test_a_symlinked_staged_model_is_refused(host, tmp_path):
    d = _stage(host, b"draft-bytes")
    real = tmp_path / "elsewhere.gguf"; real.write_bytes(b"model-bytes")
    m = hashlib.sha256(b"model-bytes").hexdigest()
    (host["home"] / ".meshembed" / "serve-models" / f"{m}.gguf").symlink_to(real)
    assert _run(host, _request(host, {"action": "start", "plan": _plan(model_sha=m, draft_sha=d)})) == "refused:model_not_staged"


@pytest.mark.parametrize("req,code", [
    ({"action": "stop", "reason": "x; rm -rf /"}, "refused:stop_reason"),
    ({"action": "stop"}, "refused:stop_reason"),
    ({"action": "reboot"}, "refused:request_action"),
    ({"action": "start", "plan": {}, "extra": 1}, "refused:request_keys"),
])
def test_malformed_requests_are_refused(host, req, code):
    assert _run(host, _request(host, req)) == code and host["calls"] == []


def test_host_settings_are_computed_here_not_taken_from_the_plan():
    hs = SL.host_settings(8, {"MemTotal": 16000, "MemAvailable": 5000})
    assert hs == {"threads": 6, "repack_flag": "--no-repack", "memory_max_mb": 3976, "cpu_quota_pct": 600}
    assert SL.host_settings(2, {"MemTotal": 65536, "MemAvailable": 40000})["threads"] == 1
    assert SL.host_settings(16, {"MemTotal": 65536, "MemAvailable": 40000})["repack_flag"] == "--repack"


# --- auditor 14:41Z fixes -------------------------------------------------------------------------------------

def test_f1_the_env_file_is_group_readable_by_the_service_group(host):
    m, d = _stage(host, b"model-bytes"), _stage(host, b"draft-bytes")
    seen = []
    _, trust = _key()
    t = host["tmp"]
    code = SL.run_once(_request(host, {"action": "start", "plan": _plan(model_sha=m, draft_sha=d)}), "meshembed",
                       state=t / "state", now=NOW, etc=t / "etc", models=t / "models", units=t / "units",
                       systemctl=host["systemctl"], nid="node-a", trusted=trust,
                       settings={"threads": 4, "repack_flag": "--no-repack", "memory_max_mb": 6000, "cpu_quota_pct": 400},
                       gid_of=lambda name: seen.append(name) or os.getgid())
    assert code == "started:sv-1" and seen == ["mesh-serve"]


def test_f2_a_plan_with_less_than_a_minute_left_is_refused(host):
    m, d = _stage(host, b"model-bytes"), _stage(host, b"draft-bytes")
    code = _run(host, _request(host, {"action": "start", "plan": _plan(model_sha=m, draft_sha=d, expires_at=NOW + 59)}))
    assert code == "refused:plan_expires_too_soon" and host["calls"] == []
    assert not (host["tmp"] / "units" / "meshembed-serve.service.d" / "20-owner.conf").exists()


def test_f3_no_idle_and_no_cpu_signal_is_owner_unknown():
    assert OF.decide({**IDLE, "human_idle_s": None, "other_cpu_frac": None}) == (False, "owner:unknown")
    assert OF.decide({**IDLE, "human_idle_s": None, "other_cpu_frac": 0.2}) == (True, "ok")     # the CPU proxy


def test_bytes_changed_in_place_during_the_copy_are_refused_and_nothing_is_left(host, monkeypatch):
    data = b"A" * 65536                                       # larger than the reader's buffer: the change lands
    sha = _stage(host, data)                                   # in bytes not yet read
    src = host["home"] / ".meshembed" / "serve-models" / f"{sha}.gguf"
    monkeypatch.setattr(SL, "CHUNK", 1024)
    real_fdopen = os.fdopen
    def fdopen(fd, *a, **k):                                   # after the first chunk, the owner rewrites the file
        f = real_fdopen(fd, *a, **k)
        real_read = f.read
        state = {"n": 0}
        def read(n=-1):
            b = real_read(n)
            state["n"] += 1
            if state["n"] == 1:
                with open(src, "r+b") as w:
                    w.seek(32768); w.write(b"B" * 32768)
            return b
        f.read = read
        return f
    monkeypatch.setattr(SL.os, "fdopen", fdopen)
    with pytest.raises(SL.Refused, match="model_sha_mismatch"):
        SL.place_model(sha, src.parent, os.getuid(), host["tmp"] / "models")
    assert list((host["tmp"] / "models").iterdir()) == []      # no dst, no .part


def test_a_file_renamed_over_the_staging_path_during_the_copy_cannot_get_installed(host, monkeypatch):
    data = b"good" * 1024
    sha = _stage(host, data)
    src = host["home"] / ".meshembed" / "serve-models" / f"{sha}.gguf"
    evil = src.with_name("evil")
    evil.write_bytes(b"evil" * 1024)
    monkeypatch.setattr(SL, "CHUNK", 1024)
    real_fdopen = os.fdopen
    def fdopen(fd, *a, **k):
        f = real_fdopen(fd, *a, **k)
        real_read = f.read
        state = {"n": 0}
        def read(n=-1):
            b = real_read(n)
            state["n"] += 1
            if state["n"] == 1:
                os.replace(evil, src)                          # swap the PATH; the open fd keeps the good bytes
            return b
        f.read = read
        return f
    monkeypatch.setattr(SL.os, "fdopen", fdopen)
    dst = SL.place_model(sha, src.parent, os.getuid(), host["tmp"] / "models")
    assert dst.read_bytes() == data                           # exactly the hashed bytes, never the swapped file


def test_an_error_mid_copy_leaves_no_part_file(host, monkeypatch):
    sha = _stage(host, b"x" * 4096)
    src = host["home"] / ".meshembed" / "serve-models" / f"{sha}.gguf"
    monkeypatch.setattr(SL.os, "fsync", lambda fd: (_ for _ in ()).throw(OSError("disk")))
    with pytest.raises(OSError):
        SL.place_model(sha, src.parent, os.getuid(), host["tmp"] / "models")
    assert list((host["tmp"] / "models").iterdir()) == []


# --- M3: the no-draft unit is chosen by the SIGNED plan (auditor 19:22Z (b)) ------------------------------------

def test_a_null_draft_plan_is_accepted(tmp_path):
    _, trust = _key()
    body = SP.verify_serve_plan(_plan(draft_sha=None), "node-a", now=NOW, nonces=NonceStore(tmp_path / "n.json"),
                                trusted=trust)
    assert body["draft_sha"] is None


def test_a_null_draft_plan_starts_the_no_draft_unit_with_no_draft_key(host):
    m = _stage(host, b"model-bytes")
    code = _run(host, _request(host, {"action": "start", "plan": _plan(model_sha=m, draft_sha=None)}))
    assert code == "started:sv-1"
    t = host["tmp"]
    e = (t / "etc" / "serve.env").read_text()
    assert "DRAFT" not in e                      # the no-draft G0 profile refuses any draft key: nothing to refuse
    assert (t / "units" / "meshembed-serve-nodraft.service.d" / "20-owner.conf").exists()
    assert host["calls"] == [("stop", "meshembed-serve.service"), ("daemon-reload",),
                             ("restart", "meshembed-serve-nodraft.service")]


def test_the_unit_follows_the_signed_plan_only():
    assert SL.unit_for({"draft_sha": None}) == "meshembed-serve-nodraft"
    assert SL.unit_for({"draft_sha": "b" * 64}) == "meshembed-serve"

