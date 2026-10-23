"""M2 build #5a: the root split launcher acts only on a plan IT re-verified, for THIS node (id
from a root-owned file), from a request it can trust, and writes only validated values."""
from __future__ import annotations

import base64
import json
import os
import time
from pathlib import Path

import pytest

from meshembed_node import split_handoff as H
from meshembed_node import split_launch as L
from meshembed_node import split_plan_verify as V

pytestmark = pytest.mark.unit

GOLD = json.loads((Path(__file__).parent / "fixtures" / "split_plan_golden.json").read_text())
TRUST = {"v1": GOLD["public_key_b64"]}
WG = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
SHA = "ab" * 32
NOW = time.time()


def _env(members=(("coord", "10.44.0.1", [0, 30]), ("me", "10.44.0.2", [30, 48])), coordinator="coord",
         kind="primary", nonce=None, lifetime=3600):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    k = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(GOLD["seed_hex"]))
    body = {"v": 2, "type": "meshembed.split_plan", "kind": kind, "plan_id": "sp-five0000000000000000000a",
            "job_id": "job-1", "model_sha": SHA, "coordinator": coordinator,
            "members": [{"node_id": n, "overlay_ip": ip, "wg_pubkey": WG, "layers": lay, "endpoint": None}
                        for n, ip, lay in members],
            "expires_at": int(NOW) + lifetime, "nonce": nonce or os.urandom(16).hex()}
    return {"plan": body, "sig": base64.b64encode(k.sign(V.canonical(body))).decode(), "kid": "v1"}


@pytest.fixture
def box(tmp_path, monkeypatch):
    monkeypatch.setattr(L, "ROOT_UID", os.getuid())
    (tmp_path / "etc").mkdir()
    (tmp_path / "units").mkdir()
    for u in (L.STAGE_UNIT, L.COORD_UNIT, L.ENGINE_UNIT):
        (tmp_path / "units" / f"{u}.service.d").mkdir()
    (tmp_path / "models").mkdir()
    m = tmp_path / "models" / f"{SHA}.gguf"
    m.write_bytes(b"gguf")
    os.chmod(m, 0o644)
    nid = tmp_path / "node-id"
    nid.write_text("me\n")
    os.chmod(nid, 0o644)
    req = tmp_path / "split-request"
    calls = []
    state = tmp_path / "state"
    ovl = FakeOverlay()

    def put(env, mode=0o600):
        req.write_text(json.dumps(env))
        os.chmod(req, mode)

    def run(**kw):
        def applier(params, now):
            return L.apply(params, now, etc=tmp_path / "etc", units=tmp_path / "units",
                           systemctl=lambda *a: calls.append(a), gid_of=lambda name: os.getgid(), state=state)
        return L.run_once(req, _me(), state=state,
                          node_id_file=nid, trusted=TRUST, local_ips={"10.44.0.2"},
                          models_dir=tmp_path / "models", applier=kw.get("applier", applier),
                          ready=kw.get("ready", (True, "ok")), overlay=kw.get("overlay", ovl),
                          revoke=kw.get("revoke"), systemctl=lambda *a: calls.append(a),
                          now=kw.get("now", NOW))
    return {"tmp": tmp_path, "req": req, "put": put, "run": run, "calls": calls, "state": state, "nid": nid,
            "ovl": ovl}


class FakeOverlay:
    """Stands in for split_overlay_node (real wg/ip/nft are exercised by the netns harness)."""

    from meshembed_node.split_overlay_node import Refused

    def __init__(self, key=None):
        self.key = key
        self.log = []

    def ensure_key(self):
        self.log.append("ensure_key")
        return self.key or WG

    def configure(self, body, me, pub):
        from meshembed_node.split_overlay_node import configure
        out = configure(body, me, pub, runner=lambda argv, stdin: self.log.append(tuple(argv)) or b"")
        self.log.append("configured")
        return out

    def firewall(self, peers, *, listener, udp_sources=()):
        self.log.append(("firewall", tuple(peers), listener))
        return ""

    def teardown(self):
        self.log.append("teardown")


def _me():
    import pwd
    return pwd.getpwuid(os.getuid()).pw_name


def test_a_stage_gets_validated_env_a_plan_dropin_and_a_restart(box):
    box["put"](_env())
    assert box["run"]() == "stage_started"
    t = box["tmp"]
    assert (t / "etc" / "stage.env").read_text() == "STAGE_BIND=10.44.0.2\nRPC_PORT=50052\nCACHE_DIR=/var/lib/mesh-di-stage\n"
    drop = (t / "units" / f"{L.STAGE_UNIT}.service.d" / "20-plan.conf").read_text()
    assert "IPAddressAllow=\nIPAddressAllow=10.44.0.1/32 127.0.0.1\n" in drop
    assert 3500 <= int(drop.split("RuntimeMaxSec=")[1]) <= 3600
    assert box["calls"] == [("daemon-reload",), ("restart", f"{L.STAGE_UNIT}.service")]
    assert box["req"].read_text() == ""                                  # consumed
    res = json.loads((box["state"] / "last-result.json").read_text())
    assert res["result"] == "ok" and res["role"] == "stage"


def test_the_coordinator_starts_the_plans_engine_on_a_unix_socket(box):
    box["put"](_env(coordinator="me"))
    assert box["run"]() == "engine_started"
    env = (box["tmp"] / "etc" / "engine.env").read_text()
    assert f"MODEL_SHA_PIN={SHA}" in env and "RPC_STAGES=10.44.0.1:50052" in env
    assert "SLOTS=4\n" in env and "CTX=16384\n" in env
    drop = (box["tmp"] / "units" / f"{L.ENGINE_UNIT}.service.d" / "20-plan.conf").read_text()
    assert "IPAddressAllow=\nIPAddressAllow=10.44.0.1/32 127.0.0.1\n" in drop
    assert box["calls"] == [("daemon-reload",), ("restart", f"{L.ENGINE_UNIT}.service")]


def test_a_replayed_plan_is_refused_by_the_root_nonce_store(box):
    env = _env()
    box["put"](env)
    box["run"]()
    box["put"](env)
    assert box["run"]() == "refused:plan_replayed"


@pytest.mark.parametrize("mutate,code", [
    (lambda e: e["plan"].update(job_id="job-2"), "plan_signature_invalid"),       # tampered after signing
    (lambda e: e.update(kid="v9"), "plan_key_not_trusted"),
    (lambda e: e["plan"]["members"].append({"cmd": "id"}), "plan_schema_member_keys"),
])
def test_a_forged_or_tampered_plan_is_refused(box, mutate, code):
    env = _env()
    mutate(env)
    box["put"](env)
    assert box["run"]() == f"refused:{code}"
    assert box["calls"] == []


def test_a_plan_for_other_nodes_is_refused(box):
    box["put"](_env(members=(("a", "10.44.0.1", [0, 30]), ("b", "10.44.0.3", [30, 48])), coordinator="a"))
    assert box["run"]() == "refused:plan_not_for_this_node"


def test_the_node_id_comes_only_from_a_trusted_file(box):
    os.chmod(box["nid"], 0o666)                                            # writable by others
    box["put"](_env())
    assert box["run"]() == "refused:node_id_file_untrusted"


def test_own_ip_must_be_on_the_overlay_interface(box, monkeypatch):
    box["put"](_env(members=(("coord", "10.44.0.1", [0, 30]), ("me", "10.44.0.7", [30, 48]))))
    assert box["run"]() == "refused:own_overlay_ip_not_on_overlay"


def test_the_model_must_be_preplaced(box):
    (box["tmp"] / "models" / f"{SHA}.gguf").unlink()
    box["put"](_env())
    assert box["run"]() == "refused:model_not_preplaced"


def test_not_ready_means_nothing_is_started(box):
    box["put"](_env())
    assert box["run"](ready=(False, "runtime_set_mismatch")) == "refused:runtime_set_mismatch"
    assert json.loads((box["state"] / "ready.json").read_text()) == {"ready": False, "code": "runtime_set_mismatch",
                                                                      "at": int(NOW)}


@pytest.mark.parametrize("prep,code", [
    (lambda r: (r.write_text("{}"), os.chmod(r, 0o644)), "request_mode_too_open"),
    (lambda r: (r.write_text("x" * (L.MAX_REQUEST_BYTES + 1)), os.chmod(r, 0o600)), "request_too_large"),
    (lambda r: (r.write_text("not json"), os.chmod(r, 0o600)), "request_not_json"),
])
def test_an_untrustworthy_request_file_is_refused(box, prep, code):
    prep(box["req"])
    assert box["run"]() == f"refused:{code}"


def test_a_symlinked_request_is_refused(box):
    target = box["tmp"] / "elsewhere"
    target.write_text(json.dumps(_env()))
    os.chmod(target, 0o600)
    box["req"].symlink_to(target)
    assert box["run"]() == "refused:request_unreadable"


def test_no_request_still_refreshes_readiness(box):
    assert box["run"]() == "no_request"
    assert json.loads((box["state"] / "ready.json").read_text())["ready"] is True


def test_a_plan_expiring_within_a_minute_is_not_started(box):
    box["put"](_env(lifetime=30))
    assert box["run"]() == "refused:plan_expires_too_soon"


# ---- daemon side ------------------------------------------------------------------------

@pytest.fixture
def daemon(tmp_path, monkeypatch):
    monkeypatch.setenv("MESHEMBED_ENABLE_SPLIT", "1")
    H._HANDLED.clear()
    return {"req": tmp_path / "split-request", "nonces": V.NonceStore(tmp_path / "n.json")}


def test_the_daemon_queues_a_verified_plan_once_and_never_overwrites(daemon):
    a = _env()
    assert H.handoff([a], "me", path=daemon["req"], nonces=daemon["nonces"], trusted=TRUST) == a["plan"]["plan_id"]
    assert oct(daemon["req"].stat().st_mode & 0o777) == "0o600"
    assert json.loads(daemon["req"].read_text()) == a
    assert H.handoff([a], "me", path=daemon["req"], nonces=daemon["nonces"], trusted=TRUST) is None   # handled


def test_the_daemon_waits_while_the_launcher_has_not_consumed(daemon):
    daemon["req"].write_text('{"pending": 1}')
    os.chmod(daemon["req"], 0o600)
    env = _env()
    assert H.handoff([env], "me", path=daemon["req"], nonces=V.NonceStore(daemon["req"].parent / "x.json"),
                     trusted=TRUST) is None
    assert daemon["req"].read_text() == '{"pending": 1}'
    assert env["plan"]["plan_id"] not in H._HANDLED                     # retried next poll


def test_the_daemon_never_queues_a_forged_plan(daemon):
    env = _env()
    env["plan"]["job_id"] = "job-x"
    assert H.handoff([env], "me", path=daemon["req"], nonces=daemon["nonces"], trusted=TRUST) is None
    assert not daemon["req"].exists()


def test_readiness_comes_only_from_the_launchers_file(tmp_path, monkeypatch):
    monkeypatch.delenv("MESHEMBED_ENABLE_SPLIT", raising=False)
    assert H.ready(tmp_path) == {"ready": False, "code": "disabled"}
    monkeypatch.setenv("MESHEMBED_ENABLE_SPLIT", "1")
    assert H.ready(tmp_path) == {"ready": False, "code": "launcher_absent"}
    monkeypatch.setattr(H, "reachability", lambda: {"public_addr": False})
    (tmp_path / "ready.json").write_text('{"ready": true, "code": "ok"}')
    assert H.ready(tmp_path) == {"ready": True, "code": "ok", "public_addr": False}
    (tmp_path / "ready.json").write_text('{"ready": "yes"}')
    assert H.ready(tmp_path)["ready"] is False


def test_readiness_forwards_only_a_valid_public_key(tmp_path, monkeypatch):
    monkeypatch.setenv("MESHEMBED_ENABLE_SPLIT", "1")
    monkeypatch.setattr(H, "reachability", lambda: {"public_addr": True})
    (tmp_path / "ready.json").write_text(json.dumps({"ready": True, "code": "ok", "wg_pubkey": WG}))
    assert H.ready(tmp_path) == {"ready": True, "code": "ok", "wg_pubkey": WG, "public_addr": True}
    (tmp_path / "ready.json").write_text(json.dumps({"ready": True, "code": "ok", "wg_pubkey": "not a key"}))
    assert "wg_pubkey" not in H.ready(tmp_path)


def test_public_addr_is_true_only_when_the_observed_address_is_local(monkeypatch):
    monkeypatch.setattr(H, "_local_ipv4s", lambda: {"77.42.13.30", "10.44.0.1"})
    monkeypatch.setattr(H, "_primary_lan", lambda: None)
    H.set_observed("77.42.13.30")
    assert H.reachability() == {"public_addr": True}
    H.set_observed("81.0.0.9")                                    # behind NAT: observed is not ours
    assert H.reachability() == {"public_addr": False}
    H.set_observed("junk")
    assert H.reachability() == {"public_addr": False}


def test_only_a_handed_off_plan_is_relayed_as_revoked(tmp_path, monkeypatch):
    monkeypatch.setenv("MESHEMBED_ENABLE_SPLIT", "1")
    H._HANDLED.clear()
    H._HANDLED["sp-mine"] = "queued"
    p = tmp_path / "split-revoke"
    assert H.relay_revocations(["sp-not-mine"], path=p) is None and not p.exists()
    assert H.relay_revocations(["sp-not-mine", "sp-mine"], path=p) == "sp-mine"
    assert json.loads(p.read_text()) == {"plan_id": "sp-mine"} and oct(p.stat().st_mode & 0o777) == "0o600"



# ---- overlay automation step 3 (launcher side) ----

def test_the_plan_builds_meshdi0_and_the_firewall_before_the_unit_starts(box):
    box["put"](_env())
    assert box["run"]() == "stage_started"
    log = box["ovl"].log
    assert log[0] == "ensure_key" and "configured" in log
    link_add = next(a for a in log if isinstance(a, tuple) and a[:3] == ("ip", "link", "add"))
    assert link_add[3] == "meshdi0"                                            # never wg0
    wgset = next(a for a in log if isinstance(a, tuple) and a[:2] == ("wg", "set"))
    assert "private-key" in wgset and not any("PRIVATE" in str(x) for x in wgset)  # a PATH, not the key
    assert any(a[0] == "firewall" for a in log if isinstance(a, tuple))
    ready = json.loads((box["state"] / "ready.json").read_text())
    assert ready["wg_pubkey"] == WG and ready["ready"] is True


def test_a_plan_for_another_key_is_refused_before_anything_is_configured(box):
    other = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
    box["ovl"].key = other                                                     # this host holds another key
    box["put"](_env())
    assert box["run"]() == "refused:own_wg_key_mismatch"
    assert "configured" not in box["ovl"].log and box["calls"] == []


def test_a_revocation_of_the_applied_plan_tears_down_and_stops_units(box):
    box["put"](_env())
    assert box["run"]() == "stage_started"
    rv = box["tmp"] / "split-revoke"
    pid = json.loads((box["state"] / "applied.json").read_text())["plan_id"]
    rv.write_text(json.dumps({"plan_id": "sp-some-other-plan"}))
    os.chmod(rv, 0o600)
    assert box["run"](revoke=rv) == "no_request"                              # not the applied plan: ignored
    rv.write_text(json.dumps({"plan_id": pid}))
    os.chmod(rv, 0o600)
    assert box["run"](revoke=rv) == "revoked_torn_down"
    assert box["ovl"].log[-1] == "teardown"
    assert ("stop", f"{L.STAGE_UNIT}.service") in box["calls"]


def test_an_expired_plan_is_torn_down_on_the_next_pass(box):
    box["put"](_env())
    assert box["run"]() == "stage_started"
    exp = json.loads((box["state"] / "applied.json").read_text())["expires_at"]
    assert box["run"](now=exp + 1) == "expired_torn_down"
    assert box["ovl"].log[-1] == "teardown"


def test_no_wireguard_tools_means_not_ready_with_a_reason(box):
    class NoWg(FakeOverlay):
        def ensure_key(self):
            raise OSError("wg: not found")
    box["put"](_env())
    assert box["run"](overlay=NoWg()) == "refused:wireguard_unavailable"
    ready = json.loads((box["state"] / "ready.json").read_text())
    assert ready == {"ready": False, "code": "wireguard_unavailable", "at": ready["at"]}


# --- the stage weight cache (C.2 kit, auditor 2026-10-21 15:04Z condition 4) ----------------------------------

def _cache(box_or_none=None):
    root = L.STAGE_CACHE_ROOT
    (root / "rpc").mkdir(parents=True, exist_ok=True)
    (root / "rpc" / "sha256t-0000000000000001").write_bytes(b"w")
    return root


def test_the_cache_is_purged_when_the_plan_expires(box):
    box["put"](_env())
    assert box["run"]() == "stage_started"
    root = _cache()
    exp = json.loads((box["state"] / "applied.json").read_text())["expires_at"]
    assert box["run"](now=exp + 1) == "expired_torn_down"
    assert not (root / "rpc").exists() and root.exists()


def test_the_cache_is_purged_on_revocation(box):
    box["put"](_env())
    assert box["run"]() == "stage_started"
    root = _cache()
    rv = box["tmp"] / "split-revoke"
    rv.write_text(json.dumps({"plan_id": json.loads((box["state"] / "applied.json").read_text())["plan_id"]}))
    os.chmod(rv, 0o600)
    assert box["run"](revoke=rv) == "revoked_torn_down"
    assert not (root / "rpc").exists()


def test_the_cache_is_kept_for_the_same_coordinator_and_purged_for_another(box):
    box["put"](_env())
    assert box["run"]() == "stage_started"                     # first plan: nothing recorded -> purge (nothing there)
    root = _cache()
    box["put"](_env(nonce=os.urandom(16).hex()))
    assert box["run"]() == "stage_started"
    assert (root / "rpc" / "sha256t-0000000000000001").exists()    # same coordinator: the weights are its own
    box["put"](_env(members=(("other", "10.44.0.3", [0, 30]), ("me", "10.44.0.2", [30, 48])), coordinator="other",
                    nonce=os.urandom(16).hex()))
    assert box["run"]() == "stage_started"
    assert not (root / "rpc").exists()                             # another coordinator: purged before the start


def test_a_failed_purge_is_retried_at_the_next_start(box, monkeypatch):
    # auditor 16:50Z nit: the new coordinator is recorded only after a successful purge
    box["put"](_env())
    assert box["run"]() == "stage_started"
    root = _cache()
    other = dict(members=(("other", "10.44.0.3", [0, 30]), ("me", "10.44.0.2", [30, 48])), coordinator="other")

    real, fail = L.shutil.rmtree, [True]

    def once(p):
        if fail.pop() if fail else False:
            raise OSError("busy")
        real(p)
    monkeypatch.setattr(L.shutil, "rmtree", once)
    box["put"](_env(nonce=os.urandom(16).hex(), **other))
    assert box["run"]() != "stage_started"                         # the purge failed: no start
    assert (root / "rpc").exists()
    box["put"](_env(nonce=os.urandom(16).hex(), **other))
    assert box["run"]() == "stage_started"
    assert not (root / "rpc").exists()                             # same "new" coordinator, still purged


def test_a_symlinked_cache_dir_is_unlinked_never_followed(tmp_path):
    target = tmp_path / "precious"
    target.mkdir()
    (target / "keep").write_text("x")
    root = L.STAGE_CACHE_ROOT
    root.mkdir(parents=True, exist_ok=True)
    (root / "rpc").symlink_to(target)
    L.purge_stage_cache()
    assert not (root / "rpc").exists() and (target / "keep").exists()
