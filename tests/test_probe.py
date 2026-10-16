"""M2 build #4, node half: measure only the members of a VERIFIED probe plan, numbers only."""
from __future__ import annotations

import base64
import json
import socket
import time
from pathlib import Path

import pytest

from meshembed_node import probe as P
from meshembed_node import split_plan_verify as V

pytestmark = pytest.mark.unit

GOLD = json.loads((Path(__file__).parent / "fixtures" / "split_plan_golden.json").read_text())
TRUST = {"v1": GOLD["public_key_b64"]}
WG = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="


def _probe_env(members, *, kind="probe", lifetime=600, nonce="ab" * 16):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    k = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(GOLD["seed_hex"]))
    probe = kind == "probe"
    body = {"v": 2, "type": "meshembed.split_plan", "kind": kind, "plan_id": "sp-probe0000000000000000000",
            "job_id": None if probe else "job-1", "model_sha": None if probe else "0" * 64,
            "coordinator": None if probe else members[0][0],
            "members": [{"node_id": n, "overlay_ip": ip, "wg_pubkey": WG,
                         "layers": None if probe else [i, i + 1], "endpoint": None} for i, (n, ip) in enumerate(members)],
            "expires_at": int(time.time()) + lifetime, "nonce": nonce}
    return {"plan": body, "sig": base64.b64encode(k.sign(V.canonical(body))).decode(), "kid": "v1"}


class FakeBackend:
    def __init__(self, env):
        self.env, self.reports = env, []

    def __call__(self, path, payload):
        if path == "/node_probe_plan":
            assert payload == {"node_id": "me"}
            return {"plan": self.env}
        assert path == "/node_probe_report"
        self.reports.append(payload)
        return {"ok": True, "stored": len(payload["results"])}


MEMBERS = [("me", "10.44.0.1"), ("peer-a", "10.44.0.2"), ("peer-b", "10.44.0.3")]


def test_measures_only_the_other_members_and_reports_numbers_only(tmp_path):
    be, asked = FakeBackend(_probe_env(MEMBERS)), []
    n = P.run_once(be, "me", nonces=V.NonceStore(tmp_path / "n.json"), trusted=TRUST,
                   measure_fn=lambda ip: asked.append(ip) or 1.5)
    assert n == 2 and asked == ["10.44.0.2", "10.44.0.3"]                 # never itself, nothing else
    assert be.reports == [{"node_id": "me", "plan_id": "sp-probe0000000000000000000",
                           "results": [{"peer_node_id": "peer-a", "rtt_ms": 1.5},
                                       {"peer_node_id": "peer-b", "rtt_ms": 1.5}]}]


def test_an_unverified_plan_measures_nothing(tmp_path):
    """No compiled-in key (today's daemons): every plan refused, no packet sent, no report."""
    be, asked = FakeBackend(_probe_env(MEMBERS)), []
    assert P.run_once(be, "me", nonces=V.NonceStore(tmp_path / "n.json"),
                      measure_fn=lambda ip: asked.append(ip) or 1.0) is None
    assert asked == [] and be.reports == []


def test_a_tampered_target_is_refused_before_any_measurement(tmp_path):
    env = _probe_env(MEMBERS)
    env["plan"]["members"][1]["overlay_ip"] = "10.44.9.9"            # redirect a probe -> sig fails
    be, asked = FakeBackend(env), []
    assert P.run_once(be, "me", nonces=V.NonceStore(tmp_path / "n.json"), trusted=TRUST,
                      measure_fn=lambda ip: asked.append(ip) or 1.0) is None
    assert asked == [] and be.reports == []


def test_a_split_plan_is_not_a_probe_plan(tmp_path):
    be, asked = FakeBackend(_probe_env(MEMBERS, kind="primary")), []
    assert P.run_once(be, "me", nonces=V.NonceStore(tmp_path / "n.json"), trusted=TRUST,
                      measure_fn=lambda ip: asked.append(ip) or 1.0) is None
    assert asked == []


def test_a_plan_not_naming_this_node_measures_nothing(tmp_path):
    be, asked = FakeBackend(_probe_env([("x", "10.44.0.5"), ("y", "10.44.0.6")])), []
    assert P.run_once(be, "me", nonces=V.NonceStore(tmp_path / "n.json"), trusted=TRUST,
                      measure_fn=lambda ip: asked.append(ip) or 1.0) is None
    assert asked == []


def test_unreachable_peers_are_left_out_and_nothing_measured_sends_no_report(tmp_path):
    be = FakeBackend(_probe_env(MEMBERS))
    assert P.run_once(be, "me", nonces=V.NonceStore(tmp_path / "n.json"), trusted=TRUST,
                      measure_fn=lambda ip: None) == 0
    assert be.reports == []
    be2 = FakeBackend(_probe_env(MEMBERS, nonce="cd" * 16))
    P.run_once(be2, "me", nonces=V.NonceStore(tmp_path / "n.json"), trusted=TRUST,
               measure_fn=lambda ip: 2.0 if ip.endswith(".3") else None)
    assert be2.reports[0]["results"] == [{"peer_node_id": "peer-b", "rtt_ms": 2.0}]


def test_no_plan_pending_is_a_no_op(tmp_path):
    assert P.run_once(lambda path, payload: {"plan": None}, "me", trusted=TRUST,
                      nonces=V.NonceStore(tmp_path / "n.json")) is None


def test_off_unless_enabled(monkeypatch):
    monkeypatch.delenv("MESHEMBED_ENABLE_SPLIT", raising=False)
    assert P.enabled() is False
    monkeypatch.setenv("MESHEMBED_ENABLE_SPLIT", "1")
    assert P.enabled() is True


def test_tcp_fallback_measures_a_round_trip_when_icmp_is_refused():
    """Closed port -> RST -> one RTT; open port -> SYN/ACK -> one RTT. No exec, no listener of ours."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    try:
        port = srv.getsockname()[1]
        assert len(P._tcp_rtts("127.0.0.1", 3, 1.0, port=port)) == 3
    finally:
        srv.close()
    assert len(P._tcp_rtts("127.0.0.1", 2, 1.0, port=port)) == 2          # now closed: RST
    assert P.measure("127.0.0.1", pings=2, timeout=1.0, icmp_socket=lambda: None) is not None


def test_no_answer_is_no_number():
    # TEST-NET-1 is never routed: timeout / unreachable -> None, never a made-up value
    assert P.measure("192.0.2.1", pings=1, timeout=0.3, icmp_socket=lambda: None) is None


def test_icmp_is_used_when_the_kernel_allows_it():
    sock = P._icmp_socket()
    if sock is None:
        pytest.skip("net.ipv4.ping_group_range excludes this gid (the TCP fallback covers it)")
    sock.close()
    assert P.measure("127.0.0.1", pings=2, timeout=1.0) is not None
