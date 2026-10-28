"""AR1 G9 daemon side (auditor 13:19Z S1, S2): the agent's only door. Golden vectors from shared/run_ticket_golden.json."""
import json
import os
import socket
import stat
import threading
from pathlib import Path

import pytest

from meshembed_node import agent_bridge as B
from meshembed_node import run_ticket_verify as V

GOLD = json.loads((Path(__file__).parent / "fixtures" / "run_ticket_golden.json").read_text())
T = GOLD["valid"]["ticket"]
NOW = T["issued_at"] + 10
KEY = "meah_" + "k" * 43


class Backend:
    def __init__(self, status=200, out=None):
        self.calls, self.status, self.out = [], status, out

    def __call__(self, path, body, headers, timeout):
        self.calls.append((path, json.loads(json.dumps(body)), dict(headers)))
        if path.endswith("/state") and body["state"] == "started":
            return self.status, {}
        return self.status, (self.out if self.out is not None else {"choices": [{"message": {"content": "4"}}]})


@pytest.fixture
def bridge(tmp_path):
    rev = V.Revocations(tmp_path / "rev.json")
    rev.update([], [], NOW)
    ctx = dict(admin_keys={GOLD["keys"]["admin"]["kid"]: GOLD["keys"]["admin"]["pub"]}, revocations=rev,
               nonces=V.RunNonces(tmp_path / "n.json"), policy_versions=V.PolicyVersions(tmp_path / "pv.json"),
               trusted={GOLD["keys"]["ticket"]["kid"]: GOLD["keys"]["ticket"]["pub"]},
               plan_keys={GOLD["keys"]["plan"]["kid"]: GOLD["keys"]["plan"]["pub"]})
    be = Backend()
    b = B.AgentBridge(node_id="agent-host-1", tenant="t-pool-1", agent_uid=os.getuid(), post=be, lane_key=lambda: KEY,
                      verify_ctx=ctx, clock=lambda: NOW)
    return b, be


def item(**kw):
    i = {"ticket": GOLD["valid"], "task": GOLD["task_text"], "definition": GOLD["definition"],
         "policy": GOLD["policy_personal"]}
    i.update(kw)
    return i


def msg(b, **m):
    return b.handle(json.dumps(m).encode())


def test_a_verified_run_is_handed_over_without_the_key(bridge):
    b, be = bridge
    assert b.offer(item()) == "accepted"
    assert be.calls[-1] == (f"/agent/v1/runs/{T['ticket_id']}/state", {"state": "started"}, {"X-Agent-Host-Key": KEY})
    r = msg(b, op="next_run")["ok"]
    assert r["task"] == GOLD["task_text"] and r["ticket_id"] == T["ticket_id"] and r["run_id"].startswith("run-")
    assert r["models"] == ["meshembed/qwen3-4b-q8"] and r["class_ceiling"] == "internal"
    assert KEY not in json.dumps(r)                                     # S1: the agent never sees the lane key
    assert msg(b, op="next_run") == {"code": "no_run"}                   # handed out once


def test_a_rejected_ticket_is_reported_and_never_held(bridge):
    b, be = bridge
    assert b.offer(item(task="another text")) == "ticket_task_mismatch"
    assert be.calls[-1][1] == {"state": "stopped", "code": "ticket_task_mismatch"}
    assert msg(b, op="next_run") == {"code": "no_run"}
    assert b.offer({"ticket": GOLD["plan_to_ticket_verifier"]}) == "bad_item"


def test_no_start_recorded_no_run(bridge):
    b, be = bridge
    be.status = 409
    assert b.offer(item()) == "start_not_recorded" and msg(b, op="next_run") == {"code": "no_run"}


@pytest.mark.parametrize("raw,code", [
    (b"not json", "bad_message"),
    (b"\xff\xfe", "bad_message"),
    (b"[1]", "bad_message"),
    (json.dumps({"op": "exec", "cmd": "id"}).encode(), "bad_message"),
    (json.dumps({"op": "next_run", "extra": 1}).encode(), "bad_message"),
    (json.dumps({"op": "step", "ticket_id": "rt-" + "0" * 24}).encode(), "bad_message"),
    (b"[" * 5000, "bad_message"),
    (b"x" * (B.MAX_MSG + 1), "message_too_large"),
])
def test_hostile_messages_get_closed_codes(bridge, raw, code):
    b, _ = bridge
    assert b.handle(raw) == {"code": code}


def test_steps_only_for_tickets_handed_to_this_agent(bridge):
    b, be = bridge
    step = {"model": "meshembed/qwen3-4b-q8", "messages": [{"role": "user", "content": "x"}]}
    assert msg(b, op="step", ticket_id="rt-" + "a" * 24, request=step) == {"code": "ticket_not_held"}
    b.offer(item())
    assert msg(b, op="step", ticket_id=T["ticket_id"], request=step) == {"code": "ticket_not_held"}   # not handed yet
    msg(b, op="next_run")
    out = msg(b, op="step", ticket_id=T["ticket_id"], request=step)
    assert out["ok"]["choices"][0]["message"]["content"] == "4"
    assert be.calls[-1] == ("/agent/v1/steps/chat", {"ticket_id": T["ticket_id"], "request": step},
                            {"X-Agent-Host-Key": KEY})
    be.status, be.out = 403, {"detail": "model_not_in_definition"}
    assert msg(b, op="step", ticket_id=T["ticket_id"], request=step) == {"code": "model_not_in_definition"}
    be.out = {"detail": "a long sentence with /etc/passwd"}
    assert msg(b, op="step", ticket_id=T["ticket_id"], request=step) == {"code": "step_failed"}   # never echoed
    assert msg(b, op="step", ticket_id=T["ticket_id"], request="nope") == {"code": "bad_message"}


def test_result_and_state_forget_the_run(bridge):
    b, be = bridge
    b.offer(item())
    msg(b, op="next_run")
    assert msg(b, op="result", ticket_id=T["ticket_id"], answer="x" * (B.MAX_ANSWER_CHARS + 1)) == \
        {"code": "answer_too_large"}
    assert msg(b, op="result", ticket_id=T["ticket_id"], answer="done") == {"ok": "delivered"}
    assert be.calls[-1][0] == f"/agent/v1/runs/{T['ticket_id']}/result" and T["ticket_id"] not in b.runs
    assert msg(b, op="state", ticket_id=T["ticket_id"], code="done") == {"code": "ticket_not_held"}


def test_state_stop_codes_are_closed(bridge):
    b, be = bridge
    b.offer(item())
    msg(b, op="next_run")
    assert msg(b, op="state", ticket_id=T["ticket_id"], code="Not A Code!") == {"code": "bad_message"}
    assert msg(b, op="state", ticket_id=T["ticket_id"], code="budget_done") == {"ok": "stopped"}
    assert be.calls[-1][1] == {"state": "stopped", "code": "budget_done"} and not b.runs


def test_resume_goes_back_through_verify_ticket(bridge, tmp_path):
    b, be = bridge
    b.offer(item())
    run_id = msg(b, op="next_run")["ok"]["run_id"]
    assert msg(b, op="resume", ticket_id=T["ticket_id"], run_id="run-" + "0" * 24) == {"code": "ticket_not_held"}
    assert msg(b, op="resume", ticket_id=T["ticket_id"], run_id=run_id)["ok"]["run_id"] == run_id
    b.ctx["revocations"].update([("invoice-checker", 3)], [], NOW)
    assert msg(b, op="resume", ticket_id=T["ticket_id"], run_id=run_id) == {"code": "definition_revoked"}
    assert not b.runs                                                    # forgotten on a refused resume


def test_expired_tickets_are_not_live(bridge):
    b, be = bridge
    b.offer(item())
    msg(b, op="next_run")
    b.clock = lambda: T["expires_at"] + 1
    assert msg(b, op="step", ticket_id=T["ticket_id"], request={}) == {"code": "ticket_not_held"}


def test_no_lane_key_no_backend_call(bridge):
    b, be = bridge
    b.lane_key = lambda: None
    assert b.offer(item()) == "start_not_recorded" and be.calls == []


def _talk(b, payloads):
    srv, cli = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    t = threading.Thread(target=b.serve_connection, args=(srv,))
    t.start()
    replies = []
    try:
        for p in payloads:
            try:
                cli.sendall(p)
            except (BrokenPipeError, ConnectionResetError):
                replies.append(None)                                     # closed by the bridge: no reply
                continue
            data = b""
            cli.settimeout(2)
            try:
                while not data.endswith(b"\n"):
                    chunk = cli.recv(65536)
                    if not chunk:
                        break
                    data += chunk
            except socket.timeout:
                pass
            replies.append(json.loads(data) if data else None)
    finally:
        cli.close()
        t.join(5)
    return replies, t.is_alive()


def test_socket_peer_must_be_the_agent_uid(bridge):
    b, _ = bridge
    b.agent_uid = os.getuid() + 1
    replies, alive = _talk(b, [b'{"op": "next_run"}\n'])
    assert replies == [None] and not alive                               # closed, no reply


def test_socket_serves_lines_and_survives_garbage(bridge):
    b, _ = bridge
    b.offer(item())
    replies, alive = _talk(b, [b"garbage\n", b'{"op": "next_run"}\n'])
    assert replies[0] == {"code": "bad_message"} and replies[1]["ok"]["ticket_id"] == T["ticket_id"]
    replies, alive = _talk(b, [b"y" * (B.MAX_MSG + 70000)])
    assert replies == [{"code": "message_too_large"}] and not alive


def test_listen_requires_a_private_directory(bridge, tmp_path):
    b, _ = bridge
    d = tmp_path / "run"
    d.mkdir(mode=0o777)
    os.chmod(d, 0o777)
    with pytest.raises(PermissionError):
        b.listen(d / "agent.sock")
    os.chmod(d, 0o750)
    s = b.listen(d / "agent.sock")
    try:
        assert stat.S_IMODE(os.stat(d / "agent.sock").st_mode) == 0o660
    finally:
        s.close()


def test_read_lane_key(tmp_path):
    f = tmp_path / "lane.key"
    f.write_text(KEY + "\n")
    os.chmod(f, 0o644)
    assert B.read_lane_key(f) is None                                    # readable by others: refused
    os.chmod(f, 0o600)
    assert B.read_lane_key(f) == KEY
    f.write_text("not-a-key")
    assert B.read_lane_key(f) is None
    assert B.read_lane_key(tmp_path / "missing") is None
