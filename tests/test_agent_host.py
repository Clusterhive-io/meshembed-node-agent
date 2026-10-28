"""AR1 G9 agent side (auditor 13:19Z S1, S3, S5; A10 G5, G8): the loop, the checks, the checkpoints."""
import json
import os
import stat

import pytest

from meshembed_node import agent_host as A

RUN = {"ticket_id": "rt-" + "a" * 24, "run_id": "run-" + "b" * 24, "user_id": "u-opaque-7",
       "task": "TEST TASK: add 2 and 2. See https://example.test/doc", "class_ceiling": "internal",
       "models": ["meshembed/qwen3-4b-q8"], "tools": ["calc"],
       "budgets": {"steps": 3, "tool_calls": 10, "tokens": 1000, "wall_s": 600}, "expires_at": 10 ** 10}
HOST_KEY = b"\x01" * 32


class FakeBridge:
    def __init__(self, answers, run=RUN, resume_ok=True):
        self.answers, self.run, self.resume_ok, self.calls = list(answers), dict(run), resume_ok, []

    def call(self, op, **kw):
        self.calls.append((op, kw))
        if op == "next_run":
            return {"ok": self.run}
        if op == "resume":
            return {"ok": self.run} if self.resume_ok else {"code": "definition_revoked"}
        if op == "step":
            a = self.answers.pop(0)
            return a if isinstance(a, dict) and ("ok" in a or "code" in a) else \
                {"ok": {"choices": [{"message": {"content": a}}]}}
        if op in ("result", "state"):
            return {"ok": op}
        return {"code": "bad_message"}


def test_done_on_a_passing_answer():
    br = FakeBridge(["4"])
    assert A.run_once(br) == "done"
    step = [c for c in br.calls if c[0] == "step"][0][1]
    assert step["request"]["model"] == "meshembed/qwen3-4b-q8" and step["request"]["builtin_tools"] is True
    assert ("result", {"ticket_id": RUN["ticket_id"], "answer": "4"}) in br.calls


def test_no_tools_in_the_definition_no_tools_asked():
    br = FakeBridge(["4"], run=dict(RUN, tools=[]))
    A.run_once(br)
    assert "builtin_tools" not in [c for c in br.calls if c[0] == "step"][0][1]["request"]


def test_a_failed_check_goes_back_to_the_model_then_the_budget_stops_it():
    br = FakeBridge(["", "see https://attacker.test/x?d=secret", "  "])
    assert A.run_once(br) == "stopped:steps_exhausted"
    second = [c for c in br.calls if c[0] == "step"][1][1]["request"]["messages"]
    assert "empty_answer" in second[-1]["content"]
    assert br.calls[-1] == ("state", {"ticket_id": RUN["ticket_id"], "code": "steps_exhausted"})


@pytest.mark.parametrize("answer,code", [
    ("", "empty_answer"), (None, "empty_answer"), ("x" * (A.MAX_ANSWER_CHARS + 1), "answer_too_long"),
    ("![x](https://attacker.test/p.png)", "remote_url_not_in_task"),          # G5: rendering exfiltration
    ("as in https://example.test/doc", None),                                 # a URL the task itself contains
])
def test_checks(answer, code):
    assert A.check_answer(answer, RUN["task"]) == code


def test_step_errors_and_wall_time_stop_the_run():
    assert A.run_once(FakeBridge([{"code": "run_budget_exhausted"}])) == "stopped:run_budget_exhausted"
    t = [0.0]

    def clock():
        t[0] += 400
        return t[0]
    assert A.run_once(FakeBridge(["", "", ""]), clock=clock) == "stopped:wall_time_exhausted"


def test_checkpoints_are_bound_to_run_user_and_step(tmp_path):
    A.save_checkpoint(tmp_path, HOST_KEY, RUN, 2, [{"role": "user", "content": "x"}])
    p = tmp_path / f"{RUN['ticket_id']}.ckpt"
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    assert A.load_checkpoint(tmp_path, HOST_KEY, RUN) == (2, [{"role": "user", "content": "x"}])
    raw = p.read_text()
    assert "content" not in raw and RUN["task"] not in raw                     # encrypted at rest
    # S5: moved to another run's or user's slot, or replayed to another step: does not decrypt
    assert A.load_checkpoint(tmp_path, HOST_KEY, dict(RUN, run_id="run-" + "c" * 24)) is None
    assert A.load_checkpoint(tmp_path, HOST_KEY, dict(RUN, user_id="u-other")) is None
    rec = json.loads(raw)
    rec["step"] = 1
    p.write_text(json.dumps(rec))
    assert A.load_checkpoint(tmp_path, HOST_KEY, RUN) is None
    other = dict(RUN, ticket_id="rt-" + "d" * 24)
    assert A.load_checkpoint(tmp_path, HOST_KEY, other, path=p) is None
    assert A.load_checkpoint(tmp_path, b"\x02" * 32, RUN) is None              # another host key


def test_resume_continues_from_the_checkpoint_and_purges_on_done(tmp_path):
    msgs = [{"role": "user", "content": RUN["task"]}, {"role": "assistant", "content": ""},
            {"role": "user", "content": "fix"}]
    A.save_checkpoint(tmp_path, HOST_KEY, RUN, 1, msgs)
    assert A.pending_resumes(tmp_path) == [(RUN["ticket_id"], RUN["run_id"])]
    br = FakeBridge(["4"])
    assert A.run_once(br, state_dir=tmp_path, host_key=HOST_KEY, resume=A.pending_resumes(tmp_path)[0]) == "done"
    assert br.calls[0] == ("resume", {"ticket_id": RUN["ticket_id"], "run_id": RUN["run_id"]})
    assert [c for c in br.calls if c[0] == "step"][0][1]["request"]["messages"] == msgs
    assert not list(tmp_path.glob("*.ckpt"))


def test_a_refused_resume_drops_the_state(tmp_path):
    A.save_checkpoint(tmp_path, HOST_KEY, RUN, 1, [])
    assert A.run_once(FakeBridge([], resume_ok=False), state_dir=tmp_path, host_key=HOST_KEY,
                      resume=(RUN["ticket_id"], RUN["run_id"])) == "definition_revoked"
    assert not list(tmp_path.glob("*.ckpt"))


def test_failed_checks_are_checkpointed(tmp_path):
    A.run_once(FakeBridge(["", "", ""]), state_dir=tmp_path, host_key=HOST_KEY)
    assert not list(tmp_path.glob("*.ckpt"))                                   # purged at the stop
    br = FakeBridge(["", {"code": "step_failed"}])
    A.run_once(br, state_dir=tmp_path, host_key=HOST_KEY)
    assert not list(tmp_path.glob("*.ckpt"))


def test_the_agent_module_opens_no_network_socket():
    src = open(A.__file__).read()
    assert "AF_INET" not in src and "requests" not in src and "http.client" not in src and "urllib" not in src
    assert "socket.AF_UNIX" in src                                             # S1: the daemon socket only
