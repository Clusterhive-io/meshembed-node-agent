"""The platform pushes the model mirror; the node adopts and persists it.

Until now the weights source was an SSH hop per machine. The inference switch
had removed SSH from installing the runtime; this removes it from the source.
A value on the poll wins over the machine's environment while set (the
dashboard must be able to correct a stale machine); absent/empty leaves the
environment alone; a bad value is ignored and the node keeps working.
"""
from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from meshembed_node import llm, worker  # noqa: E402

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    persisted = {}
    monkeypatch.setattr(worker, "_persist_env_flag", lambda k, v: persisted.__setitem__(k, v))
    monkeypatch.setattr(worker, "_schedule_warm", lambda pinned: persisted.setdefault("_warm_calls", []).append(pinned))
    monkeypatch.setattr(llm, "MIRROR", "")
    monkeypatch.delenv("MESHEMBED_GGUF_MIRROR", raising=False)
    monkeypatch.setattr(worker, "_MIRROR_ADOPTED", None)
    return persisted


def test_a_pushed_mirror_is_adopted_and_persisted(_isolate):
    assert worker._adopt_mirror("http://192.168.30.188:18081/gguf/") is True
    assert llm.MIRROR == "http://192.168.30.188:18081/gguf"          # trailing slash gone
    assert _isolate["MESHEMBED_GGUF_MIRROR"] == "http://192.168.30.188:18081/gguf"


def test_the_platform_value_wins_over_the_machine_environment(_isolate, monkeypatch):
    """A stale machine must be correctable from the dashboard."""
    monkeypatch.setattr(llm, "MIRROR", "https://old.example/gguf")
    assert worker._adopt_mirror("https://new.example/gguf") is True
    assert llm.MIRROR == "https://new.example/gguf"


def test_absent_or_empty_leaves_the_environment_alone(_isolate, monkeypatch):
    monkeypatch.setattr(llm, "MIRROR", "https://local.example/gguf")
    for v in (None, "", "   ", 0, {}):
        assert worker._adopt_mirror(v) is False
    assert llm.MIRROR == "https://local.example/gguf"
    assert _isolate == {}


def test_an_unchanged_value_does_not_rewrite_the_env_file(_isolate, monkeypatch):
    """Every poll carries the value; only a CHANGE touches disk."""
    monkeypatch.setattr(llm, "MIRROR", "https://m.example/gguf")
    assert worker._adopt_mirror("https://m.example/gguf") is False
    assert _isolate == {}


def test_a_change_schedules_a_warm_pass_with_the_pinned_set(_isolate):
    """Warming runs at boot and on a pin change only; a mirror arriving
    mid-life must trigger the fetch it just made possible, or the node clears
    no_mirror and still holds nothing until a restart."""
    assert worker._adopt_mirror("https://m.example/gguf", ["meshembed/qwen2.5-3b-instruct-q4"]) is True
    assert _isolate["_warm_calls"] == [["meshembed/qwen2.5-3b-instruct-q4"]]


def test_no_change_no_warm_pass(_isolate, monkeypatch):
    monkeypatch.setattr(llm, "MIRROR", "https://m.example/gguf")
    worker._adopt_mirror("https://m.example/gguf", None)
    worker._adopt_mirror("", None)
    assert "_warm_calls" not in _isolate


def test_a_bad_scheme_is_ignored_and_the_node_keeps_working(_isolate, monkeypatch):
    monkeypatch.setattr(llm, "MIRROR", "https://good.example/gguf")
    assert worker._adopt_mirror("ftp://x/y") is False
    assert worker._adopt_mirror("javascript:alert(1)") is False
    assert llm.MIRROR == "https://good.example/gguf"


def test_readiness_sees_the_adopted_mirror(_isolate):
    """The readiness report reads the same global ensure_model does, so the
    dashboard's `no_mirror` clears on the very next poll."""
    worker._adopt_mirror("https://m.example/gguf")
    assert llm.MIRROR and llm.readiness().get("mirror") is True
