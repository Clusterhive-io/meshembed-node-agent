"""PN-3 (SV-PIN-1's node half; auditor 2026-11-02 17:34:57Z): the serve duty starts a plan only for a model ticked on
this node (the poll's pinned_models; empty/null = serve nothing), stops at once when its model is unticked, and acts on
nothing when a poll does not carry the key (unknown)."""
from __future__ import annotations

import pytest

from test_serve_duty import World
from test_serve_mvp import _plan, host  # noqa: F401

pytestmark = pytest.mark.unit
MODEL = "meshembed/qwen3-4b-q8"                         # what World's model_id_for answers


@pytest.fixture
def w(tmp_path):
    return World(tmp_path)


@pytest.mark.parametrize("pins", [[], None, ["meshembed/other-model"]])
def test_a_plan_for_an_unticked_model_is_never_started(w, pins):
    d = w.duty()
    d.on_get_job({"serve_plans": [_plan(draft_sha=None)], "pinned_models": pins})
    assert w.request() is None and w.staged == []


def test_a_ticked_model_starts(w):
    d = w.duty()
    env = _plan(draft_sha=None)
    d.on_get_job({"serve_plans": [env], "pinned_models": [MODEL]})
    assert w.request() == {"action": "start", "plan": env}


def test_unticking_the_running_model_stops_it_at_once(w):
    d = w.duty()
    env = _plan(draft_sha=None)
    d.on_get_job({"serve_plans": [env], "pinned_models": [MODEL]})
    w.running = "sv-1"
    w.req.write_text("")
    d.on_get_job({"serve_plans": [env], "pinned_models": []})
    r = w.request()
    assert r["action"] == "stop" and "model_not_ticked" in r["reason"]


def test_a_poll_without_the_key_starts_nothing_and_stops_nothing(w):
    d = w.duty()
    env = _plan(draft_sha=None)
    raw_on_get_job = type(d).on_get_job                    # bypass World's default tick
    raw_on_get_job(d, {"serve_plans": [env]})
    assert w.request() is None
    d.on_get_job({"serve_plans": [env], "pinned_models": [MODEL]})
    assert w.request()["action"] == "start"
    w.running = "sv-1"
    w.req.write_text("")
    raw_on_get_job(d, {"serve_plans": [env]})
    assert w.request() is None                             # unknown: the running plan is not stopped
