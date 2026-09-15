"""Why a machine is not serving generation, as the machine sees it.

"Not ready" has five causes and they looked identical from outside: no
runtime, no mirror, too little RAM, too little disk, or simply not warmed
yet. The daemon knows which; these pin that it says so, and that computing
it can never break a poll.
"""
from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from meshembed_node import llm  # noqa: E402

pytestmark = pytest.mark.unit


def _spec(model_id="m", min_ram_gb=4.0):
    return llm.ModelSpec(model_id=model_id, file="f.gguf", sha256="0" * 64,
                         size_mb=100, min_ram_gb=min_ram_gb, context=2048)


def _patch(monkeypatch, *, runtime=True, mirror="https://m", ram=16.0,
           catalog=None, on_disk=False, free_disk=100.0):
    monkeypatch.setattr(llm, "runtime_available", lambda: runtime)
    monkeypatch.setattr(llm, "MIRROR", mirror)
    monkeypatch.setattr(llm, "_usable_ram_gb", lambda: ram)
    monkeypatch.setattr(llm, "load_catalog", lambda: catalog if catalog is not None else {"m": _spec()})
    monkeypatch.setattr(llm, "_verified_path", lambda s: pathlib.Path("/x") if on_disk else None)
    monkeypatch.setattr(llm, "_free_disk_gb", lambda p: free_disk)


def test_no_runtime_is_reported_as_such(monkeypatch):
    """The operator never opted in -- not a fault, and not the same thing as
    a missing mirror."""
    _patch(monkeypatch, runtime=False)
    assert llm.readiness()["blocked"] == "no_runtime"


def test_a_runtime_with_nowhere_to_fetch_from_says_no_mirror(monkeypatch):
    _patch(monkeypatch, mirror="")
    r = llm.readiness()
    assert r["blocked"] == "no_mirror" and r["runtime"] is True and r["mirror"] is False


def test_a_machine_too_small_for_anything_in_the_catalogue(monkeypatch):
    _patch(monkeypatch, ram=1.0, catalog={"m": _spec(min_ram_gb=8.0)})
    r = llm.readiness()
    assert r["blocked"] == "insufficient_ram" and r["fits"] == 0


def test_a_full_disk_is_distinguished_from_a_missing_mirror(monkeypatch):
    _patch(monkeypatch, free_disk=0.5)
    assert llm.readiness()["blocked"] == "insufficient_disk"


def test_everything_in_place_but_not_fetched_yet_is_warming(monkeypatch):
    _patch(monkeypatch)
    assert llm.readiness()["blocked"] == "warming"


def test_a_serving_node_is_not_blocked_at_all(monkeypatch):
    _patch(monkeypatch, on_disk=True)
    r = llm.readiness()
    assert r["blocked"] is None and r["models_ready"] == 1


def test_ram_is_measured_as_available_not_installed(monkeypatch):
    """A workstation whose owner is using it must not be handed a model it
    cannot fit -- the same rule servable_models applies."""
    _patch(monkeypatch, ram=3.9, catalog={"m": _spec(min_ram_gb=4.0)})
    assert llm.readiness()["blocked"] == "insufficient_ram"


def test_it_never_raises_and_says_unknown_instead(monkeypatch):
    """Computing a diagnostic must never cost the node its poll."""
    def boom():
        raise RuntimeError("psutil exploded")
    monkeypatch.setattr(llm, "runtime_available", boom)
    assert llm.readiness()["blocked"] == "unknown"
