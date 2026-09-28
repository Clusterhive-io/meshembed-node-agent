"""The node half of capacity-aware scheduling (docs/DESIGN_CAPACITY_AWARE_SCHEDULING.md).

Node 23711, 2026-09-27: a 16 GB hub fetched the 7B on a quiet moment, then took
a 3B item with ~230 MB available and sat in D state loading it.
"""
from __future__ import annotations

import pathlib
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from meshembed_node import llm, worker  # noqa: E402

pytestmark = pytest.mark.unit


def _spec(mid, ram):
    return SimpleNamespace(model_id=mid, file=mid + ".gguf", sha256="a" * 64, size_mb=100,
                           min_ram_gb=ram, context=2048, url=None)


@pytest.fixture(autouse=True)
def _reserve(monkeypatch):
    monkeypatch.setenv("MESHEMBED_RAM_RESERVE_MB", "2048")
    monkeypatch.setattr(llm, "_LOADED", None)


def test_the_reserve_is_reported_on_the_poll():
    assert worker._ram_reserve_mb() == 2048


def test_a_bad_reserve_value_falls_back_rather_than_breaking(monkeypatch):
    monkeypatch.setenv("MESHEMBED_RAM_RESERVE_MB", "lots")
    assert llm.ram_reserve_gb() == 1.0


def test_fits_now_keeps_the_reserve(monkeypatch):
    three_b = _spec("m", 4.0)
    monkeypatch.setattr(llm, "_usable_ram_gb", lambda: 0.23)      # the 23711 reading
    assert not llm.fits_now(three_b)
    monkeypatch.setattr(llm, "_usable_ram_gb", lambda: 5.0)       # 5 - 2 reserve = 3 < 4
    assert not llm.fits_now(three_b)
    monkeypatch.setattr(llm, "_usable_ram_gb", lambda: 6.5)
    assert llm.fits_now(three_b)


def test_the_resident_model_always_fits(monkeypatch):
    monkeypatch.setattr(llm, "_usable_ram_gb", lambda: 0.5)
    monkeypatch.setattr(llm, "_LOADED", ("m", 1.8))
    assert llm.fits_now(_spec("m", 4.0))


def test_the_resident_model_is_flagged_loaded(monkeypatch):
    cat = {"s": _spec("s", 1.5), "m": _spec("m", 4.0)}
    monkeypatch.setattr(llm, "runtime_available", lambda: True)
    monkeypatch.setattr(llm, "load_catalog", lambda *a, **k: cat)
    monkeypatch.setattr(llm, "_verified_path", lambda spec: "/x/" + spec.file)
    monkeypatch.setattr(llm, "_usable_ram_gb", lambda: 6.0)
    monkeypatch.setattr(llm, "_LOADED", ("m", 1.8))
    monkeypatch.setattr(llm, "execution_class", lambda: {})
    got = {e["model_id"]: e.get("loaded") for e in llm.installed_llm_models()}
    assert got == {"s": None, "m": True}


def test_warm_never_fetches_what_cannot_fit_beside_the_reserve(monkeypatch):
    """The momentary reading alone would allow it (11 - 2 reserve = 9 >= 8);
    total memory minus the reserve (10 - 2 = 8 < 8.5) does not."""
    cat = {"l": _spec("l", 8.5)}
    fetched = []
    monkeypatch.setattr(llm, "runtime_available", lambda: True)
    monkeypatch.setattr(llm, "load_catalog", lambda *a, **k: cat)
    monkeypatch.setattr(llm, "_verified_path", lambda spec: None)
    monkeypatch.setattr(llm, "_free_disk_gb", lambda p: 500.0)
    monkeypatch.setattr(llm, "ensure_model", lambda spec, *a, **k: fetched.append(spec.model_id) or "/x")
    monkeypatch.setattr(llm, "_usable_ram_gb", lambda: 11.0)
    monkeypatch.setattr(llm, "_total_ram_gb", lambda: 10.0)
    llm.warm_models()
    assert fetched == []
    monkeypatch.setattr(llm, "_total_ram_gb", lambda: 16.0)       # same reading, a bigger box
    llm.warm_models()
    assert fetched == ["l"]


def test_a_short_node_declines_instead_of_loading(monkeypatch):
    """The generate path reports declined:insufficient_memory, not generate_error."""
    import inspect
    src = inspect.getsource(worker)
    assert 'raise _Declined("insufficient_memory")' in src
    assert 'error = f"declined:{exc}"' in src
    assert src.index("if not _llm.fits_now(spec):") < src.index("_llm_runner().generate(")
