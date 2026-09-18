"""Heat and metered links: the two remaining laptop guards."""
from __future__ import annotations

import pathlib
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from meshembed_node import llm, resources, worker  # noqa: E402

pytestmark = pytest.mark.unit


def test_unknown_temperature_is_not_hot():
    assert resources.too_hot({}, temp=None) is None


def test_the_ceiling_is_configurable_and_defaults_to_85():
    assert resources.too_hot({}, temp=84.9) is None
    assert resources.too_hot({}, temp=85.0) == 85.0
    assert resources.too_hot({"max_temp_c": 70}, temp=72.0) == 72.0


def test_cpu_temp_reads_the_hottest_cpu_sensor(monkeypatch):
    import psutil
    fake = {"coretemp": [SimpleNamespace(current=61.0), SimpleNamespace(current=73.5)],
            "nvme": [SimpleNamespace(current=99.0)]}
    monkeypatch.setattr(psutil, "sensors_temperatures", lambda: fake)
    assert resources.cpu_temp_c() == 73.5


def test_a_hot_machine_pauses_even_with_no_operator_limits(monkeypatch):
    monkeypatch.setattr(resources, "_battery", lambda: None)
    monkeypatch.setattr(resources, "cpu_temp_c", lambda: 91.0)
    assert worker._should_pause({}) is True
    monkeypatch.setattr(resources, "cpu_temp_c", lambda: 60.0)
    monkeypatch.setattr(resources, "over_ram_cap", lambda limits: None)
    assert worker._should_pause({}) is False


def test_metered_link_blocks_the_fetch_unless_allowed():
    assert resources.weights_fetch_allowed({}, metered=True) is False
    assert resources.weights_fetch_allowed({}, metered=False) is True
    assert resources.weights_fetch_allowed({}, metered=None) is True          # unknown = unmetered
    assert resources.weights_fetch_allowed({"allow_metered_downloads": True}, metered=True) is True


def test_ensure_model_refuses_on_a_metered_link(monkeypatch, tmp_path):
    monkeypatch.setattr(llm, "MIRROR", "http://mirror.example/gguf")
    monkeypatch.setattr(llm, "_verified_path", lambda spec: None)
    monkeypatch.setattr(resources, "network_is_metered", lambda: True)
    llm.set_limits({})
    spec = SimpleNamespace(model_id="m", file="m.gguf", sha256="a" * 64, size_mb=1, min_ram_gb=1, context=512)
    assert llm.ensure_model(spec) is None
    llm.set_limits({"allow_metered_downloads": True})
    # with the override the fetch proceeds past the guard (and fails on the fake mirror, which is fine here)
    monkeypatch.setattr(llm, "CACHE_DIR", tmp_path)
    try:
        llm.ensure_model(spec, timeout=1)
    except Exception:
        pass
    llm.set_limits({})
