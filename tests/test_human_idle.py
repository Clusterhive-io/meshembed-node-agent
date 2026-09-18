"""The human, not the load: an unattended machine is usable capacity."""
from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from meshembed_node import resources, worker  # noqa: E402

pytestmark = pytest.mark.unit


def test_away_needs_a_measured_idle_time():
    assert resources.human_is_away({}, idle=None) is False          # unknowable is not away
    assert resources.human_is_away({}, idle=599.0) is False
    assert resources.human_is_away({}, idle=600.0) is True
    assert resources.human_is_away({"idle_override_s": 120}, idle=130.0) is True


def test_an_unattended_machine_is_not_paused_by_the_load_reserve(monkeypatch):
    """The owner reserved 2 cores; the box is at 100% because a backup runs;
    nobody has typed for 15 minutes -> work."""
    monkeypatch.setattr(resources, "_battery", lambda: None)
    monkeypatch.setattr(resources, "over_ram_cap", lambda limits: None)
    monkeypatch.setattr(resources, "human_idle_seconds", lambda: 900.0)
    import psutil
    monkeypatch.setattr(psutil, "cpu_percent", lambda interval=0: 100.0)
    assert worker._should_pause({"pause_when_busy": True, "reserve_cpu_cores": 2}) is False


def test_a_present_owner_still_gets_the_reserve(monkeypatch):
    monkeypatch.setattr(resources, "_battery", lambda: None)
    monkeypatch.setattr(resources, "over_ram_cap", lambda limits: None)
    monkeypatch.setattr(resources, "human_idle_seconds", lambda: 5.0)
    import psutil
    monkeypatch.setattr(psutil, "cpu_percent", lambda interval=0: 100.0)
    monkeypatch.setattr(psutil, "cpu_count", lambda: 4)
    assert worker._should_pause({"pause_when_busy": True, "reserve_cpu_cores": 2}) is True


def test_headless_boxes_keep_the_old_rule(monkeypatch):
    monkeypatch.setattr(resources, "_battery", lambda: None)
    monkeypatch.setattr(resources, "over_ram_cap", lambda limits: None)
    monkeypatch.setattr(resources, "human_idle_seconds", lambda: None)
    import psutil
    monkeypatch.setattr(psutil, "cpu_percent", lambda interval=0: 100.0)
    monkeypatch.setattr(psutil, "cpu_count", lambda: 4)
    assert worker._should_pause({"pause_when_busy": True, "reserve_cpu_cores": 2}) is True


def test_idle_probe_never_raises(monkeypatch):
    import subprocess
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(OSError("no tool")))
    assert resources.human_idle_seconds() in (None, 0.0) or isinstance(resources.human_idle_seconds(), float)
