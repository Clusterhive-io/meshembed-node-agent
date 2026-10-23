"""Router R4 corroboration (auditor 2026-10-21 20:05Z): the node reports battery presence/plugged as psutil sees it;
'cannot tell' is omitted (the backend never reads a missing report as a desktop)."""
from types import SimpleNamespace

from meshembed_node import worker


def test_no_battery_is_reported_as_absent(monkeypatch):
    monkeypatch.setattr(worker.psutil, "sensors_battery", lambda: None)
    assert worker._battery_report() == {"present": False}


def test_a_battery_reports_present_and_plugged(monkeypatch):
    monkeypatch.setattr(worker.psutil, "sensors_battery", lambda: SimpleNamespace(power_plugged=False, percent=50))
    assert worker._battery_report() == {"present": True, "plugged": False}
    monkeypatch.setattr(worker.psutil, "sensors_battery", lambda: SimpleNamespace(power_plugged=None, percent=50))
    assert worker._battery_report() == {"present": True, "plugged": None}


def test_cannot_tell_is_omitted(monkeypatch):
    def boom():
        raise RuntimeError("no sensors")
    monkeypatch.setattr(worker.psutil, "sensors_battery", boom)
    assert worker._battery_report() is None
    monkeypatch.delattr(worker.psutil, "sensors_battery")
    assert worker._battery_report() is None
