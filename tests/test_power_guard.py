"""On battery, a node does not work. At any cap, for any operator.

A laptop is not a small desktop: four cores at 100% draw two to three times
idle, so an unnoticed hour of inference is a visibly flat battery and an
audible fan. Neither is a policy problem -- both are why a node gets
uninstalled, and an uninstalled node is worth less than a slow one.

The guard is deliberately not part of the negotiated envelope: it applies
even to an operator who never configured a reservation, which is most of
them.
"""
from __future__ import annotations

import pathlib
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from meshembed_node import resources, worker  # noqa: E402

pytestmark = pytest.mark.unit


def _battery(monkeypatch, plugged=True, percent=100.0):
    monkeypatch.setattr(resources, "_battery",
                        lambda: SimpleNamespace(power_plugged=plugged, percent=percent))


def test_a_desktop_is_never_blocked(monkeypatch):
    """No battery, no question -- and it costs one call to find out."""
    monkeypatch.setattr(resources, "_battery", lambda: None)
    assert resources.power_block_reason() is None
    assert resources.power_block_reason({"pause_when_busy": True}) is None


def test_on_battery_blocks(monkeypatch):
    _battery(monkeypatch, plugged=False, percent=95.0)
    assert resources.power_block_reason() == "on_battery"


def test_a_full_battery_on_mains_does_not_block(monkeypatch):
    _battery(monkeypatch, plugged=True, percent=95.0)
    assert resources.power_block_reason() is None


def test_charging_from_flat_still_blocks(monkeypatch):
    """Plugged in but under the floor: taking cores from a laptop trying to
    recover is the same insult more slowly."""
    _battery(monkeypatch, plugged=True, percent=8.0)
    assert resources.power_block_reason() == "battery_low"


def test_the_floor_is_configurable(monkeypatch):
    _battery(monkeypatch, plugged=True, percent=30.0)
    assert resources.power_block_reason() is None
    assert resources.power_block_reason({"min_battery_pct": 50}) == "battery_low"


def test_a_docked_machine_can_opt_out(monkeypatch):
    """Reports a battery it never runs on."""
    _battery(monkeypatch, plugged=False, percent=5.0)
    assert resources.power_block_reason({"ignore_battery": True}) is None


def test_a_bad_reading_never_blocks_the_node(monkeypatch):
    """A metrics hiccup must not silently idle a fleet."""
    class _Bad:
        @property
        def power_plugged(self):
            raise OSError("acpi went away")
    monkeypatch.setattr(resources, "_battery", lambda: _Bad())
    assert resources.power_block_reason() is None


def test_the_guard_applies_with_no_operator_limits_at_all(monkeypatch):
    """The case that matters: an operator who configured nothing."""
    _battery(monkeypatch, plugged=False, percent=90.0)
    assert worker._should_pause(None) is True
    assert worker._should_pause({}) is True


def test_it_is_checked_before_the_busy_back_off(monkeypatch):
    """pause_when_busy is off, so only the power guard can pause here."""
    _battery(monkeypatch, plugged=False, percent=90.0)
    assert worker._should_pause({"pause_when_busy": False}) is True
