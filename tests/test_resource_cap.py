"""The lend envelope, enforced on the machine.

docs/NODE_RESOURCE_CAP.md. A lend schedule that only the scheduler honours is
a promise; this is the control. What must hold: a percentage or an explicit
core count becomes a real ceiling of at least one core, nonsense never
silently uncaps or zeroes a node, a RAM ceiling stops the daemon pulling work
rather than killing it mid-chunk, and none of it can stop a node working when
the platform lacks a feature.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from meshembed_node import resources as rs  # noqa: E402


# ── the ceiling arithmetic ─────────────────────────────────────────────────

def test_a_percentage_becomes_a_core_count():
    assert rs.cores_allowed({"max_cpu_pct": 25}, 16) == 4
    assert rs.cores_allowed({"max_cpu_pct": 50}, 8) == 4
    assert rs.cores_allowed({"max_cpu_pct": 10}, 4) == 1, "rounds down, never below one"


def test_an_explicit_core_count_is_honoured_and_clamped():
    assert rs.cores_allowed({"max_cpu_cores": 2}, 16) == 2
    assert rs.cores_allowed({"max_cpu_cores": 99}, 8) == 8, "cannot exceed the machine"


def test_percentage_wins_over_cores():
    """A fleet policy is expressed as a share; a per-node number is the
    exception. If both are set the share is the one that was meant."""
    assert rs.cores_allowed({"max_cpu_pct": 25, "max_cpu_cores": 15}, 16) == 4


def test_no_ceiling_is_none_not_zero():
    assert rs.cores_allowed(None, 8) is None
    assert rs.cores_allowed({}, 8) is None
    assert rs.cores_allowed({"max_cpu_pct": 100}, 8) is None, "100% is no ceiling"
    assert rs.cores_allowed({"pause_when_busy": True}, 8) is None


def test_nonsense_never_uncaps_or_zeroes_a_node():
    for bad in ({"max_cpu_pct": "half"}, {"max_cpu_pct": -5}, {"max_cpu_pct": 0},
                {"max_cpu_cores": "two"}, {"max_cpu_cores": 0}, {"max_cpu_cores": -1}):
        assert rs.cores_allowed(bad, 8) is None, f"{bad} should mean no ceiling, not a broken one"


# ── applying it ────────────────────────────────────────────────────────────

def test_applying_a_cap_sets_thread_limits_and_reports_the_truth(monkeypatch):
    for var in ("OMP_NUM_THREADS", "MKL_NUM_THREADS"):
        monkeypatch.delenv(var, raising=False)
    applied = rs.apply_cpu_cap({"max_cpu_cores": 1})
    assert applied["cores"] == 1 and applied["threads"] is True
    assert os.environ["OMP_NUM_THREADS"] == "1" and os.environ["MKL_NUM_THREADS"] == "1"
    assert applied["total_cores"] >= 1
    # The report says what actually happened: affinity and priority are
    # platform-dependent and must be observable, not assumed.
    assert set(applied) == {"total_cores", "cores", "threads", "affinity", "priority"}


def test_no_cap_leaves_the_machine_alone(monkeypatch):
    monkeypatch.delenv("OMP_NUM_THREADS", raising=False)
    applied = rs.apply_cpu_cap(None)
    assert applied["cores"] is None and applied["threads"] is False
    assert "OMP_NUM_THREADS" not in os.environ, "no ceiling must not pin threads"


def test_a_cap_at_or_above_the_machine_is_not_applied(monkeypatch):
    monkeypatch.delenv("OMP_NUM_THREADS", raising=False)
    total = os.cpu_count() or 1
    applied = rs.apply_cpu_cap({"max_cpu_cores": total + 5})
    assert applied["threads"] is False, "capping to more than the machine is no cap"


def test_applying_never_raises_even_without_psutil(monkeypatch):
    """A machine that cannot report itself must still work, with the weaker
    forms of the same cap."""
    import builtins
    real_import = builtins.__import__

    def no_psutil(name, *a, **kw):
        if name == "psutil":
            raise ImportError("no psutil here")
        return real_import(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", no_psutil)
    applied = rs.apply_cpu_cap({"max_cpu_cores": 1})
    assert applied["affinity"] is False and applied["priority"] is False
    assert applied["threads"] is True, "the portable half still applies"


# ── the RAM ceiling ────────────────────────────────────────────────────────

def test_ram_ceiling_reports_when_over_and_nothing_when_under():
    assert rs.over_ram_cap({"max_ram_gb": 0.000001}) is not None, "any process exceeds 1 KB"
    assert rs.over_ram_cap({"max_ram_gb": 10_000}) is None
    assert rs.over_ram_cap(None) is None and rs.over_ram_cap({}) is None
    for bad in ({"max_ram_gb": "lots"}, {"max_ram_gb": 0}, {"max_ram_gb": -2}):
        assert rs.over_ram_cap(bad) is None


def test_the_daemon_pauses_at_the_ram_ceiling_without_pause_when_busy():
    """The ceiling is not the back-off: it binds even when the owner never
    asked us to yield while they work."""
    from meshembed_node.worker import _should_pause
    assert _should_pause({"max_ram_gb": 0.000001}) is True
    assert _should_pause({"max_ram_gb": 10_000}) is False
    assert _should_pause({}) is False


def test_the_cap_is_applied_every_poll_not_only_at_start():
    """A change from the dashboard must take effect without a restart."""
    import inspect
    from meshembed_node import worker
    src = inspect.getsource(worker)
    assert "apply_cpu_cap(node_limits)" in src
    i = src.index("apply_cpu_cap(node_limits)")
    assert "node_limits = resp.get(" in src[:i], "applied after the poll response, per cycle"
