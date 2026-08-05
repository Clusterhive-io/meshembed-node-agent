"""Unit tests for Detection Layer A: daemon-side runtime anomaly checks.

Covers the encode-timing tracker (baseline + anomaly classification),
the per-check predicates with mocked /proc reads, and the top-level
collect() function that aggregates everything into the list the
daemon ships in /get_job payloads.

Pure-Python, no docker, no GPU.
"""
from __future__ import annotations

import importlib
import os
import platform
from pathlib import Path
from unittest.mock import mock_open, patch

import pytest

pytestmark = pytest.mark.unit


def _fresh_module():
    """Reload runtime_anomalies so the module-level _tracker resets
    between tests."""
    import meshembed_node.runtime_anomalies as mod
    return importlib.reload(mod)


# ---------------------------------------------------------------------------
# _EncodeTimingTracker
# ---------------------------------------------------------------------------

class TestEncodeTimingTracker:
    def test_no_baseline_below_sample_threshold(self):
        mod = _fresh_module()
        t = mod._EncodeTimingTracker()
        for d in [0.1, 0.1, 0.1, 0.1]:
            assert t.record(d) is False
        assert t.has_baseline is False

    def test_baseline_locks_in_after_N_samples(self):
        mod = _fresh_module()
        t = mod._EncodeTimingTracker()
        for _ in range(mod._ENCODE_BASELINE_SAMPLE):
            t.record(0.1)
        assert t.has_baseline is True

    def test_anomaly_fires_above_3x_baseline(self):
        mod = _fresh_module()
        t = mod._EncodeTimingTracker()
        for _ in range(mod._ENCODE_BASELINE_SAMPLE):
            t.record(0.1)
        # 0.4s > 0.1 * 3 = 0.3s -- anomaly
        assert t.record(0.4) is True
        assert t._last_anomaly is True

    def test_below_threshold_does_not_fire(self):
        mod = _fresh_module()
        t = mod._EncodeTimingTracker()
        for _ in range(mod._ENCODE_BASELINE_SAMPLE):
            t.record(0.1)
        # 0.25 < 0.1 * 3 -- ok
        assert t.record(0.25) is False
        assert t._last_anomaly is False

    def test_zero_or_negative_duration_clamped(self):
        mod = _fresh_module()
        t = mod._EncodeTimingTracker()
        assert t.record(0.0) is False
        assert t.record(-1.5) is False
        # Sample list should not contain those.
        assert all(s > 0 for s in t._samples)

    def test_median_baseline_robust_to_outlier(self):
        mod = _fresh_module()
        t = mod._EncodeTimingTracker()
        # 4 normal + 1 outlier: median should still be ~0.1
        for d in [0.1, 0.1, 0.1, 0.1, 99.0]:
            t.record(d)
        assert t._baseline is not None
        assert 0.05 < t._baseline < 0.2


# ---------------------------------------------------------------------------
# Platform-gated checks (Linux-only)
# ---------------------------------------------------------------------------

class TestPtraceCheck:
    def test_returns_false_on_non_linux(self):
        mod = _fresh_module()
        with patch.object(platform, "system", return_value="Darwin"):
            assert mod._check_ptrace_attached() is False

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux-only check")
    def test_tracerpid_zero_means_no_debugger(self):
        mod = _fresh_module()
        fake_proc = "Name:\tpython\nState:\tR (running)\nTracerPid:\t0\n"
        with patch("builtins.open", mock_open(read_data=fake_proc)):
            assert mod._check_ptrace_attached() is False

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux-only check")
    def test_tracerpid_nonzero_means_debugger_attached(self):
        mod = _fresh_module()
        fake_proc = "Name:\tpython\nTracerPid:\t12345\n"
        with patch("builtins.open", mock_open(read_data=fake_proc)):
            assert mod._check_ptrace_attached() is True

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux-only check")
    def test_proc_read_failure_returns_false_not_crash(self):
        mod = _fresh_module()
        with patch("builtins.open", side_effect=PermissionError("nope")):
            assert mod._check_ptrace_attached() is False


class TestSuspiciousMapsCheck:
    def test_returns_false_on_non_linux(self):
        mod = _fresh_module()
        with patch.object(platform, "system", return_value="Darwin"):
            assert mod._check_suspicious_maps() is False

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux-only check")
    def test_clean_maps_returns_false(self):
        mod = _fresh_module()
        clean = "00400000-00401000 r-xp 00000000 08:01 /usr/bin/python3\n"
        with patch("builtins.open", mock_open(read_data=clean)):
            assert mod._check_suspicious_maps() is False

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux-only check")
    @pytest.mark.parametrize("marker", [
        "libthread_db",
        "libfrida",
        "frida-agent",
        "gdb-tools",
    ])
    def test_each_trigger_detected(self, marker):
        mod = _fresh_module()
        dirty = (
            f"00400000-00401000 r-xp 00000000 08:01 /path/{marker}.so.0\n"
        )
        with patch("builtins.open", mock_open(read_data=dirty)):
            assert mod._check_suspicious_maps() is True


# ---------------------------------------------------------------------------
# Top-level collect()
# ---------------------------------------------------------------------------

class TestCollect:
    def test_clean_environment_returns_empty_list(self):
        mod = _fresh_module()
        with patch.object(mod, "_check_ptrace_attached", return_value=False), \
             patch.object(mod, "_check_gcore_artifact", return_value=False), \
             patch.object(mod, "_check_suspicious_maps", return_value=False):
            assert mod.collect() == []

    def test_ptrace_signal_in_collect(self):
        mod = _fresh_module()
        with patch.object(mod, "_check_ptrace_attached", return_value=True), \
             patch.object(mod, "_check_gcore_artifact", return_value=False), \
             patch.object(mod, "_check_suspicious_maps", return_value=False):
            assert mod.collect() == ["ptrace_attached"]

    def test_all_three_signals_aggregated(self):
        mod = _fresh_module()
        with patch.object(mod, "_check_ptrace_attached", return_value=True), \
             patch.object(mod, "_check_gcore_artifact", return_value=True), \
             patch.object(mod, "_check_suspicious_maps", return_value=True):
            result = mod.collect()
        assert set(result) == {
            "ptrace_attached",
            "gcore_artifact",
            "debugger_lib_loaded",
        }

    def test_encode_timing_is_telemetry_only_and_never_reported(self):
        """Encode-timing anomalies must NOT reach collect().

        Regression guard. This used to report `encode_duration_anomaly`, which
        the backend treated as a runtime_inspection_detected event -> permanent
        eject. It fired on ordinary slow/cold/suspended encodes and banned
        honest nodes (and re-banned them on unban, because the daemon kept
        re-reporting). Policy now: HARD signals only (ptrace / debugger lib /
        gcore). The timing signal is still tracked + logged as telemetry, it
        just never bans anyone.
        """
        mod = _fresh_module()
        with patch.object(mod, "_check_ptrace_attached", return_value=False), \
             patch.object(mod, "_check_gcore_artifact", return_value=False), \
             patch.object(mod, "_check_suspicious_maps", return_value=False):
            # Establish baseline, then trigger a 10x-baseline encode.
            for _ in range(mod._ENCODE_BASELINE_SAMPLE):
                mod.record_encode_duration(0.1)
            mod.record_encode_duration(1.0)

            # Still DETECTED (telemetry preserved for investigation)...
            assert mod._tracker._last_anomaly is True
            # ...but NOT reported, so it can never ban a node.
            assert "encode_duration_anomaly" not in mod.collect()
            assert mod.collect() == []
