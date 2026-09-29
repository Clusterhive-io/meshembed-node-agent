"""Measured power for cost (power.py): the idle baseline and per-item draw."""
from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from meshembed_node import power  # noqa: E402

pytestmark = pytest.mark.unit


def _zone(tmp_path, name, energy, maxr=262143328850):
    z = tmp_path / name
    z.mkdir()
    (z / "energy_uj").write_text(str(energy))
    (z / "max_energy_range_uj").write_text(str(maxr))
    return z


def test_package_energy_over_time_is_watts(tmp_path, monkeypatch):
    z = _zone(tmp_path, "intel-rapl:0", 1_000_000)
    rapl = power.RaplCounter([str(z)])
    clock = iter([100.0, 110.0])
    monkeypatch.setattr(power.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(power, "gpu_watts_now", lambda: None)
    m = power.PowerMeter(rapl=rapl, gpu=False)
    tok = m.begin()
    (z / "energy_uj").write_text(str(1_000_000 + 250_000_000))     # 250 J in 10 s
    out = m.end(tok)
    assert out == {"source": "rapl", "cpu_w": 25.0}


def test_a_wrapped_counter_is_not_negative(tmp_path):
    z = _zone(tmp_path, "intel-rapl:0", 0, maxr=1_000_000_000)
    rapl = power.RaplCounter([str(z)])
    assert rapl.joules_between({str(z): 999_000_000}, {str(z): 1_000_000}) == pytest.approx(2.0)


def test_the_idle_baseline_is_reported_with_the_item(tmp_path, monkeypatch):
    z = _zone(tmp_path, "intel-rapl:0", 0)
    rapl = power.RaplCounter([str(z)])
    monkeypatch.setattr(power, "gpu_watts_now", lambda: None)
    m = power.PowerMeter(rapl=rapl, gpu=False)
    t = [0.0]
    monkeypatch.setattr(power.time, "monotonic", lambda: t[0])

    def fake_sleep(s):
        t[0] += s
        (z / "energy_uj").write_text(str(int(8.0 * s * 1e6)))      # 8 W idle
    m.sample_idle(30, sleep=fake_sleep)
    assert m.cpu_idle_w == 8.0 and not m.idle_is_stale()
    tok = m.begin()
    t[0] += 10
    (z / "energy_uj").write_text(str(int(8.0 * 30 * 1e6 + 30 * 10 * 1e6)))   # 30 W for 10 s
    assert m.end(tok) == {"source": "rapl", "cpu_w": 30.0, "cpu_idle_w": 8.0}


def test_nothing_readable_means_nothing_reported(monkeypatch):
    monkeypatch.setattr(power, "gpu_watts_now", lambda: None)
    m = power.PowerMeter(rapl=power.RaplCounter([]), gpu=False)
    assert not m.available and m.begin() is None and m.end(None) is None


def test_an_absurd_reading_is_dropped():
    assert power._clamp(-1) is None and power._clamp(1e9) is None and power._clamp(42.04) == 42.0


def test_a_measurement_failure_never_fails_an_item(monkeypatch):
    from meshembed_node import worker

    def boom():
        raise RuntimeError("sysfs vanished")
    monkeypatch.setattr(power, "meter", boom)
    assert worker._power_begin() is None and worker._power_end({"x": 1}) is None
