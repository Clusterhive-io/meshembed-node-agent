"""The daemon's memory budget is its cgroup's, not the host's.

N-23711 (2026-10-11): a 16 GB host, MemoryHigh=6G on the unit. Host MemAvailable
said a 7B fit; the cgroup did not, and every load swapped for 15-26 minutes.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from meshembed_node import membudget as mb

pytestmark = pytest.mark.unit

G = 1024 ** 3
M = 1024 ** 2


def _tree(tmp_path: Path, *, svc: dict, parent: dict = None, rel="system.slice/meshembed-node.service"):
    root = tmp_path / "cg"
    d = root / rel
    d.mkdir(parents=True)
    for k, v in svc.items():
        (d / k).write_text(str(v))
    if parent:
        for k, v in parent.items():
            (d.parent / k).write_text(str(v))
    proc = tmp_path / "proc_cgroup"
    proc.write_text(f"0::/{rel}\n")
    return proc, root


def test_the_n23711_shape(tmp_path):
    """6 GB high, 5 GB held of which 0.5 GB reclaimable cache: 1.5 GB left, not the host's 9 GB."""
    proc, root = _tree(tmp_path, svc={"memory.high": 6 * G, "memory.max": 12 * G,
                                      "memory.current": 5 * G,
                                      "memory.stat": f"anon 4\ninactive_file {G // 2}\n"})
    cg = mb.cgroup_memory(proc, root)
    assert cg["limit"] == 6 * G and cg["high"] == 6 * G and cg["max"] == 12 * G
    assert mb.available_mb(host_mb=9000, cg=cg) == 1536


def test_no_limit_keeps_the_host_figure(tmp_path):
    proc, root = _tree(tmp_path, svc={"memory.high": "max", "memory.max": "max",
                                      "memory.current": 5 * G, "memory.stat": ""})
    cg = mb.cgroup_memory(proc, root)
    assert cg["limit"] is None
    assert mb.available_mb(host_mb=9000, cg=cg) == 9000


def test_a_parent_slice_limit_binds(tmp_path):
    proc, root = _tree(tmp_path, svc={"memory.high": "max", "memory.max": "max",
                                      "memory.current": 1 * G, "memory.stat": ""},
                       parent={"memory.max": 4 * G})
    cg = mb.cgroup_memory(proc, root)
    assert cg["limit"] == 4 * G
    assert mb.available_mb(host_mb=9000, cg=cg) == 3072


def test_the_host_figure_wins_when_it_is_lower(tmp_path):
    proc, root = _tree(tmp_path, svc={"memory.max": 12 * G, "memory.current": 1 * G, "memory.stat": ""})
    assert mb.available_mb(host_mb=2000, cg=mb.cgroup_memory(proc, root)) == 2000


def test_over_the_limit_is_zero_not_negative(tmp_path):
    proc, root = _tree(tmp_path, svc={"memory.high": 6 * G, "memory.current": 7 * G, "memory.stat": ""})
    assert mb.available_mb(host_mb=9000, cg=mb.cgroup_memory(proc, root)) == 0


def test_cgroup_v1_or_not_linux_is_the_host_figure(tmp_path):
    proc = tmp_path / "proc_cgroup"
    proc.write_text("12:memory:/system.slice/x\n")          # v1 only: no 0:: line
    cg = mb.cgroup_memory(proc, tmp_path / "nope")
    assert cg["limit"] is None
    assert mb.available_mb(host_mb=9000, cg=cg) == 9000
    assert mb.cgroup_memory(tmp_path / "missing", tmp_path)["limit"] is None


def test_cpu_quota(tmp_path):
    proc, root = _tree(tmp_path, svc={"cpu.max": "400000 100000"})
    assert mb.cpu_quota_cores(proc, root) == 4.0
    (root / "system.slice/meshembed-node.service/cpu.max").write_text("max 100000")
    assert mb.cpu_quota_cores(proc, root) is None


def test_pressure_is_parsed(tmp_path):
    (tmp_path / "memory").write_text(
        "some avg10=12.50 avg60=30.00 avg300=5.00 total=1\nfull avg10=40.00 avg60=45.25 avg300=9.00 total=2\n")
    p = mb.pressure("memory", tmp_path)
    assert p == {"some_avg10": 12.5, "some_avg60": 30.0, "full_avg10": 40.0, "full_avg60": 45.25}
    assert mb.pressure("io", tmp_path) is None


def test_report_never_raises_and_carries_the_budget():
    r = mb.report(cache_dir=Path("/"))
    assert isinstance(r, dict)
    assert "available_mb" in r and r["available_mb"] <= r["host_available_mb"]
