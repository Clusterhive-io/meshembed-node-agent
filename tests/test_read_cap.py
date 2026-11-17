"""DISK-AWARE NODE item (4): an in-process read cap, proven by a probe before a cold read; fail closed (design Rev 1, D-3)."""
from __future__ import annotations

import hashlib
import math
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from meshembed_node import llm, model_blocks as mb, read_cap as rc  # noqa: E402

MIB = 1024 * 1024


class Clock:
    def __init__(self): self.t = 1000.0; self.slept = []
    def now(self): return self.t
    def sleep(self, s): self.slept.append(s); self.t += s


def _file(tmp_path, n=3 * MIB):
    p = tmp_path / "f.bin"; p.write_bytes(b"\x01" * n); return p


def test_limiter_paces_to_the_cap():
    c = Clock(); lim = rc.RateLimiter(MIB, c.now, c.sleep)
    for _ in range(5):
        lim.wait(MIB)
    assert abs(c.t - 1000.0 - 5.0) < 1e-6, "5 MiB at 1 MiB/s takes 5 s"


def test_a_stall_banks_no_burst_credit():
    c = Clock(); lim = rc.RateLimiter(32 * MIB, c.now, c.sleep)
    lim.wait(8 * MIB)
    c.t += 60.0                                    # a 60 s stall
    slept = c.t
    total_sleep = 0.0
    for _ in range(240):                           # 1920 MB afterwards, as the auditor's run
        before = c.t
        lim.wait(8 * MIB)
        total_sleep += c.t - before
    # at 32 MiB/s, 1920 MiB needs 60 s; with the bound at most MAX_LAG_S of credit may be banked
    assert total_sleep >= 60.0 - rc.MAX_LAG_S - 0.5, total_sleep


def test_probe_holds_when_the_limiter_paces(tmp_path):
    c = Clock(); p = _file(tmp_path)
    rate = rc.probe(p, MIB, nbytes=3 * MIB, clock=c.now, sleep=c.sleep)
    assert rate == pytest.approx(MIB, rel=0.01)


def test_probe_fails_closed_when_the_cap_is_not_holding(tmp_path):
    p = _file(tmp_path); t = {"v": 0.0}
    def clock():
        t["v"] += 0.001                                            # the reads cost 1 ms each and nothing paces them
        return t["v"]
    with pytest.raises(rc.ReadCapError, match="not holding"):
        rc.probe(p, MIB, nbytes=3 * MIB, clock=clock, sleep=lambda s: None)


@pytest.mark.parametrize("bad_elapsed", [0.0, -1.0, float("nan"), float("inf")])
def test_probe_fails_closed_on_an_unparsable_measurement(tmp_path, bad_elapsed):
    p = _file(tmp_path); calls = iter([0.0, 0.0, 0.0, 0.0, 0.0])
    ticks = {"n": 0}
    def clock():
        ticks["n"] += 1
        return 0.0 if ticks["n"] == 1 else bad_elapsed
    with pytest.raises(rc.ReadCapError, match="unparsable|not holding"):
        rc.probe(p, MIB, nbytes=MIB, clock=clock, sleep=lambda s: None)


def test_probe_fails_on_an_empty_or_unreadable_file(tmp_path):
    (tmp_path / "e.bin").write_bytes(b"")
    with pytest.raises(rc.ReadCapError):
        rc.probe(tmp_path / "e.bin", MIB)
    with pytest.raises(rc.ReadCapError):
        rc.probe(tmp_path / "absent.bin", MIB)


@pytest.mark.parametrize("v,want", [(8, 8 * MIB), (0.5, MIB // 2), (None, rc.DEFAULT_CAP_BPS), (0, rc.DEFAULT_CAP_BPS),
                                    (-3, rc.DEFAULT_CAP_BPS), ("9", rc.DEFAULT_CAP_BPS), (True, rc.DEFAULT_CAP_BPS),
                                    (float("nan"), rc.DEFAULT_CAP_BPS), (10**9, rc.DEFAULT_CAP_BPS)])
def test_cap_from_limits_takes_only_a_sane_positive_number(v, want):
    assert rc.cap_from_limits({"max_model_read_mb_s": v} if v is not None else {}) == want


def test_idle_wait_returns_when_quiet_and_defers_when_busy():
    c = Clock()
    rc.wait_until_idle(MIB, rate_fn=lambda: 0.0, clock=c.now, sleep=c.sleep)
    rc.wait_until_idle(MIB, rate_fn=lambda: None, clock=c.now, sleep=c.sleep)          # unmeasurable: does not block
    with pytest.raises(rc.ReadCapError, match="deferred"):
        rc.wait_until_idle(MIB, rate_fn=lambda: 10 * MIB, max_wait_s=12, clock=c.now, sleep=c.sleep)
    assert c.t - 1000.0 >= 12


def test_idle_wait_proceeds_once_the_disk_goes_quiet():
    c = Clock(); rates = iter([9 * MIB, 9 * MIB, 0.0])
    rc.wait_until_idle(MIB, rate_fn=lambda: next(rates), clock=c.now, sleep=c.sleep)
    assert len(c.slept) == 2


# ---- wired into llm._verified_path ----

BS = 16
BODY = bytes(range(256)) * 2 + b"tail!"


@pytest.fixture(autouse=True)
def _clean():
    mb.forget_all(); llm._DEFERRED.clear()
    yield
    mb.forget_all(); llm._DEFERRED.clear()


@pytest.fixture
def quiet_disk(monkeypatch):
    monkeypatch.setattr(rc, "wait_until_idle", lambda *a, **k: None)


def _spec(tmp_path, monkeypatch):
    (tmp_path / "f.bin").write_bytes(BODY)
    m = mb.build_manifest(tmp_path / "f.bin", BS); raw = mb.manifest_bytes(m); (tmp_path / "m.blocks.json").write_bytes(raw)
    monkeypatch.setattr(llm, "CACHE_DIR", tmp_path); monkeypatch.setattr(llm, "_BLOCKS_DIR", tmp_path)
    return llm.ModelSpec(model_id="t/cap", file="f.bin", sha256=m["sha256"], size_mb=1, min_ram_gb=0.001, context=512,
                         blocks_manifest="m.blocks.json", blocks_manifest_sha256=hashlib.sha256(raw).hexdigest()), m


def test_a_cold_read_runs_probe_then_verifies_under_the_limiter(tmp_path, monkeypatch, quiet_disk):
    spec, m = _spec(tmp_path, monkeypatch); seen = []
    monkeypatch.setattr(rc, "probe", lambda p, bps, **k: seen.append(("probe", bps)) or float(bps))
    real = mb.verify_file
    monkeypatch.setattr(mb, "verify_file", lambda p, mm, limiter=None: seen.append(("verify", limiter is not None)) or real(p, mm, limiter))
    monkeypatch.setattr(rc.RateLimiter, "wait", lambda self, n: None)
    assert llm._verified_path(spec) == tmp_path / "f.bin"
    assert seen == [("probe", rc.DEFAULT_CAP_BPS), ("verify", True)], "the probe comes BEFORE the read, and the read is limited"


def test_a_failed_probe_means_no_read_no_serve_and_no_redownload(tmp_path, monkeypatch, quiet_disk):
    spec, m = _spec(tmp_path, monkeypatch)
    monkeypatch.setattr(rc, "probe", lambda *a, **k: (_ for _ in ()).throw(rc.ReadCapError("the cap is not holding")))
    monkeypatch.setattr(mb, "verify_file", lambda *a, **k: pytest.fail("no unthrottled fallback: the read must not start"))
    monkeypatch.setattr(llm, "_download", lambda *a, **k: pytest.fail("a deferred file is present, not missing: no re-download"))
    assert llm._verified_path(spec) is None
    assert spec.model_id in llm._DEFERRED
    assert llm.ensure_model(spec) is None


def test_a_busy_disk_defers_the_same_way(tmp_path, monkeypatch):
    spec, m = _spec(tmp_path, monkeypatch)
    monkeypatch.setattr(rc, "wait_until_idle", lambda *a, **k: (_ for _ in ()).throw(rc.ReadCapError("disk busy")))
    monkeypatch.setattr(llm, "_download", lambda *a, **k: pytest.fail("no re-download"))
    assert llm.ensure_model(spec) is None and spec.model_id in llm._DEFERRED


def test_a_cached_verified_file_is_not_probed_again(tmp_path, monkeypatch, quiet_disk):
    spec, m = _spec(tmp_path, monkeypatch)
    monkeypatch.setattr(mb, "_now_ns", lambda: __import__("time").time_ns() + 3 * 10**9)    # not racily clean
    monkeypatch.setattr(rc.RateLimiter, "wait", lambda self, n: None)
    monkeypatch.setattr(rc, "probe", lambda p, bps, **k: float(bps))
    assert llm._verified_path(spec) is not None
    monkeypatch.setattr(rc, "probe", lambda *a, **k: pytest.fail("a fully cached verdict needs no cold read, so no probe"))
    assert llm._verified_path(spec) is not None


def test_verify_file_waits_on_the_limiter_once_per_block_it_reads(tmp_path):
    (tmp_path / "f.bin").write_bytes(BODY)
    m = mb.build_manifest(tmp_path / "f.bin", BS)
    class Counting:
        n = 0
        def wait(self, k): Counting.n += k
    assert mb.verify_file(tmp_path / "f.bin", m, Counting())[0] is True
    assert Counting.n == len(BODY), "every byte read passed through the limiter"
