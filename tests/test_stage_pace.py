"""SP-CAP (auditor DESIGN GO 2026-11-09T16:46:37Z, PROD-STALL-2): both full copies of a serve start are paced, never
below the rate the backend's plan load deadline assumes. Fake clock / sleep; small files; no network, no root."""
from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from meshembed_node import serve_duty as SDY  # noqa: E402
from meshembed_node import serve_launch as SL  # noqa: E402
from meshembed_node import stage_pace as SPACE  # noqa: E402


@pytest.mark.parametrize("raw,want", [(None, 20.0), ("", 20.0), ("  ", 20.0), ("junk", 20.0), ("nan", 20.0),
                                      ("0", 0.0), ("-3", 0.0), ("5", 15.0), ("15", 15.0), ("50", 50.0)])
def test_the_cap_from_the_environment(raw, want):
    env = {} if raw is None else {SPACE.ENV: raw}
    assert SPACE.mbps(env) == want


def test_the_floor_equals_the_rate_the_backend_deadline_assumes():
    # backend/app/serve_warmset.py STAGE_MIN_MBPS: a node cap below it makes a plan miss its load deadline
    assert SPACE.FLOOR_MBPS == 15.0 and SPACE.DEFAULT_MBPS >= SPACE.FLOOR_MBPS


class _Clock:
    def __init__(self):
        self.t, self.slept = 100.0, []

    def now(self):
        return self.t

    def sleep(self, s):
        self.slept.append(s)
        self.t += s


def test_the_pacer_holds_the_rate_and_never_sleeps_when_uncapped():
    c = _Clock()
    p = SPACE.Pacer(20, clock=c.now, sleep=c.sleep)
    for _ in range(3):
        p.account(10 * SPACE.MB)                              # 30 MB at 20 MB/s, done "instantly"
    assert c.t - 100.0 == pytest.approx(1.5)
    c2 = _Clock()
    p2 = SPACE.Pacer(0, clock=c2.now, sleep=c2.sleep)
    p2.account(10 * SPACE.MB)
    assert c2.slept == []


def test_a_paced_copy_is_byte_identical(tmp_path):
    src = tmp_path / "w.gguf"
    data = os.urandom(3 * 1024 * 1024 + 17)
    src.write_bytes(data)
    c = _Clock()
    n = SPACE.copy_paced(str(src), str(tmp_path / "out"), 20, chunk=1 << 20,
                         pacer=SPACE.Pacer(20, clock=c.now, sleep=c.sleep))
    assert n == len(data) and (tmp_path / "out").read_bytes() == data and c.slept


class _Recorder:
    total = 0

    def __init__(self, rate, *a, **k):
        _Recorder.rate = rate

    def account(self, n):
        _Recorder.total += n


def test_the_root_launcher_copy_goes_through_the_pacer(tmp_path, monkeypatch):
    data = b"GGUF" + os.urandom(2 * 1024 * 1024)
    sha = hashlib.sha256(data).hexdigest()
    staging, models = tmp_path / "staging", tmp_path / "models"
    staging.mkdir(); models.mkdir()
    (staging / f"{sha}.gguf").write_bytes(data)
    _Recorder.total = 0
    monkeypatch.setattr(SL.SPACE, "Pacer", _Recorder)
    monkeypatch.setenv(SPACE.ENV, "40")
    dst = SL.place_model(sha, staging, os.getuid(), models)
    assert dst.read_bytes() == data
    assert _Recorder.total == len(data) and _Recorder.rate == 40.0


def test_the_daemon_staging_copy_goes_through_the_pacer(tmp_path, monkeypatch):
    src = tmp_path / "cache.gguf"
    data = os.urandom(1024 * 1024)
    src.write_bytes(data)
    seen = {}

    def fake_copy(s, d, rate, **k):
        seen["rate"] = rate
        Path(d).write_bytes(Path(s).read_bytes())
        return len(data)
    monkeypatch.setattr(SDY.SPACE, "copy_paced", fake_copy)
    monkeypatch.setenv(SPACE.ENV, "0")

    class Spec:
        sha256 = "ab" * 32
    from meshembed_node import llm
    monkeypatch.setattr(llm, "load_catalog", lambda **k: {"m": Spec()})
    monkeypatch.setattr(llm, "ensure_model", lambda spec: src)
    assert SDY.stage_from_catalogue(Spec.sha256, staging=tmp_path / "stg") is True
    assert (tmp_path / "stg" / f"{Spec.sha256}.gguf").read_bytes() == data and seen["rate"] == 0.0
