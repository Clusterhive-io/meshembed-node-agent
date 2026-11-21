"""HASFILE (0.3.87, auditor GO 2026-11-20 H1-H6): the node's serve-file report is a SEPARATE claim beside installed_models."""
import json
import os
from pathlib import Path

from meshembed_node import llm



def _cat(*specs):
    return {s.model_id: s for s in specs}


def test_installed_llm_models_never_gains_a_serve_only_row():
    """F-1 stays byte-for-byte: serve_files is a different function and installed_llm_models' catalogue read excludes serve_only."""
    src = Path(llm.__file__).read_text(encoding="utf-8")
    body = src[src.index("def installed_llm_models"):src.index("def installed_llm_models") + 3500]
    assert "serve_files" not in body and "include_serve_only" not in body


def _fields():
    return llm.ModelSpec.__dataclass_fields__


def _mk(model_id, sha, serve_only=True):
    kw = {}
    for name, f in _fields().items():
        if name == "model_id":
            kw[name] = model_id
        elif name == "sha256":
            kw[name] = sha
        elif name == "serve_only":
            kw[name] = serve_only
        elif f.default is not f.default_factory.__class__ and False:
            pass
    # fill remaining required fields generically
    import dataclasses
    for name, f in _fields().items():
        if name in kw:
            continue
        if f.default is dataclasses.MISSING and f.default_factory is dataclasses.MISSING:
            kw[name] = "x" if f.type in (str, "str") else 1
    return llm.ModelSpec(**kw)


SHA = "a" * 64


def _run(tmp_path, *, content=b"gguf", uid=None, serve_only=True, catalog_sha=None, sync=True):
    d = tmp_path / "models"
    d.mkdir(exist_ok=True)
    import hashlib
    sha = hashlib.sha256(content).hexdigest() if catalog_sha is None else catalog_sha
    f = d / f"{sha}.gguf"
    f.write_bytes(content)
    st = tmp_path / "state.json"
    started = []
    uid = os.getuid() if uid is None else uid
    out = llm.serve_files(_cat(_mk("m30", sha, serve_only)), d, st, owner_uid=uid, start=(lambda fn: (started.append(fn), fn()) if sync else started.append(fn)))
    return out, started, st, sha


def test_a_present_file_is_reported_only_after_a_verify_and_the_cache_then_serves_it(tmp_path, monkeypatch):
    monkeypatch.setattr(llm.read_cap, "wait_until_idle", lambda *a, **k: None)
    monkeypatch.setattr(llm.read_cap, "probe", lambda *a, **k: None)
    first, started, st, sha = _run(tmp_path)
    assert first == [] and len(started) == 1                      # not reported until verified; ONE background verify started
    assert json.loads(st.read_text())[sha]["size"] == 4
    d = tmp_path / "models"
    second = llm.serve_files(_cat(_mk("m30", sha)), d, st, owner_uid=os.getuid(), start=lambda fn: (_ for _ in ()).throw(AssertionError("no re-hash")))
    assert second == [{"model_id": "m30", "sha": sha}]


def test_a_file_that_does_not_hash_to_its_pin_is_never_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(llm.read_cap, "wait_until_idle", lambda *a, **k: None)
    monkeypatch.setattr(llm.read_cap, "probe", lambda *a, **k: None)
    out, started, st, sha = _run(tmp_path, catalog_sha="b" * 64)
    assert out == [] and json.loads(st.read_text())[sha]["ok"] is False              # F1: the NEGATIVE is recorded


def test_not_root_owned_a_symlink_or_a_non_serve_only_model_is_not_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(llm.read_cap, "wait_until_idle", lambda *a, **k: None)
    monkeypatch.setattr(llm.read_cap, "probe", lambda *a, **k: None)
    out, started, _st, _ = _run(tmp_path, uid=os.getuid() + 12345)      # owner is not the expected (root) uid
    assert out == [] and started == []
    out, started, _st, _ = _run(tmp_path / "b" if (tmp_path / "b").mkdir() is None else tmp_path, serve_only=False)
    assert out == [] and started == []
    d = tmp_path / "sl"
    d.mkdir()
    real = tmp_path / "real.gguf"
    real.write_bytes(b"x")
    (d / f"{SHA}.gguf").symlink_to(real)
    assert llm.serve_files(_cat(_mk("m30", SHA)), d, tmp_path / "s2.json", owner_uid=os.getuid(), start=lambda fn: fn()) == []


def test_a_replaced_file_is_re_verified(tmp_path, monkeypatch):
    monkeypatch.setattr(llm.read_cap, "wait_until_idle", lambda *a, **k: None)
    monkeypatch.setattr(llm.read_cap, "probe", lambda *a, **k: None)
    _o, _s, st, sha = _run(tmp_path)
    f = tmp_path / "models" / f"{sha}.gguf"
    f.unlink()
    f.write_bytes(b"gguf")                                              # same bytes, replaced file: the cache must not match
    os.utime(f, ns=(1_000_000_000_000_000_000, 1_000_000_000_000_000_000))    # a distinct mtime, deterministic (coarse fs clocks)
    seen = []
    out = llm.serve_files(_cat(_mk("m30", sha)), tmp_path / "models", st, owner_uid=os.getuid(), start=lambda fn: seen.append(fn))
    assert out == [] and len(seen) == 1


def test_the_report_is_bounded_and_the_worker_sends_it_as_its_own_key():
    assert llm.SERVE_FILES_MAX == 8
    w = (Path(llm.__file__).with_name("worker.py")).read_text(encoding="utf-8")
    assert w.count('payload["serve_file_models"] = _sf') == 2          # /register and /get_job
    assert 'payload["installed_models"] = installed_models + ' not in w and "installed_models.extend" not in w


def test_windows_reports_nothing_and_stats_nothing(tmp_path, monkeypatch):
    """The st_uid / lstat checks never run on Windows: serve_files returns [] for os.name == 'nt' before touching the filesystem."""
    monkeypatch.setattr(llm.os, "name", "nt")
    monkeypatch.setattr(llm.os, "lstat", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no stat on Windows")))
    assert llm.serve_files(_cat(_mk("m30", SHA)), tmp_path, tmp_path / "s.json", start=lambda fn: fn()) == []


def test_f1_a_bad_file_is_hashed_once_and_again_only_when_it_changes(tmp_path, monkeypatch):
    monkeypatch.setattr(llm.read_cap, "wait_until_idle", lambda *a, **k: None)
    monkeypatch.setattr(llm.read_cap, "probe", lambda *a, **k: None)
    out, started, st, sha = _run(tmp_path, catalog_sha="b" * 64)                    # hashes once, records the negative
    d = tmp_path / "models"
    again = llm.serve_files(_cat(_mk("m30", sha)), d, st, owner_uid=os.getuid(), start=lambda fn: (_ for _ in ()).throw(AssertionError("re-hashed")))
    assert again == []                                                              # not reported, NOT re-hashed (18 GB on 187, every poll)
    f = d / f"{sha}.gguf"
    os.utime(f, ns=(2_000_000_000_000_000_000, 2_000_000_000_000_000_000))          # the file changed: hashed again
    seen = []
    llm.serve_files(_cat(_mk("m30", sha)), d, st, owner_uid=os.getuid(), start=lambda fn: seen.append(fn))
    assert len(seen) == 1


def test_f2_the_report_is_not_gated_on_the_batch_inference_switch(monkeypatch):
    from meshembed_node import worker
    monkeypatch.setattr(worker, "_LLM_ENABLED_BY_BACKEND", False)
    monkeypatch.setattr(llm, "serve_files", lambda *a, **k: [{"model_id": "m30", "sha": SHA}])
    assert worker._serve_file_models() == [{"model_id": "m30", "sha": SHA}]         # batch inference OFF: the file claim is still sent
    monkeypatch.setattr(llm, "serve_files", lambda *a, **k: [])
    assert worker._serve_file_models() == []                                        # [] clears an old claim
