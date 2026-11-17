"""HF-SQUAT (auditor HIGH 2026-11-08T17:20:37Z; DESIGN GO 17:23:59Z with HP-1..HP-5): an embedding model loads ONLY
from files that match the signed pin table, verified before any load. Fake snapshots + a loader stub that FAILS the
test if it is called on anything unverified; no network."""
from __future__ import annotations

import ast
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from meshembed_node import embed_pins as P  # noqa: E402

MID = "intfloat/fake-e5"
REV = "a" * 40
FILES = {
    "config.json": b'{"model_type": "bert"}',
    "modules.json": json.dumps([{"idx": 0, "name": "0", "path": "", "type": "sentence_transformers.models.Transformer"},
                                {"idx": 1, "name": "1", "path": "1_Pooling",
                                 "type": "sentence_transformers.models.Pooling"}]).encode(),
    "1_Pooling/config.json": b'{"word_embedding_dimension": 4}',
    "tokenizer_config.json": b'{"model_max_length": 512}',
    "model.safetensors": b"WEIGHTS-v1",
}


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _table(files=None, mid=MID, **over):
    f = files or FILES
    e = {"model_id": mid, "revision": REV, "weights_sha": _sha(f["model.safetensors"]),
         "files": {p: _sha(b) for p, b in f.items()}}
    e.update(over)
    return e


@pytest.fixture
def env(tmp_path, monkeypatch):
    snap = tmp_path / "snap"
    pinned = tmp_path / "pinned"
    monkeypatch.setenv("MESHEMBED_PINNED_MODELS_DIR", str(pinned))
    P._verified.clear()
    calls = []

    def write(files):
        for p, b in files.items():
            q = snap / p
            q.parent.mkdir(parents=True, exist_ok=True)
            q.write_bytes(b)

    def download(repo, revision, allow_patterns):
        calls.append((repo, revision, tuple(allow_patterns)))
        return str(snap)
    write(FILES)
    return {"snap": snap, "pinned": pinned, "write": write, "download": download, "calls": calls, "tmp": tmp_path}


def _prepare(env, entry=None, mid=MID):
    entry = entry or _table()
    table = {entry["model_id"]: {k: entry[k] for k in ("revision", "files", "weights_sha")}}
    return P.prepare(mid, table, download=env["download"])


def test_a_pinned_model_yields_a_private_view_of_exactly_its_files(env):
    view = _prepare(env)
    got = sorted(str(p.relative_to(view)) for p in Path(view).rglob("*") if p.is_file() or p.is_symlink())
    assert got == sorted(FILES) and all(os.path.islink(os.path.join(view, p)) for p in FILES)
    assert env["calls"] == [(MID, REV, tuple(sorted(FILES)))]          # by revision, exactly the pinned paths
    mode = os.stat(view).st_mode
    assert not mode & (stat.S_IWGRP | stat.S_IWOTH)


@pytest.mark.parametrize("change, code", [
    ({"model.safetensors": b"WEIGHTS-evil"}, "model_pin_mismatch"),     # weights changed
    ({"tokenizer_config.json": b'{"x": 1}'}, "model_pin_mismatch"),     # HP-5: a non-weights file changed too
    ({"modules.json": b"[]"}, "model_pin_mismatch"),
])
def test_one_changed_byte_in_any_pinned_file_is_refused_before_load(env, change, code):
    env["write"](change)
    with pytest.raises(P.PinError, match=code):
        _prepare(env)


def test_a_missing_pinned_file_is_refused(env):
    (env["snap"] / "1_Pooling" / "config.json").unlink()
    with pytest.raises(P.PinError, match="pinned_file_missing"):
        _prepare(env)


def test_a_file_planted_in_the_view_is_refused(env):
    view = _prepare(env)
    Path(view, "pytorch_model.bin").write_bytes(b"pickle")
    with pytest.raises(P.PinError, match="unexpected_file_in_view"):
        _prepare(env)


def test_a_foreign_module_type_is_refused(env):
    files = dict(FILES)
    files["modules.json"] = json.dumps([{"idx": 0, "name": "0", "path": "", "type": "evilpkg.Module"}]).encode()
    env["write"](files)
    with pytest.raises(P.PinError, match="module_type_refused"):
        _prepare(env, _table(files))


@pytest.mark.parametrize("cfg", ["config.json", "tokenizer_config.json", "1_Pooling/config.json"])
def test_hp5_custom_code_auto_map_is_refused_even_when_pinned(env, cfg):
    files = dict(FILES)
    files[cfg] = b'{"auto_map": {"AutoModel": "modeling_evil.EvilModel"}}'
    env["write"](files)
    with pytest.raises(P.PinError, match="custom_code_refused"):
        _prepare(env, _table(files))


def test_hp3_a_cache_dir_writable_by_others_is_refused(env):
    env["pinned"].mkdir(parents=True)
    env["pinned"].chmod(0o777)
    with pytest.raises(P.PinError, match="cache_dir_writable_by_others"):
        _prepare(env)


class _WinStat:
    """os.stat() of a directory as CPython-on-Windows reports it: no read-only attribute -> 0o777; no real uid."""
    st_mode = stat.S_IFDIR | 0o777
    st_uid = 0


def _call_as(monkeypatch, osname, fn, *, stat_result=None):
    """Run fn() with os.name (and optionally os.stat) patched ONLY around the call: pathlib and pytest's own reporting
    must not see a fake os.name. Returns (value, exception) for the assertions made AFTER the patch is undone."""
    seen = []
    with monkeypatch.context() as m:
        m.setattr(P.os, "name", osname)
        if stat_result is not None:
            m.setattr(P.os, "stat", lambda p, *a, **k: seen.append(p) or stat_result)
        try:
            return fn(), None, seen
        except Exception as exc:                          # noqa: BLE001 - asserted by the caller
            return None, exc, seen


def test_hp3_win_posix_modes_is_false_only_on_nt(monkeypatch):
    assert _call_as(monkeypatch, "nt", P._posix_modes)[0] is False
    assert _call_as(monkeypatch, "posix", P._posix_modes)[0] is True


def test_hp3_win_a_0o777_directory_is_not_refused_under_windows_semantics(monkeypatch, tmp_path):
    # HP3-WIN (2026-11-13): v0.3.84 refused EVERY model on Windows (160: cache_dir_writable_by_others x31). With
    # os.name == "nt" and the stat CPython-on-Windows returns, the POSIX mode test must not run.
    _, exc, seen = _call_as(monkeypatch, "nt", lambda: P.check_private_dir(str(tmp_path)), stat_result=_WinStat())
    assert exc is None
    assert seen == [str(tmp_path)]                      # the stat still runs: a missing directory still raises


def test_hp3_win_the_same_0o777_stat_is_refused_on_posix(monkeypatch, tmp_path):
    # Negative control: the SAME stat result on POSIX is refused, so the Windows branch is the only change.
    monkeypatch.setattr(P.os, "getuid", lambda: 0, raising=False)
    _, exc, _ = _call_as(monkeypatch, "posix", lambda: P.check_private_dir(str(tmp_path)), stat_result=_WinStat())
    assert isinstance(exc, P.PinError) and "cache_dir_writable_by_others" in str(exc)


def test_hp3_win_a_missing_directory_still_raises_under_windows_semantics(monkeypatch, tmp_path):
    _, exc, _ = _call_as(monkeypatch, "nt", lambda: P.check_private_dir(str(tmp_path / "absent")))
    assert isinstance(exc, FileNotFoundError)


def test_hp3_win_prepare_end_to_end_under_windows_semantics(env, monkeypatch):
    # The whole prepare() with every directory reporting 0o777 (as on Windows): refused while POSIX modes apply, and
    # it succeeds once _posix_modes() is False (what os.name == "nt" gives): the 160 case end to end, the pin checks
    # themselves unchanged. (_posix_modes is the seam: a global os.name = "nt" would break pathlib on this host.)
    real_stat = os.stat

    def win_stat(p, *a, **k):
        st = real_stat(p, *a, **k)
        if stat.S_ISDIR(st.st_mode):
            w = _WinStat()
            w.st_uid = st.st_uid                                         # only the mode differs from the real stat
            return w
        return st
    monkeypatch.setattr(P.os, "stat", win_stat)
    with pytest.raises(P.PinError, match="cache_dir_writable_by_others"):
        _prepare(env)
    monkeypatch.setattr(P, "_posix_modes", lambda: False)
    monkeypatch.setattr(P, "_symlinks_allowed", lambda: False)       # as on Windows (WN-1): a copy / hardlink
    assert _prepare(env)


def test_our_generation_namespace_and_unpinned_ids_are_refused(env):
    for mid in ("meshembed/qwen3-30b-a3b-q4", "Meshembed/qwen3-30b-a3b-q4", "MESHEMBED/x"):   # HF: case-insensitive
        with pytest.raises(P.PinError, match="not_an_embedding_repo"):
            P.prepare(mid, {mid: _table()}, download=env["download"])
    with pytest.raises(P.PinError, match="not_pinned"):
        P.prepare("sentence-transformers/all-MiniLM-L6-v2", {}, download=env["download"])
    assert env["calls"] == []                                             # nothing downloaded for either


def test_a_weights_sha_that_disagrees_with_the_catalogue_is_refused(env):
    with pytest.raises(P.PinError, match="weights_sha_disagrees_with_catalogue"):
        _prepare(env, _table(weights_sha="b" * 64))


def test_hp2_verification_is_per_process_and_a_later_change_is_seen(env):
    _prepare(env)
    leftovers = {p.name for p in env["snap"].rglob("*")} | {p.name for p in env["pinned"].rglob("*")}
    assert not any("verified" in n or n.endswith((".ok", ".marker")) for n in leftovers)   # no marker on disk
    os.utime(env["snap"] / "model.safetensors", ns=(1, 1))
    env["write"]({"model.safetensors": b"WEIGHTS-evil"})                 # a change after the first verify
    with pytest.raises(P.PinError, match="model_pin_mismatch"):
        _prepare(env)


@pytest.mark.parametrize("bad", [
    {"revision": "main"}, {"revision": "abc"}, {"files": {"../x.json": "0" * 64, "model.safetensors": "0" * 64}},
    {"files": {"pytorch_model.bin": "0" * 64}}, {"files": {"model.safetensors": "0" * 64, "x.py": "0" * 64}},
    {"model_id": "meshembed/qwen2.5-7b-instruct-q4"}, {"model_id": "MeshEmbed/qwen2.5-7b-instruct-q4"},
])
def test_the_table_loader_drops_malformed_entries(tmp_path, bad):
    e = _table()
    e.update(bad)
    f = tmp_path / "t.json"
    f.write_text(json.dumps({"models": [e]}))
    assert P.load_table(f) == {}


def test_the_shipped_table_is_valid_and_not_empty():
    raw = json.loads(P.TABLE_PATH.read_text())
    table = P.load_table()
    assert table and len(table) == len(raw["models"])                    # nothing dropped as malformed
    for mid, e in table.items():
        anchor = "model.safetensors" if "model.safetensors" in e["files"] else "model.safetensors.index.json"
        assert e["files"][anchor] == e["weights_sha"], mid
    assert "intfloat/multilingual-e5-small" in table                     # the daemon's default model


def test_p7_one_load_path_in_the_whole_package():
    pkg = ROOT / "meshembed_node"
    hits = {}
    for f in pkg.glob("*.py"):
        src = f.read_text(encoding="utf-8")
        for needle in ("snapshot_download(", "_ST(", "SentenceTransformer(", "from_pretrained(", "hf_hub_download("):
            for line in src.splitlines():
                code = line.split("#", 1)[0]
                if needle in code and "def " not in code and '"""' not in code and "`" not in code:
                    hits.setdefault(needle, []).append(f.name)
    assert hits == {"snapshot_download(": ["embed_pins.py"], "_ST(": ["encoder.py"]}, hits
    enc = (pkg / "encoder.py").read_text(encoding="utf-8")
    assert "_ST(local_dir, device=_DEVICE, local_files_only=True, trust_remote_code=False)" in enc


def test_hp4_the_generator_never_imports_a_model_loader():
    src = (ROOT.parent / "scripts/catalogue/embed_pins.py").read_text(encoding="utf-8")
    mods = set()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Import):
            mods |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods.add(node.module)
    assert not any(m.split(".")[0] in ("sentence_transformers", "transformers", "torch") for m in mods), mods


def test_the_encoder_loads_only_a_verified_view_and_never_on_a_refusal(monkeypatch, tmp_path):
    from meshembed_node import encoder as E
    seen = []

    class _Stub:
        def __init__(self, path, **kw):
            seen.append((path, kw))
            raise RuntimeError("stop here")                              # we only want the call's arguments
    monkeypatch.setattr(E, "_ST", _Stub)
    monkeypatch.setattr(E, "_HAVE_ST", True)
    enc = E.Encoder.__new__(E.Encoder)
    import threading
    from collections import OrderedDict
    enc._lock, enc._cache, enc._pinned, enc._cache_size, enc._sha_by_model = threading.RLock(), OrderedDict(), None, 1, {}
    monkeypatch.setattr(P, "prepare", lambda name: (_ for _ in ()).throw(P.PinError(f"not_pinned:{name}")))
    assert enc._ensure_loaded("evil/model", eager=False) == (None, "")
    assert seen == []                                                     # a refusal never reaches the loader
    monkeypatch.setattr(P, "prepare", lambda name: str(tmp_path))
    enc._ensure_loaded("intfloat/multilingual-e5-small", eager=False)
    assert seen == [(str(tmp_path), {"device": E._DEVICE, "local_files_only": True, "trust_remote_code": False})]


def test_negative_control_without_the_verify_step_a_tampered_file_passes(env, monkeypatch):
    env["write"]({"model.safetensors": b"WEIGHTS-evil"})
    monkeypatch.setattr(P, "_sha256", lambda p: _table()["files"][os.path.relpath(p, env["snap"])]
                        if str(p).startswith(str(env["snap"])) else _table()["files"][
                            os.path.relpath(os.path.realpath(p), env["snap"])])
    view = _prepare(env)                                                  # the bypass lets the evil bytes through
    assert Path(view, "model.safetensors").read_bytes() == b"WEIGHTS-evil"


# ── WN-1 (auditor 2026-11-08T17:37:36Z): a Windows service cannot make symlinks; hardlink, else copy, then verify ──

@pytest.mark.parametrize("fail", [("symlink",), ("symlink", "link")])
def test_wn1_without_symlinks_the_view_falls_back_and_is_still_verified(env, monkeypatch, fail):
    def refuse(*_a, **_k):
        raise OSError("not permitted")
    for f in fail:
        monkeypatch.setattr(P.os, f, refuse)
    view = _prepare(env)
    for rel, data in FILES.items():
        p = Path(view, rel)
        assert p.is_file() and not p.is_symlink() and p.read_bytes() == data
    if fail == ("symlink",):
        assert os.stat(Path(view, "model.safetensors")).st_ino == os.stat(env["snap"] / "model.safetensors").st_ino
    view = _prepare(env)                                                  # a second prepare keeps the verified copies


def test_wn1_a_tampered_copy_in_the_view_is_refused(env, monkeypatch):
    monkeypatch.setattr(P.os, "symlink", lambda *a, **k: (_ for _ in ()).throw(OSError("no")))
    monkeypatch.setattr(P.os, "link", lambda *a, **k: (_ for _ in ()).throw(OSError("no")))
    view = _prepare(env)
    Path(view, "model.safetensors").write_bytes(b"WEIGHTS-evil")         # the copy changed after placement
    P._verified.clear()
    view = _prepare(env)                                                  # replaced by a fresh verified copy
    assert Path(view, "model.safetensors").read_bytes() == FILES["model.safetensors"]


def test_wn1_windows_never_tries_a_symlink(env, monkeypatch):
    calls = []
    monkeypatch.setattr(P, "_symlinks_allowed", lambda: False)
    monkeypatch.setattr(P.os, "symlink", lambda *a, **k: calls.append("symlink"))
    view = _prepare(env)
    assert calls == [] and Path(view, "config.json").read_bytes() == FILES["config.json"]


@pytest.mark.skipif(sys.platform == "win32", reason="st_ctime is creation time on Windows (HP2-W): the key cannot see a rewrite there")
def test_hp2_a_same_size_rewrite_with_its_mtime_restored_is_rehashed_and_refused(env):
    """auditor 2026-11-09T16:25:14Z: the in-process verified cache keys on ctime too. A cached pinned file rewritten IN
    PLACE (same inode, same size) with its mtime put back must be re-hashed by the next prepare() and refused."""
    import time
    _prepare(env)                                                    # verified + cached in this process
    f = env["snap"] / "model.safetensors"
    before = os.stat(f)
    with open(f, "r+b") as fh:                                       # in place: same inode, same size
        fh.write(b"WEIGHTS-v2")
    os.utime(f, ns=(before.st_atime_ns, before.st_mtime_ns))         # mtime restored
    for _ in range(100):                                             # ctime is coarse-clocked: make sure it moved
        if os.stat(f).st_ctime_ns != before.st_ctime_ns:
            break
        time.sleep(0.01)
        os.utime(f, ns=(before.st_atime_ns, before.st_mtime_ns))
    after = os.stat(f)
    assert (after.st_ino, after.st_size, after.st_mtime_ns) == (before.st_ino, before.st_size, before.st_mtime_ns)
    assert after.st_ctime_ns != before.st_ctime_ns
    with pytest.raises(P.PinError, match="model_pin_mismatch"):
        _prepare(env)


def test_hp2w_windows_never_fills_the_verified_cache_and_rehashes_every_call(env, monkeypatch):
    """HP-2-W (auditor 2026-11-16T20:55:44Z, option 1): on Windows st_ctime_ns is the creation time, which the file's owner can
    set, so the HP-2 cache key cannot guard there. With _posix_modes() False nothing is cached and each call re-hashes."""
    monkeypatch.setattr(P, "_posix_modes", lambda: False)
    P._verified.clear()
    f = env["snap"] / "model.safetensors"
    calls = []
    real = hashlib.sha256
    monkeypatch.setattr(P.hashlib, "sha256", lambda *a, **k: (calls.append(1), real(*a, **k))[1])
    d1 = P._sha256(str(f))
    d2 = P._sha256(str(f))
    assert d1 == d2 and len(calls) == 2 and P._verified == {}


def test_hp2w_posix_still_caches(env, monkeypatch):
    monkeypatch.setattr(P, "_posix_modes", lambda: True)
    P._verified.clear()
    f = env["snap"] / "model.safetensors"
    P._sha256(str(f))
    assert len(P._verified) == 1


pytestmark = pytest.mark.unit   # CI-COVER (b) 2026-11-09: so CI T1 (scripts/run-tests.sh unit) runs this file
