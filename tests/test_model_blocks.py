"""DISK-AWARE NODE item (1): per-block manifest, verified per block, cached in memory (design Rev 1, auditor GO 12:14:36Z, D-1)."""
from __future__ import annotations

import hashlib
import os
import sys
import types
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from meshembed_node import llm, model_blocks as mb  # noqa: E402

BS = 16
BODY = bytes(range(256)) * 2 + b"tail!"            # 517 bytes = 33 blocks of 16 (the last one short)


@pytest.fixture(autouse=True)
def _fresh_cache():
    mb.forget_all()
    yield
    mb.forget_all()


def _manifest_file(dirp: Path, body: bytes = BODY, name: str = "m.blocks.json"):
    (dirp / "f.bin").write_bytes(body)
    m = mb.build_manifest(dirp / "f.bin", BS)
    raw = mb.manifest_bytes(m)
    (dirp / name).write_bytes(raw)
    return m, hashlib.sha256(raw).hexdigest()


# ---- the manifest is trusted only after its pin matches (D-1) ----

def test_manifest_loads_when_pin_and_model_sha_match(tmp_path):
    m, pin = _manifest_file(tmp_path)
    got = mb.load_manifest(tmp_path / "m.blocks.json", pin, m["sha256"])
    assert got == m and len(got["blocks"]) == 33


def test_manifest_refused_on_a_wrong_pin_before_anything_is_parsed(tmp_path, monkeypatch):
    m, pin = _manifest_file(tmp_path)
    called = []
    real = mb.json.loads
    monkeypatch.setattr(mb.json, "loads", lambda *a, **k: called.append(1) or real(*a, **k))
    assert mb.load_manifest(tmp_path / "m.blocks.json", "0" * 64, m["sha256"]) is None
    assert called == [], "no byte of an unpinned manifest may be parsed"


def test_manifest_refused_for_another_models_sha_or_bad_shape(tmp_path):
    m, pin = _manifest_file(tmp_path)
    assert mb.load_manifest(tmp_path / "m.blocks.json", pin, "1" * 64) is None
    bad = dict(m, blocks=m["blocks"][:-1])                       # block count does not match size / block_size
    raw = mb.manifest_bytes(bad); (tmp_path / "b.json").write_bytes(raw)
    assert mb.load_manifest(tmp_path / "b.json", hashlib.sha256(raw).hexdigest(), m["sha256"]) is None
    bad2 = dict(m, blocks=["zz" * 32] + m["blocks"][1:])         # not hex
    raw = mb.manifest_bytes(bad2); (tmp_path / "c.json").write_bytes(raw)
    assert mb.load_manifest(tmp_path / "c.json", hashlib.sha256(raw).hexdigest(), m["sha256"]) is None
    assert mb.load_manifest(tmp_path / "absent.json", pin, m["sha256"]) is None


def test_manifest_that_is_a_symlink_is_refused(tmp_path):
    m, pin = _manifest_file(tmp_path)
    os.symlink(tmp_path / "m.blocks.json", tmp_path / "link.json")
    assert mb.load_manifest(tmp_path / "link.json", pin, m["sha256"]) is None


# ---- per-block verification of a file on disk ----

def _fill_in_the_future(monkeypatch, secs=2):
    """Make the cache fill look `secs` later than the file's ctime, i.e. an entry that is no longer racily clean."""
    monkeypatch.setattr(mb, "_now_ns", lambda: __import__("time").time_ns() + secs * 10**9)


def test_verify_reads_every_block_once_then_none_from_the_cache(tmp_path, monkeypatch):
    m, _ = _manifest_file(tmp_path)
    _fill_in_the_future(monkeypatch)
    assert mb.verify_file(tmp_path / "f.bin", m) == (True, 33, 33)
    assert mb.verify_file(tmp_path / "f.bin", m) == (True, 0, 33), "a verified, unchanged file is not read again"


def test_mbw_windows_never_fills_or_reads_the_cache_and_every_call_reverifies(tmp_path, monkeypatch):
    """MB-W (auditor 2026-11-17T10:38:32Z): on Windows st_ctime_ns is the settable creation time and there is no owner check, so the
    cache key cannot guard there: no lookup, no fill, every call reads every block; needs_read is always True."""
    m, _ = _manifest_file(tmp_path)
    _fill_in_the_future(monkeypatch)
    monkeypatch.setattr(mb, "_cache_usable", lambda: False)
    assert mb.verify_file(tmp_path / "f.bin", m) == (True, 33, 33)
    assert mb._VERIFIED == {}
    assert mb.verify_file(tmp_path / "f.bin", m) == (True, 33, 33), "Windows re-verifies every call"
    assert mb.needs_read(tmp_path / "f.bin", m) is True


def test_mbw_posix_still_caches(tmp_path, monkeypatch):
    m, _ = _manifest_file(tmp_path)
    _fill_in_the_future(monkeypatch)
    monkeypatch.setattr(mb, "_cache_usable", lambda: True)
    assert mb.verify_file(tmp_path / "f.bin", m) == (True, 33, 33)
    assert len(mb._VERIFIED) == 1 and mb.needs_read(tmp_path / "f.bin", m) is False
    assert mb.verify_file(tmp_path / "f.bin", m) == (True, 0, 33)

def test_a_racily_clean_entry_is_not_trusted_and_is_re_verified(tmp_path):
    """Auditor 13:09:41Z (a): a file changed within RACY_NS of the cache fill is read again, not served from the cache."""
    m, _ = _manifest_file(tmp_path)
    assert mb.verify_file(tmp_path / "f.bin", m) == (True, 33, 33)
    assert mb.verify_file(tmp_path / "f.bin", m) == (True, 33, 33), "filled within the window of its ctime: read again"


def test_an_immediate_same_size_rewrite_fails_with_no_sleep(tmp_path):
    m, _ = _manifest_file(tmp_path)
    p = tmp_path / "f.bin"
    st = os.stat(p)
    assert mb.verify_file(p, m)[0]
    data = bytearray(BODY); data[0] ^= 1
    p.write_bytes(bytes(data))                                   # same tick as the fill, same size
    os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns))
    assert mb.verify_file(p, m)[0] is False


def test_the_trust_rule_itself():
    t = 10**18 + 123_456_789
    assert mb._trusted(t, t + mb.RACY_NS) is True
    assert mb._trusted(t, t + mb.RACY_NS - 1) is False
    assert mb._trusted(t, t - 5) is False, "a ctime in the future of the fill (clock jump) is not trusted"
    whole = 10**18                                               # ends in 000000000: a coarse-timestamp filesystem
    assert mb._trusted(whole, whole + 10**9) is False
    assert mb._trusted(whole, whole + 10**9 + mb.RACY_NS) is True


def test_a_bad_block_stops_the_read_at_that_block(tmp_path):
    m, _ = _manifest_file(tmp_path)
    data = bytearray(BODY); data[5 * BS + 1] ^= 0xFF
    (tmp_path / "f.bin").write_bytes(bytes(data))
    ok, read, total = mb.verify_file(tmp_path / "f.bin", m)
    assert (ok, read, total) == (False, 6, 33), "blocks 0..5 read, the rest never touched"


def test_mtime_cannot_replay_an_old_verdict(tmp_path, monkeypatch):
    """The key is size+ctime+inode, not mtime: rewriting the bytes and restoring the old mtime must be re-verified."""
    m, _ = _manifest_file(tmp_path)
    p = tmp_path / "f.bin"
    st = os.stat(p)
    _fill_in_the_future(monkeypatch)                             # a TRUSTED entry: only the key can protect it now
    assert mb.verify_file(p, m)[0]
    assert mb.verify_file(p, m) == (True, 0, 33)
    import time; time.sleep(0.02)                                # a later tick, so ctime moves
    data = bytearray(BODY); data[0] ^= 1
    p.write_bytes(bytes(data))
    os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns))             # touch -d back
    ok, read, _ = mb.verify_file(p, m)
    assert ok is False and read >= 1


def test_symlinked_or_wrong_size_file_is_refused(tmp_path):
    m, _ = _manifest_file(tmp_path)
    os.symlink(tmp_path / "f.bin", tmp_path / "l.bin")
    assert mb.verify_file(tmp_path / "l.bin", m)[0] is False
    (tmp_path / "short.bin").write_bytes(BODY[:-1])
    assert mb.verify_file(tmp_path / "short.bin", m)[0] is False


@pytest.mark.skipif(not hasattr(os, "getuid") or os.getuid() == 0, reason="needs a non-root owner check")
def test_file_owned_by_another_user_is_refused(tmp_path, monkeypatch):
    m, _ = _manifest_file(tmp_path)
    monkeypatch.setattr(os, "getuid", lambda: os.stat(tmp_path / "f.bin").st_uid + 1)
    assert mb.verify_file(tmp_path / "f.bin", m)[0] is False


def test_windows_there_is_no_uid_and_a_regular_file_is_still_verified_not_refused(tmp_path, monkeypatch):
    # TT-3 / Windows semantics (v0.3.85 train): os.getuid does not exist on Windows (st_uid is 0 there), so the owner check must be
    # skipped, never read as "owned by someone else". Patched ONLY around the call; the file is an ordinary regular file.
    m, _ = _manifest_file(tmp_path)
    monkeypatch.delattr(os, "getuid", raising=False)
    assert mb._own_regular_file(tmp_path / "f.bin") is not None
    assert mb.verify_file(tmp_path / "f.bin", m)[0] is True


# ---- a download is checked as it streams ----

def _chunks(b: bytes, n: int):
    return [b[i:i + n] for i in range(0, len(b), n)]


@pytest.mark.parametrize("n", [1, 7, 16, 33, 517])
def test_stream_accepts_the_right_bytes_at_any_chunking(tmp_path, n):
    m, _ = _manifest_file(tmp_path)
    sv = mb.StreamVerifier(m)
    assert all(sv.feed(c) for c in _chunks(BODY, n)) and sv.finish()


def test_stream_rejects_at_the_block_that_is_wrong_not_at_the_end(tmp_path):
    m, _ = _manifest_file(tmp_path)
    data = bytearray(BODY); data[2 * BS + 3] ^= 1
    sv, fed = mb.StreamVerifier(m), 0
    for c in _chunks(bytes(data), BS):
        if not sv.feed(c):
            break
        fed += 1
    assert fed == 2, "blocks 0 and 1 accepted, block 2 rejected as it arrives"


def test_stream_rejects_a_short_or_long_download(tmp_path):
    m, _ = _manifest_file(tmp_path)
    sv = mb.StreamVerifier(m)
    for c in _chunks(BODY[:-1], 16):
        sv.feed(c)
    assert sv.finish() is False
    sv = mb.StreamVerifier(m)
    assert all(sv.feed(c) for c in _chunks(BODY, 16))
    assert sv.feed(b"x") is False


# ---- wired into llm.py ----

def _spec(tmp_path, m, pin, **over):
    kw = dict(model_id="t/blk", file="f.bin", sha256=m["sha256"], size_mb=1, min_ram_gb=0.001, context=512,
              blocks_manifest="m.blocks.json", blocks_manifest_sha256=pin)
    kw.update(over)
    return llm.ModelSpec(**kw)


def _wire(monkeypatch, tmp_path):
    monkeypatch.setattr(llm, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(llm, "_BLOCKS_DIR", tmp_path)


def test_llm_verified_path_uses_blocks_and_does_not_write_a_sidecar(tmp_path, monkeypatch):
    m, pin = _manifest_file(tmp_path); _wire(monkeypatch, tmp_path)
    assert llm._verified_path(_spec(tmp_path, m, pin)) == tmp_path / "f.bin"
    assert not (tmp_path / "f.bin.verified").exists()


def test_llm_refuses_a_corrupt_file_and_every_unverifiable_manifest(tmp_path, monkeypatch):
    m, pin = _manifest_file(tmp_path); _wire(monkeypatch, tmp_path)
    assert llm._verified_path(_spec(tmp_path, m, "0" * 64)) is None          # wrong pin: fail closed, NOT the whole-file path
    assert llm._verified_path(_spec(tmp_path, m, pin, blocks_manifest="")) is None      # half an entry
    assert llm._verified_path(_spec(tmp_path, m, "")) is None
    assert llm._verified_path(_spec(tmp_path, m, pin, blocks_manifest="../m.blocks.json")) is None
    assert llm._verified_path(_spec(tmp_path, m, pin, blocks_manifest="absent.json")) is None
    data = bytearray(BODY); data[100] ^= 1
    (tmp_path / "f.bin").write_bytes(bytes(data))
    assert llm._verified_path(_spec(tmp_path, m, pin)) is None


def test_llm_refuses_an_unsafe_manifest_name_before_opening_anything(tmp_path, monkeypatch):
    m, pin = _manifest_file(tmp_path); _wire(monkeypatch, tmp_path)
    monkeypatch.setattr(mb, "load_manifest", lambda *a, **k: pytest.fail("an unsafe name must be refused BEFORE any file is opened"))
    for bad in ("C:m.blocks.json", "m.blocks.json:x", "a/b.json", "..\\m.json", ".hidden"):
        assert llm._blocks_for(_spec(tmp_path, m, pin, blocks_manifest=bad)) == (None, True), bad


def test_llm_without_a_manifest_is_exactly_the_old_path(tmp_path, monkeypatch):
    monkeypatch.setattr(llm, "CACHE_DIR", tmp_path)
    (tmp_path / "f.bin").write_bytes(BODY)
    spec = llm.ModelSpec(model_id="t/old", file="f.bin", sha256=hashlib.sha256(BODY).hexdigest(), size_mb=1, min_ram_gb=0.001, context=512)
    assert llm._verified_path(spec) == tmp_path / "f.bin" and (tmp_path / "f.bin.verified").exists()


class _Resp:
    def __init__(self, body): self._b = body
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def raise_for_status(self): pass
    def iter_content(self, n):
        for i in range(0, len(self._b), n):
            yield self._b[i:i + n]


def _fake_requests(monkeypatch, body, calls):
    mod = types.ModuleType("requests")
    mod.get = lambda url, **k: calls.append(url) or _Resp(body)
    monkeypatch.setitem(sys.modules, "requests", mod)
    monkeypatch.setattr(llm, "_DOWNLOAD_CHUNK", 10)
    monkeypatch.setattr(llm, "_FETCH_BACKOFF_S", (0, 0, 0))
    monkeypatch.setattr(llm, "MIRROR", "http://mirror")


def test_llm_download_streams_and_verifies_without_a_whole_file_hash_read(tmp_path, monkeypatch):
    m, pin = _manifest_file(tmp_path); _wire(monkeypatch, tmp_path)
    (tmp_path / "f.bin").unlink()
    calls = []; _fake_requests(monkeypatch, BODY, calls)
    monkeypatch.setattr(llm, "_sha256_file", lambda p: pytest.fail("a manifest download must not re-read the file for a whole-file hash"))
    spec = _spec(tmp_path, m, pin)
    assert llm._download(spec, 5) == tmp_path / "f.bin"
    assert (tmp_path / "f.bin").read_bytes() == BODY
    assert llm._verified_path(spec) == tmp_path / "f.bin", "the first load verifies once (a fresh file is racily clean)"


def test_llm_download_of_wrong_bytes_is_discarded_at_once_and_not_retried(tmp_path, monkeypatch):
    m, pin = _manifest_file(tmp_path); _wire(monkeypatch, tmp_path)
    (tmp_path / "f.bin").unlink()
    bad = bytearray(BODY); bad[40] ^= 1
    calls = []; _fake_requests(monkeypatch, bytes(bad), calls)
    assert llm._download(_spec(tmp_path, m, pin), 5) is None
    assert len(calls) == 1, "wrong bytes are not retried"
    assert not (tmp_path / "f.bin").exists() and not (tmp_path / "f.part").exists()


def test_the_release_tool_writes_exactly_what_build_manifest_builds(tmp_path, monkeypatch, capsys):
    """Auditor LOW-3: the manifest's sha256 field is the catalogue's model sha, from the same read; the printed pin is the file's sha."""
    import importlib.util
    root = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location("make_block_manifest", root / "scripts" / "catalogue" / "make_block_manifest.py")
    tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)
    model = tmp_path / "m.gguf"; model.write_bytes(BODY)
    sha = hashlib.sha256(BODY).hexdigest()
    monkeypatch.setattr(tool, "ROOT", tmp_path)
    monkeypatch.setattr(sys, "argv", ["x", str(model), sha, "--block-mib", "1"])
    assert tool.main() == 0
    out = tmp_path / "node-agent" / "meshembed_node" / "llm_blocks" / f"{sha}.blocks.json"
    assert out.read_bytes() == mb.manifest_bytes(mb.build_manifest(model, 1024 * 1024))
    assert mb.load_manifest(out, hashlib.sha256(out.read_bytes()).hexdigest(), sha)["sha256"] == sha
    monkeypatch.setattr(sys, "argv", ["x", str(model), "0" * 64])
    assert tool.main() == 2
