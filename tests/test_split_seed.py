"""Split weight-cache seeder (di-step2): FNV-keyed files, verify-before-use, sha gate.

The seeder writes the same filename + bytes the rpc-server would cache, offline from a
sha256-verified GGUF. It never touches the rpc protocol. These tests pin: only above-
threshold tensors are cached; the filename is the 16-hex FNV-1a of the bytes; the content
round-trips; a sha256 mismatch refuses before writing; verify_cache catches corruption and
GGUF mismatch; and the coordinator refuses a stage whose cache is missing/incomplete/wrong.
"""
from __future__ import annotations

import hashlib
import json
import os

import pytest

from meshembed_node import split_seed as ss

# A small threshold keeps the byte-wise FNV fast in tests; it is the same code path the
# real 10 MiB HASH_THRESHOLD takes.
THR = 64


def _big(byte: int, n: int = THR + 8) -> bytes:
    return bytes([byte]) * n


def test_fnv1a_matches_the_reference_vector():
    # FNV-1a of "" is the offset basis; of "a" the documented 64-bit value.
    assert ss.fnv1a_hash(b"") == 0xCBF29CE484222325
    assert ss.fnv1a_hash(b"a") == 0xAF63DC4C8601EC8C
    assert ss.cache_filename(ss.fnv1a_hash(b"a")) == "af63dc4c8601ec8c"


def test_only_above_threshold_tensors_are_cached(tmp_path):
    cache = str(tmp_path)
    tensors = [("blk.0.weight", _big(1)), ("blk.0.norm", b"\x02" * 8)]  # norm is sub-threshold
    m = ss.seed_cache(cache, tensors, model_id="m", gguf_sha256="deadbeef", threshold=THR)
    assert len(m["entries"]) == 1 and m["entries"][0]["name"] == "blk.0.weight"
    files = {f for f in os.listdir(cache) if f != ss.MANIFEST_NAME}
    assert files == {ss.cache_filename(ss.fnv1a_hash(_big(1)))}


def test_cache_file_name_and_bytes_match_what_the_server_expects(tmp_path):
    cache = str(tmp_path)
    raw = _big(7)
    ss.seed_cache(cache, [("w", raw)], model_id="m", gguf_sha256="s", threshold=THR)
    key = ss.cache_filename(ss.fnv1a_hash(raw))
    with open(os.path.join(cache, key), "rb") as fh:
        assert fh.read() == raw          # verbatim bytes, as ofs.write() stores them


def test_duplicate_tensor_bytes_are_written_once(tmp_path):
    cache = str(tmp_path)
    raw = _big(3)
    m = ss.seed_cache(cache, [("a", raw), ("b", raw)], model_id="m", gguf_sha256="s", threshold=THR)
    assert len(m["entries"]) == 2                       # both referenced
    assert len([f for f in os.listdir(cache) if f != ss.MANIFEST_NAME]) == 1  # one file


def test_seed_from_gguf_refuses_on_sha256_mismatch(tmp_path):
    gguf = tmp_path / "model.gguf"
    gguf.write_bytes(b"not-a-real-model")
    real = hashlib.sha256(b"not-a-real-model").hexdigest()
    with pytest.raises(ss.SeedError):
        ss.seed_from_gguf(str(tmp_path / "c"), str(gguf), model_id="m",
                          expected_sha256="0" * 64, tensor_iter=lambda p: [("w", _big(1))], threshold=THR)
    # correct sha256 -> it proceeds and seeds
    m = ss.seed_from_gguf(str(tmp_path / "c2"), str(gguf), model_id="m",
                          expected_sha256=real, tensor_iter=lambda p: [("w", _big(1))], threshold=THR)
    assert m["complete"] and m["gguf_sha256"] == real


def test_verify_cache_passes_then_catches_corruption_and_gguf_mismatch(tmp_path):
    cache = str(tmp_path)
    ss.seed_cache(cache, [("w", _big(5))], model_id="m", gguf_sha256="abc", threshold=THR)
    assert ss.verify_cache(cache, expected_sha256="abc")["complete"]
    with pytest.raises(ss.SeedError):
        ss.verify_cache(cache, expected_sha256="different")          # wrong GGUF pin
    # corrupt the cached file -> hash no longer matches its name
    key = ss.cache_filename(ss.fnv1a_hash(_big(5)))
    with open(os.path.join(cache, key), "ab") as fh:
        fh.write(b"x")
    with pytest.raises(ss.SeedError):
        ss.verify_cache(cache)


def test_verify_cache_refuses_incomplete_or_absent_manifest(tmp_path):
    with pytest.raises(ss.SeedError):
        ss.verify_cache(str(tmp_path))                               # no manifest
    (tmp_path / ss.MANIFEST_NAME).write_text(json.dumps({"complete": False, "entries": []}))
    with pytest.raises(ss.SeedError):
        ss.verify_cache(str(tmp_path))                               # incomplete


# ── CLI (python -m meshembed_node.split_seed) ─────────────────────────────────
def test_cli_verify_ok_then_reports_refusal(tmp_path, capsys):
    cache = str(tmp_path / "c")
    ss.seed_cache(cache, [("w", _big(9))], model_id="m", gguf_sha256="abc", threshold=THR)
    assert ss.main(["verify", "--cache-dir", cache]) == 0
    assert "cache OK" in capsys.readouterr().out
    # wrong pin -> exit 2, REFUSED, no traceback
    assert ss.main(["verify", "--cache-dir", cache, "--sha256", "nope"]) == 2
    assert "REFUSED" in capsys.readouterr().out


def test_cli_seed_sha_mismatch_refuses_before_touching_the_gguf(tmp_path, capsys):
    gguf = tmp_path / "m.gguf"
    gguf.write_bytes(b"content")
    rc = ss.main(["seed", "--gguf", str(gguf), "--sha256", "0" * 64,
                  "--model", "m", "--cache-dir", str(tmp_path / "c")])
    assert rc == 2 and "REFUSED" in capsys.readouterr().out
    # nothing was written on refusal
    assert not (tmp_path / "c").exists() or not any((tmp_path / "c").iterdir())
