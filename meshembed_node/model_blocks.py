"""DISK-AWARE NODE item (1): per-block hashes of a model file, verified per block and cached in memory.

Design: for-docs/DESIGN_NOTE_DISK_AWARE_NODE_2026-11-14.md Rev 1 (auditor design GO 2026-11-14T12:14:36Z, D-1 / D-5).

A model's catalogue entry may name a block manifest (`blocks_manifest`) and pin its sha256 (`blocks_manifest_sha256`). The
catalogue ships inside the signed daemon release, so that pin is covered by the release signature: the manifest file is
checked against the pin BEFORE a single block hash in it is used (D-1). The manifest also repeats the model's whole-file
sha256 and must equal the catalogue's pin for that model; the whole-file sha stays the identity, the blocks are how it
is checked early (a bad block rejects a download at its first wrong byte) and how a later load avoids a second full read.

The verified-block cache is IN MEMORY only (dropped on every boot, never written to disk) and keyed by
(resolved path, size, ctime_ns, inode) for a regular, non-symlink file owned by this process's own user, never by mtime
(settable with `touch -d`). Pure stdlib: the same code runs on linux, mac and windows.

Racily clean (auditor ruling 2026-11-14T13:09:41Z, option (a), after a same-size rewrite inside one ctime tick replayed a stale
verdict): an entry records the time it was filled, and is NOT trusted when the file's ctime is within RACY_NS (20 ms) of that
time, or within a second of it when ctime has a whole-second value (a coarse-timestamp filesystem). An untrusted entry is
re-verified in full and re-filled; a later call, once the file is older than the window, is served from the cache.
Residual, stated: the attacker this cannot stop is the same user as the daemon (who can change the daemon itself). On Windows
st_ctime is the CREATION time and there is no owner check (no getuid): the key cannot see an in-place same-size rewrite there, so
MB-W (2026-11-17) skips the cache entirely on Windows: every call re-verifies.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat as _stat
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

BLOCK_SIZE = 8 * 1024 * 1024
MANIFEST_VERSION = 1
_MAX_MANIFEST_BYTES = 8 * 1024 * 1024          # 8 MiB block => a 1 TB file is 131072 hashes; far below this
_HEX = set("0123456789abcdef")


def _is_hex64(s: object) -> bool:
    return isinstance(s, str) and len(s) == 64 and set(s) <= _HEX


def build_manifest(path: Path, block_size: int = BLOCK_SIZE) -> dict:
    """Hash a file into a manifest (the release tool's job; also used by tests)."""
    whole = hashlib.sha256()
    blocks: List[str] = []
    size = 0
    with Path(path).open("rb") as fh:
        while True:
            buf = fh.read(block_size)
            if not buf:
                break
            whole.update(buf)
            blocks.append(hashlib.sha256(buf).hexdigest())
            size += len(buf)
    return {"version": MANIFEST_VERSION, "block_size": block_size, "size": size,
            "sha256": whole.hexdigest(), "blocks": blocks}


def manifest_bytes(manifest: dict) -> bytes:
    """The canonical bytes a manifest is shipped as; its sha256 is the catalogue's pin."""
    return (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def load_manifest(path: Path, pinned_sha256: str, model_sha256: str) -> Optional[dict]:
    """Read a manifest file; None unless its bytes match the pin FIRST and its content is well formed and names this model."""
    if not (_is_hex64(pinned_sha256) and _is_hex64(model_sha256)):
        return None
    try:
        st = os.lstat(path)
        if not _stat.S_ISREG(st.st_mode) or st.st_size <= 0 or st.st_size > _MAX_MANIFEST_BYTES:
            return None
        raw = Path(path).read_bytes()
    except OSError:
        return None
    if hashlib.sha256(raw).hexdigest() != pinned_sha256:       # D-1: nothing in the file is used before this holds
        return None
    try:
        m = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(m, dict) or m.get("version") != MANIFEST_VERSION or m.get("sha256") != model_sha256:
        return None
    bs, size, blocks = m.get("block_size"), m.get("size"), m.get("blocks")
    if not (isinstance(bs, int) and not isinstance(bs, bool) and 1 <= bs <= 256 * 1024 * 1024):
        return None
    if not (isinstance(size, int) and not isinstance(size, bool) and size > 0):
        return None
    if not isinstance(blocks, list) or len(blocks) != -(-size // bs) or not all(_is_hex64(b) for b in blocks):
        return None
    return m


RACY_NS = 20_000_000                                          # 20 ms; one ext4 ctime tick is ~4 ms
_LOCK = threading.Lock()
_VERIFIED: Dict[Tuple[str, int, int, int], Tuple[Set[int], int]] = {}   # key -> (verified block indexes, fill time ns); memory only


def _now_ns() -> int:
    return time.time_ns()


def _trusted(ctime_ns: int, fill_ns: int) -> bool:
    """False for a racily clean entry: the file was last changed too close to the moment the verdict was recorded."""
    age = fill_ns - ctime_ns
    if age < RACY_NS:
        return False
    if ctime_ns % 1_000_000_000 == 0 and age < 1_000_000_000 + RACY_NS:      # a whole-second ctime: coarse filesystem
        return False
    return True


def _key(path: Path, st: os.stat_result) -> Tuple[str, int, int, int]:
    return (os.path.realpath(path), st.st_size, st.st_ctime_ns, st.st_ino)


def _own_regular_file(path: Path) -> Optional[os.stat_result]:
    """The file's stat if it is a regular, non-symlink file owned by this user (where the OS has owners), else None."""
    try:
        st = os.lstat(path)
    except OSError:
        return None
    if not _stat.S_ISREG(st.st_mode):
        return None
    getuid = getattr(os, "getuid", None)
    if getuid is not None and st.st_uid != getuid():
        return None
    return st


def _cache_usable() -> bool:
    """MB-W (auditor 2026-11-17T10:38:32Z, the HP-2-W rule): False on Windows. There st_ctime_ns is the CREATION time, which the
    file's owner can set (SetFileTime) together with mtime, and there is no owner check, so the key cannot see a same-size in-place
    rewrite: no lookup and no fill, every call re-verifies (cost only, never a stale verdict)."""
    return os.name != "nt"


def forget_all() -> None:
    """Drop the cache (tests; a boot does this by being a new process)."""
    with _LOCK:
        _VERIFIED.clear()


def needs_read(path: Path, manifest: dict) -> bool:
    """True when verifying this file would read it (not fully cached for the same key, or racily clean): the caller then
    applies the read cap (read_cap.py) BEFORE calling verify_file. A file that cannot be verified at all also reads (False
    would hide the refusal verify_file gives)."""
    st = _own_regular_file(path)
    if st is None or st.st_size != manifest["size"] or not _cache_usable():
        return True
    with _LOCK:
        entry = _VERIFIED.get(_key(path, st))
    return not (entry is not None and _trusted(st.st_ctime_ns, entry[1]) and len(entry[0]) == len(manifest["blocks"]))


def verify_file(path: Path, manifest: dict, limiter=None) -> Tuple[bool, int, int]:
    """Verify a file against a manifest block by block, skipping blocks this process already verified for the same
    (path, size, ctime_ns, inode). Returns (ok, blocks_read, blocks_total). Stops at the first wrong block."""
    st = _own_regular_file(path)
    total = len(manifest["blocks"])
    if st is None or st.st_size != manifest["size"]:
        return False, 0, total
    key = _key(path, st)
    use_cache = _cache_usable()
    entry = None
    if use_cache:
        with _LOCK:
            entry = _VERIFIED.get(key)
    done = set(entry[0]) if entry is not None and _trusted(st.st_ctime_ns, entry[1]) else set()
    if len(done) == total:
        return True, 0, total
    bs, read = manifest["block_size"], 0
    try:
        with Path(path).open("rb") as fh:
            for i, want in enumerate(manifest["blocks"]):
                if i in done:
                    continue
                fh.seek(i * bs)
                buf = fh.read(bs)
                read += 1
                if limiter is not None:
                    limiter.wait(len(buf))
                if hashlib.sha256(buf).hexdigest() != want:
                    with _LOCK:
                        _VERIFIED.pop(key, None)
                    return False, read, total
                done.add(i)
    except OSError:
        return False, read, total
    st2 = _own_regular_file(path)                              # the file must not have changed while it was read
    if st2 is None or _key(path, st2) != key:
        return False, read, total
    if use_cache:
        with _LOCK:
            _VERIFIED[key] = (done, _now_ns())                 # filled AFTER the last block and the final stat
    return True, read, total


class StreamVerifier:
    """Check a download block by block AS IT ARRIVES: feed() returns False at the first wrong block, so a bad mirror
    costs one block of traffic, not the whole file; finish() checks the total size. No second read of the file is needed."""

    def __init__(self, manifest: dict) -> None:
        self._m = manifest
        self._buf = bytearray()
        self._i = 0
        self._bytes = 0

    def feed(self, chunk: bytes) -> bool:
        bs = self._m["block_size"]
        self._bytes += len(chunk)
        if self._bytes > self._m["size"]:
            return False
        self._buf += chunk
        while len(self._buf) >= bs:
            if self._i >= len(self._m["blocks"]) or hashlib.sha256(bytes(self._buf[:bs])).hexdigest() != self._m["blocks"][self._i]:
                return False
            del self._buf[:bs]
            self._i += 1
        return True

    def finish(self) -> bool:
        if self._bytes != self._m["size"]:
            return False
        if self._buf:
            if self._i >= len(self._m["blocks"]) or hashlib.sha256(bytes(self._buf)).hexdigest() != self._m["blocks"][self._i]:
                return False
            self._i += 1
            self._buf.clear()
        return self._i == len(self._m["blocks"])
