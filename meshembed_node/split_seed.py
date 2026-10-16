"""Split-inference weight-cache seeder (di-step2).

A stage in a distributed split loads only its layer slice from the local rpc
weight-cache instead of receiving the weights over the wire at every connect.
This module fills that cache *offline* from the sha256-verified mirror GGUF, so
the coordinator transfers (near-)zero weight bytes when the chain forms, and
refuses to start a chain whose stage cannot prove a verified cache.

How the cache works (llama.cpp ggml-rpc, pinned b11445 / 58cb9138):
  - Only tensors with ``USAGE_WEIGHTS`` and byte-size > ``HASH_THRESHOLD``
    (10 MiB) take the hash-cache path; everything smaller is sent inline.
  - The cache key is the 64-bit FNV-1a hash of the *raw* tensor bytes.
  - The file is ``<cache_dir>/<key as 16 lowercase hex>`` holding those bytes
    verbatim (``snprintf("%016" PRIx64)`` + ``ofs.write(data, size)``).

So seeding needs nothing from the rpc-server message/parsing path: we compute
FNV-1a over the GGUF tensor bytes and drop them at the same filename the server
would. This module NEVER links or invokes rpc-server, set_tensor_hash or
deserialize_tensor (the CVE-fenced path); it only reads a GGUF and writes files.

Byte-identity assumption: for a weight that llama.cpp maps verbatim from the
GGUF (the standard quant types, no load-time transform), the bytes the client
would hash equal the GGUF's on-disk tensor bytes, so our FNV key matches the
server's. ``verify_cache`` re-hashes every file so a format we got wrong fails
closed here rather than silently missing at connect.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import Callable, Iterable, Iterator, Tuple

# Mirror of ggml-rpc.cpp HASH_THRESHOLD. Must track the rpc-server we ship;
# a mismatch only costs cache misses (fail-closed at the coordinator), never a
# wrong result, because the server re-derives the key itself.
HASH_THRESHOLD = 10 * 1024 * 1024

_FNV_OFFSET = 0xCBF29CE484222325
_FNV_PRIME = 0x100000001B3
_MASK64 = (1 << 64) - 1

MANIFEST_NAME = "MANIFEST.json"

# A (name, raw_bytes) source. The GGUF adapter is one; tests inject their own.
TensorSource = Iterable[Tuple[str, bytes]]


class SeedError(Exception):
    """Seeding or verification failed; the cache must not be used."""


def fnv1a_hash(data: bytes) -> int:
    """64-bit FNV-1a, byte-exact with ggml-rpc.cpp fnv_hash().

    The algorithm is a sequential XOR-then-multiply chain, so it cannot be vectorised while
    staying byte-identical to the server. In pure Python it runs at a few MB/s, which is fine
    for the offline one-shot seed of a stage's own layer slice (minutes per model) but is a
    known follow-up to move to a native routine if whole-model seeding is ever needed.
    """
    h = _FNV_OFFSET
    prime, mask = _FNV_PRIME, _MASK64
    for b in data:
        h = ((h ^ b) * prime) & mask
    return h


def cache_filename(hash_value: int) -> str:
    """The server's on-disk name for a cached tensor: 16 lowercase hex."""
    return f"{hash_value:016x}"


def sha256_file(path: str, *, _chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_chunk), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass(frozen=True)
class SeedEntry:
    name: str
    key: str          # cache filename (16 hex)
    nbytes: int


def _atomic_write(path: str, data: bytes) -> None:
    tmp = f"{path}.tmp.{os.getpid()}"
    with open(tmp, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def seed_cache(
    cache_dir: str,
    tensors: TensorSource,
    *,
    model_id: str,
    gguf_sha256: str,
    threshold: int = HASH_THRESHOLD,
) -> dict:
    """Write the above-threshold weight tensors into ``cache_dir`` and a manifest.

    Verify-before-use: every file is read back and re-hashed before it is
    recorded, and the manifest is marked ``complete`` only after all entries
    verify. The manifest pins ``gguf_sha256`` so the coordinator can refuse a
    stage seeded from the wrong weights.
    """
    os.makedirs(cache_dir, exist_ok=True)
    entries: list[SeedEntry] = []
    seen_keys: set[str] = set()

    for name, raw in tensors:
        if len(raw) <= threshold:
            continue
        key = cache_filename(fnv1a_hash(raw))
        path = os.path.join(cache_dir, key)
        if key not in seen_keys:
            _atomic_write(path, raw)
            # verify-before-use: read back and re-hash this exact file.
            with open(path, "rb") as fh:
                back = fh.read()
            if cache_filename(fnv1a_hash(back)) != key or len(back) != len(raw):
                raise SeedError(f"cache verify failed for tensor {name!r} (key {key})")
            seen_keys.add(key)
        entries.append(SeedEntry(name=name, key=key, nbytes=len(raw)))

    manifest = {
        "version": 1,
        "model_id": model_id,
        "gguf_sha256": gguf_sha256,
        "threshold": threshold,
        "entries": [e.__dict__ for e in entries],
        "complete": True,
    }
    _atomic_write(os.path.join(cache_dir, MANIFEST_NAME),
                  json.dumps(manifest, sort_keys=True).encode())
    return manifest


def load_manifest(cache_dir: str) -> dict:
    path = os.path.join(cache_dir, MANIFEST_NAME)
    if not os.path.exists(path):
        raise SeedError("no cache manifest")
    with open(path, "rb") as fh:
        return json.loads(fh.read())


def verify_cache(cache_dir: str, *, expected_sha256: str | None = None) -> dict:
    """Re-hash every cached file against the manifest; raise on any mismatch.

    This is what a stage runs before it starts rpc-server, and the shape the
    coordinator trusts. Pass ``expected_sha256`` (the catalogue pin) to also
    bind the cache to a specific GGUF.
    """
    manifest = load_manifest(cache_dir)
    if not manifest.get("complete"):
        raise SeedError("cache manifest is incomplete")
    if expected_sha256 is not None and manifest.get("gguf_sha256") != expected_sha256:
        raise SeedError("cache was seeded from a different GGUF (sha256 mismatch)")
    for entry in manifest.get("entries", []):
        key = entry["key"]
        path = os.path.join(cache_dir, key)
        if not os.path.exists(path):
            raise SeedError(f"cached tensor file missing: {key}")
        with open(path, "rb") as fh:
            data = fh.read()
        if cache_filename(fnv1a_hash(data)) != key:
            raise SeedError(f"cached tensor file corrupt (hash != name): {key}")
        if len(data) != entry["nbytes"]:
            raise SeedError(f"cached tensor file wrong size: {key}")
    return manifest


def gguf_tensor_iter(gguf_path: str) -> Iterator[Tuple[str, bytes]]:
    """Yield (tensor_name, raw_bytes) for every tensor in a GGUF file.

    Uses the ``gguf`` library (present wherever llama-cpp-python runs, i.e. on a
    stage). ``ReaderTensor.data`` is a numpy view of the raw on-disk bytes for
    the tensor (quantized types stay as their packed uint8 blocks), so
    ``.tobytes()`` is exactly what the rpc client would hash.
    """
    from gguf import GGUFReader  # node-side dependency; not needed to seed tests

    reader = GGUFReader(gguf_path)
    for tensor in reader.tensors:
        yield tensor.name, tensor.data.tobytes()


def seed_from_gguf(
    cache_dir: str,
    gguf_path: str,
    *,
    model_id: str,
    expected_sha256: str,
    tensor_iter: Callable[[str], Iterable[Tuple[str, bytes]]] = gguf_tensor_iter,
    threshold: int = HASH_THRESHOLD,
) -> dict:
    """Verify the GGUF's sha256, then seed the cache from it.

    Fail-closed: a sha256 mismatch refuses before a single byte is cached.
    """
    actual = sha256_file(gguf_path)
    if actual != expected_sha256:
        raise SeedError(
            f"GGUF sha256 mismatch for {model_id}: expected {expected_sha256}, got {actual}")
    return seed_cache(
        cache_dir, tensor_iter(gguf_path),
        model_id=model_id, gguf_sha256=expected_sha256, threshold=threshold)


def main(argv: "list[str] | None" = None) -> int:
    """`python -m meshembed_node.split_seed` -- seed or verify a stage weight-cache.

    Stays clear of the rpc protocol: `seed` reads a GGUF and writes cache files; `verify`
    re-hashes the cache. Prints counts/sizes only, never tensor names' contents or any
    document text. Exit 0 on success, 2 on a SeedError, 1 on a usage/IO error.
    """
    import argparse

    parser = argparse.ArgumentParser(
        prog="python -m meshembed_node.split_seed",
        description="Seed or verify a split-inference rpc weight-cache from a GGUF.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_seed = sub.add_parser("seed", help="sha256-verify a GGUF and fill the cache from it")
    p_seed.add_argument("--gguf", required=True)
    p_seed.add_argument("--sha256", required=True, help="expected GGUF sha256 (the catalogue pin)")
    p_seed.add_argument("--model", required=True, help="model id (manifest label)")
    p_seed.add_argument("--cache-dir", required=True)

    p_verify = sub.add_parser("verify", help="re-hash the cache against its manifest")
    p_verify.add_argument("--cache-dir", required=True)
    p_verify.add_argument("--sha256", default=None, help="bind to this GGUF pin (optional)")

    args = parser.parse_args(argv)
    try:
        if args.cmd == "seed":
            manifest = seed_from_gguf(
                args.cache_dir, args.gguf,
                model_id=args.model, expected_sha256=args.sha256)
            total = sum(e["nbytes"] for e in manifest["entries"])
            print(f"seeded {len(manifest['entries'])} tensor(s), "
                  f"{total} bytes, into {args.cache_dir} (gguf {args.sha256})")
            return 0
        if args.cmd == "verify":
            manifest = verify_cache(args.cache_dir, expected_sha256=args.sha256)
            print(f"cache OK: {len(manifest['entries'])} tensor(s), "
                  f"model {manifest.get('model_id')}, gguf {manifest.get('gguf_sha256')}")
            return 0
    except SeedError as exc:
        print(f"split_seed: REFUSED: {exc}")
        return 2
    except OSError as exc:
        print(f"split_seed: IO error: {exc}")
        return 1
    return 1


if __name__ == "__main__":
    import sys

    sys.exit(main())
