"""HF-SQUAT (auditor HIGH 2026-11-08T17:20:37Z; design docs DESIGN_NOTE_HF_PINNED_LOADER_2026-11-08, DESIGN GO
17:23:59Z with HP-1..HP-5): an embedding model is loaded ONLY from files that match the signed pin table.

- The table (embed_pins.json) ships inside the signed node package (HP-1). Per model_id: the Hugging Face COMMIT
  revision, the sha256 of EVERY file the loader reads, and the weights sha the backend's catalogue pins.
- prepare(model_id) downloads exactly those files at that revision, verifies each sha (HP-2: once per process, never
  trusted from a marker on disk), refuses an unsafe cache dir (HP-3), refuses foreign module types and custom code
  (P-5, HP-5), and returns a private directory that holds only the verified files (symlinks to the verified blobs).
- Nothing here instantiates a model: the caller loads that directory with local_files_only=True and
  trust_remote_code=False (P-4).
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import stat
import threading
from pathlib import Path
from typing import Dict, Optional

log = logging.getLogger("meshembed_node.embed_pins")

TABLE_PATH = Path(__file__).with_name("embed_pins.json")
_REV = re.compile(r"^[0-9a-f]{40}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
# weights / code formats that are never read, whatever a folder holds (only *.safetensors weights are pinned)
_FORBIDDEN_SUFFIXES = (".bin", ".pt", ".pth", ".pkl", ".pickle", ".ckpt", ".h5", ".msgpack", ".ot", ".py", ".onnx")
_ALLOWED_MODULE_PREFIX = "sentence_transformers.models."

_lock = threading.Lock()
_verified: Dict[tuple, str] = {}        # (path, size, mtime_ns, inode) -> sha256, THIS process only (HP-2)


class PinError(RuntimeError):
    """A model that may not be loaded; the message is a short code + the model id, never file content."""


def load_table(path: Path = TABLE_PATH) -> Dict[str, dict]:
    """The signed pin table. A malformed entry is dropped (that model is then not loadable), never repaired."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        log.warning("embed_pins.table_unreadable exc=%s", exc)
        return {}
    # NE-1 (auditor 2026-11-09T08:18:53Z): valid JSON of the wrong shape fails CLOSED and quietly, never an
    # AttributeError out of installed_models() on every poll
    models = raw.get("models") if isinstance(raw, dict) else None
    if not isinstance(models, list):
        log.warning("embed_pins.table_malformed")
        return {}
    out = {}
    for e in models:
        if not isinstance(e, dict):
            log.warning("embed_pins.entry_refused model=?")
            continue
        mid, rev, files, wsha = e.get("model_id"), e.get("revision"), e.get("files"), e.get("weights_sha")
        ok = (isinstance(mid, str) and not _our_namespace(mid) and isinstance(rev, str) and _REV.match(rev)
              and isinstance(files, dict) and files and isinstance(wsha, str) and _SHA.match(wsha)
              and all(isinstance(p, str) and _safe_rel(p) and isinstance(s, str) and _SHA.match(s)
                      for p, s in files.items())
              and any(p.endswith(".safetensors") for p in files)
              and not any(p.endswith(_FORBIDDEN_SUFFIXES) for p in files))
        if ok:
            out[mid] = {"revision": rev, "files": dict(files), "weights_sha": wsha}
        else:
            log.warning("embed_pins.entry_refused model=%s", mid)
    return out


def _our_namespace(model_id: str) -> bool:
    """P-6: our generation namespace, in ANY case. Hugging Face resolves namespaces case-insensitively (the org was
    registered 2026-11-08 18:33Z as 'Meshembed'), so 'MeshEmbed/x' reaches the same repo as 'meshembed/x'."""
    return model_id.lower().startswith("meshembed/")


def _safe_rel(p: str) -> bool:
    return bool(p) and not p.startswith("/") and ".." not in Path(p).parts and "\\" not in p


def _sha256(path: str) -> str:
    st = os.stat(path)
    key = (os.path.realpath(path), st.st_size, st.st_mtime_ns, st.st_ino)
    with _lock:
        if key in _verified:
            return _verified[key]
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    digest = h.hexdigest()
    with _lock:
        _verified[key] = digest
    return digest


def check_private_dir(path: str) -> None:
    """HP-3: a directory the loader reads must belong to this process's user and not be group / world writable."""
    st = os.stat(path)
    if hasattr(os, "getuid") and st.st_uid != os.getuid():
        raise PinError(f"cache_dir_not_owned:{path}")
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise PinError(f"cache_dir_writable_by_others:{path}")


def hf_cache_dir() -> str:
    from huggingface_hub import constants
    return str(constants.HF_HUB_CACHE)


def pinned_root() -> str:
    """Where the verified views live: the node's own state (~/.meshembed/pinned-models), never a shared /tmp."""
    return os.environ.get("MESHEMBED_PINNED_MODELS_DIR") or os.path.join(os.path.expanduser("~"), ".meshembed",
                                                                         "pinned-models")


def _check_modules_and_config(view: str, model_id: str) -> None:
    """P-5 + HP-5: only sentence-transformers' own module classes; no custom code (auto_map) in any config."""
    mj = os.path.join(view, "modules.json")
    if os.path.isfile(mj):
        for m in json.loads(Path(mj).read_text(encoding="utf-8")):
            t = str(m.get("type", ""))
            if not t.startswith(_ALLOWED_MODULE_PREFIX):
                raise PinError(f"module_type_refused:{model_id}")
    for root, _dirs, files in os.walk(view):
        for f in files:
            if f.endswith(".json"):
                try:
                    data = json.loads(Path(root, f).read_text(encoding="utf-8"))
                except ValueError:
                    raise PinError(f"config_unreadable:{model_id}")
                if isinstance(data, dict) and ("auto_map" in data or data.get("trust_remote_code")):
                    raise PinError(f"custom_code_refused:{model_id}")


def prepare(model_id: str, table: Optional[Dict[str, dict]] = None, *, download=None) -> str:
    """Download (if needed) and VERIFY the pinned files of model_id; return a private directory holding only them.
    Raises PinError on anything else. `download(repo, revision, allow_patterns)` -> snapshot dir (injectable for
    tests; the default is huggingface_hub.snapshot_download)."""
    if _our_namespace(model_id):
        raise PinError(f"not_an_embedding_repo:{model_id}")            # P-6: never our generation namespace
    entry = (table if table is not None else load_table()).get(model_id)
    if entry is None:
        raise PinError(f"not_pinned:{model_id}")
    files, rev = entry["files"], entry["revision"]
    if download is None:
        from huggingface_hub import snapshot_download

        def download(repo, revision, allow_patterns):
            return snapshot_download(repo, revision=revision, allow_patterns=allow_patterns)
        cache = hf_cache_dir()
        os.makedirs(cache, mode=0o700, exist_ok=True)
        check_private_dir(cache)
    snap = download(model_id, rev, sorted(files))
    for rel, want in sorted(files.items()):
        p = os.path.join(snap, rel)
        if not os.path.isfile(p):
            raise PinError(f"pinned_file_missing:{model_id}")
        if _sha256(p) != want:
            raise PinError(f"model_pin_mismatch:{model_id}")
    root = pinned_root()
    os.makedirs(root, mode=0o700, exist_ok=True)
    check_private_dir(root)
    view = os.path.join(root, model_id.replace("/", "__") + "@" + rev)
    os.makedirs(view, mode=0o700, exist_ok=True)
    check_private_dir(view)
    # the view holds ONLY the pinned files: anything else in it (an old file, a planted one) refuses the load
    expected = {os.path.normpath(r) for r in files}
    for r, _d, fs in os.walk(view):
        for f in fs:
            if f.endswith(".tmp-link"):                                # a crash between symlink and rename
                os.unlink(os.path.join(r, f))
                continue
            rel = os.path.normpath(os.path.relpath(os.path.join(r, f), view))
            if rel not in expected:
                raise PinError(f"unexpected_file_in_view:{model_id}")
    for rel in files:
        target = os.path.realpath(os.path.join(snap, rel))
        link = os.path.join(view, rel)
        os.makedirs(os.path.dirname(link), mode=0o700, exist_ok=True)
        if os.path.islink(link) and os.path.realpath(link) == target:
            pass                                                        # already the verified blob
        elif os.path.isfile(link) and not os.path.islink(link) and _sha256(link) == files[rel]:
            pass                                                        # an earlier hardlink / copy, re-verified
        else:
            _place(target, link)
        if _sha256(link) != files[rel]:                                 # what the loader will open
            raise PinError(f"model_pin_mismatch:{model_id}")
    _check_modules_and_config(view, model_id)
    # the catalogue's weights sha is what the node always reported: model.safetensors, or the sharded index
    anchor = "model.safetensors" if "model.safetensors" in files else "model.safetensors.index.json"
    if files.get(anchor) != entry["weights_sha"]:
        raise PinError(f"weights_sha_disagrees_with_catalogue:{model_id}")
    return view


def _symlinks_allowed() -> bool:
    return os.name != "nt"


def _place(target: str, link: str) -> str:
    """WN-1 (auditor 2026-11-08T17:37:36Z): put the verified blob at `link` -- a symlink where the OS lets this user
    make one, else a hardlink, else a COPY (a Windows service has no SeCreateSymbolicLinkPrivilege). The caller hashes
    whatever lands there before any load. Returns which way it went."""
    tmp = link + ".tmp-link"
    if os.path.lexists(tmp):
        os.unlink(tmp)
    how = "symlink"
    try:
        if not _symlinks_allowed():
            raise OSError("no symlinks for a Windows service")
        os.symlink(target, tmp)
    except OSError:
        try:
            os.link(target, tmp)
            how = "hardlink"
        except OSError:
            import shutil
            shutil.copyfile(target, tmp)
            how = "copy"
    os.replace(tmp, link)
    return how


def weights_sha(model_id: str, table: Optional[Dict[str, dict]] = None) -> str:
    """The catalogue weights sha for a pinned model ("" when not pinned): what installed_models reports once
    prepare() has verified the files in this process."""
    e = (table if table is not None else load_table()).get(model_id)
    return e["weights_sha"] if e else ""
