"""Encoder: sentence-transformers with automatic device detection.

Preference order:
  CUDA (NVIDIA)  →  MPS (Apple Silicon)  →  CPU
"""
from __future__ import annotations

import hashlib
import logging
import platform
import time
from typing import List, Optional, Tuple

import numpy as np

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Accelerator detection
# ---------------------------------------------------------------------------

def _detect_accelerator() -> tuple[str, str, int]:
    """Return (device, gpu_model_name, vram_free_mb).

    Verifies TWO things for CUDA: pynvml finds a GPU **and** torch can
    actually use it. Without the torch check, an out-of-date driver
    would cause `SentenceTransformer(device="cuda")` to silently fall
    back to CPU (or, worse, blow up with a stack trace in some cases).
    """
    # 1. CUDA (NVIDIA — Linux / Windows) — requires torch.cuda.is_available()
    try:
        import torch
        if torch.cuda.is_available():
            # torch can use CUDA. Try pynvml for the model name + VRAM,
            # but if pynvml is missing we still report cuda with VRAM=0.
            gpu_name = "NVIDIA GPU"
            vram = 0
            try:
                import pynvml
                pynvml.nvmlInit()
                handle = pynvml.nvmlDeviceGetHandleByIndex(0)
                gpu_name = pynvml.nvmlDeviceGetName(handle)
                if isinstance(gpu_name, bytes):
                    gpu_name = gpu_name.decode()
                info = pynvml.nvmlDeviceGetMemoryInfo(handle)
                vram = int(info.free / 1024 / 1024)
            except Exception:
                # Fall back to torch for the device name.
                try:
                    gpu_name = torch.cuda.get_device_name(0)
                except Exception:
                    pass
            log.info("Accelerator: CUDA — %s, free VRAM %d MB", gpu_name, vram)
            return "cuda", gpu_name, vram
        else:
            # torch sees CUDA but can't use it (driver too old, etc.).
            # Log the diagnosis and fall through to CPU.
            try:
                import pynvml
                pynvml.nvmlInit()
                handle = pynvml.nvmlDeviceGetHandleByIndex(0)
                name = pynvml.nvmlDeviceGetName(handle)
                if isinstance(name, bytes):
                    name = name.decode()
                log.warning(
                    "NVIDIA GPU detected (%s) but torch.cuda can't use it "
                    "— driver likely too old. Falling back to CPU.", name,
                )
            except Exception:
                pass
    except ImportError:
        log.warning("torch not installed; skipping CUDA detection")
    except Exception as exc:
        log.warning("CUDA detection error: %s", exc)

    # 2. MPS (Apple Silicon — macOS arm64)
    if platform.system() == "Darwin" and platform.machine() == "arm64":
        try:
            import torch
            if torch.backends.mps.is_available():
                import psutil
                # Unified memory: report available RAM as a VRAM proxy.
                vram = int(psutil.virtual_memory().available / 1024 / 1024)
                chip = _apple_chip_name()
                log.info("Accelerator: MPS — %s, free RAM %d MB", chip, vram)
                return "mps", chip, vram
        except Exception:
            pass

    # 3. CPU fallback.
    cpu = platform.processor() or platform.machine() or "CPU"
    log.info("Accelerator: CPU — %s", cpu)
    return "cpu", cpu, 0


def _apple_chip_name() -> str:
    """Read the Apple chip name via sysctl when available."""
    try:
        import subprocess
        out = subprocess.check_output(
            ["sysctl", "-n", "machdep.cpu.brand_string"],
            stderr=subprocess.DEVNULL,
            timeout=2,
        ).decode().strip()
        if out:
            return out
    except Exception:
        pass
    return f"Apple Silicon ({platform.machine()})"


_DEVICE, _GPU_MODEL, _VRAM_FREE_MB = _detect_accelerator()

# Exported for worker.py
GPU_MODEL: str = _GPU_MODEL


def vram_free_mb() -> int:
    """Current free VRAM. CUDA: live nvml query. MPS / CPU: free RAM proxy."""
    if _DEVICE == "cuda":
        try:
            import pynvml
            handle = pynvml.nvmlDeviceGetHandleByIndex(0)
            info = pynvml.nvmlDeviceGetMemoryInfo(handle)
            return int(info.free / 1024 / 1024)
        except Exception:
            return 0
    if _DEVICE == "mps":
        import psutil
        return int(psutil.virtual_memory().available / 1024 / 1024)
    return 0


# ---------------------------------------------------------------------------
# sentence-transformers wrapper
# ---------------------------------------------------------------------------

try:
    from sentence_transformers import SentenceTransformer as _ST
    _HAVE_ST = True
except ImportError:
    _ST = None  # type: ignore
    _HAVE_ST = False


class Encoder:
    """Multimodel encoder with a bounded LRU cache.

    Hybrid lazy-load contract (multimodel expansion 2026-05-23):
      * The configured default model is loaded eagerly at __init__.
      * Additional models are lazy-loaded on first `encode(model_name=X)`
        call where X is not the default.
      * The cache holds at most `MESHEMBED_MODEL_CACHE_SIZE` entries
        (default 3); least-recently-used eviction.
      * Each cached entry tracks (sentence_transformer, sha, last_used_at)
        so the worker can report per-model SHA + an installed_models list
        with usage timestamps.

    The public `model_name` / `model_sha` properties continue to mirror
    the *default* model so existing register / poll payloads keep working
    unchanged; the worker uses `encode(model_name=...)` to pick a
    per-assignment model when it differs from the default.
    """

    def __init__(self, model_name: str) -> None:
        import os
        from collections import OrderedDict

        self.default_model_name = model_name
        # cache: model_name -> (st_instance, sha, last_used_ts)
        self._cache: "OrderedDict[str, Tuple[object, str, float]]" = OrderedDict()
        self._cache_size = max(
            1, int(os.environ.get("MESHEMBED_MODEL_CACHE_SIZE", "3") or "3"),
        )

        # Eagerly load the default model so the daemon's first /get_job
        # response can include a non-empty installed_models list.
        self._ensure_loaded(model_name, eager=True)

    # ---- backward-compatible accessors -------------------------------
    @property
    def model_name(self) -> str:
        return self.default_model_name

    @property
    def _model(self):
        """Legacy attribute — returns the default model's ST instance or
        None if it never loaded. Existing code paths that read
        `encoder._model is not None` keep working."""
        entry = self._cache.get(self.default_model_name)
        return entry[0] if entry else None

    @property
    def model_sha(self) -> str:
        entry = self._cache.get(self.default_model_name)
        return entry[1] if entry else ""

    # ---- public API ---------------------------------------------------
    def installed_models(self) -> List[dict]:
        """Snapshot for the daemon's /get_job + /nodes/register payload."""
        return [
            {
                "model_id": name,
                "sha": sha or "",
                "last_used_at": last_used,
            }
            for name, (_st, sha, last_used) in self._cache.items()
        ]

    def encode(
        self,
        texts: List[str],
        model_name: Optional[str] = None,
    ) -> Tuple[List[List[float]], float, str]:
        """Return (embeddings, gpu_seconds, model_sha_used).

        `model_name` overrides the default. If the model isn't in the
        cache, we attempt to load it (lazy). If load fails (out of disk,
        HF Hub unreachable, etc.) we fall back to the deterministic
        hash-embed for the *default* model so the daemon doesn't crash
        mid-job -- but the model_sha_used field will be empty so the
        backend can reject the result in strict-sha mode.
        """
        name = model_name or self.default_model_name
        t0 = time.perf_counter()
        st_instance, sha = self._get_or_load(name)
        if st_instance is not None:
            vecs = st_instance.encode(texts, normalize_embeddings=True)
            embeddings = np.asarray(vecs, dtype=np.float32).tolist()
        else:
            embeddings = [self._hash_embed(t) for t in texts]
            sha = ""
        elapsed = time.perf_counter() - t0
        return embeddings, round(elapsed, 3), sha

    # ---- cache internals ---------------------------------------------
    def _get_or_load(self, name: str) -> Tuple[Optional[object], str]:
        if name in self._cache:
            st_instance, sha, _ = self._cache[name]
            # Touch LRU position + bump last_used_at.
            self._cache.move_to_end(name)
            self._cache[name] = (st_instance, sha, time.time())
            return st_instance, sha
        # Cache miss -> lazy load.
        return self._ensure_loaded(name, eager=False)

    def _ensure_loaded(
        self, name: str, eager: bool,
    ) -> Tuple[Optional[object], str]:
        if name in self._cache:
            st_instance, sha, _ = self._cache[name]
            return st_instance, sha
        if not _HAVE_ST:
            return None, ""
        log.info(
            "encoder.lazy_load model=%s device=%s (cache_size=%d/%d eager=%s)",
            name, _DEVICE, len(self._cache), self._cache_size, eager,
        )
        try:
            st_instance = _ST(name, device=_DEVICE)
        except Exception as exc:
            log.warning(
                "encoder.lazy_load_failed model=%s exc=%s — keeping cache as-is",
                name, exc,
            )
            return None, ""
        try:
            sha = _compute_model_sha(st_instance, name)
        except Exception:
            sha = ""
        # Evict LRU if at capacity.
        while len(self._cache) >= self._cache_size:
            evicted, _ = self._cache.popitem(last=False)
            log.info("encoder.evict_lru model=%s", evicted)
        self._cache[name] = (st_instance, sha, time.time())
        log.info(
            "encoder.lazy_load_ok model=%s sha=%s",
            name, sha[:16] + "..." if sha else "(none)",
        )
        return st_instance, sha

    @staticmethod
    def _hash_embed(text: str, size: int = 128) -> List[float]:
        digest = hashlib.sha256(text.encode()).digest()
        seed = int.from_bytes(digest[:8], "big")
        rng = np.random.default_rng(seed)
        vec = rng.normal(0, 1, size).astype(np.float32)
        norm = float(np.linalg.norm(vec)) or 1.0
        return (vec / norm).tolist()


def _compute_model_sha(model: object, model_name: str) -> str:
    """sha256 of the model's checkpoint file (model.safetensors etc).

    The backend uses this to verify that the daemon is running the same
    bytes registered in `supported_models`. We hash whichever weight file
    sentence-transformers loaded -- preferring safetensors over pytorch_model.bin
    because the format is reproducible across torch versions.

    Returns "" on any failure (missing file, permission error, etc.).
    The daemon stays functional with an empty sha -- it just won't
    receive work from a backend running in strict-sha mode.
    """
    import os
    try:
        # sentence-transformers exposes the local cache path via the
        # _first_module() (a Transformer that wraps a HF AutoModel).
        # Different ST versions expose this slightly differently; try a
        # few well-known attribute paths and bail to "" otherwise.
        local_dir = None
        try:
            first = model._first_module()             # type: ignore[attr-defined]
            local_dir = getattr(first.auto_model, "name_or_path", None)
        except Exception:
            pass
        if not local_dir or not os.path.isdir(local_dir):
            # Fall back to the model_name -- if it's already a local path
            # we'll find the files; if it's a HF id, we can't help here.
            local_dir = model_name if os.path.isdir(model_name) else None
        if not local_dir:
            return ""

        # Prefer safetensors. The big sharded variants list filenames in a
        # _index.json; we hash a single sentinel file rather than walking
        # the shards (good enough for "did the bytes change" detection).
        candidates = [
            "model.safetensors",
            "pytorch_model.bin",
            "model.safetensors.index.json",
            "pytorch_model.bin.index.json",
        ]
        for name in candidates:
            path = os.path.join(local_dir, name)
            if os.path.isfile(path):
                h = hashlib.sha256()
                with open(path, "rb") as f:
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        h.update(chunk)
                return h.hexdigest()
        return ""
    except Exception as exc:
        log.warning("model_sha.compute_failed model=%s err=%s", model_name, exc)
        return ""
