"""Encoder: sentence-transformers with automatic device detection.

Preference order:
  CUDA (NVIDIA)  →  MPS (Apple Silicon)  →  CPU
"""
from __future__ import annotations

import hashlib
import logging
import os
import platform
import threading
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


# ---------------------------------------------------------------------------
# Inference precision (MESHEMBED_PRECISION: fp32 | fp16 | int8).
#
# MEASURED against the live fp32 canary references (ST 5.1.1, canary prompt):
#   fp16  -> cosine 0.999999 on bge-base / e5-large / MiniLM-L6.
#            Clears the 0.999 canary pass threshold with enormous margin, so it
#            needs NO per-precision reference vectors. Safe to enable.
#   int8  -> cosine 0.9226-0.9743. bge-base lands BELOW 0.95, i.e. the canary
#            FAIL band (beta +5.0). That is not a false positive: at ~0.92 the
#            embeddings are materially different, which is exactly the
#            "degraded/different model" signature the canary exists to catch.
#
# So int8 is gated behind an explicit override. Enabling it without
# per-precision canary references will get an HONEST node penalised, and the
# customer silently gets lower-fidelity vectors. It must become a visible tier
# with its own references + a retrieval-quality benchmark before general use.
# ---------------------------------------------------------------------------
def encode_batch_size() -> int:
    """How many texts to push through the model at once.

    sentence-transformers defaults to 32, which is tuned for a laptop, not for a
    24 GB accelerator: on a GPU it leaves most of the card idle and pays the
    per-batch overhead ~16x more often than necessary. We pick a device-aware
    default and let the operator override with MESHEMBED_BATCH_SIZE.

    Conservative on purpose — batch size is bounded by VRAM, and an OOM mid-job
    fails a customer's subjob. Bigger wins come from measuring on real hardware,
    which is what the override is for.
    """
    raw = (os.environ.get("MESHEMBED_BATCH_SIZE", "") or "").strip()
    if raw:
        try:
            n = int(raw)
            if n > 0:
                return n
            log.warning("encoder.bad_batch_size %r — must be > 0; using auto", raw)
        except ValueError:
            log.warning("encoder.bad_batch_size %r — not an int; using auto", raw)
    if _DEVICE == "cuda":
        # Scale with free VRAM; these are deliberately safe rather than optimal.
        vram = _VRAM_FREE_MB or 0
        if vram >= 20000:
            return 128
        if vram >= 10000:
            return 64
        return 32
    if _DEVICE == "mps":
        return 32
    return 16  # CPU: smaller batches keep latency and RAM sane


_VALID_PRECISIONS = ("fp32", "fp16", "int8")


def configured_precision() -> str:
    """Effective precision, after safety gating. Always one of _VALID_PRECISIONS."""
    raw = (os.environ.get("MESHEMBED_PRECISION", "fp32") or "fp32").strip().lower()
    if raw not in _VALID_PRECISIONS:
        log.warning("encoder.bad_precision %r — falling back to fp32", raw)
        return "fp32"
    if raw == "fp16" and _DEVICE == "cpu":
        # torch CPU fp16 is emulated: slower than fp32 and with no memory win.
        # The whole point of fp16 is GPU, so don't silently degrade CPU nodes.
        log.warning("encoder.fp16_on_cpu_ignored — fp16 needs a GPU; using fp32")
        return "fp32"
    if raw == "int8" and os.environ.get("MESHEMBED_ALLOW_INT8", "0") != "1":
        log.warning(
            "encoder.int8_refused — int8 scores ~0.92-0.97 against the fp32 canary "
            "reference, which lands in the canary warn/FAIL bands and will PENALISE "
            "this node. Set MESHEMBED_ALLOW_INT8=1 only if the backend has "
            "per-precision references. Using fp32."
        )
        return "fp32"
    return raw


def _apply_precision(st_instance, model_name: str):
    """Cast/quantise a freshly loaded model per configured_precision(). Any failure
    leaves the model at fp32 — never break encoding over an optimisation."""
    precision = configured_precision()
    if precision == "fp32":
        return st_instance
    try:
        import torch
        if precision == "fp16":
            st_instance = st_instance.half()
        elif precision == "int8":
            st_instance[0].auto_model = torch.quantization.quantize_dynamic(
                st_instance[0].auto_model, {torch.nn.Linear}, dtype=torch.qint8
            )
        log.info("encoder.precision_applied model=%s precision=%s device=%s",
                 model_name, precision, _DEVICE)
    except Exception as exc:  # noqa: BLE001
        log.warning("encoder.precision_failed model=%s precision=%s exc=%s — staying fp32",
                    model_name, precision, exc)
    return st_instance

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

    def __init__(self, model_name: str, preload: bool = True) -> None:
        import os
        from collections import OrderedDict

        self.default_model_name = model_name
        # cache: model_name -> (st_instance, sha, last_used_ts)
        self._cache: "OrderedDict[str, Tuple[object, str, float]]" = OrderedDict()
        self._cache_size = max(
            1, int(os.environ.get("MESHEMBED_MODEL_CACHE_SIZE", "3") or "3"),
        )
        # Guards _cache against concurrent access: the worker preloads the
        # default model on a background thread (so registration/polling isn't
        # blocked by the first model download) while the poll loop reads
        # installed_models() and encode() may run concurrently.
        self._lock = threading.RLock()
        # Operator "field of play": when non-None, the node serves ONLY these
        # model_ids -- preload them, evict others, refuse lazy-loads outside the
        # set. None = serve default + lazy-load any (the historical behaviour).
        self._pinned: Optional[set] = None

        # preload=True keeps the old eager behaviour (used by tests / direct
        # callers). The daemon passes preload=False and loads the default model
        # on a background thread via ensure_default_loaded() so a multi-hundred-
        # MB first-boot download doesn't keep the node from registering/polling.
        if preload:
            self._ensure_loaded(model_name, eager=True)

    def ensure_default_loaded(self) -> None:
        """Blocking load of the default model. Safe to call from a background
        thread; once it completes, installed_models() includes the default and
        the next poll reports it so the backend starts routing work."""
        try:
            self._ensure_loaded(self.default_model_name, eager=True)
        except Exception as exc:  # never let the preload thread crash silently
            log.warning("encoder.preload_failed model=%s exc=%s",
                        self.default_model_name, exc)

    def set_served_models(self, model_ids: Optional[List[str]]) -> None:
        """Apply the operator's model allow-list (the 'field of play'). When
        non-empty the node serves ONLY these model_ids: preload them, evict
        anything else (so installed_models() reflects the set and the scheduler
        only routes matching jobs), and refuse lazy-loads outside the set.
        Empty/None lifts the restriction (default + lazy-load any).

        Safe to call repeatedly from a background thread; a no-op when the set
        is unchanged and already loaded. Downloads happen OUTSIDE the lock."""
        desired = [m for m in (model_ids or []) if m]
        with self._lock:
            if not desired:
                if self._pinned is not None:
                    self._pinned = None
                    log.info("encoder.field_of_play_cleared -> default + lazy-load")
                return
            new_set = set(desired)
            already = self._pinned == new_set and all(m in self._cache for m in desired)
            self._pinned = new_set
            # Hold the whole pinned set in cache (don't let the LRU evict one).
            self._cache_size = max(self._cache_size, len(desired))
            # Evict anything not pinned so installed_models() == the allow-list.
            for name in [k for k in list(self._cache) if k not in new_set]:
                del self._cache[name]
            if already:
                return
            missing = [m for m in desired if m not in self._cache]
            log.info("encoder.field_of_play set=%s preloading=%s", sorted(new_set), missing)
        # Preload the pinned models outside the lock (each can be a slow download).
        for name in missing:
            try:
                self._ensure_loaded(name, eager=True)
            except Exception as exc:
                log.warning("encoder.field_of_play.preload_failed model=%s exc=%s", name, exc)

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
        with self._lock:
            items = list(self._cache.items())
        return [
            {
                "model_id": name,
                "sha": sha or "",
                "last_used_at": last_used,
            }
            for name, (_st, sha, last_used) in items
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
            vecs = st_instance.encode(
                texts, normalize_embeddings=True, batch_size=encode_batch_size(),
            )
            embeddings = np.asarray(vecs, dtype=np.float32).tolist()
        else:
            embeddings = [self._hash_embed(t) for t in texts]
            sha = ""
        elapsed = time.perf_counter() - t0
        return embeddings, round(elapsed, 3), sha

    # ---- cache internals ---------------------------------------------
    def _get_or_load(self, name: str) -> Tuple[Optional[object], str]:
        with self._lock:
            if name in self._cache:
                st_instance, sha, _ = self._cache[name]
                # Touch LRU position + bump last_used_at.
                self._cache.move_to_end(name)
                self._cache[name] = (st_instance, sha, time.time())
                return st_instance, sha
        # Cache miss -> lazy load (handles its own locking + slow download).
        return self._ensure_loaded(name, eager=False)

    def _ensure_loaded(
        self, name: str, eager: bool,
    ) -> Tuple[Optional[object], str]:
        # Fast path: already cached (held briefly under the lock).
        with self._lock:
            if name in self._cache:
                st_instance, sha, _ = self._cache[name]
                return st_instance, sha
            # Operator field-of-play: refuse any model outside the allow-list so
            # the node never serves a model the operator didn't sanction. (Set
            # members are loaded before this gate via set_served_models.)
            if self._pinned is not None and name not in self._pinned:
                log.info("encoder.field_of_play.refuse model=%s (not in operator allow-list)", name)
                return None, ""
        if not _HAVE_ST:
            return None, ""
        log.info(
            "encoder.lazy_load model=%s device=%s (cache_size=%d/%d eager=%s)",
            name, _DEVICE, len(self._cache), self._cache_size, eager,
        )
        # Load OUTSIDE the lock: this can download hundreds of MB and take
        # minutes, and we must not block installed_models()/encode() readers
        # (especially the background preload thread) for that whole window.
        try:
            st_instance = _ST(name, device=_DEVICE)
            st_instance = _apply_precision(st_instance, name)
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
        with self._lock:
            # Another thread may have loaded the same model while we were
            # downloading; if so, keep theirs and discard ours.
            if name in self._cache:
                cached_st, cached_sha, _ = self._cache[name]
                return cached_st, cached_sha
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
