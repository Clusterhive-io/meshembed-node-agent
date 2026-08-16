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
    log.info("Accelerator: CPU — %s", _cpu_name())
    return "cpu", _cpu_name(), 0


def _cpu_name() -> str:
    """A CPU label a human can act on.

    This value lands in `nodes.gpu_model` -- the field really means "accelerator",
    and on a CPU-only node it is the CPU. It used to be
    `platform.processor() or platform.machine()`, and platform.processor() is
    EMPTY on most Linux builds, so the dashboard showed "x86_64" or "i386" for
    every CPU node. That is not wrong, it is just useless: the operator deciding
    whether a box is worth running cannot tell a Xeon from a Celeron.

    Best-effort per platform, falling back to the old behaviour rather than
    failing -- a node must never be blocked from reporting because it cannot name
    its own CPU.
    """
    import subprocess

    try:
        if platform.system() == "Linux":
            with open("/proc/cpuinfo", "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if line.lower().startswith("model name"):
                        name = line.split(":", 1)[1].strip()
                        if name:
                            return name
        elif platform.system() == "Darwin":
            out = subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                capture_output=True, text=True, timeout=5,
            )
            if out.returncode == 0 and out.stdout.strip():
                return out.stdout.strip()
        elif platform.system() == "Windows":
            # platform.processor() IS meaningful on Windows (it returns the
            # brand string), unlike on Linux where it is usually empty.
            if platform.processor().strip():
                return platform.processor().strip()
    except Exception:
        pass
    return platform.processor() or platform.machine() or "CPU"


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
def _is_cuda_oom(exc: Exception) -> bool:
    """CUDA memory-exhaustion in its several disguises. Message-based on
    purpose: torch.cuda.OutOfMemoryError only covers the first form, and cuBLAS
    failures surface as generic RuntimeErrors."""
    msg = str(exc)
    return (
        "CUDA out of memory" in msg
        or "CUBLAS_STATUS_NOT_INITIALIZED" in msg
        or "CUBLAS_STATUS_ALLOC_FAILED" in msg
        or "CUDA error: out of memory" in msg
    )


def _free_accelerator_memory() -> None:
    """gc first (the model refs must actually die), then hand torch's reserved
    blocks back to the driver. Safe no-op on CPU/MPS or without torch."""
    import gc
    gc.collect()
    try:
        import torch
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
    except Exception:
        pass


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
      * The RESIDENT cache holds at most `MESHEMBED_MODEL_CACHE_SIZE` entries
        (default 3), further capped on a GPU by free VRAM
        (`MESHEMBED_MODEL_VRAM_MB`); least-recently-used eviction. An operator
        allow-list larger than that budget stays fully ELIGIBLE (reported by
        installed_models, downloaded to disk) but only budget-many are held in
        VRAM at once -- so a big catalog cannot OOM a small card.
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
        _configured = max(
            1, int(os.environ.get("MESHEMBED_MODEL_CACHE_SIZE", "3") or "3"),
        )
        # VRAM-budget the RESIDENT cache on a GPU: holding every assigned model
        # resident is what OOMs a small card (the 16-model catalog on an 8 GB
        # M60). Cap the LRU at what free VRAM can hold; eligibility to SERVE a
        # model (installed_models / the operator allow-list) is tracked
        # separately, so bounding residency does not stop the backend routing
        # any assigned model -- it just lazy-loads on demand. CPU keeps the
        # configured size (system RAM is the constraint there, not VRAM).
        if _DEVICE == "cuda":
            _budget = _vram_budget_models(vram_free_mb())
            self._cache_size = max(1, min(_configured, _budget))
            if self._cache_size < _configured:
                log.info(
                    "encoder.vram_budget resident cache capped %d -> %d (free VRAM %d MB)",
                    _configured, self._cache_size, vram_free_mb(),
                )
        else:
            self._cache_size = _configured
        # Operator allow-list as an ordered list (eligibility, reported by
        # installed_models even when a model is evicted from VRAM), and a disk
        # sha per known model so we can report an evicted model's sha.
        self._served: Optional[List[str]] = None
        self._sha_by_model: dict = {}
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
        non-empty the node serves ONLY these model_ids and refuses lazy-loads
        outside the set. ELIGIBILITY (what installed_models() reports, so the
        scheduler routes it) covers the WHOLE set and is downloaded to disk;
        RESIDENCY (what's held in VRAM) stays bounded by the VRAM-budgeted LRU,
        so a large allow-list no longer OOMs a small GPU -- evicted models
        lazy-load on demand. Empty/None lifts the restriction (default +
        lazy-load any).

        Safe to call repeatedly from a background thread; a no-op when the set
        is unchanged. Downloads + VRAM warmup happen OUTSIDE the lock."""
        desired = [m for m in (model_ids or []) if m]
        with self._lock:
            if not desired:
                if self._pinned is not None:
                    self._pinned = None
                    self._served = None
                    log.info("encoder.field_of_play_cleared -> default + lazy-load")
                return
            new_set = set(desired)
            unchanged = self._pinned == new_set
            self._pinned = new_set
            self._served = list(desired)
            # Residency stays VRAM-budgeted -- do NOT bump _cache_size to
            # len(desired). Holding every assigned model resident is exactly what
            # OOMs a small GPU (16 models on an 8 GB M60). The LRU bounds
            # residency; _served + _sha_by_model keep the whole allow-list
            # ELIGIBLE in installed_models(), so the backend still routes any of
            # them -- an evicted one just lazy-loads on its next job.
            for name in [k for k in list(self._cache) if k not in new_set]:
                del self._cache[name]
        if unchanged:
            return
        log.info("encoder.field_of_play set=%s (resident cap %d)", sorted(new_set), self._cache_size)
        # Make every served model SERVEABLE (downloaded to disk + sha known)
        # WITHOUT loading it into VRAM, then warm at most _cache_size into VRAM;
        # the rest load lazily on first use. Runs outside the lock (slow I/O).
        for name in desired:
            self._ensure_on_disk(name)
        for name in desired[: self._cache_size]:
            try:
                self._ensure_loaded(name, eager=True)
            except Exception as exc:
                log.warning("encoder.field_of_play.warm_failed model=%s exc=%s", name, exc)

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
        """Snapshot for the daemon's /get_job + /nodes/register payload.

        When an operator allow-list is set, report the WHOLE set (eligibility),
        not just what is resident in VRAM -- otherwise the VRAM-budgeted LRU
        evicting a model would stop the backend routing it. sha comes from the
        resident entry when loaded, else from the disk sha map. Unpinned nodes
        report their cache contents as before."""
        with self._lock:
            resident = {n: (sha, lu) for n, (_st, sha, lu) in self._cache.items()}
            served = list(self._served) if self._served is not None else None
            sha_map = dict(self._sha_by_model)
        if served is not None:
            out = []
            for name in served:
                if name in resident:
                    sha, last_used = resident[name]
                else:
                    sha, last_used = sha_map.get(name, ""), 0.0
                out.append({"model_id": name, "sha": sha or "", "last_used_at": last_used})
            return out
        return [
            {"model_id": name, "sha": sha or "", "last_used_at": last_used}
            for name, (sha, last_used) in resident.items()
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
            try:
                vecs = st_instance.encode(
                    texts, normalize_embeddings=True, batch_size=encode_batch_size(),
                )
            except Exception as exc:  # noqa: BLE001
                # CUDA-OOM RECOVERY (2026-08-16, Tesla M60). The LRU cache holds
                # up to MESHEMBED_MODEL_CACHE_SIZE models resident on the GPU;
                # on an 8 GB card three models leave ~nothing free, and the next
                # encode dies — either "CUDA out of memory" outright, or as
                # CUBLAS_STATUS_NOT_INITIALIZED (cublasCreate cannot even
                # allocate its workspace). Failing the customer's subjob while
                # sitting on gigabytes of EVICTABLE idle models is absurd: drop
                # every cached model except the active one, return the VRAM,
                # and retry once. A second failure is a real error and raises.
                if not _is_cuda_oom(exc):
                    raise
                log.warning(
                    "encoder.cuda_oom model=%s — evicting idle models and retrying"
                    " once (%s)", name, str(exc).splitlines()[0][:160],
                )
                self._evict_all_except(name)
                vecs = st_instance.encode(
                    texts, normalize_embeddings=True, batch_size=encode_batch_size(),
                )
            embeddings = np.asarray(vecs, dtype=np.float32).tolist()
        else:
            embeddings = [self._hash_embed(t) for t in texts]
            sha = ""
        elapsed = time.perf_counter() - t0
        return embeddings, round(elapsed, 3), sha

    def _evict_all_except(self, keep: str) -> None:
        """Drop every cached model but `keep`, then return freed VRAM to CUDA.

        Deleting the python refs alone is not enough: torch's caching allocator
        keeps the blocks reserved until empty_cache(), which is exactly the
        'reserved by PyTorch but unallocated' memory the OOM messages point at.
        """
        with self._lock:
            evicted = [n for n in list(self._cache) if n != keep]
            for n in evicted:
                del self._cache[n]
        if evicted:
            log.warning("encoder.oom_evict models=%s", ",".join(evicted))
        _free_accelerator_memory()

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
            _any_evicted = False
            while len(self._cache) >= self._cache_size:
                evicted, _ = self._cache.popitem(last=False)
                _any_evicted = True
                log.info("encoder.evict_lru model=%s", evicted)
            self._cache[name] = (st_instance, sha, time.time())
            # Remember the sha so installed_models() can still report this model
            # after the LRU later evicts it from VRAM.
            if sha:
                self._sha_by_model[name] = sha
        if _any_evicted:
            # Eviction only dropped the python refs; without this the blocks
            # stay 'reserved by PyTorch' and the VRAM never comes back.
            _free_accelerator_memory()
        log.info(
            "encoder.lazy_load_ok model=%s sha=%s",
            name, sha[:16] + "..." if sha else "(none)",
        )
        return st_instance, sha

    def _ensure_on_disk(self, name: str) -> None:
        """Download a served model's files to the HF cache and record its sha,
        WITHOUT loading it into VRAM. This is what makes an evicted-but-eligible
        model routable: installed_models() can report it, and encode() can
        lazy-load it fast on demand. No-op once the sha is known."""
        with self._lock:
            if self._sha_by_model.get(name):
                return
        if not _HAVE_ST:
            return
        sha = _model_sha_from_disk(name)
        if not sha:
            # Not on disk yet -> fetch the files (no torch / no VRAM), then hash.
            try:
                from huggingface_hub import snapshot_download
                snapshot_download(name)
            except Exception as exc:
                log.warning("encoder.predownload_failed model=%s exc=%s", name, exc)
                return
            sha = _model_sha_from_disk(name)
        if sha:
            with self._lock:
                self._sha_by_model[name] = sha
            log.info("encoder.on_disk model=%s sha=%s", name, sha[:16])

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
            # `name_or_path` is the HF *model id* (e.g. "intfloat/multilingual-
            # e5-small") for anything loaded from the hub -- i.e. every catalog
            # model -- so it is never a directory and this function used to
            # return "" 100% of the time. That silently made model_sha
            # verification inert everywhere: no daemon ever reported a sha, so
            # the backend had nothing to check (ROGUE_LAB FINDING 6).
            #
            # Resolve the real snapshot directory out of the HF cache instead.
            # local_files_only=True means this NEVER downloads -- if the model
            # is not cached we simply fall through and return "" as before.
            local_dir = model_name if os.path.isdir(model_name) else None
            if not local_dir:
                try:
                    from huggingface_hub import snapshot_download
                    local_dir = snapshot_download(model_name, local_files_only=True)
                except Exception as exc:  # not cached / hub lib missing / offline
                    log.debug("encoder.sha_cache_lookup_failed model=%s exc=%s",
                              model_name, exc)
                    local_dir = None
        if not local_dir or not os.path.isdir(local_dir):
            return ""

        return _sha_of_snapshot_dir(local_dir)
    except Exception as exc:
        log.warning("model_sha.compute_failed model=%s err=%s", model_name, exc)
        return ""


def _sha_of_snapshot_dir(local_dir: str) -> str:
    """sha256 of the checkpoint file inside an HF snapshot dir. Prefers
    safetensors; for sharded variants hashes the _index.json sentinel (good
    enough for 'did the bytes change'). "" if no candidate file is present."""
    import os
    candidates = [
        "model.safetensors",
        "pytorch_model.bin",
        "model.safetensors.index.json",
        "pytorch_model.bin.index.json",
    ]
    for fname in candidates:
        path = os.path.join(local_dir, fname)
        if os.path.isfile(path):
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            return h.hexdigest()
    return ""


def _model_sha_from_disk(name: str) -> str:
    """Compute a model's sha from the HF cache WITHOUT loading it into VRAM.
    Returns "" if the model is not on disk (never downloaded). Lets the daemon
    report an eligible model in installed_models() while it is evicted from the
    VRAM cache -- decoupling eligibility from residency (PART: M60 OOM fix)."""
    import os
    try:
        local_dir = name if os.path.isdir(name) else None
        if not local_dir:
            from huggingface_hub import snapshot_download
            local_dir = snapshot_download(name, local_files_only=True)
        if not local_dir or not os.path.isdir(local_dir):
            return ""
        return _sha_of_snapshot_dir(local_dir)
    except Exception as exc:  # not cached / hub lib missing / offline
        log.debug("encoder.sha_from_disk_failed model=%s exc=%s", name, exc)
        return ""


def _vram_budget_models(free_mb: int) -> int:
    """How many models can safely stay RESIDENT given free VRAM. Conservative:
    each resident model costs its weights plus torch workspace. Tunable via
    MESHEMBED_MODEL_VRAM_MB (default 2000). Returns >=1 always -- the reactive
    OOM-evict in encode() is the floor if even one model is too big."""
    import os
    try:
        per = max(256, int(os.environ.get("MESHEMBED_MODEL_VRAM_MB", "2000") or "2000"))
    except ValueError:
        per = 2000
    if free_mb <= 0:
        return 1
    return max(1, int(free_mb * 0.75 / per))
