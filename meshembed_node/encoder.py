"""Encoder: sentence-transformers with automatic device detection.

Preference order:
  CUDA (NVIDIA)  →  MPS (Apple Silicon)  →  CPU
"""
from __future__ import annotations

import hashlib
import logging
import platform
import time
from typing import List, Tuple

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
    def __init__(self, model_name: str) -> None:
        self.model_name = model_name
        self._model = None
        self.model_sha: str = ""
        if _HAVE_ST:
            log.info("Loading model %s on device=%s …", model_name, _DEVICE)
            try:
                self._model = _ST(model_name, device=_DEVICE)
                log.info("Model loaded")
                self.model_sha = _compute_model_sha(self._model, model_name)
                log.info(
                    "Model fingerprint: %s sha=%s",
                    model_name,
                    self.model_sha[:16] + "..." if self.model_sha else "(none)",
                )
            except Exception as exc:
                log.warning("Could not load model: %s — using hash fallback", exc)

    def encode(self, texts: List[str]) -> Tuple[List[List[float]], float]:
        """Return (embeddings, gpu_seconds)."""
        t0 = time.perf_counter()
        if self._model is not None:
            vecs = self._model.encode(texts, normalize_embeddings=True)
            embeddings = np.asarray(vecs, dtype=np.float32).tolist()
        else:
            embeddings = [self._hash_embed(t) for t in texts]
        elapsed = time.perf_counter() - t0
        return embeddings, round(elapsed, 3)

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
