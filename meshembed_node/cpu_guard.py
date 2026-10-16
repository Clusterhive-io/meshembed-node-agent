"""Can this CPU run the LLM runtime? Decided BEFORE anything imports it.

docs/DESIGN_CPU_FEATURE_GUARD_2026-10-14.md. The Z400 (Xeon W3680, Westmere: no
AVX2/FMA/F16C) crash-looped for two days: every poll asked `llm.readiness()`,
which imported `llama_cpp`, whose `libggml-cpu` executes instructions that CPU
does not have -> SIGILL -> systemd restart, 12,172 times. The node never polled,
so embeddings were lost too and the backend saw nothing.

An import that can kill the process cannot be "tried" in-process. So:

1. Fast path, the CPU flags (no import): on x86 the CPU wheel needs AVX2, FMA
   and F16C. Missing -> never import, never probe.
2. Authoritative path, a SUBPROCESS probe: `python -I -c "import llama_cpp; ..."`.
   A child killed by SIGILL (or any other non-clean exit) means "do not import
   it here". This also catches a future wheel built for a newer baseline that
   the flag list does not know about.

The definitive answers (ok / sigill) are cached per runtime version, boot and
interpreter in `~/.meshembed/llm_probe.json`, so a node probes once per boot.
A timeout or another failure is not cached (retried at the next start) but
still keeps this process away from the import: fail safe, embeddings go on.
"""
from __future__ import annotations

import importlib.util
import json
import logging
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)

# What the x86 CPU wheel needs (llama-cpp-python 0.3.35 from the project's own
# index, the only x86 build the installers fetch).
REQUIRED_X86 = ("avx2", "fma", "f16c")
PROBE_TIMEOUT_S = 60
PROBE_CODE = ("import llama_cpp; llama_cpp.llama_backend_init(); "
              "llama_cpp.llama_print_system_info()")
# How "killed by an illegal instruction" looks: POSIX returncode -SIGILL, a shell's
# 128+4, Windows STATUS_ILLEGAL_INSTRUCTION (unsigned and signed).
_SIGILL_CODES = {-4, 132, 0xC000001D, -1073741795}

_VERDICT: Optional[Dict[str, Any]] = None


def _is_x86(machine: Optional[str] = None) -> bool:
    m = (machine if machine is not None else platform.machine()).lower()
    return m in ("x86_64", "amd64", "i386", "i686", "x86")


def cpu_flags(system: Optional[str] = None, cpuinfo_text: Optional[str] = None,
              sysctl: Optional[Callable[[str], str]] = None) -> Optional[set]:
    """The CPU's feature flags we care about, lower-case; None when unknowable."""
    system = system or platform.system()
    if system == "Linux":
        try:
            text = cpuinfo_text if cpuinfo_text is not None else Path("/proc/cpuinfo").read_text()
        except OSError:
            return None
        for line in text.splitlines():
            if line.startswith("flags") and ":" in line:
                return set(line.split(":", 1)[1].split())
        return None
    if system == "Windows":
        try:
            import ctypes
            present = ctypes.windll.kernel32.IsProcessorFeaturePresent  # type: ignore[attr-defined]
        except Exception:
            return None
        # PF_AVX2_INSTRUCTIONS_AVAILABLE = 40. Windows has no constant for FMA or
        # F16C; every AVX2 CPU shipped (Haswell+, Zen+) also has both.
        return {"avx2", "fma", "f16c"} if present(40) else set()
    if system == "Darwin":
        def _sysctl(key: str) -> str:
            return subprocess.run(["sysctl", "-n", key], capture_output=True, text=True,
                                  timeout=5).stdout
        read = sysctl or _sysctl
        try:
            text = (read("machdep.cpu.features") + " " + read("machdep.cpu.leaf7_features")).lower()
        except Exception:
            return None
        return set(text.split()) if text.strip() else None
    return None


def missing_features(flags: Optional[set], machine: Optional[str] = None) -> List[str]:
    """Required features the CPU lacks; [] when fine OR when we cannot tell."""
    if flags is None or not _is_x86(machine):
        return []
    return [f for f in REQUIRED_X86 if f not in flags]


def runtime_installed() -> bool:
    """Is the runtime importable at all -- answered WITHOUT importing it."""
    if "llama_cpp" in sys.modules:             # already imported here: it exists
        return True
    try:
        return importlib.util.find_spec("llama_cpp") is not None
    except Exception:
        return False


def runtime_version() -> Optional[str]:
    try:
        from importlib.metadata import version
        return version("llama-cpp-python")
    except Exception:
        return None


def _boot_id() -> str:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError:
        pass
    try:
        import psutil
        return str(int(psutil.boot_time()))
    except Exception:
        return ""


def _cache_path() -> Path:
    return Path.home() / ".meshembed" / "llm_probe.json"


def probe(python: Optional[str] = None, timeout: float = PROBE_TIMEOUT_S,
          run: Callable[..., Any] = subprocess.run) -> Tuple[str, Optional[int]]:
    """Import the runtime in a child: 'ok' | 'sigill' | 'timeout' | 'error'."""
    cmd = [python or sys.executable, "-I", "-c", PROBE_CODE]
    kw: Dict[str, Any] = {"capture_output": True, "timeout": timeout}
    if os.name == "nt":
        kw["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        rc = run(cmd, **kw).returncode
    except subprocess.TimeoutExpired:
        return "timeout", None
    except Exception:
        return "error", None
    if rc == 0:
        return "ok", 0
    return ("sigill" if rc in _SIGILL_CODES else "error"), rc


def _cache_key() -> Dict[str, str]:
    return {"runtime": runtime_version() or "", "boot": _boot_id(), "python": sys.executable}


def _read_cache(key: Dict[str, str]) -> Optional[str]:
    try:
        rec = json.loads(_cache_path().read_text(encoding="utf-8"))
        if all(rec.get(k) == v for k, v in key.items()) and rec.get("result") in ("ok", "sigill"):
            return rec["result"]
    except Exception:
        pass
    return None


def _write_cache(key: Dict[str, str], result: str) -> None:
    try:
        p = _cache_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({**key, "result": result}), encoding="utf-8")
    except Exception:                               # best effort: a read-only home re-probes
        pass


def verdict(refresh: bool = False) -> Dict[str, Any]:
    """{'ok', 'reason', 'missing', 'probe'} -- ok=False means: do not import llama_cpp."""
    global _VERDICT
    if _VERDICT is not None and not refresh:
        return _VERDICT
    if "llama_cpp" in sys.modules:
        # Already imported in this process and we are still alive: nothing to guard.
        return {"ok": True, "reason": None, "missing": [], "probe": "loaded"}
    if not runtime_installed():
        # Nothing to protect against; not cached, an install may follow.
        return {"ok": True, "reason": None, "missing": [], "probe": "not_installed"}
    missing = missing_features(cpu_flags())
    if missing:
        out = {"ok": False, "reason": "cpu_unsupported", "missing": missing, "probe": "skipped"}
    else:
        key = _cache_key()
        result = _read_cache(key)
        rc = None
        if result is None:
            result, rc = probe()
            if result in ("ok", "sigill"):
                _write_cache(key, result)
        if result == "ok":
            out = {"ok": True, "reason": None, "missing": [], "probe": "ok"}
        elif result == "sigill":
            out = {"ok": False, "reason": "cpu_unsupported", "missing": [], "probe": "sigill"}
        else:
            out = {"ok": False, "reason": "runtime_probe_failed", "missing": [], "probe": result,
                   "returncode": rc}
    if not out["ok"]:
        log.warning("llm: runtime disabled on this machine (%s%s; probe %s) -- embeddings only",
                    out["reason"], f": missing {','.join(out['missing'])}" if out["missing"] else "",
                    out["probe"])
    _VERDICT = out
    return out
