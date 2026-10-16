"""CPU-feature guard + crash-loop safe mode (docs/DESIGN_CPU_FEATURE_GUARD_2026-10-14.md).

The Z400 case: a CPU without AVX2 must never import llama_cpp in-process, must report
why, and must keep serving embeddings. Nothing here imports a real runtime.
"""
import subprocess
import sys
import types
from pathlib import Path

import pytest

from meshembed_node import cpu_guard, llm, safe_mode

WESTMERE = "processor\t: 0\nflags\t\t: fpu vme sse sse2 ssse3 sse4_1 sse4_2 popcnt aes\n"
HASWELL = "processor\t: 0\nflags\t\t: fpu sse4_2 avx avx2 fma f16c bmi2\n"


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.delenv("MESHEMBED_SAFE_MODE", raising=False)
    monkeypatch.setattr(cpu_guard, "_VERDICT", None)
    monkeypatch.setattr(safe_mode, "_ACTIVE", None)
    monkeypatch.setattr(safe_mode, "_HEALTHY", False)
    sys.modules.pop("llama_cpp", None)
    yield


# ── flags ────────────────────────────────────────────────────────────────────
def test_linux_flags_parsed():
    assert {"avx2", "fma", "f16c"} <= cpu_guard.cpu_flags("Linux", cpuinfo_text=HASWELL)


def test_westmere_misses_all_three():
    flags = cpu_guard.cpu_flags("Linux", cpuinfo_text=WESTMERE)
    assert cpu_guard.missing_features(flags, "x86_64") == ["avx2", "fma", "f16c"]


def test_arm_and_unknown_are_not_flag_blocked():
    assert cpu_guard.missing_features(set(), "aarch64") == []
    assert cpu_guard.missing_features(None, "x86_64") == []


def test_macos_flags_from_sysctl():
    vals = {"machdep.cpu.features": "FPU SSE4.2 AVX1.0 FMA F16C",
            "machdep.cpu.leaf7_features": "BMI1 AVX2 BMI2"}
    flags = cpu_guard.cpu_flags("Darwin", sysctl=lambda k: vals[k])
    assert cpu_guard.missing_features(flags, "x86_64") == []


# ── probe ────────────────────────────────────────────────────────────────────
def _runner(rc=None, exc=None):
    def run(cmd, **kw):
        assert cmd[1] == "-I"                       # isolated, never the cwd/site of an attacker
        assert kw["timeout"] > 0
        if exc:
            raise exc
        return types.SimpleNamespace(returncode=rc)
    return run


@pytest.mark.parametrize("rc,want", [(0, "ok"), (-4, "sigill"), (132, "sigill"),
                                     (0xC000001D, "sigill"), (1, "error"), (-11, "error")])
def test_probe_classifies_exit(rc, want):
    assert cpu_guard.probe(python="py", run=_runner(rc))[0] == want


def test_probe_timeout():
    exc = subprocess.TimeoutExpired(cmd="py", timeout=1)
    assert cpu_guard.probe(python="py", run=_runner(exc=exc))[0] == "timeout"


# ── verdict ──────────────────────────────────────────────────────────────────
def test_missing_flags_block_without_probing(monkeypatch):
    real = cpu_guard.cpu_flags
    monkeypatch.setattr(cpu_guard, "runtime_installed", lambda: True)
    monkeypatch.setattr(cpu_guard, "cpu_flags", lambda: real("Linux", cpuinfo_text=WESTMERE))
    monkeypatch.setattr(cpu_guard, "_is_x86", lambda m=None: True)
    monkeypatch.setattr(cpu_guard, "probe", lambda *a, **k: pytest.fail("must not probe"))
    v = cpu_guard.verdict()
    assert v == {"ok": False, "reason": "cpu_unsupported", "missing": ["avx2", "fma", "f16c"],
                 "probe": "skipped"}


def test_sigill_probe_blocks_and_is_cached(monkeypatch, tmp_path):
    real = cpu_guard.cpu_flags
    monkeypatch.setattr(cpu_guard, "runtime_installed", lambda: True)
    monkeypatch.setattr(cpu_guard, "cpu_flags", lambda: real("Linux", cpuinfo_text=HASWELL))
    monkeypatch.setattr(cpu_guard, "runtime_version", lambda: "0.3.35")
    monkeypatch.setattr(cpu_guard, "_boot_id", lambda: "boot-1")
    calls = []
    monkeypatch.setattr(cpu_guard, "probe", lambda *a, **k: calls.append(1) or ("sigill", -4))
    assert cpu_guard.verdict()["probe"] == "sigill"
    assert cpu_guard.verdict(refresh=True)["reason"] == "cpu_unsupported"
    assert len(calls) == 1                           # the second answer came from the cache
    monkeypatch.setattr(cpu_guard, "_boot_id", lambda: "boot-2")
    cpu_guard.verdict(refresh=True)
    assert len(calls) == 2                           # a new boot probes again


def test_timeout_blocks_this_process_but_is_not_cached(monkeypatch):
    real = cpu_guard.cpu_flags
    monkeypatch.setattr(cpu_guard, "runtime_installed", lambda: True)
    monkeypatch.setattr(cpu_guard, "cpu_flags", lambda: real("Linux", cpuinfo_text=HASWELL))
    calls = []
    monkeypatch.setattr(cpu_guard, "probe", lambda *a, **k: calls.append(1) or ("timeout", None))
    assert cpu_guard.verdict()["reason"] == "runtime_probe_failed"
    cpu_guard.verdict(refresh=True)
    assert len(calls) == 2


def test_already_imported_runtime_is_trusted(monkeypatch):
    monkeypatch.setitem(sys.modules, "llama_cpp", types.ModuleType("llama_cpp"))
    monkeypatch.setattr(cpu_guard, "probe", lambda *a, **k: pytest.fail("must not probe"))
    assert cpu_guard.verdict()["ok"] is True


# ── llm integration: the import never happens when blocked ───────────────────
def test_runtime_available_never_imports_on_unsupported_cpu(monkeypatch):
    monkeypatch.setattr(cpu_guard, "runtime_installed", lambda: True)
    monkeypatch.setattr(cpu_guard, "verdict", lambda refresh=False: {
        "ok": False, "reason": "cpu_unsupported", "missing": ["avx2"], "probe": "skipped"})
    import builtins
    real_import = builtins.__import__

    def guard(name, *a, **k):
        if name == "llama_cpp" or name.startswith("llama_cpp."):
            raise AssertionError("llama_cpp imported on an unsupported CPU")
        return real_import(name, *a, **k)
    monkeypatch.setattr(builtins, "__import__", guard)
    assert llm.runtime_available() is False
    assert llm.gpu_offload_available() is False
    assert llm.execution_class()["runtime"] is None
    r = llm.readiness()
    assert r["blocked"] == "cpu_unsupported" and r["cpu"]["missing"] == ["avx2"]
    with pytest.raises(RuntimeError, match="runtime_unavailable"):
        llm.LlamaRunner()._load(llm.ModelSpec.__new__(llm.ModelSpec))


def test_readiness_without_runtime_is_still_no_runtime(monkeypatch):
    monkeypatch.setattr(cpu_guard, "runtime_installed", lambda: False)
    assert llm.readiness()["blocked"] == "no_runtime"


# ── crash-loop safe mode ─────────────────────────────────────────────────────
def test_third_start_without_a_poll_is_safe_mode():
    safe_mode.record_start(now=1)
    assert not safe_mode.active()
    safe_mode.record_start(now=2)
    assert not safe_mode.active()
    safe_mode.record_start(now=3)
    assert safe_mode.active()
    assert safe_mode.report() == {"reason": "crash_loop", "starts": 3}


def test_a_successful_poll_clears_the_breadcrumb(tmp_path):
    safe_mode.record_start(now=1)
    safe_mode.record_start(now=2)
    safe_mode.mark_healthy()
    assert not (tmp_path / ".meshembed" / "start_guard.json").exists()
    safe_mode._HEALTHY = False
    safe_mode.record_start(now=3)                    # counting starts again from 1
    assert not safe_mode.active()


def test_safe_mode_turns_the_runtime_off(monkeypatch):
    for t in (1, 2, 3):
        safe_mode.record_start(now=t)
    monkeypatch.setattr(cpu_guard, "runtime_installed", lambda: True)
    monkeypatch.setattr(cpu_guard, "verdict", lambda refresh=False: pytest.fail("must not probe"))
    assert llm.runtime_available() is False
    assert llm.readiness()["blocked"] == "safe_mode"


def test_operator_can_force_safe_mode(monkeypatch):
    monkeypatch.setenv("MESHEMBED_SAFE_MODE", "1")
    assert safe_mode.active()
    assert safe_mode.report()["reason"] == "operator"
