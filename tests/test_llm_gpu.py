"""GPU offload decisions, without a card."""
from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from meshembed_node import llm  # noqa: E402

pytestmark = pytest.mark.unit


def test_all_layers_when_the_build_can_offload_none_when_it_cannot():
    assert llm.gpu_layers_choice(env={}, offload=True) == -1
    assert llm.gpu_layers_choice(env={}, offload=False) == 0


def test_the_operator_can_pin_the_layer_count():
    assert llm.gpu_layers_choice(env={"MESHEMBED_LLM_GPU_LAYERS": "0"}, offload=True) == 0
    assert llm.gpu_layers_choice(env={"MESHEMBED_LLM_GPU_LAYERS": "20"}, offload=False) == 20
    assert llm.gpu_layers_choice(env={"MESHEMBED_LLM_GPU_LAYERS": "junk"}, offload=True) == -1


def test_gpu_info_never_raises_and_is_cached(monkeypatch):
    monkeypatch.setattr(llm, "_GPU_INFO", None)
    import subprocess
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError("nvidia-smi")))
    info = llm.gpu_info()
    assert info["name"] is None and info["kind"] is None
    assert llm.gpu_info() is info


def test_gpu_info_parses_nvidia_smi(monkeypatch):
    monkeypatch.setattr(llm, "_GPU_INFO", None)
    import subprocess, types
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: types.SimpleNamespace(stdout="NVIDIA GeForce RTX 4070, 12282, 560.35.03\n"))
    monkeypatch.setattr("platform.system", lambda: "Linux")
    info = llm.gpu_info()
    assert info == {"name": "NVIDIA GeForce RTX 4070", "vram_mb": 12282, "driver": "560.35.03", "kind": "cuda"}


def test_readiness_carries_the_gpu_block():
    r = llm.readiness()
    assert "gpu" in r and set(r["gpu"]) >= {"name", "vram_mb", "driver", "kind", "offload"}
    assert isinstance(r["gpu"]["offload"], bool)
