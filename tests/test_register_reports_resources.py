"""The daemon must MEASURE its resources at enrolment, not hardcode them.

Backend half in `backend/tests/test_register_reports_resources.py`. This half
lives here because it imports `meshembed_node`, whose dependencies (psutil) exist
only in the node-agent environment -- in the backend test container the import
fails and the test would look broken rather than absent.

Reported 2026-08-08: a freshly onboarded node showed "unknown / 0 MB / 0 MB"
because the register payload carried the literal string "unknown" and no memory
figures, even though the installer had already detected the GPU and prints it.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def test_the_daemon_measures_rather_than_hardcoding():
    """Guards the other half. The backend can only store what it is sent, and
    the CLI used to send the literal string "unknown"."""
    import inspect
    from meshembed_node import __main__ as m

    src = inspect.getsource(m)
    reg = src[src.index('"invite_token": args.invite'):]
    reg = reg[: reg.index("resp = requests.post")]
    assert '"gpu_model":    "unknown"' not in reg, (
        "gpu_model must be measured, not hardcoded"
    )
    assert '"vram_free_mb"' in reg and '"ram_free_mb"' in reg


def test_resource_probes_are_best_effort():
    """A machine that cannot read its own metrics must still enrol."""
    import inspect
    from meshembed_node import __main__ as m

    src = inspect.getsource(m)
    block = src[src.index("gpu_model, vram_free_mb, ram_free_mb ="):]
    block = block[: block.index("payload = {")]
    assert block.count("except Exception") >= 2, (
        "each probe needs its own guard, or one unreadable metric blocks enrolment"
    )


def test_cpu_only_nodes_get_an_actionable_label():
    """`gpu_model` really means "accelerator", and on a CPU-only node it is the
    CPU. It used to be `platform.processor() or platform.machine()`, and
    platform.processor() is EMPTY on most Linux builds -- so every CPU node in the
    dashboard read "x86_64" or "i386".

    Not wrong, just useless: an operator deciding whether a box is worth running
    cannot tell a Xeon from a Celeron. Observed on live prod nodes 2026-08-08.
    """
    import inspect
    from meshembed_node import encoder

    src = inspect.getsource(encoder._cpu_name)
    assert "/proc/cpuinfo" in src, "no Linux CPU model lookup"
    assert "machdep.cpu.brand_string" in src, "no macOS lookup"
    assert "Windows" in src, "no Windows branch"
    # and it must never raise -- a node that cannot name its CPU must still report
    assert "except Exception" in src
    assert encoder._cpu_name(), "must always return something"


def test_cpu_name_is_used_by_the_detector():
    import inspect
    from meshembed_node import encoder

    src = inspect.getsource(encoder._detect_accelerator)
    assert "_cpu_name()" in src
    assert "platform.processor() or platform.machine() or \"CPU\"" not in src, (
        "the old uninformative fallback must not remain in the detector"
    )
