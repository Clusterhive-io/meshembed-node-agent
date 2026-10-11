"""The 203/EXEC crash-loop (Helsinki 2026-10-10, ~15k restarts) must be BRAKED and
EXPLAINED, in both the packaged unit and the install.sh-generated one.

DESIGN_NODE_SELF_HEAL.md increment 1:
  * StartLimit brake (bounded restarts, never reboots the host), and
  * an ExecStartPre exec-check so a missing/non-exec interpreter reads as a clear
    message instead of an opaque main-process 203/EXEC, and ExecStart is skipped.
"""
from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_PACKAGING_UNIT = (_ROOT / "packaging" / "meshembed-node.service").read_text()
_INSTALL_SH = (_ROOT / "install.sh").read_text()


def _has_start_limit(text: str) -> bool:
    return (
        "StartLimitIntervalSec=300" in text
        and "StartLimitBurst=5" in text
        and "StartLimitAction=none" in text
    )


def test_packaging_unit_has_the_brake_and_precheck():
    assert _has_start_limit(_PACKAGING_UNIT), "packaging unit missing the StartLimit brake"
    assert "StartLimitAction=none" in _PACKAGING_UNIT  # never reboots the host
    assert "ExecStartPre=" in _PACKAGING_UNIT
    # the launcher AND its shebang INTERPRETER are checked (Helsinki 203 was the
    # interpreter, not the launcher), without hardcoding the venv path
    assert 'test -x "$L"' in _PACKAGING_UNIT
    assert "interpreter (from shebang)" in _PACKAGING_UNIT
    assert "/opt/meshembed-node/.venv/bin/python" not in _PACKAGING_UNIT, (
        "do not hardcode a venv path the package may not use -- resolve the shebang instead"
    )


def test_generated_unit_has_the_brake_and_precheck():
    # The heredoc that install.sh writes to /etc/systemd/system/meshembed-node.service
    assert _has_start_limit(_INSTALL_SH), "install.sh generated unit missing the StartLimit brake"
    assert 'ExecStartPre=/bin/sh -c \'test -x "$VENV_PY"' in _INSTALL_SH, (
        "the generated unit must verify the venv interpreter is executable before ExecStart"
    )


def test_brake_is_bounded_not_a_reboot():
    # The whole point: stop the loop, do NOT escalate to a host reboot/poweroff.
    for unit in (_PACKAGING_UNIT, _INSTALL_SH):
        assert "StartLimitAction=reboot" not in unit
        assert "StartLimitAction=poweroff" not in unit


def test_hardening_is_not_weakened_by_the_brake():
    # Increment 1 adds a brake + precheck only; it must not loosen confinement.
    assert "ProtectHome=true" in _PACKAGING_UNIT
    assert "ProtectSystem=strict" in _PACKAGING_UNIT
