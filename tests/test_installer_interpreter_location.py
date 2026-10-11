"""The runtime interpreter must NOT land where the hardened unit cannot exec it.

2026-10-10 Helsinki incident (N-1736297, crash-looped ~15k times): install.sh ran
`uv venv --python 3.12`, and uv placed the managed interpreter under its default
$HOME/.local/share/uv/python. For a ROOT install $HOME is /root; the generated
unit drops to the meshembed user with ProtectHome=true, which masks /root -- so
the venv's bin/python (a symlink into /root) could not be exec'd: status=203/EXEC.

The fix RELOCATES the interpreter beside the venv (under /opt for root) via
UV_PYTHON_INSTALL_DIR, WITHOUT weakening the sandbox. These tests pin that the
installer sets that dir from the venv's parent and never falls back to the
masked $HOME/.local default, and that the relocated dir is made exec-able.
"""
from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]


def _install_sh() -> str:
    return (_ROOT / "install.sh").read_text()


def test_uv_python_install_dir_is_pinned_beside_the_venv():
    src = _install_sh()
    # The interpreter dir is exported and derived from the venv's PARENT, not left
    # to uv's $HOME/.local default (which is /root for a root install).
    assert "export UV_PYTHON_INSTALL_DIR=" in src, "installer must pin UV_PYTHON_INSTALL_DIR"
    assert 'dirname "$VENV_DIR"' in src, "the interpreter dir must derive from the venv parent (/opt for root)"


def test_pin_appears_before_the_uv_venv_call():
    src = _install_sh()
    pin = src.find("export UV_PYTHON_INSTALL_DIR=")
    venv = src.find('uv venv --python "$BASE_PY"')   # the real fresh-install call, not the comment
    assert pin != -1 and venv != -1 and pin < venv, (
        "UV_PYTHON_INSTALL_DIR must be exported BEFORE `uv venv` so the managed "
        "interpreter is downloaded into the relocated dir, not /root"
    )


def test_relocated_interpreter_is_made_exec_able():
    src = _install_sh()
    # the dropped service user must be able to read+exec the relocated interpreter
    assert 'chmod -R a+rX "$UV_PYTHON_INSTALL_DIR"' in src


def test_fix_does_not_weaken_the_sandbox():
    # The fix must RELOCATE, never loosen: ProtectHome stays true, and /root is
    # never added to the writable/readable paths to reach the old location.
    src = _install_sh()
    assert "ProtectHome=true" in src
    assert "ProtectHome=read-only" not in src and "ProtectHome=false" not in src
    assert "ReadWritePaths=/root" not in src and "ReadOnlyPaths=/root" not in src
