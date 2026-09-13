"""What the wheel ships is what a node runs.

The OTA path is `pip install` from the tag tarball, so a file that is in the
repository but not in the built distribution does not exist on any node.
v0.3.54 shipped without llm_catalog.json for exactly that reason and every
node would have advertised no LLM models. Build the wheel and look inside it,
rather than trusting the config line.
"""
from __future__ import annotations

import glob
import pathlib
import subprocess
import sys
import zipfile

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_pyproject_declares_the_catalog_as_package_data():
    try:
        import tomllib
    except ImportError:                                # py<3.11
        pytest.skip("tomllib unavailable")
    cfg = tomllib.loads((ROOT / "pyproject.toml").read_text())
    data = cfg["tool"]["setuptools"]["package-data"]["meshembed_node"]
    assert "llm_catalog.json" in data


def test_the_built_wheel_contains_every_data_file_the_daemon_opens(tmp_path):
    """Build the wheel for real; skip only if the build toolchain is absent."""
    # pip's default build isolation fetches setuptools into a scratch env, so
    # this needs the index reachable; offline it skips rather than lies.
    r = subprocess.run(
        [sys.executable, "-m", "pip", "wheel", "-q", "--no-deps",
         "-w", str(tmp_path), str(ROOT)],
        capture_output=True, text=True, timeout=300,
    )
    if r.returncode != 0:
        pytest.skip(f"wheel build unavailable here: {r.stderr[-200:]}")
    whl = glob.glob(str(tmp_path / "*.whl"))[0]
    names = set(zipfile.ZipFile(whl).namelist())
    assert "meshembed_node/llm_catalog.json" in names, sorted(
        n for n in names if not n.endswith(".py"))
