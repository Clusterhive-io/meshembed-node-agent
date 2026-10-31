"""v0.3.80 (auditor 2026-10-30 06:31Z F80-1..F80-6, 06:45Z W-1..W-4 + D-1..D-4): the start path's optional duties can
never end the node, and with their flags unset they import, start and write NOTHING."""
from __future__ import annotations

import re
import sys
import threading
from pathlib import Path

import pytest

from meshembed_node import selfcheck as SC
from meshembed_node import worker as W

pytestmark = pytest.mark.unit
PKG = Path(W.__file__).resolve().parent


def _block(monkeypatch, mod):
    """Make `from . import <mod>` raise, whatever ran before: no sys.modules entry AND no package attribute
    (from-import reads the package attribute first)."""
    import meshembed_node
    monkeypatch.setitem(sys.modules, f"meshembed_node.{mod}", None)
    monkeypatch.delattr(meshembed_node, mod, raising=False)


class _Cfg:
    backend_url, api_key, node_id = "http://127.0.0.1:9", "k", "node-x"


def test_w1_the_agent_host_decision_comes_before_any_import():
    assert W.agent_host_skip({}) == "agent_host_off"
    assert W.agent_host_skip({"MESHEMBED_AGENT_HOST": "0"}) == "agent_host_off"
    assert W.agent_host_skip({"MESHEMBED_AGENT_HOST": "1"}, platform="win32") == "agent_host_linux_only"
    assert W.agent_host_skip({"MESHEMBED_AGENT_HOST": "1"}, platform="darwin") == "agent_host_linux_only"
    assert W.agent_host_skip({"MESHEMBED_AGENT_HOST": "1"}, platform="linux") is None


def test_f80_4_flag_unset_imports_starts_and_writes_nothing(monkeypatch, tmp_path):
    monkeypatch.delenv("MESHEMBED_AGENT_HOST", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    _block(monkeypatch, "agent_daemon")                                  # any import attempt would raise
    threads = {t.name for t in threading.enumerate()}
    assert W._start_agent_host(_Cfg()) == "agent_host_off"
    assert {t.name for t in threading.enumerate()} == threads           # no thread
    assert list(tmp_path.iterdir()) == []                                # no file under HOME


def test_w1_on_windows_with_the_flag_set_the_node_goes_on(monkeypatch):
    monkeypatch.setenv("MESHEMBED_AGENT_HOST", "1")
    monkeypatch.setattr(W.sys, "platform", "win32")
    _block(monkeypatch, "agent_daemon")
    assert W._start_agent_host(_Cfg()) == "agent_host_linux_only"


def test_w1_an_import_failure_on_linux_is_contained(monkeypatch):
    monkeypatch.setenv("MESHEMBED_AGENT_HOST", "1")
    monkeypatch.setattr(W.sys, "platform", "linux")
    _block(monkeypatch, "agent_daemon")                                  # ImportError inside the try
    assert W._start_agent_host(_Cfg()) == "agent_host_error"


def test_w3_a_serve_duty_import_failure_is_contained(monkeypatch):
    _block(monkeypatch, "serve_duty")
    assert W._start_serve_duty(_Cfg()) == "serve_error"
    assert W._SERVE_OFF == "serve_error"


def test_w2_agent_daemon_has_no_top_level_posix_import():
    src = (PKG / "agent_daemon.py").read_text(encoding="utf-8")
    assert not re.search(r"^(import (grp|pwd)|from (grp|pwd) import)", src, re.M)
    assert re.search(r"^    import grp$", src, re.M) and re.search(r"^    import pwd$", src, re.M)


def test_d4_selfcheck_passes_here_and_fails_closed_with_closed_codes(monkeypatch, capsys):
    ok, problems = SC.check()
    assert ok and problems == []
    real = SC.importlib.import_module

    def boom(name, *a, **k):
        if name == "meshembed_node.agent_bridge":
            raise ModuleNotFoundError("No module named 'grp'")
        return real(name, *a, **k)
    monkeypatch.setattr(SC.importlib, "import_module", boom)
    assert SC.main() == 1
    out = capsys.readouterr().out
    assert out.startswith("meshembed-node selfcheck FAILED: agent_bridge:ModuleNotFoundError") and "grp" not in out


def test_d4_the_selfcheck_allow_list_is_exactly_the_root_launchers():
    assert set(SC.LINUX_ONLY_BY_DESIGN) == {"serve_launch", "split_launch"}
    for name in SC.LINUX_ONLY_BY_DESIGN:                  # imported by no package module
        for f in PKG.glob("*.py"):
            if f.stem in (name, "serve_launch", "selfcheck"):
                continue
            assert not re.search(rf"\bimport {name}\b|from \.{name} import|from \. import {name}\b",
                                 f.read_text(encoding="utf-8")), (name, f.name)


def test_f80_6_every_catalogue_load_reads_the_packaged_file():
    """The 0.3.78 'catalog unreadable' line was the OLD process reading the NEW package file mid-update: no node code
    loads a catalogue from anywhere but CATALOG_PATH (the backend never sends catalogue entries to a node)."""
    calls = []
    for f in PKG.glob("*.py"):
        for line in f.read_text(encoding="utf-8").splitlines():
            code = line.split("#", 1)[0]
            if code.lstrip().startswith("def "):
                continue
            for m in re.finditer(r"load_catalog\(([^)]*)\)", code):
                calls.append((f.name, m.group(1).strip()))
    assert calls
    for name, args in calls:
        first = args.split(",")[0].strip()
        assert first in ("", "path=CATALOG_PATH", "include_serve_only=True") or first.startswith("include_serve_only"), \
            (name, args)


def test_d4_selfcheck_as_the_installers_run_it_writes_nothing(tmp_path):
    """python -I -m meshembed_node selfcheck, as all three installers call it: exit 0, one closed line, no file."""
    import subprocess
    env = {"HOME": str(tmp_path), "PATH": "/usr/bin:/bin", "PYTHONPATH": str(PKG.parent)}
    p = subprocess.run([sys.executable, "-c", "import sys; sys.argv=['meshembed_node','selfcheck']; "
                        "import runpy; runpy.run_module('meshembed_node', run_name='__main__')"],
                       env=env, capture_output=True, text=True, timeout=120)
    assert p.returncode == 0, p.stdout + p.stderr
    assert p.stdout.strip() == "meshembed-node selfcheck ok"
    assert p.stderr == ""                                                # SC-1: nothing on stderr at all
    assert list(tmp_path.iterdir()) == []                                # nothing written under HOME


def test_sc1_the_selfcheck_keeps_stderr_empty_whatever_an_import_does(monkeypatch, capfd):
    """SC-1: a module that warns, logs or writes to fd 2 itself while it imports leaves stderr EMPTY (install.ps1 runs
    under EAP Stop, and Windows PowerShell 5.1 can turn a native stderr line into a terminating error)."""
    import logging
    import os
    import warnings

    def noisy():
        print("to sys.stderr", file=sys.stderr)
        os.write(2, b"straight to fd 2\n")
        warnings.warn("a FutureWarning at import", FutureWarning)
        logging.getLogger("meshembed_node.noisy").warning("a warning through the last-resort handler")
        return True, []
    monkeypatch.setattr(SC, "check", noisy)
    assert SC.main() == 0
    out, err = capfd.readouterr()
    assert out == "meshembed-node selfcheck ok\n" and err == ""
    print("stderr works again afterwards", file=sys.stderr)
    assert capfd.readouterr().err == "stderr works again afterwards\n"


def test_sc1_install_ps1_never_redirects_the_selfchecks_stderr():
    src = (PKG.parent / "install.ps1").read_text(encoding="utf-8")
    line = next(ln for ln in src.splitlines() if "-I -m meshembed_node selfcheck" in ln)
    assert "2>" not in line                                              # no 2>&1 / 2>$null on that call
    block = src[src.index("$scOut = & {"):src.index(line)]
    assert "$ErrorActionPreference = 'Continue'" in block                 # and a local Continue around it


@pytest.mark.parametrize("installer,check,before", [
    ("install.sh", '"$VENV_PY" -I -m meshembed_node selfcheck',
     ['# ── Upgrade path: harden the unit, restart the running daemon', 'systemctl enable --now meshembed-node.service']),
    ("install-mac.sh", '"$PYTHON_BIN" -I -m meshembed_node selfcheck',
     ['# ── self-register (skipped on UPGRADE_ONLY)', 'launchctl bootstrap "$LAUNCHCTL_TARGET"']),
    ("install.ps1", '$scOut = & {',
     ['Step "Register node with backend"', 'Step "Start the daemon"', 'Write-Host "  [OK] INSTALLATION VERIFIED"']),
])
def test_d4_every_installer_selfchecks_before_any_start_and_fails_on_it(installer, check, before):
    src = (PKG.parent / installer).read_text(encoding="utf-8")
    i = src.index(check)
    for marker in before:
        assert i < src.index(marker), (installer, marker)                # before registering / (re)starting
    tail = src[i:i + 400]
    assert ("|| fail " in tail) if installer != "install.ps1" else ("FailWithDiagnostic" in tail)
