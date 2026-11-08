"""ABRT-CORE on every OS (auditor 2026-11-03 13:04:26Z, 13:14:55Z item 4): the daemon process asks for no core / no heap
dump itself, and the macOS plist pins the core limit to 0."""
from __future__ import annotations

import re
import sys
from pathlib import Path

from meshembed_node import worker

MAC = (Path(__file__).resolve().parents[1] / "install-mac.sh").read_text()


def test_posix_sets_rlimit_core_0():
    calls = []
    assert worker.no_crash_dumps("linux", setrlimit=lambda: calls.append("core0")) == "rlimit_core_0" and calls
    assert worker.no_crash_dumps("darwin", setrlimit=lambda: calls.append("core0")) == "rlimit_core_0"


def test_windows_sets_wer_noheap_process_scoped():
    flags = []
    assert worker.no_crash_dumps("win32", wer_set_flags=lambda f: flags.append(f) or 0) == "wer_noheap"
    assert flags == [0x1]                                            # WER_FAULT_REPORTING_FLAG_NOHEAP, this process only
    assert worker.no_crash_dumps("win32", wer_set_flags=lambda f: 1) == "wer_noheap_failed"   # an HRESULT error


def test_the_real_posix_call_really_lowers_the_limit_in_a_child():
    if sys.platform.startswith("win"):
        return
    import subprocess
    out = subprocess.run([sys.executable, "-c", "import resource; from meshembed_node import worker; "
                          "print(worker.no_crash_dumps()); print(resource.getrlimit(resource.RLIMIT_CORE))"],
                         capture_output=True, text=True, cwd=str(Path(__file__).resolve().parents[1]), check=True)
    assert out.stdout.splitlines() == ["rlimit_core_0", "(0, 0)"]


def test_run_calls_it_right_after_the_pause_check():
    # P-c keeps the pause check FIRST (test_real_pause); the no-dump call is the next statement, before anything loads
    src = Path(worker.__file__).read_text()
    body = src[src.index("def run(cfg: Config) -> None:"):]
    code = [l.strip() for l in body.splitlines()[1:] if l.strip() and not l.strip().startswith("#")][:3]
    assert code[:2] == ["from . import pause as _pause", '_pause.enforce("start")']
    assert code[2].startswith('log.info("crash dumps: %s", no_crash_dumps())')


def test_the_mac_plist_pins_core_0():
    assert re.search(r"<key>SoftResourceLimits</key>\s*<dict><key>Core</key><integer>0</integer></dict>", MAC)
    assert re.search(r"<key>HardResourceLimits</key>\s*<dict><key>Core</key><integer>0</integer></dict>", MAC)
