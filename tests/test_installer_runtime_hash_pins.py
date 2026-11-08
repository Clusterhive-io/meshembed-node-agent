"""IH-4 (RT-HASH, auditor 2026-11-07T07:15:37Z; design docs/DESIGN_IH4_RUNTIME_HASH_PINNING_2026-11-07.md, DESIGN GO
11:31:49Z, IH4-1 closed 11:33:08Z): the inference runtime is executable code, so the three installers install it only
from a pin table in the signed installer: per (variant, machine) an upstream URL + sha256, with --require-hashes
--no-deps; jinja2 3.1.6 and diskcache 5.6.3 by hash from PyPI only; no extra index, no fall-through. No pin for the
machine = no runtime (runtime_unpinned_platform). The closure is checked after the install (pip check); a failure
removes the runtime (runtime_deps_missing).

The source checks below are backed by an EXECUTED run of the Linux functions with uv stubbed (the control flow and
the exact requirements file). The real install against upstream was run by hand on 189 (2026-11-07, uv 0.11.19,
Python 3.12): installed and imported, uv pip check clean; a tampered hash gave rc 1 and no runtime; an unpinned
machine gave rc 2; without numpy the check failed."""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
SH = (ROOT / "install.sh").read_text(encoding="utf-8")
MAC = (ROOT / "install-mac.sh").read_text(encoding="utf-8")
PS1 = (ROOT / "install.ps1").read_text(encoding="utf-8")
BASE = "https://github.com/abetlen/llama-cpp-python/releases/download"

# The design's table (each sha read twice: GitHub's asset digest + our own download, except the CUDA rows, which are
# confirmed on the CUDA proof host at the per-build GO). (installer, key) -> (URL path under BASE, sha256)
PINS = {
    ("sh", "cpu/x86_64"): ("v0.3.35/llama_cpp_python-0.3.35-py3-none-manylinux2014_x86_64.manylinux_2_17_x86_64.whl",
                           "d172f3d3c8cdd194c3c47c71cb077ed6e61354a2d0f939ceeac0c8fd29999596"),
    ("sh", "cpu/aarch64"): ("v0.3.35/llama_cpp_python-0.3.35-py3-none-manylinux2014_aarch64.manylinux_2_17_aarch64.whl",
                            "b5a4abd4d1d506d6f06b997c21d0532670a3f5350c9e6cfb3e54c33bf1322584"),
    ("sh", "cu121/x86_64"): ("v0.3.35-cu121/llama_cpp_python-0.3.35-py3-none-manylinux_2_35_x86_64.whl",
                             "42dbf9adfde6bca98741980788035446fd5540747b86f5c42b9b810a52113a5d"),
    ("sh", "cu124/x86_64"): ("v0.3.35-cu124/llama_cpp_python-0.3.35-py3-none-manylinux_2_35_x86_64.whl",
                             "62fc788a4ecee5a579f40708ccfe0c4d566dd5c9959497bdc0544dbba94d82aa"),
    ("mac", "cpu/arm64"): ("v0.3.35/llama_cpp_python-0.3.35-py3-none-macosx_11_0_arm64.whl",
                           "f16df6e77c2b9ced0ebe7b50de33a125b4d0463f758edf7b516e2b1296fbbcf5"),
    ("mac", "metal/arm64"): ("v0.3.35-metal/llama_cpp_python-0.3.35-py3-none-macosx_11_0_arm64.whl",
                             "faf9a2b38df5cbf9427a074f974c00abbb799185753c474672fd461c198b7a0a"),
    ("ps1", "cpu/AMD64"): ("v0.3.35/llama_cpp_python-0.3.35-py3-none-win_amd64.whl",
                           "31590ea000d5aff6f05f1e428048e72318a83709288159a5bd4dabec530080bb"),
    ("ps1", "cu124/AMD64"): ("v0.3.35-cu124/llama_cpp_python-0.3.35-py3-none-win_amd64.whl",
                             "84f7218c1e9cf21014b9770c65064c5a3674dd2f4fbc312c5d6bb40cec0fb269"),
}
DEPS = ["jinja2==3.1.6 --hash=sha256:85ece4451f492d0c13c5dd7c13a64681a86afae63a5f347908daf103ce6d2f67",
        "diskcache==5.6.3 --hash=sha256:5e31b2d5fbad117cc363ebaf6b689474db18a1f6438bc82358b024abd4c2ca19"]
SRC = {"sh": SH, "mac": MAC, "ps1": PS1}


def _sh_pins(src: str) -> dict:
    body = src[src.index("_llm_pin() {"):]
    body = body[:body.index("\n}\n")]
    return {k: (u, h) for k, u, h in re.findall(r'^\s*([a-z0-9]+/[A-Za-z0-9_]+)\)\s+echo "\$\{LLM_PIN_URL\}/(\S+) ([0-9a-f]+)" ;;',
                                               body, re.M)}


def _ps1_pins(src: str) -> dict:
    body = src[src.index("$LlmPins = @{"):]
    body = body[:body.index("\n}\n")]
    return {k: (u, h) for k, u, h in re.findall(r'"([a-z0-9]+/[A-Za-z0-9_]+)"\s*=\s*@\("\$LlmPinUrl/(\S+)", "([0-9a-f]+)"\)', body)}


def _deps(src: str) -> list:
    return re.findall(r'(?:jinja2|diskcache)==[0-9.]+ --hash=sha256:[0-9a-f]+', src)


def runtime_install_problems(src: str) -> list:
    """What is wrong with an installer's runtime install, [] when it is pinned (the negative control calls this)."""
    out = []
    if "--extra-index-url" in src:
        out.append("an extra index")
    if re.search(r'"llama-cpp-python==', src) or re.search(r'"jinja2>=', src):
        out.append("an unpinned requirement")
    joined = re.sub(r"[\\`]\n\s*", " ", src)                # one line per command: shell \ and PowerShell ` joins
    calls = [ln for ln in joined.splitlines() if "pip install" in ln]
    pinned = [c for c in calls if "-r " in c and ("runtime.txt" in c or "$req" in c or "deps.txt" in c)]
    if not pinned:
        out.append("no pinned install line")
    for c in pinned:
        for flag in ("--require-hashes", "--no-deps", "--index-url https://pypi.org/simple"):
            if flag not in c:
                out.append(f"{flag} missing in: {c[:80]}")
    for _k, (_u, h) in (_ps1_pins(src) if "$LlmPins" in src else _sh_pins(src)).items():
        if not re.fullmatch(r"[0-9a-f]{64}", h):
            out.append(f"a pin that is not 64 hex: {h}")
    return out


@pytest.mark.parametrize("name", ["sh", "mac", "ps1"])
def test_every_installer_installs_the_runtime_only_by_hash(name):
    assert runtime_install_problems(SRC[name]) == []


def test_the_pin_tables_are_the_designs_table():
    got = {("sh", k): v for k, v in _sh_pins(SH).items()}
    got |= {("mac", k): v for k, v in _sh_pins(MAC).items()}
    got |= {("ps1", k): v for k, v in _ps1_pins(PS1).items()}
    assert got == PINS


def test_the_two_added_packages_are_pinned_identically_everywhere():
    for name, src in SRC.items():
        assert _deps(src) == DEPS, name
        assert "jinja2>=" not in src, name


def test_the_closure_is_checked_and_a_failure_removes_the_runtime():
    assert 'uv pip check --python "$VENV_PY"' in SH
    assert '"$PYTHON_BIN" -m pip check' in MAC
    assert "& $NodePython -m pip check" in PS1
    for name, src in SRC.items():
        assert "runtime_deps_missing" in src and "runtime_unpinned_platform" in src, name
        assert re.search(r"pip uninstall[^\n]*llama-cpp-python", src), name


def test_negative_control_a_hash_removed_or_an_index_added_is_caught():
    no_hash = SH.replace("--require-hashes ", "", 1)
    assert runtime_install_problems(no_hash)
    with_index = SH.replace("--index-url https://pypi.org/simple -r", "--extra-index-url https://example.invalid -r", 1)
    assert runtime_install_problems(with_index)
    old_line = SH + '\n    uv pip install "llama-cpp-python==0.3.35" "jinja2>=3.1.6"\n'
    assert runtime_install_problems(old_line)
    bad_pin = SH.replace("d172f3d3c8cdd194c3c47c71cb077ed6e61354a2d0f939ceeac0c8fd29999596", "d172f3d3", 1)
    assert runtime_install_problems(bad_pin)


# ── executed: the Linux functions under bash -euo pipefail with uv stubbed ─────────────────────────────────────────

def _fns() -> str:
    start = SH.index("LLM_PIN_URL=")
    end = SH.index("\n}\n", SH.index("_llm_install_pinned() {")) + 3
    return SH[start:end]


def _run(machine: str, uv_rc: int, variant: str = "cpu"):
    with tempfile.TemporaryDirectory() as d:
        dpath = Path(d)
        (dpath / "bin").mkdir()
        uv = dpath / "bin" / "uv"
        uv.write_text("#!/usr/bin/env bash\n"
                      f'echo "$@" > "{d}/argv"\n'
                      'while [ $# -gt 0 ]; do [ "$1" = "-r" ] && cp "$2" "' + d + '/req"; shift; done\n'
                      f"exit {uv_rc}\n")
        uv.chmod(0o755)
        script = (f"set -euo pipefail\nVENV_PY=/nonexistent/python\nuname() {{ echo {machine}; }}\n{_fns()}\n"
                  f'_llm_install_pinned {variant} && rc=0 || rc=$?\necho "rc=$rc"\n')
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                           env={**os.environ, "PATH": f"{d}/bin:{os.environ['PATH']}"}, timeout=30)
        req = (dpath / "req").read_text() if (dpath / "req").exists() else None
        argv = (dpath / "argv").read_text() if (dpath / "argv").exists() else None
        return r, req, argv


def test_executed_a_pinned_machine_installs_exactly_the_pinned_set():
    r, req, argv = _run("x86_64", 0)
    assert r.returncode == 0 and "rc=0" in r.stdout, r.stderr
    url, sha = PINS[("sh", "cpu/x86_64")]
    assert req.splitlines() == [f"llama-cpp-python @ {BASE}/{url} --hash=sha256:{sha}"] + DEPS
    for flag in ("--require-hashes", "--no-deps", "--only-binary :all:", "--index-url https://pypi.org/simple"):
        assert flag in argv, argv
    assert "--extra-index-url" not in argv


def test_executed_a_failed_install_is_rc_1_and_the_script_goes_on():
    r, _req, _argv = _run("x86_64", 1)
    assert r.returncode == 0 and "rc=1" in r.stdout, r.stderr


def test_executed_an_unpinned_machine_is_rc_2_and_nothing_is_fetched():
    for machine, variant in (("riscv64", "cpu"), ("aarch64", "cu124"), ("x86_64", "metal")):
        r, req, argv = _run(machine, 0, variant)
        assert r.returncode == 0 and "rc=2" in r.stdout, (machine, variant, r.stderr)
        assert req is None and argv is None, (machine, variant)


# ── IH4-2 (auditor 2026-11-07T12:22:02Z): a REUSED venv that already holds an old, unhashed runtime ─────────────────

IH42_BLOCK = '''    # IH4-2: on a reused venv an OLD unhashed runtime may still be there: anything but a verified install removes it
    if [ "$_LLM_RC" != 0 ]; then
        uv pip uninstall --python "$VENV_PY" --break-system-packages llama-cpp-python >/dev/null 2>&1 || true
    fi
'''


def _runtime_block(src: str) -> str:
    start = src.index('if [ "${MESHEMBED_ENABLE_LLM:-0}" = "1" ]; then\n    # Which build of the runtime.')
    return src[start:src.index("\nfi\n", start) + 4]


def _run_block(machine: str, install_rc: int, src: str = SH, check_rc: int = 0):
    """The whole Linux runtime block under bash -euo pipefail. The venv starts WITH llama_cpp (an old install); uv is a
    stub that logs each call, installs on rc 0 and uninstalls on 'pip uninstall'; the venv python answers find_spec
    from that state."""
    with tempfile.TemporaryDirectory() as d:
        b = Path(d) / "bin"
        b.mkdir()
        (Path(d) / "has_llama").write_text("old unhashed install")
        (b / "uv").write_text(
            "#!/usr/bin/env bash\n"
            f'echo "$*" >> "{d}/calls"\n'
            f'case "$2" in\n'
            f'  install) [ {install_rc} = 0 ] && echo pinned > "{d}/has_llama"; exit {install_rc} ;;\n'
            f'  uninstall) rm -f "{d}/has_llama"; exit 0 ;;\n'
            f'  check) exit {check_rc} ;;\n'
            "esac\nexit 0\n")
        (b / "venvpy").write_text(f'#!/usr/bin/env bash\n[ -f "{d}/has_llama" ]\n')
        for f in ("uv", "venvpy"):
            (b / f).chmod(0o755)
        script = ("set -euo pipefail\ninfo() { :; }\nwarn() { :; }\n"
                  f"VENV_PY={b}/venvpy\nuname() {{ echo {machine}; }}\nMESHEMBED_ENABLE_LLM=1\n"
                  'MESHEMBED_LLM_BACKEND=cpu\nLLM_SKIPPED=""\n'
                  f"{src[src.index('LLM_PIN_URL='):src.index(chr(10) + '}' + chr(10), src.index('_llm_install_pinned() {')) + 3]}\n"
                  f"{_runtime_block(src)}\n"
                  'echo "skipped=$LLM_SKIPPED idx=$_LLM_IDX"\n')
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                           env={**os.environ, "PATH": f"{b}:{os.environ['PATH']}"}, timeout=30)
        calls = (Path(d) / "calls").read_text() if (Path(d) / "calls").exists() else ""
        return r, calls, (Path(d) / "has_llama").exists()


def test_ih42_a_failed_install_removes_the_old_runtime():
    r, calls, has = _run_block("x86_64", 1)
    assert r.returncode == 0, r.stderr
    assert "pip uninstall" in calls and not has
    assert "skipped=runtime_install_failed idx=" in r.stdout


def test_ih42_an_unpinned_machine_removes_the_old_runtime():
    r, calls, has = _run_block("riscv64", 0)
    assert r.returncode == 0, r.stderr
    assert "pip install" not in calls and "pip uninstall" in calls and not has
    assert "skipped=runtime_unpinned_platform idx=" in r.stdout


def test_ih42_a_pinned_install_forces_the_replacement():
    r, calls, has = _run_block("x86_64", 0)
    assert r.returncode == 0 and has, r.stderr
    install = next(c for c in calls.splitlines() if c.startswith("pip install"))
    for pkg in ("llama-cpp-python", "jinja2", "diskcache"):
        assert f"--reinstall-package {pkg}" in install, install
    assert "skipped= idx=cpu" in r.stdout


def test_ih42_a_failed_closure_check_removes_it():
    r, calls, has = _run_block("x86_64", 0, check_rc=1)
    assert r.returncode == 0 and not has, r.stderr
    assert "skipped=runtime_deps_missing idx=" in r.stdout


def test_ih42_negative_control_without_the_uninstall_the_old_runtime_survives():
    assert SH.count(IH42_BLOCK) == 1
    r, _calls, has = _run_block("x86_64", 1, src=SH.replace(IH42_BLOCK, ""))
    assert r.returncode == 0 and has and "skipped= idx=cpu" in r.stdout      # the fail-open IH4-2 closes


def test_ih42_mac_and_windows_force_the_replacement_and_remove_on_failure():
    assert "--require-hashes --no-deps --force-reinstall" in MAC
    assert 'if [ "$_LLM_RC" != 0 ]; then\n    "$PYTHON_BIN" -m pip uninstall -y $PIP_EXTRA llama-cpp-python' in MAC
    assert "--require-hashes --no-deps --force-reinstall" in PS1
    assert "if ($llmRc -ne 0) { & $NodePython -m pip uninstall -y llama-cpp-python *> $null }" in PS1
    assert "--no-deps --force-reinstall $PIP_EXTRA \"$_dir/$INTEL_MAC_LLAMA_WHEEL\"" in MAC
