"""`meshembed-node maintenance <cmd>`: look after an installed node without calling pip/uv by hand.

docs/DESIGN_NODE_MAINTENANCE_2026-10-14.md. Uses the install manifest (install_manifest.py) as a
HINT and re-checks everything live. Two invariants (auditor design GO 2026-10-14 21:31Z):

- The inference runtime is a wheel, i.e. executable code: it only ever ARRIVES through the
  signed installer (`llm-enable` runs the same verified path as an OTA), never a bare pip
  install. Removing it (`llm-disable`) is always allowed.
- Never loosen permissions. A root-owned install (the hardened layout) is maintained with
  sudo; this command says so instead of working around it.
"""
from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from . import cpu_guard, install_manifest, safe_mode

RUNTIME_DIST = "llama-cpp-python"
EXIT_OK, EXIT_FAIL, EXIT_NEED_ROOT, EXIT_REFUSED = 0, 1, 2, 3


def _run(cmd: List[str], timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _pip_ok(run: Callable = _run) -> bool:
    try:
        return run([sys.executable, "-m", "pip", "--version"], timeout=30).returncode == 0
    except Exception:
        return False


def _uv_path(manifest: Optional[Dict[str, Any]]) -> Optional[str]:
    uv = (((manifest or {}).get("tools") or {}).get("uv") or {}).get("path")
    if uv and os.path.isfile(uv) and os.access(uv, os.X_OK):
        return uv
    return shutil.which("uv")


def _needs_root() -> bool:
    """The interpreter's environment is not ours to write (root-owned hardened install)."""
    if os.name == "nt":
        return False
    return not os.access(sys.prefix, os.W_OK)


def _restart_hint() -> str:
    system = platform.system()
    if system == "Linux":
        return "sudo systemctl restart meshembed-node"
    if system == "Darwin":
        return f"launchctl kickstart -k gui/{os.getuid()}/io.clusterhive.meshembed-node"
    if system == "Windows":
        return "Stop-ScheduledTask -TaskName 'MeshEmbed Node'; Start-ScheduledTask -TaskName 'MeshEmbed Node'"
    return "restart the meshembed-node service"


def _set_env_flag(key: str, value: str) -> None:
    """KEY=value in ~/.meshembed/.env, same form as the daemon's _persist_env_flag."""
    env_file = Path.home() / ".meshembed" / ".env"
    try:
        lines = env_file.read_text(encoding="utf-8-sig").splitlines() if env_file.exists() else []
    except OSError:
        lines = []
    kept = [ln for ln in lines if not ln.strip().startswith(f"{key}=")] + [f"{key}={value}"]
    env_file.parent.mkdir(parents=True, exist_ok=True)
    env_file.write_text("\n".join(kept) + "\n", encoding="utf-8")


def status(as_json: bool = False, run: Callable = _run) -> int:
    m = install_manifest.read()
    flags = cpu_guard.cpu_flags()
    missing = cpu_guard.missing_features(flags)
    installed = cpu_guard.runtime_installed()
    # The probe runs in a CHILD: a CPU that cannot run the runtime kills the child, not us.
    v = cpu_guard.verdict() if installed and not missing else None
    out = {
        "manifest": str(install_manifest.default_path()) if m else None,
        "python": {"path": sys.executable, "version": platform.python_version(),
                   "venv": sys.prefix if sys.prefix != sys.base_prefix else None},
        "pip": _pip_ok(run),
        "uv": _uv_path(m),
        "node_version": install_manifest._dist_version("meshembed-node"),
        "llm_runtime": {"installed": installed, "version": install_manifest._dist_version(RUNTIME_DIST)
                        if installed else None,
                        "cpu_missing": missing, "usable": bool(v and v["ok"])},
        "safe_mode_breadcrumb": (Path.home() / ".meshembed" / "start_guard.json").exists(),
        "root_owned": _needs_root(),
    }
    if as_json:
        print(json.dumps(out, indent=1))
    else:
        print(f"python        {out['python']['path']} ({out['python']['version']})")
        print(f"venv          {out['python']['venv'] or '(system interpreter)'}")
        print(f"pip           {'ok' if out['pip'] else 'MISSING (run: maintenance repair-venv)'}")
        print(f"uv            {out['uv'] or '-'}")
        print(f"node          {out['node_version']}")
        lr = out["llm_runtime"]
        state = ("not installed" if not lr["installed"] else
                 f"installed {lr['version']}, {'usable' if lr['usable'] else 'NOT usable on this machine'}")
        print(f"llm runtime   {state}")
        if lr["cpu_missing"]:
            print(f"cpu           lacks {','.join(lr['cpu_missing'])}: cannot run the inference runtime")
        print(f"manifest      {out['manifest'] or '(none: installed before v0.3.75)'}")
        if out["root_owned"]:
            print("install       root-owned: run maintenance changes with sudo")
    return EXIT_OK


def llm_disable(run: Callable = _run) -> int:
    if _needs_root():
        print("This install is root-owned: run `sudo meshembed-node maintenance llm-disable`.")
        return EXIT_NEED_ROOT
    m = install_manifest.read()
    if cpu_guard.runtime_installed():
        uv = _uv_path(m)
        cmd = ([uv, "pip", "uninstall", "--python", sys.executable, RUNTIME_DIST] if uv
               else [sys.executable, "-m", "pip", "uninstall", "-y", RUNTIME_DIST])
        r = run(cmd)
        if r.returncode != 0:
            print(f"could not remove {RUNTIME_DIST}: {(r.stderr or r.stdout).strip()[-300:]}")
            return EXIT_FAIL
        print(f"removed {RUNTIME_DIST}")
    else:
        print("the inference runtime is not installed")
    _set_env_flag("MESHEMBED_ENABLE_LLM", "0")
    if m:
        m.setdefault("extras", {}).setdefault("llm_runtime", {}).update(
            {"installed": False, "version": None, "build": None,
             "skipped_reason": m["extras"]["llm_runtime"].get("skipped_reason") or "disabled_by_owner"})
        install_manifest.write(install_manifest.default_path().parent, m)
    print(f"MESHEMBED_ENABLE_LLM=0 saved. Restart the node: {_restart_hint()}")
    print("Also switch inference OFF for this node in the dashboard, or an update will reinstall it.")
    return EXIT_OK


def llm_enable(perform: Optional[Callable] = None) -> int:
    missing = cpu_guard.missing_features(cpu_guard.cpu_flags())
    if missing:
        print(f"Refused: this CPU lacks {','.join(missing)} and cannot run the inference runtime "
              "(it would crash the node). Embeddings keep working.")
        return EXIT_REFUSED
    from . import __version__
    tag = f"v{__version__}"
    if _needs_root():
        print("This install is root-owned. As root, re-run the signed installer for "
              f"{tag} with MESHEMBED_ENABLE_LLM=1 (the installer verifies the release signature).")
        return EXIT_NEED_ROOT
    if perform is None:
        from .worker import _perform_self_update as perform     # the OTA's signed, verified path
    try:
        perform(tag, enable_llm=True, reexec=False)
    except Exception as exc:
        print(f"signed installer failed: {exc}")
        return EXIT_FAIL
    print(f"inference runtime installed by the signed installer for {tag}. Restart the node: {_restart_hint()}")
    return EXIT_OK


def repair_venv(run: Callable = _run) -> int:
    if _needs_root():
        print("This install is root-owned: run `sudo meshembed-node maintenance repair-venv`.")
        return EXIT_NEED_ROOT
    if not _pip_ok(run):
        r = run([sys.executable, "-m", "ensurepip", "--upgrade"])
        if r.returncode != 0 or not _pip_ok(run):
            print("pip could not be restored with ensurepip (this Python has none). "
                  "Re-run the signed installer for this version to rebuild the environment.")
            return EXIT_FAIL
        print("pip restored (ensurepip)")
    else:
        print("pip ok")
    r = run([sys.executable, "-I", "-c", "import meshembed_node"])
    if r.returncode != 0:
        print("the node package does not import: re-run the signed installer for this version.")
        return EXIT_FAIL
    print("node package imports")
    return EXIT_OK


def main(cmd: str, as_json: bool = False) -> int:
    if cmd == "status":
        return status(as_json)
    if cmd == "llm-disable":
        return llm_disable()
    if cmd == "llm-enable":
        return llm_enable()
    if cmd == "repair-venv":
        return repair_venv()
    print(f"unknown maintenance command: {cmd}")
    return EXIT_FAIL
