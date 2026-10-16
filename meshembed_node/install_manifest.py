"""The install manifest: where this node's Python and package tools are, and what got installed.

docs/DESIGN_NODE_MAINTENANCE_2026-10-14.md. Written by all three installers (they call
`python -I -m meshembed_node.install_manifest ...` once the package is in place) and read by
`meshembed-node maintenance` and by the poll. The Z400 fix of 2026-10-14 needed `pip uninstall`
in a venv that had no pip, and a guess at where uv lived; this file removes the guessing.

Owner-only (0600 where the OS has modes), no secrets: paths, versions, CPU flags. Everything
in it is a HINT -- maintenance re-checks the paths before using them, and the backend routes on
nothing here.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

SCHEMA = 1
FILENAME = "install.json"
_FLAGS_OF_INTEREST = {"sse4_2", "avx", "avx2", "fma", "f16c", "avx512f"}


def default_path() -> Path:
    return Path.home() / ".meshembed" / FILENAME


def _dist_version(dist: str) -> Optional[str]:
    try:
        from importlib import metadata
        return metadata.version(dist)
    except Exception:
        return None


def _uv_version(uv: Optional[str]) -> Optional[str]:
    if not uv:
        return None
    try:
        out = subprocess.run([uv, "--version"], capture_output=True, text=True, timeout=10).stdout
        return out.split()[1] if len(out.split()) > 1 else None
    except Exception:
        return None


def _cpu_model() -> Optional[str]:
    if platform.system() == "Darwin":                 # platform.processor() says "i386" there
        try:
            out = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True,
                                 text=True, timeout=5).stdout.strip()
            if out:
                return out
        except Exception:
            pass
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or None


def build(*, kind: str, tag: Optional[str], base: Optional[str], llm_build: Optional[str],
          llm_skipped: Optional[str], uv: Optional[str]) -> Dict[str, Any]:
    from . import cpu_guard
    flags = cpu_guard.cpu_flags()
    missing = cpu_guard.missing_features(flags)
    llm_installed = cpu_guard.runtime_installed()           # find_spec only: never imported here
    return {
        "schema": SCHEMA,
        "written_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "installer": {"os": platform.system().lower(), "tag": tag, "kind": kind},
        "python": {"path": sys.executable, "version": platform.python_version(),
                   "base": base or "existing"},
        "venv": sys.prefix if sys.prefix != sys.base_prefix else None,
        "tools": {"pip": {"available": _dist_version("pip") is not None, "version": _dist_version("pip")},
                  "uv": {"path": uv, "version": _uv_version(uv)} if uv else None},
        "node": {"version": _dist_version("meshembed-node")},
        "extras": {"llm_runtime": {
            "installed": llm_installed,
            "version": _dist_version("llama-cpp-python") if llm_installed else None,
            "build": (llm_build or None) if llm_installed else None,
            "skipped_reason": llm_skipped or None}},
        "cpu": {"model": _cpu_model(),
                "flags": sorted((flags or set()) & _FLAGS_OF_INTEREST),
                "llm_capable": not missing},
    }


def write(directory: Path, doc: Dict[str, Any]) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / FILENAME
    tmp = path.with_suffix(".json.tmp")
    old = os.umask(0o077) if os.name != "nt" else None
    try:
        tmp.write_text(json.dumps(doc, indent=1), encoding="utf-8")
        if os.name != "nt":
            os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        if old is not None:
            os.umask(old)
    return path


def read(path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    try:
        doc = json.loads((path or default_path()).read_text(encoding="utf-8"))
        return doc if isinstance(doc, dict) else None
    except Exception:
        return None


def summary(doc: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    """The poll's hint: strings and booleans only."""
    doc = doc if doc is not None else read()
    if not doc:
        return None
    tools = doc.get("tools") or {}
    llm = ((doc.get("extras") or {}).get("llm_runtime")) or {}
    return {
        "python": (doc.get("python") or {}).get("version"),
        "tool": "uv" if tools.get("uv") else "pip",
        "pip": bool((tools.get("pip") or {}).get("available")),
        "llm_runtime": bool(llm.get("installed")),
        "llm_skipped": llm.get("skipped_reason"),
        "kind": (doc.get("installer") or {}).get("kind"),
    }


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(prog="meshembed_node.install_manifest")
    ap.add_argument("--dir", required=True)
    ap.add_argument("--kind", default="fresh")
    ap.add_argument("--tag")
    ap.add_argument("--base")
    ap.add_argument("--llm-build")
    ap.add_argument("--llm-skipped")
    ap.add_argument("--uv", default=shutil.which("uv"))
    a = ap.parse_args(argv)
    doc = build(kind=a.kind, tag=a.tag, base=a.base, llm_build=a.llm_build,
                llm_skipped=a.llm_skipped, uv=a.uv or None)
    print(write(Path(a.dir), doc))
    return 0


if __name__ == "__main__":
    sys.exit(main())
