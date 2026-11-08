"""The OTA / upgrade-only path of install.sh runs at TOP LEVEL and ends with `exit 0`: a function it calls (directly, or
through another function) must be DEFINED above the block, or bash says "command not found" (rc 127) and, under
set -euo pipefail, the upgrade aborts. Found 2026-11-02 in #22 (iop-fixes): refresh_owned_units_from_unit, called by
the upgrade block, calls install_limits_units / install_serve_units, which #22 defines BELOW the block's exit."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit
ROOT = Path(__file__).resolve().parents[1]
DEF = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\(\) *\{")


def _functions(lines):
    """{name: (def line index, body lines)} for column-0 definitions closed by a column-0 '}'."""
    out, i = {}, 0
    while i < len(lines):
        m = DEF.match(lines[i])
        if m:
            j = i + 1
            while j < len(lines) and lines[j] != "}":
                j += 1
            out[m.group(1)] = (i, lines[i + 1:j])
            i = j
        i += 1
    return out


def _calls(body, names):
    found = set()
    for line in body:
        code = line.split("#", 1)[0]
        for n in names:
            if re.search(rf"(^|[\s;&|(]){re.escape(n)}($|[\s;&|)])", code):
                found.add(n)
    return found


def upgrade_order_problems(text: str):
    lines = text.splitlines()
    fns = _functions(lines)
    starts = [k for k, l in enumerate(lines) if l.startswith('if [ "$UPGRADE_ONLY" -eq 1 ]; then')]
    assert starts, "no upgrade-only block found"
    start = starts[-1]
    end = next(k for k in range(start, len(lines)) if lines[k].strip() == "exit 0")
    todo, seen = list(_calls(lines[start:end], fns)), set()
    while todo:
        n = todo.pop()
        if n in seen:
            continue
        seen.add(n)
        todo.extend(_calls(fns[n][1], fns) - seen)
    return sorted(n for n in seen if fns[n][0] > start)


def test_every_function_the_upgrade_path_calls_is_defined_above_it():
    assert upgrade_order_problems((ROOT / "install.sh").read_text(encoding="utf-8")) == []


def test_negative_control_iop_fixes_f9bb9034_had_them_below():
    """#22's own install.sh (f9bb9034) must FAIL this check: it is the defect this test exists for."""
    try:
        old = subprocess.run(["git", "show", "f9bb9034:node-agent/install.sh"], cwd=ROOT, capture_output=True,
                             text=True, check=True, timeout=30).stdout
    except (OSError, subprocess.SubprocessError):
        pytest.skip("f9bb9034 not in this clone")
    assert {"install_limits_units", "install_serve_units"} <= set(upgrade_order_problems(old))
