"""ABRT-CORE (auditor 2026-11-03 13:04:26Z, MEDIUM, A3) and PATH-LIMIT (12:55:28Z, MEDIUM), both found by the split-serve
sandbox bed 2026-11-03 (docs/RECORD_SPLIT_SERVE_BED_2026-11-03.md):
- every unit the installer writes, and every drop-in the split launcher writes for a DI unit, carries LimitCORE=0 (a
  llama-server / ggml-rpc-server / daemon core would hold hidden states, prompt text or the node key);
- the .path units are healed by ONE root heal timer (HT-1..HT-4, tests/test_path_heal.py)."""
from __future__ import annotations

import json
import re
from pathlib import Path

from meshembed_node import split_launch as L

INSTALL = (Path(__file__).resolve().parents[1] / "install.sh").read_text()


def _units_written(text: str) -> dict:
    """{unit file name: its heredoc body} for every `cat > /etc/systemd/system/<name> << TAG` and every
    `_write_unit_atomic /etc/systemd/system/<name> << TAG` (IOP-4b's atomic writer) in the installer."""
    out = {}
    for m in re.finditer(r'(?:cat >|_write_unit_atomic) "?/etc/systemd/system/([^"\s]+?)"? << \'?(\w+)\'?\n(.*?)\n\2\n',
                         text, re.S):
        out[m.group(1)] = m.group(3)
    return out


def _service_section_has_limitcore_0(body: str) -> bool:
    sec = re.search(r"^\[Service\]\n(.*?)(?=^\[|\Z)", body, re.S | re.M)
    return bool(sec) and re.search(r"^LimitCORE=0$", sec.group(1), re.M) is not None


def test_every_service_unit_the_installer_writes_has_limitcore_0():
    units = _units_written(INSTALL)
    services = {n: b for n, b in units.items() if n.endswith(".service") and "[Service]" in b}
    assert {"meshembed-node-update.service", "meshembed-serve-launch.service", "meshembed-split-launch.service",
            "meshembed-agent.service"} <= set(services)
    missing = [n for n, b in services.items() if not _service_section_has_limitcore_0(b)]
    assert missing == []


def test_the_serve_units_drop_in_has_limitcore_0():
    units = _units_written(INSTALL)
    drop = units["$d.service.d/10-node.conf"]
    assert _service_section_has_limitcore_0(drop) and "BindsTo=meshembed-node.service" in drop


def test_the_lint_refuses_a_unit_without_it():
    # the negative control: the same check on a unit without LimitCORE=0 (or with it outside [Service]) fails
    bad = "cat > /etc/systemd/system/x.service << UNIT\n[Unit]\nLimitCORE=0\n[Service]\nType=oneshot\nUNIT\n"
    assert not _service_section_has_limitcore_0(_units_written(bad)["x.service"])
    good = bad.replace("[Service]\nType=oneshot", "[Service]\nLimitCORE=0\nType=oneshot")
    assert _service_section_has_limitcore_0(_units_written(good)["x.service"])


def test_every_di_drop_in_the_launcher_writes_has_limitcore_0():
    src = (Path(L.__file__)).read_text()
    writers = re.findall(r'\[Service\]\\n[^"]*', src)
    assert len(writers) >= 3 and all(w.startswith("[Service]\\nLimitCORE=0\\n") for w in writers)


def test_the_split_launcher_burst_is_generous_but_not_unlimited():
    body = _units_written(INSTALL)["meshembed-split-launch.service"]
    burst = int(re.search(r"^StartLimitBurst=(\d+)$", body, re.M).group(1))
    interval = int(re.search(r"^StartLimitIntervalSec=(\d+)$", body, re.M).group(1))
    assert interval > 0 and burst / interval >= 0.5                  # a relay burst every ~5 s never trips it
