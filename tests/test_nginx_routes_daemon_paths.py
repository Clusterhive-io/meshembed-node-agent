"""Every backend path the daemon calls is routed by the public nginx.

2026-09-27: /node_heartbeat (fast flip) was missing from the daemon-paths
location, so a node on the public name would have heartbeated into the SPA and
never flipped. LAN nodes hit :18080 directly and would not have shown it.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
NGINX = ROOT / "frontend" / "nginx.conf"
DAEMON = Path(__file__).resolve().parents[1] / "meshembed_node"

# A monorepo contract: the public node-agent repo has no frontend/ to check.
pytestmark = [pytest.mark.unit,
              pytest.mark.skipif(not NGINX.exists(), reason="nginx.conf lives in the monorepo only")]

# Known and recorded (docs/DESIGN_FAST_FLIP.md): attestation is not routed for
# public-name nodes today. Remove from this set when it is.
KNOWN_UNROUTED = {"/attestation/challenge", "/attestation/quote"}


def _daemon_paths():
    src = "\n".join(p.read_text() for p in DAEMON.glob("*.py"))
    paths = set(re.findall(r'backend_url[^)\n]*?"(/[A-Za-z_/-]+)"', src))
    paths |= set(re.findall(r'f"\{[a-z_.]*backend[a-z_]*\}(/[A-Za-z_/-]+)', src))
    return paths


def _daemon_location():
    conf = NGINX.read_text()
    m = re.search(r"location ~ (\^/\([^)]*\)\$) \{", conf)
    assert m, "daemon-paths location not found in nginx.conf"
    regex = re.compile(m.group(1))
    exact = set(re.findall(r"location = (/[A-Za-z_/-]+) \{\s*limit_req zone=node_", conf))

    class _Loc:
        def match(self, p):
            return p in exact or regex.match(p)
    return _Loc()


def _block(conf: str, opener: str) -> str:
    i = conf.index(opener)
    return conf[i:conf.index("}", i)]


def test_every_node_path_is_rate_limited_per_key_and_per_ip():
    """A key zone ignores requests without a key, so each has an IP zone too."""
    conf = NGINX.read_text()
    for opener in (re.search(r"location ~ \^/\(nodes/register[^{]*\{", conf).group(0),
                   "location = /node_heartbeat {"):
        b = _block(conf, opener)
        assert re.search(r"limit_req zone=node\w*_key ", b) and re.search(r"limit_req zone=node\w*_ip ", b), opener


def test_the_scan_finds_the_core_paths():
    assert {"/get_job", "/report_result", "/node_heartbeat"} <= _daemon_paths()


def test_every_daemon_path_reaches_the_backend():
    loc = _daemon_location()
    missing = sorted(p for p in _daemon_paths() - KNOWN_UNROUTED if not loc.match(p))
    assert not missing, f"daemon paths not routed by nginx.conf: {missing}"
