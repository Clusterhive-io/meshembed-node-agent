"""Regression guard for the 2026-06-16 OTA incident.

The daemon must report its INSTALLED package version, never a stale
MESHEMBED_AGENT_VERSION env override. An old systemd unit had baked
`MESHEMBED_AGENT_VERSION=0.3.26`; after the package was upgraded the daemon kept
reporting 0.3.26, so the backend signalled updates forever and the version never
appeared to change. A node must not be able to lie about its version.
"""
from __future__ import annotations

import meshembed_node
from meshembed_node.config import Config


def test_agent_version_ignores_stale_env_override(monkeypatch, tmp_path):
    # A stale override (as baked into an old unit) must be IGNORED.
    monkeypatch.setenv("MESHEMBED_AGENT_VERSION", "0.0.1-stale")
    monkeypatch.setenv("MESHEMBED_NODE_API_KEY", "test-key")
    monkeypatch.setenv("MESHEMBED_NODE_ID", "test-node")
    # Keep generated key/fingerprint files out of the real HOME.
    monkeypatch.setenv("HOME", str(tmp_path))

    cfg = Config()

    assert cfg.agent_version == meshembed_node.__version__, (
        "agent_version must equal the installed package version"
    )
    assert cfg.agent_version != "0.0.1-stale", (
        "a stale MESHEMBED_AGENT_VERSION env must NOT override the real version"
    )
