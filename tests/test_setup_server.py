"""Smoke tests for the local-browser setup server (port 7842).

We don't spin up the full HTTPServer here -- the goal is to exercise
the credential-save path + the well-formed-HTML response surface
without binding to a port (which can race in CI).

The end-to-end "launch server + browser + register" flow is covered
by T3 Playwright e2e once a stub backend is available.
"""
from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from meshembed_node import setup_server

pytestmark = pytest.mark.unit


def test_constants_bind_loopback_only():
    """The setup server must NEVER bind a LAN/WAN interface."""
    assert setup_server.SETUP_HOST == "127.0.0.1"
    assert setup_server.SETUP_PORT == 7842


def test_save_credentials_writes_env_file(tmp_path, monkeypatch):
    """Credentials land in ~/.meshembed/.env with chmod 600."""
    monkeypatch.setenv("HOME", str(tmp_path))
    # _save_credentials uses Path.home() internally; HOME env drives it
    # on POSIX, so the env override sends it into tmp_path.
    setup_server._save_credentials(
        backend_url="https://meshembed.test",
        node_id="node-test",
        api_key="key-test",
    )
    env_file = tmp_path / ".meshembed" / ".env"
    assert env_file.is_file()
    content = env_file.read_text()
    assert "MESHEMBED_BACKEND=https://meshembed.test" in content
    assert "MESHEMBED_NODE_API_KEY=key-test" in content
    assert "MESHEMBED_NODE_ID=node-test" in content
    # 0o600 = rw-------
    mode = oct(env_file.stat().st_mode & 0o777)
    assert mode == "0o600", f"expected 0o600, got {mode}"


def test_save_credentials_creates_parent_dir(tmp_path, monkeypatch):
    """First-time install: ~/.meshembed/ doesn't exist yet."""
    monkeypatch.setenv("HOME", str(tmp_path))
    assert not (tmp_path / ".meshembed").exists()
    setup_server._save_credentials("https://x", "node-x", "key-x")
    assert (tmp_path / ".meshembed").is_dir()


def test_save_credentials_overwrites_existing(tmp_path, monkeypatch):
    """A re-run replaces stale credentials cleanly."""
    monkeypatch.setenv("HOME", str(tmp_path))
    setup_server._save_credentials("https://old", "node-old", "key-old")
    setup_server._save_credentials("https://new", "node-new", "key-new")
    content = (tmp_path / ".meshembed" / ".env").read_text()
    assert "https://new" in content
    assert "node-new" in content
    assert "old" not in content
