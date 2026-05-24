"""Shared fixtures for the node-agent test suites.

The big one here is `mock_backend` -- a real HTTP server running in a
background thread that mimics the MeshEmbed backend's contract for
/nodes/register, /get_job, /report_result, /attestation/challenge,
/attestation/quote. Tests can drive the daemon's `_register`, `_poll`,
`_report`, `_attempt_signed_quote` functions and observe what the
fake backend received -- end-to-end against the daemon's real HTTP
code path (no monkey-patching of requests).
"""
from __future__ import annotations

import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional, Tuple

import pytest


class MockBackend:
    """Records every incoming request + returns whatever the test
    queues for the next response. Each endpoint can also have a
    persistent "default" handler.

    Thread-safe: handlers run in the HTTPServer thread, tests read
    `received` from the main thread. We use a lock around mutations."""

    def __init__(self) -> None:
        self.received: Dict[str, List[dict]] = {}
        self.queued_responses: Dict[str, List[dict]] = {}
        self._lock = threading.Lock()
        # Default responses per endpoint -- used when the queue is empty.
        self.defaults: Dict[str, dict] = {
            "/nodes/register": {
                "node_id": "node-mock-1",
                "node_number": 1,
                "api_key": "mock-api-key",
            },
            "/get_job": {"assignment": None, "update_now": False},
            "/report_result": {"ok": True},
            "/attestation/challenge": {
                "nonce": "aa" * 32, "valid_for_seconds": 300,
            },
            "/attestation/quote": {"status": "accepted"},
        }
        # The bound URL is set after the server starts.
        self.base_url: str = ""

    def queue(self, path: str, body: dict) -> None:
        """Push a one-shot response onto the queue for this endpoint."""
        with self._lock:
            self.queued_responses.setdefault(path, []).append(body)

    def record(self, path: str, payload: dict) -> None:
        with self._lock:
            self.received.setdefault(path, []).append(payload)

    def pop_response(self, path: str) -> dict:
        with self._lock:
            queue = self.queued_responses.get(path, [])
            if queue:
                return queue.pop(0)
        return self.defaults.get(path, {"ok": True})

    def calls(self, path: str) -> List[dict]:
        with self._lock:
            return list(self.received.get(path, []))

    def call_count(self, path: str) -> int:
        return len(self.calls(path))


def _make_handler(backend: MockBackend):
    """Build a BaseHTTPRequestHandler subclass closed over `backend`."""

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            # Quiet -- tests would be spammed by the default stderr logger.
            return

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", "0") or 0)
            raw = self.rfile.read(length) if length > 0 else b""
            try:
                payload = json.loads(raw.decode("utf-8")) if raw else {}
            except Exception:
                payload = {}
            backend.record(self.path, payload)
            response = backend.pop_response(self.path)
            data = json.dumps(response).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/healthz":
                body = b'{"status":"ok"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.end_headers()

    return _Handler


class _ReuseAddrServer(HTTPServer):
    allow_reuse_address = True
    daemon_threads = True


@pytest.fixture
def mock_backend():
    """Spin up the mock backend, yield it, tear down at end of test."""
    backend = MockBackend()
    handler_cls = _make_handler(backend)
    # Port 0 lets the OS pick a free port -- avoids races with other tests.
    server = _ReuseAddrServer(("127.0.0.1", 0), handler_cls)
    backend.base_url = f"http://127.0.0.1:{server.server_address[1]}"
    thread = threading.Thread(
        target=server.serve_forever,
        name="mock-backend",
        daemon=True,
    )
    thread.start()
    try:
        yield backend
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
