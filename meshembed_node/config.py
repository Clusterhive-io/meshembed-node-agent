"""Daemon configuration. Reads environment variables; never accepts
secrets via CLI so they don't show up in `ps aux` or shell history."""
from __future__ import annotations

import logging
import os
import sys
from typing import Optional

log = logging.getLogger(__name__)


def _require(var: str) -> str:
    val = os.environ.get(var, "").strip()
    if not val:
        print(f"[error] required environment variable not set: {var}", file=sys.stderr)
        sys.exit(1)
    return val


class Config:
    backend_url: str
    api_key: str
    node_id: str
    model: str
    poll_min_s: float
    poll_max_s: float
    agent_version: str
    max_chunks: int
    # ed25519 — Sprint 3. Empty values mean "unsigned mode" (legacy node
    # compatibility); production daemons always carry a keypair.
    node_privkey: str   # hex 32 bytes
    node_pubkey: str    # hex 32 bytes
    # Hardware-binding identifiers, collected once at startup and attached
    # to every /get_job and /report_result. The backend compares them with
    # what was recorded at /nodes/register — mismatch → 401
    # hardware_mismatch. See `fingerprint.collect_fingerprint`.
    machine_fingerprint: Optional[str] = None
    gpu_uuid: Optional[str] = None
    is_vm: bool = False

    def __init__(self) -> None:
        self._load_dotenv()
        self.backend_url = os.environ.get(
            "MESHEMBED_BACKEND", "https://meshembed.clusterhive.io"
        ).rstrip("/")
        self.api_key = _require("MESHEMBED_NODE_API_KEY")
        self.node_id = _require("MESHEMBED_NODE_ID")
        self.model = os.environ.get(
            "MESHEMBED_MODEL", "intfloat/multilingual-e5-small"
        )
        self.poll_min_s = float(os.environ.get("MESHEMBED_POLL_MIN_S", "1"))
        self.poll_max_s = float(os.environ.get("MESHEMBED_POLL_MAX_S", "30"))
        self.agent_version = os.environ.get("MESHEMBED_AGENT_VERSION", "0.3.1")
        self.max_chunks = int(os.environ.get("MESHEMBED_MAX_CHUNKS", "1"))

        # ed25519: auto-generate when missing and print instructions.
        privkey_env = os.environ.get("MESHEMBED_NODE_PRIVKEY", "").strip()
        if not privkey_env:
            self._autogenerate_keypair()
        else:
            from .crypto import pubkey_from_privkey
            self.node_privkey = privkey_env
            self.node_pubkey = pubkey_from_privkey(privkey_env)

        # Hardware-binding identifiers — best-effort. Failures are
        # non-fatal (logged then ignored) because we still want the
        # daemon to come up; the server is in lax mode so requests
        # without these go through. When the server flips to strict
        # mode, this will hard-fail.
        try:
            from .fingerprint import collect_fingerprint
            fp, gpu, is_vm = collect_fingerprint()
            self.machine_fingerprint = fp
            self.gpu_uuid = gpu
            self.is_vm = is_vm
        except Exception as exc:
            logging.getLogger(__name__).warning(
                "fingerprint.collect_failed: %s", exc,
            )
            self.machine_fingerprint = None
            self.gpu_uuid = None
            self.is_vm = False

    def _load_dotenv(self) -> None:
        """Load ~/.meshembed/.env if present and the vars aren't already in env.

        Reads the file as UTF-8-with-BOM-tolerant. Windows installers
        that write the file with PowerShell's Set-Content -Encoding UTF8
        leave a BOM on byte 0; without `utf-8-sig` the first key reads
        as "﻿MESHEMBED_BACKEND" and silently fails to set anything.
        """
        import pathlib
        env_file = pathlib.Path.home() / ".meshembed" / ".env"
        if not env_file.exists():
            return
        for line in env_file.read_text(encoding="utf-8-sig").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            if key and key not in os.environ:
                os.environ[key] = value.strip()

    def _autogenerate_keypair(self) -> None:
        """Generate a keypair on first run and print it so the operator can persist it."""
        from .crypto import generate_keypair
        priv, pub = generate_keypair()
        self.node_privkey = priv
        self.node_pubkey = pub
        log.warning(
            "MESHEMBED_NODE_PRIVKEY not set — generated a temporary keypair.\n"
            "  Add this line to your .env to persist across restarts:\n"
            "  MESHEMBED_NODE_PRIVKEY=%s\n"
            "  MESHEMBED_NODE_PUBKEY=%s  (informational, not required)",
            priv, pub,
        )
