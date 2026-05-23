"""Daemon helper for Layer E.2 -- signed TPM 2.0 quotes.

Wraps the system `tpm2_quote` binary (from the tpm2-tools package).
If the binary is missing, we degrade gracefully: the daemon
attestation status stays at E.1 (unsigned PCR self-report).

Workflow:

  1. Daemon poll cycle: every N minutes (default 60), call
     `backend.attestation_challenge(node_id)` to get a fresh nonce.

  2. Daemon runs `tpm2_quote -c <ek_handle> -l sha256:0,1,4,5,7,8,9,10
        -q <nonce_hex> -m quote.msg -s quote.sig -o pcrs.bin`

  3. Daemon reads the three files + the EK public part, base64s them,
     and POSTs to /attestation/quote.

  4. Backend verifies (see backend/app/tpm_quote_verifier.py) and
     marks `nodes.quote_signature_status='valid_*'` on success.

Requirements on the operator's host:

  * `tpm2_quote` binary in PATH (apt: tpm2-tools; pacman: tpm2-tools).
  * TPM 2.0 device accessible (/dev/tpmrm0 or /dev/tpm0).
  * Either the standard EK handle (0x81010001) loaded by `tpm2_createek`,
    or a custom AIK handle exposed via MESHEMBED_TPM_QUOTE_KEY_HANDLE.

If any of these are missing, quote() returns None and the daemon
falls back to E.1 reporting.
"""
from __future__ import annotations

import base64
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional, Tuple

log = logging.getLogger(__name__)


_DEFAULT_EK_HANDLE = "0x81010001"  # TCG-standard EK on most TPM stacks
_PCR_SELECTION = "sha256:0,1,4,5,7,8,9,10"


def _have_tpm2_quote() -> bool:
    return shutil.which("tpm2_quote") is not None


def _have_tpm2_readpublic() -> bool:
    return shutil.which("tpm2_readpublic") is not None


def _read_ek_public(handle: str, workdir: Path) -> Optional[bytes]:
    """Dump the EK public part to a file via tpm2_readpublic and
    return its bytes. Returns None on any failure."""
    if not _have_tpm2_readpublic():
        return None
    out_path = workdir / "ek.pub"
    cmd = [
        "tpm2_readpublic", "-c", handle, "-o", str(out_path), "-f", "pem",
    ]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=15,
        )
    except subprocess.TimeoutExpired:
        log.warning("tpm2_readpublic.timeout handle=%s", handle)
        return None
    except FileNotFoundError:
        return None
    if proc.returncode != 0:
        log.warning(
            "tpm2_readpublic.failed handle=%s rc=%d stderr=%s",
            handle, proc.returncode, proc.stderr[:200],
        )
        return None
    try:
        return out_path.read_bytes()
    except OSError:
        return None


def quote(nonce_hex: str) -> Optional[Tuple[str, str, str]]:
    """Run tpm2_quote against `nonce_hex` and return
    (quote_msg_b64, quote_sig_b64, ek_pub_b64) on success.

    Returns None if the host lacks the tooling or the call fails.
    Callers should treat None as "fall back to E.1 unsigned report"
    -- this is not a fatal condition.
    """
    if not _have_tpm2_quote():
        log.debug("tpm2_quote not in PATH -- daemon stays at E.1")
        return None

    handle = os.environ.get(
        "MESHEMBED_TPM_QUOTE_KEY_HANDLE", _DEFAULT_EK_HANDLE,
    )
    with tempfile.TemporaryDirectory(prefix="meshembed-quote-") as tmp:
        tmpdir = Path(tmp)
        msg_path = tmpdir / "quote.msg"
        sig_path = tmpdir / "quote.sig"
        pcrs_path = tmpdir / "pcrs.bin"
        cmd = [
            "tpm2_quote",
            "-c", handle,
            "-l", _PCR_SELECTION,
            "-q", nonce_hex,
            "-m", str(msg_path),
            "-s", str(sig_path),
            "-o", str(pcrs_path),
        ]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=20,
            )
        except subprocess.TimeoutExpired:
            log.warning("tpm2_quote.timeout handle=%s", handle)
            return None
        except FileNotFoundError:
            return None
        if proc.returncode != 0:
            log.warning(
                "tpm2_quote.failed handle=%s rc=%d stderr=%s",
                handle, proc.returncode, proc.stderr[:200],
            )
            return None
        try:
            msg_b = msg_path.read_bytes()
            sig_b = sig_path.read_bytes()
        except OSError:
            return None
        ek_b = _read_ek_public(handle, tmpdir) or b""
        return (
            base64.b64encode(msg_b).decode("ascii"),
            base64.b64encode(sig_b).decode("ascii"),
            base64.b64encode(ek_b).decode("ascii"),
        )
