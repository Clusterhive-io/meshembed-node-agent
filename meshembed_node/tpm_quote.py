"""Daemon helper for Layer E.2 -- signed TPM 2.0 quotes.

Wraps the `tpm2-tools` binaries. If they're missing (or no TPM), quote() returns
None and the daemon stays at E.1 (unsigned PCR self-report) -- never fatal.

IMPORTANT (2026-08-20 fix): the Endorsement Key (EK) is a RESTRICTED DECRYPTION
key and CANNOT sign a quote -- `tpm2_quote -c <ek_handle>` fails on real hardware.
A quote must be signed by a restricted SIGNING key. We resolve one, in order:

  1. MESHEMBED_TPM_QUOTE_KEY_HANDLE -- an operator-provisioned persistent AK
     (best: EK-certified, stable across quotes so the backend can track the TPM).
  2. An EK-certified AK provisioned on the fly (tpm2_createek + tpm2_createak) --
     production-correct; keeps the future EK-cert-chain option open.
  3. Fallback: an owner-hierarchy restricted signing key -- a valid TPM signer
     (verified against swtpm) when the EK/AK path is unavailable; no EK cert.

The quote is signed with sha256; we send the SIGNER's public key (PEM) as
`ek_pub` (the backend verifies the signature against it and, on E.2b, binds the
reported PCRs to the signed pcrDigest). Validated end-to-end against swtpm; only
the EK-cert chain to a manufacturer root needs genuine hardware.
"""
from __future__ import annotations

import base64
import logging
import os
import shutil
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Optional, Tuple

log = logging.getLogger(__name__)

_DEFAULT_EK_HANDLE = "0x81010001"          # TCG-standard EK persistent handle
_PCR_SELECTION = "sha256:0,1,4,5,7,8,9,10"


def _has(bin_name: str) -> bool:
    return shutil.which(bin_name) is not None


def _run(cmd, timeout: int = 20) -> Optional[subprocess.CompletedProcess]:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        log.debug("tpm cmd failed %s: %s", cmd[:1], exc)
        return None


def _read_public_pem(ctx_or_handle: str, workdir: Path) -> Optional[bytes]:
    if not _has("tpm2_readpublic"):
        return None
    out = workdir / "signer.pem"
    p = _run(["tpm2_readpublic", "-c", ctx_or_handle, "-o", str(out), "-f", "pem"])
    if p is None or p.returncode != 0:
        return None
    try:
        return out.read_bytes()
    except OSError:
        return None


def _try_create_ak(workdir: Path) -> Optional[Tuple[str, bytes]]:
    """EK -> AK (production-correct). tpm2_createak makes a restricted signing key
    certified by the EK. Returns (ak_ctx, ak_pub_pem) or None."""
    if not (_has("tpm2_createek") and _has("tpm2_createak")):
        return None
    ek = os.environ.get("MESHEMBED_TPM_EK_HANDLE", _DEFAULT_EK_HANDLE)
    # Ensure the EK exists at the standard handle (idempotent; ignore "already there").
    _run(["tpm2_createek", "-c", ek, "-G", "rsa", "-u", str(workdir / "ek.pub")])
    ak_ctx = workdir / "ak.ctx"
    p = _run([
        "tpm2_createak", "-C", ek, "-c", str(ak_ctx),
        "-G", "rsa", "-g", "sha256", "-s", "rsassa",
        "-u", str(workdir / "ak.pub"), "-f", "pem", "-n", str(workdir / "ak.name"),
    ])
    if p is None or p.returncode != 0:
        log.debug("tpm2_createak unavailable/failed (rc=%s)", getattr(p, "returncode", None))
        return None
    _run(["tpm2_flushcontext", "-t"])   # free transient slots before reuse
    pub = _read_public_pem(str(ak_ctx), workdir)
    return (str(ak_ctx), pub) if pub else None


def _try_create_owner_signer(workdir: Path) -> Optional[Tuple[str, bytes]]:
    """Fallback: an owner-hierarchy restricted RSA signing key -- a valid TPM
    signer for a quote (no EK cert). Returns (ctx, pub_pem) or None."""
    if not (_has("tpm2_createprimary") and _has("tpm2_create")):
        return None
    prim = workdir / "primary.ctx"
    if (_run(["tpm2_createprimary", "-C", "o", "-g", "sha256", "-G", "rsa2048",
              "-c", str(prim)]) or _F).returncode != 0:
        return None
    key_ctx = workdir / "signer.ctx"
    p = _run([
        "tpm2_create", "-C", str(prim), "-G", "rsa2048:rsassa:null",
        "-u", str(workdir / "signer.pub"), "-r", str(workdir / "signer.priv"),
        "-c", str(key_ctx),
        "-a", "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|sign",
    ])
    if p is None or p.returncode != 0:
        return None
    _run(["tpm2_flushcontext", "-t"])
    pub = _read_public_pem(str(key_ctx), workdir)
    return (str(key_ctx), pub) if pub else None


class _Fail:
    returncode = 1


_F = _Fail()


def _resolve_signer(workdir: Path) -> Optional[Tuple[str, bytes]]:
    handle = os.environ.get("MESHEMBED_TPM_QUOTE_KEY_HANDLE")
    if handle:
        pub = _read_public_pem(handle, workdir)
        if pub:
            return handle, pub
        log.debug("configured MESHEMBED_TPM_QUOTE_KEY_HANDLE=%s unreadable", handle)
    return _try_create_ak(workdir) or _try_create_owner_signer(workdir)


def quote(nonce_hex: str) -> Optional[Tuple[str, str, str]]:
    """Produce a signed TPM quote over `nonce_hex`. Returns
    (quote_msg_b64, quote_sig_b64, signer_pub_b64) or None (fall back to E.1)."""
    if not _has("tpm2_quote"):
        log.debug("tpm2_quote not in PATH -- daemon stays at E.1")
        return None
    with TemporaryDirectory(prefix="meshembed-quote-") as tmp:
        workdir = Path(tmp)
        signer = _resolve_signer(workdir)
        if signer is None:
            log.debug("no usable TPM signing key -- daemon stays at E.1")
            return None
        signer_ctx, signer_pub = signer
        msg_path, sig_path = workdir / "quote.msg", workdir / "quote.sig"
        p = _run([
            "tpm2_quote", "-c", signer_ctx, "-l", _PCR_SELECTION,
            "-q", nonce_hex, "-m", str(msg_path), "-s", str(sig_path), "-g", "sha256",
        ])
        if p is None or p.returncode != 0:
            log.warning("tpm2_quote.failed rc=%s stderr=%s",
                        getattr(p, "returncode", None),
                        (getattr(p, "stderr", "") or "")[:200])
            return None
        try:
            msg_b, sig_b = msg_path.read_bytes(), sig_path.read_bytes()
        except OSError:
            return None
        return (
            base64.b64encode(msg_b).decode("ascii"),
            base64.b64encode(sig_b).decode("ascii"),
            base64.b64encode(signer_pub).decode("ascii"),
        )
