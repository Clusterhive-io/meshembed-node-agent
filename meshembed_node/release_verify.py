"""Verify that an OTA installer is the artifact WE published.

Why this exists
---------------
The daemon downloads `install.sh` over HTTPS and **executes it** with the
privileges needed to install a system service. Until now the only integrity
check was `len(data) >= 100` — i.e. the sole guarantee was "TLS, and GitHub
said so". Nothing proved the script was ours.

That matters because **git tags are mutable**: `git push --force origin v0.3.42`
re-points a tag at different content, and nodes fetch *by tag*. So anyone with
write access to the release repo — a compromised GitHub account, a stolen CI
token, an insider — could hand every operator machine arbitrary code, and no
node could tell.

Note this is a different hole from the installer-tag allowlist in worker.py.
That guard constrains *where* code is fetched from (it blocks path traversal to
another repo). This one proves *what* the code is, even when it comes from the
legitimate repo.

Scheme
------
Detached Ed25519 signature over the raw installer bytes.

* Signature file: `<installer>.sig`, published next to the installer.
* Format: one line, `meshembed-relsig-v1 <key_id_hex16> <signature_hex128>`.
* The trusted public key(s) are compiled into the daemon below, so a
  compromised *backend* cannot introduce a key — only a new signed daemon
  release can, and that release must itself verify under the current key.

Uses `cryptography` (already a daemon dependency); no new packages.

Trust bootstrapping (honest caveat)
-----------------------------------
The public key ships inside the daemon, so the FIRST install is still
trust-on-first-use — the operator must trust the initial download. Every
subsequent OTA is cryptographically verified. That is the same model apt,
Sparkle and most auto-updaters use.

Key rotation
------------
`_TRUSTED_RELEASE_KEYS` is a list. To rotate: ship a release (signed by the old
key) that adds the new key, wait for the fleet to adopt it, then start signing
with the new key and drop the old one in a later release.
"""
from __future__ import annotations

import hashlib
import logging

log = logging.getLogger(__name__)

SIG_FORMAT = "meshembed-relsig-v1"
SIG_SUFFIX = ".sig"

# Ed25519 public keys trusted to sign MeshEmbed releases (hex, 32 bytes).
# The matching private key lives OFFLINE / in a CI secret and must never be
# present on a node or in this repository.
_TRUSTED_RELEASE_KEYS = [
    "110ca603f1b4d850b5a956fbe34a9f4ba21e271afd10cb02baef6cf242236408",
]


def key_id(pubkey_hex: str) -> str:
    """Short, stable identifier for a signing key (first 16 hex of sha256)."""
    return hashlib.sha256(bytes.fromhex(pubkey_hex)).hexdigest()[:16]


def sign_blob(privkey_hex: str, data: bytes) -> str:
    """Produce a `.sig` line for `data`. Used by the release tooling, not the node."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat,
    )
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(privkey_hex))
    pub_hex = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    sig = priv.sign(data).hex()
    return f"{SIG_FORMAT} {key_id(pub_hex)} {sig}"


def verify_blob(data: bytes, sig_line: str, trusted_keys=None) -> str:
    """Verify `data` against a detached signature line.

    Returns the key_id that validated it. Raises RuntimeError on ANY problem —
    malformed signature, unknown key, or a bad signature. Callers must treat an
    exception as "do not execute this".
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    keys = _TRUSTED_RELEASE_KEYS if trusted_keys is None else trusted_keys
    parts = (sig_line or "").strip().split()
    if len(parts) != 3:
        raise RuntimeError("release_signature_malformed")
    fmt, kid, sig_hex = parts
    if fmt != SIG_FORMAT:
        raise RuntimeError(f"release_signature_bad_format:{fmt!r}")

    candidates = [k for k in keys if key_id(k) == kid]
    if not candidates:
        # Signed by a key this daemon does not trust — refuse. This is the case
        # that stops a repo-compromise attacker who signs with their own key.
        raise RuntimeError(f"release_signature_untrusted_key:{kid}")

    try:
        sig = bytes.fromhex(sig_hex)
    except ValueError:
        raise RuntimeError("release_signature_not_hex")

    for pub_hex in candidates:
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(sig, data)
            return kid
        except InvalidSignature:
            continue
    raise RuntimeError("release_signature_invalid")
