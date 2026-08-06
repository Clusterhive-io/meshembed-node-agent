"""ed25519 keypair, signing and verification for MeshEmbed Node.

Each node has an ed25519 keypair:
- privkey (hex 32 bytes): kept in .env as MESHEMBED_NODE_PRIVKEY. Never
  leaves the node.
- pubkey  (hex 32 bytes): sent to the backend at registration. The
  backend stores it and uses it to verify every X-Node-Signature.

The signed payload is the SHA-256 of a canonical JSON containing:
  {callback_token, subjob_id, embeddings_sha256}

callback_token acts as a nonce (unique per subjob), preventing
replay of results. embeddings_sha256 commits to the content without
transmitting the embeddings twice.
"""
from __future__ import annotations

import hashlib
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


def generate_keypair() -> tuple[str, str]:
    """Generate a fresh keypair. Returns (privkey_hex, pubkey_hex)."""
    priv = Ed25519PrivateKey.generate()
    priv_hex = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()
    pub_hex = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    return priv_hex, pub_hex


def pubkey_from_privkey(priv_hex: str) -> str:
    """Derive the public key hex from the private key hex."""
    raw = bytes.fromhex(priv_hex)
    priv = Ed25519PrivateKey.from_private_bytes(raw)
    return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def _signed_payload(subjob_id: str, callback_token: str, embeddings: list) -> bytes:
    emb_hash = hashlib.sha256(
        json.dumps(embeddings, separators=(",", ":")).encode()
    ).hexdigest()
    canonical = json.dumps(
        {
            "callback_token": callback_token,
            "embeddings_sha256": emb_hash,
            "subjob_id": subjob_id,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode()).digest()


def sign_result(priv_hex: str, subjob_id: str, callback_token: str, embeddings: list) -> str:
    """Sign a result. Returns the signature as 64-byte hex."""
    raw = bytes.fromhex(priv_hex)
    priv = Ed25519PrivateKey.from_private_bytes(raw)
    digest = _signed_payload(subjob_id, callback_token, embeddings)
    return priv.sign(digest).hex()


def verify_result(pub_hex: str, subjob_id: str, callback_token: str,
                  embeddings: list, sig_hex: str) -> bool:
    """Verify a signature. Returns True when valid."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        digest = _signed_payload(subjob_id, callback_token, embeddings)
        pub.verify(bytes.fromhex(sig_hex), digest)
        return True
    except (InvalidSignature, ValueError):
        return False


# ---------------------------------------------------------------------------
# X25519 encryption keypair — Option B Phase 1A (2026-05-22)
# End-to-end client->daemon payload encryption for confidential and
# restricted sensitivity tiers. Backend learns the pubkey at register
# time + every poll; the client encrypts to that pubkey at submit time
# (Phase 1B wiring). Backend never decrypts; for confidential tier,
# only the assigned daemon can read the plaintext.
# ---------------------------------------------------------------------------


def generate_x25519_keypair() -> tuple[str, str]:
    """Generate a fresh X25519 keypair for payload encryption.

    Returns (privkey_hex, pubkey_hex). Both 32 bytes = 64 hex chars.
    Persisted to ~/.meshembed/encryption_key by the caller; only the
    pubkey is sent over the wire.
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    priv = X25519PrivateKey.generate()
    priv_hex = priv.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    ).hex()
    pub_hex = priv.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    ).hex()
    return priv_hex, pub_hex


def x25519_pubkey_from_privkey(priv_hex: str) -> str:
    """Derive the X25519 pubkey from the privkey hex (for verifying the
    keypair file on disk matches what the daemon advertises)."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    priv = X25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))
    return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


# ---------------------------------------------------------------------------
# Phase 1B — client->daemon payload decryption (libsodium crypto_box).
#
# Scheme: X25519 + XSalsa20-Poly1305 (libsodium `crypto_box`), via PyNaCl.
# The client generates an EPHEMERAL X25519 keypair, boxes the plaintext
# JSON {"texts": [...]} to the daemon's static pubkey with a random 24-byte
# nonce, and ships the envelope. The daemon opens it with its static privkey.
# Envelope shape is the canonical one in backend/app/payload_encryption.py
# (`FORMAT_V1`). The backend never decrypts — it only transports the envelope.
# ---------------------------------------------------------------------------

PAYLOAD_FORMAT_V1: str = "x25519-xsalsa20poly1305-v1"


def encrypt_box(recipient_pubkey_hex: str, texts: list) -> dict:
    """Reference encryptor (used by tests + mirrored by the SDK — the daemon
    itself only ever *decrypts*). Boxes ``{"texts": texts}`` to the recipient's
    X25519 pubkey and returns the canonical envelope dict."""
    import base64
    from nacl.public import PrivateKey, PublicKey, Box
    from nacl.utils import random as _rand

    plaintext = json.dumps({"texts": texts}, separators=(",", ":")).encode()
    ephemeral = PrivateKey.generate()
    box = Box(ephemeral, PublicKey(bytes.fromhex(recipient_pubkey_hex)))
    nonce = _rand(Box.NONCE_SIZE)  # 24 bytes
    ciphertext = box.encrypt(plaintext, nonce).ciphertext  # without the nonce prefix
    return {
        "format": PAYLOAD_FORMAT_V1,
        "recipient_pubkey": recipient_pubkey_hex,
        "ephemeral_pubkey": ephemeral.public_key.encode().hex(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "ciphertext_len": len(plaintext),
    }


def decrypt_box(priv_hex: str, envelope: dict) -> list:
    """Decrypt a Phase 1B payload envelope with the daemon's X25519 privkey.

    Returns the ``texts`` list. Raises on a bad format, a malformed envelope,
    a wrong key, or a Poly1305 authentication failure (tamper) — callers must
    treat any exception as a hard failure and NEVER fall back to a plaintext /
    hash-embed path for a confidential job.
    """
    import base64
    from nacl.public import PrivateKey, PublicKey, Box

    fmt = envelope.get("format")
    if fmt != PAYLOAD_FORMAT_V1:
        raise ValueError(f"unsupported_envelope_format:{fmt!r}")
    ephemeral_pub = PublicKey(bytes.fromhex(envelope["ephemeral_pubkey"]))
    box = Box(PrivateKey(bytes.fromhex(priv_hex)), ephemeral_pub)
    nonce = base64.b64decode(envelope["nonce"])
    ciphertext = base64.b64decode(envelope["ciphertext"])
    plaintext = box.decrypt(ciphertext, nonce)  # raises nacl.exceptions.CryptoError on tamper/wrong-key
    data = json.loads(plaintext)
    return data["texts"]
