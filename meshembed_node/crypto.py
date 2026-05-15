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
