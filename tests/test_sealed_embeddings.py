"""E2E-V on the node: a sealed embedding item that names a reply key gets its VECTORS
back sealed to that key (docs/DESIGN_E2E_V_SEALED_EMBEDDING_RESULTS.md)."""
from __future__ import annotations

import json
import math

import pytest

nacl = pytest.importorskip("nacl")

from meshembed_node.crypto import (                                   # noqa: E402
    PAD_MIN_BUCKET, encrypt_multi, encrypt_multi_object, generate_x25519_keypair,
    open_envelope_json, pack_vectors, pad_object, unpack_vectors,
)
from meshembed_node.worker import _seal_vectors                       # noqa: E402


def _keys():
    priv, pub = generate_x25519_keypair()
    return priv, pub


def _open(priv, env) -> dict:
    """The customer side: open what the node sealed (mirrors the SDK)."""
    import base64
    from nacl.public import Box, PrivateKey, PublicKey
    from nacl.secret import SecretBox
    pub = PrivateKey(bytes.fromhex(priv)).public_key.encode().hex()
    e = env["recipients"][pub]
    key = Box(PrivateKey(bytes.fromhex(priv)), PublicKey(bytes.fromhex(env["ephemeral_pubkey"]))).decrypt(
        base64.b64decode(e["wrapped_key"]), base64.b64decode(e["nonce"]))
    return json.loads(SecretBox(key).decrypt(base64.b64decode(env["ciphertext"]), base64.b64decode(env["nonce"])))


def test_float32_packing_is_bit_exact():
    import struct
    v = [[struct.unpack("<f", struct.pack("<f", x))[0] for x in (0.1, -2.5, 1e-7, 3.0)] for _ in range(3)]
    assert unpack_vectors(pack_vectors(v)) == v


def test_padding_reaches_a_power_of_two_bucket():
    small = pad_object(pack_vectors([[0.1] * 8]))
    assert len(json.dumps(small, separators=(",", ":")).encode()) == PAD_MIN_BUCKET
    big = pad_object(pack_vectors([[0.1] * 384] * 4))
    n = len(json.dumps(big, separators=(",", ":")).encode())
    assert n >= PAD_MIN_BUCKET and (n & (n - 1)) == 0


def test_the_node_opens_texts_and_reply_key_and_still_reads_old_envelopes():
    node_priv, node_pub = _keys()
    _, reply_pub = _keys()
    env = encrypt_multi_object([node_pub], pad_object({"texts": ["a", "b"], "reply_to": reply_pub}))
    obj = open_envelope_json(node_priv, env)
    assert obj["texts"] == ["a", "b"] and obj["reply_to"] == reply_pub
    old = encrypt_multi([node_pub], ["only texts"])
    assert open_envelope_json(node_priv, old) == {"texts": ["only texts"]}


def test_vectors_are_sealed_so_only_the_reply_key_opens_them():
    reply_priv, reply_pub = _keys()
    other_priv, _ = _keys()
    vecs = [[0.25] * 384, [-0.5] * 384]
    out, claim = _seal_vectors(vecs, reply_pub, {"encrypted_payload": {"format": "x"}})
    assert len(out) == 1 and claim == {"count": 2, "dim": 384}
    opened = _open(reply_priv, out[0])
    assert unpack_vectors(opened) == vecs
    with pytest.raises(Exception):
        _open(other_priv, out[0])
    assert "0.25" not in json.dumps(out), "no vector value travels in the clear"


def test_a_reply_key_on_a_plaintext_item_is_refused():
    _, reply_pub = _keys()
    with pytest.raises(RuntimeError, match="reply_to_on_plaintext_item"):
        _seal_vectors([[0.1] * 4], reply_pub, {"texts": ["x"]})


def test_a_malformed_reply_key_fails_the_item():
    for bad in ("short", "z" * 64, None):
        with pytest.raises(RuntimeError, match="reply_to_malformed"):
            _seal_vectors([[0.1] * 4], bad, {"encrypted_payload": {"format": "x"}})
