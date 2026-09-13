"""A sealed generation item: opened on the node, never guessed at.

The embedding envelope carries {"texts": [...]}; a generation item is an object
and seals as {"item": {...}}. Same crypto, same v2 format. What must hold: the
node gets exactly the item back, a texts envelope is refused as an item rather
than misread, a non-recipient cannot open it, and a decrypt failure fails the
subjob instead of falling back to anything.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sdk"))

from meshembed_node import crypto as ncrypto        # noqa: E402
from meshembed_node.worker import _llm_item         # noqa: E402

nacl = pytest.importorskip("nacl")
from meshembed.crypto import encrypt_item_multi, encrypt_multi   # noqa: E402


class _Cfg:
    def __init__(self, priv_hex): self.encryption_privkey = priv_hex


def _keypair():
    from nacl.public import PrivateKey
    k = PrivateKey.generate()
    return bytes(k).hex(), bytes(k.public_key).hex()


ITEM = {"custom_id": "row-1",
        "messages": [{"role": "system", "content": "Extract the parties."},
                     {"role": "user", "content": "Sale from Acme SL to Brown Ltd."}]}


def test_a_sealed_item_round_trips_to_the_node():
    priv, pub = _keypair()
    env = encrypt_item_multi([pub], ITEM)
    assert ncrypto.decrypt_envelope_object(priv, env) == ITEM


def test_the_worker_opens_a_sealed_item_from_the_assignment():
    priv, pub = _keypair()
    assignment = {"job_type": "llm_batch",
                  "encrypted_payload": encrypt_item_multi([pub], ITEM),
                  "item": None}
    assert _llm_item(assignment, _Cfg(priv)) == ITEM


def test_a_plaintext_item_still_works():
    assert _llm_item({"job_type": "llm_batch", "item": ITEM}, _Cfg("00" * 32)) == ITEM


def test_a_texts_envelope_is_not_misread_as_an_item():
    """A generation node handed an embedding envelope must refuse it, not
    generate from a stringified list."""
    priv, pub = _keypair()
    with pytest.raises(ValueError, match="carries_no_item"):
        ncrypto.decrypt_envelope_object(priv, encrypt_multi([pub], ["hola"]))


def test_a_non_recipient_cannot_open_it():
    _, pub = _keypair()
    other_priv, _ = _keypair()
    with pytest.raises(ValueError, match="not_a_recipient"):
        ncrypto.decrypt_envelope_object(other_priv, encrypt_item_multi([pub], ITEM))


def test_decrypt_failure_raises_rather_than_falling_back():
    """No plaintext to fall back to, and there must not be: a completion
    generated from a guessed prompt would be returned as the customer's."""
    other_priv, _ = _keypair()
    _, pub = _keypair()
    assignment = {"job_type": "llm_batch",
                  "encrypted_payload": encrypt_item_multi([pub], ITEM)}
    with pytest.raises(ValueError):
        _llm_item(assignment, _Cfg(other_priv))


def test_the_texts_path_is_untouched():
    priv, pub = _keypair()
    assert ncrypto.decrypt_envelope(priv, encrypt_multi([pub], ["a", "b"])) == ["a", "b"]
