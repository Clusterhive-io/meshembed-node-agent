"""Phase 1B payload decryption — daemon-side crypto_box roundtrip + failure modes.

The daemon only ever *decrypts*; `encrypt_box` is the reference encryptor the SDK
mirrors, exercised here as the "client" role. Skips cleanly if PyNaCl isn't
installed (it's a daemon dep added for Phase 1B).
"""
from __future__ import annotations

import base64

import pytest

pytest.importorskip("nacl")  # PyNaCl — Phase 1B dep

from meshembed_node import crypto


def _fresh_recipient():
    return crypto.generate_x25519_keypair()  # (priv_hex, pub_hex)


def test_roundtrip_returns_texts():
    priv, pub = _fresh_recipient()
    texts = ["hello world", "meshembed-canary", "unícode ✓ 日本語", ""]
    env = crypto.encrypt_box(pub, texts)
    assert env["format"] == crypto.PAYLOAD_FORMAT_V1
    assert env["recipient_pubkey"] == pub
    assert env["ciphertext_len"] > 0
    assert crypto.decrypt_box(priv, env) == texts


def test_backend_predicate_and_shape_agree():
    # The envelope the daemon produces must satisfy the backend's validators.
    from importlib import import_module
    try:
        pe = import_module("backend.app.payload_encryption")
    except Exception:
        pytest.skip("backend not importable in this env")
    priv, pub = _fresh_recipient()
    env = crypto.encrypt_box(pub, ["x"])
    assert pe.is_encrypted_envelope(env) is True
    pe.validate_envelope_shape(env)  # must not raise


def test_wrong_key_fails():
    _, pub = _fresh_recipient()
    other_priv, _ = _fresh_recipient()
    env = crypto.encrypt_box(pub, ["secret"])
    with pytest.raises(Exception):
        crypto.decrypt_box(other_priv, env)


def test_tamper_is_detected():
    priv, pub = _fresh_recipient()
    env = crypto.encrypt_box(pub, ["secret"])
    ct = bytearray(base64.b64decode(env["ciphertext"]))
    ct[0] ^= 0x01  # flip one bit
    env["ciphertext"] = base64.b64encode(bytes(ct)).decode()
    with pytest.raises(Exception):
        crypto.decrypt_box(priv, env)


def test_bad_format_rejected():
    priv, pub = _fresh_recipient()
    env = crypto.encrypt_box(pub, ["secret"])
    env["format"] = "rot13"
    with pytest.raises(ValueError):
        crypto.decrypt_box(priv, env)


# --- _report on the e2e path (regression for the texts=None crash) -----------

def _mock_cfg():
    from unittest.mock import MagicMock
    cfg = MagicMock()
    cfg.node_id = "node-test"
    cfg.api_key = "k"
    cfg.backend_url = "http://backend.invalid"
    cfg.machine_fingerprint = "a" * 64
    cfg.gpu_uuid = "GPU-x"
    cfg.node_privkey = ""  # unsigned -> skip result signing
    return cfg


def _patch_post(monkeypatch):
    captured = {}
    from meshembed_node import worker

    class _Resp:
        def raise_for_status(self): pass
        def json(self): return {"ok": True}

    def _fake_post(url, json=None, headers=None, timeout=None):
        captured["payload"] = json
        return _Resp()

    monkeypatch.setattr(worker.requests, "post", _fake_post)
    return worker, captured


def test_report_does_not_crash_on_e2e_assignment(monkeypatch):
    """An e2e assignment has texts=None (payload is in encrypted_payload). _report
    must count from the decrypted count the caller passes, not len(None)."""
    worker, captured = _patch_post(monkeypatch)
    assignment = {
        "job_id": "j1", "subjob_id": "s1", "chunk_index": 0,
        "callback_token": "tok", "texts": None,
        "encrypted_payload": {"format": crypto.PAYLOAD_FORMAT_V1},
    }
    ok = worker._report(_mock_cfg(), assignment, embeddings=[[0.1, 0.2]],
                        gpu_seconds=0.1, duration_ms=5, error=None, text_count=3)
    assert ok is True
    assert captured["payload"]["text_count"] == 3  # from decrypted count, not None


def test_report_fallback_counts_plaintext_when_no_text_count(monkeypatch):
    """Legacy callers pass no text_count; _report falls back to the plaintext list
    and still tolerates a None texts field."""
    worker, captured = _patch_post(monkeypatch)
    base = {"job_id": "j", "subjob_id": "s", "chunk_index": 0, "callback_token": "t"}
    # plaintext job: counts the list
    worker._report(_mock_cfg(), {**base, "texts": ["a", "b"]}, [], 0.0, 1, "err")
    assert captured["payload"]["text_count"] == 2
    # e2e job whose caller forgot text_count: must not crash on None
    worker._report(_mock_cfg(), {**base, "texts": None}, [], 0.0, 1, "err")
    assert captured["payload"]["text_count"] == 0
