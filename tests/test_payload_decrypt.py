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


# --- v2 multi-recipient envelope (pre-assignment) ----------------------------

def test_multi_roundtrip_every_recipient_can_open():
    """One sealing, K wraps: each candidate independently recovers the texts —
    the property that lets a subjob survive K-1 node failures."""
    keys = [_fresh_recipient() for _ in range(3)]
    texts = ["hello", "unícode ✓ 日本語", ""]
    env = crypto.encrypt_multi([pub for _, pub in keys], texts)
    assert env["format"] == crypto.PAYLOAD_FORMAT_V2
    assert len(env["recipients"]) == 3
    for priv, _ in keys:
        assert crypto.decrypt_multi(priv, env) == texts


def test_multi_non_recipient_is_rejected():
    _, pub = _fresh_recipient()
    outsider_priv, _ = _fresh_recipient()
    env = crypto.encrypt_multi([pub], ["secret"])
    with pytest.raises(ValueError, match="not_a_recipient"):
        crypto.decrypt_multi(outsider_priv, env)


def test_multi_tampered_ciphertext_is_detected():
    import base64
    priv, pub = _fresh_recipient()
    env = crypto.encrypt_multi([pub], ["secret"])
    ct = bytearray(base64.b64decode(env["ciphertext"]))
    ct[0] ^= 0x01
    env["ciphertext"] = base64.b64encode(bytes(ct)).decode()
    with pytest.raises(Exception):
        crypto.decrypt_multi(priv, env)


def test_multi_tampered_wrapped_key_is_detected():
    import base64
    priv, pub = _fresh_recipient()
    env = crypto.encrypt_multi([pub], ["secret"])
    wk = bytearray(base64.b64decode(env["recipients"][pub]["wrapped_key"]))
    wk[0] ^= 0x01
    env["recipients"][pub]["wrapped_key"] = base64.b64encode(bytes(wk)).decode()
    with pytest.raises(Exception):
        crypto.decrypt_multi(priv, env)


def test_multi_swapped_wrapped_key_between_recipients_fails():
    """A wrapped key is bound to ITS recipient: grafting another recipient's
    wrap under my pubkey must not decrypt (Box auth fails, no silent cross-use)."""
    (priv_a, pub_a), (_, pub_b) = _fresh_recipient(), _fresh_recipient()
    env = crypto.encrypt_multi([pub_a, pub_b], ["secret"])
    env["recipients"][pub_a] = env["recipients"][pub_b]
    with pytest.raises(Exception):
        crypto.decrypt_multi(priv_a, env)


def test_dispatcher_routes_both_formats_and_rejects_unknown():
    priv, pub = _fresh_recipient()
    v1 = crypto.encrypt_box(pub, ["a"])
    v2 = crypto.encrypt_multi([pub], ["b"])
    assert crypto.decrypt_envelope(priv, v1) == ["a"]
    assert crypto.decrypt_envelope(priv, v2) == ["b"]
    with pytest.raises(ValueError):
        crypto.decrypt_envelope(priv, {"format": "rot13"})


def test_multi_no_recipients_rejected_at_encrypt():
    with pytest.raises(ValueError, match="no_recipients"):
        crypto.encrypt_multi([], ["x"])


def test_backend_predicate_and_shape_agree_on_v2():
    from importlib import import_module
    try:
        pe = import_module("backend.app.payload_encryption")
    except Exception:
        pytest.skip("backend not importable in this env")
    pubs = [_fresh_recipient()[1] for _ in range(3)]
    env = crypto.encrypt_multi(pubs, ["x"])
    assert pe.is_encrypted_envelope(env) is True
    pe.validate_envelope_shape(env)  # must not raise


def test_daemon_opens_what_the_sdk_seals():
    """The REAL fleet path: SDK encrypt_multi -> daemon decrypt_envelope.
    The SDK ships its own copy of the reference encryptor; if the two ever
    drift, every confidential job dies at the node with decrypt_error."""
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sdk"))
    try:
        from meshembed.crypto import encrypt_multi as sdk_encrypt_multi
    except Exception:
        pytest.skip("sdk not importable in this env")

    keys = [_fresh_recipient() for _ in range(3)]
    env = sdk_encrypt_multi([pub for _, pub in keys], ["sdk sealed this"])
    for priv, _ in keys:
        assert crypto.decrypt_envelope(priv, env) == ["sdk sealed this"]


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
