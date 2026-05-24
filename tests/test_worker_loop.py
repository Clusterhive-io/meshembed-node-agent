"""End-to-end tests for the daemon worker functions against a real
in-process mock backend.

These exercise the daemon's HTTP code path (requests library + JSON
serialization + retry/timeout shape) against a stub server that
records every received payload. Tests assert on:
  * the daemon called the right endpoint
  * the payload shape matches what the backend expects (model SHAs,
    installed_models snapshot, anomalies, attestation data)
  * the daemon honors the backend's response (skips work, applies
    update signals, falls through to setup, etc.)
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from meshembed_node import worker

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _make_cfg(backend_url: str) -> MagicMock:
    """Build a minimal Config-shaped MagicMock the worker functions
    accept."""
    cfg = MagicMock()
    cfg.backend_url = backend_url
    cfg.api_key = "test-api-key"
    cfg.node_id = "node-test-worker"
    cfg.model = "intfloat/multilingual-e5-small"
    cfg.agent_version = "0.3.6"
    cfg.max_chunks = 2
    cfg.node_privkey = ""    # unsigned mode for the simple tests
    cfg.node_pubkey = ""
    cfg.encryption_privkey = ""
    cfg.encryption_pubkey = ""
    cfg.machine_fingerprint = "a" * 64
    cfg.gpu_uuid = "GPU-test-uuid"
    cfg.is_vm = False
    cfg.poll_min_s = 1.0
    cfg.poll_max_s = 60.0
    return cfg


# ---------------------------------------------------------------------------
# _register
# ---------------------------------------------------------------------------

class TestRegister:
    def test_register_posts_to_correct_endpoint(self, mock_backend):
        cfg = _make_cfg(mock_backend.base_url)
        worker._register(cfg, installed_models=[
            {"model_id": "intfloat/multilingual-e5-small", "sha": "abc"},
        ])
        calls = mock_backend.calls("/register_node")
        assert len(calls) == 1
        payload = calls[0]
        assert payload["node_id"] == cfg.node_id
        assert payload["gpu_model"] is not None
        assert payload["agent_version"] == cfg.agent_version

    def test_register_sends_installed_models_list(self, mock_backend):
        cfg = _make_cfg(mock_backend.base_url)
        models = [
            {"model_id": "model-a", "sha": "sha-a", "last_used_at": 1.0},
            {"model_id": "model-b", "sha": "sha-b", "last_used_at": 2.0},
        ]
        worker._register(cfg, installed_models=models)
        payload = mock_backend.calls("/register_node")[0]
        assert payload.get("installed_models") == models

    def test_register_sends_node_pubkey_and_encryption_pubkey(self, mock_backend):
        cfg = _make_cfg(mock_backend.base_url)
        # Hardware binding (machine_fingerprint, gpu_uuid) is sent on
        # /get_job, not /register_node. /register carries the
        # ed25519 + X25519 pubkeys.
        cfg.node_pubkey = "cafe" * 16
        cfg.encryption_pubkey = "f00d" * 16
        worker._register(cfg)
        payload = mock_backend.calls("/register_node")[0]
        assert payload.get("node_pubkey") == "cafe" * 16
        assert payload.get("encryption_pubkey") == "f00d" * 16

    def test_register_sends_daemon_files_sha(self, mock_backend):
        cfg = _make_cfg(mock_backend.base_url)
        worker._register(cfg)
        payload = mock_backend.calls("/register_node")[0]
        sha = payload.get("daemon_files_sha")
        assert isinstance(sha, str) and len(sha) == 64


# ---------------------------------------------------------------------------
# _poll
# ---------------------------------------------------------------------------

class TestPoll:
    def test_poll_returns_empty_dict_on_no_assignment(self, mock_backend):
        cfg = _make_cfg(mock_backend.base_url)
        # Default response has assignment=None.
        # Patch fingerprint + tpm + anomalies so the test runs on any
        # host (CI runners don't have TPM / NVIDIA).
        with patch("meshembed_node.runtime_anomalies.collect", return_value=[]), \
             patch("meshembed_node.attestation.collect_tpm_state",
                   return_value=(False, {})):
            resp = worker._poll(cfg)
        assert resp.get("assignment") is None

    def test_poll_includes_anomalies_when_present(self, mock_backend):
        cfg = _make_cfg(mock_backend.base_url)
        with patch("meshembed_node.runtime_anomalies.collect",
                   return_value=["ptrace_attached"]), \
             patch("meshembed_node.attestation.collect_tpm_state",
                   return_value=(False, {})):
            worker._poll(cfg)
        payload = mock_backend.calls("/get_job")[0]
        assert payload.get("runtime_anomalies") == ["ptrace_attached"]

    def test_poll_includes_tpm_state(self, mock_backend):
        cfg = _make_cfg(mock_backend.base_url)
        with patch("meshembed_node.runtime_anomalies.collect", return_value=[]), \
             patch("meshembed_node.attestation.collect_tpm_state",
                   return_value=(True, {"0": "aa" * 32, "8": "bb" * 32})):
            worker._poll(cfg)
        payload = mock_backend.calls("/get_job")[0]
        assert payload.get("tpm_available") is True
        assert payload.get("pcr_values") == {"0": "aa" * 32, "8": "bb" * 32}

    def test_poll_returns_assignment_when_present(self, mock_backend):
        cfg = _make_cfg(mock_backend.base_url)
        mock_backend.queue("/get_job", {
            "assignment": {
                "job_id": "job-1",
                "subjob_id": "subjob-1-000",
                "model": "intfloat/multilingual-e5-small",
                "task_type": "text_embeddings",
                "chunk_index": 0,
                "total_chunks": 1,
                "texts": ["hello world"],
                "timeout_seconds": 300,
                "callback_token": "tok-1",
            },
            "update_now": False,
        })
        with patch("meshembed_node.runtime_anomalies.collect", return_value=[]), \
             patch("meshembed_node.attestation.collect_tpm_state",
                   return_value=(False, {})):
            resp = worker._poll(cfg)
        assert resp.get("assignment") is not None
        assert resp["assignment"]["job_id"] == "job-1"

    def test_poll_respects_update_now_signal(self, mock_backend):
        cfg = _make_cfg(mock_backend.base_url)
        mock_backend.queue("/get_job", {
            "assignment": None,
            "update_now": True,
            "update_target_tag": "v0.3.7",
        })
        with patch("meshembed_node.runtime_anomalies.collect", return_value=[]), \
             patch("meshembed_node.attestation.collect_tpm_state",
                   return_value=(False, {})):
            resp = worker._poll(cfg)
        assert resp.get("update_now") is True
        assert resp.get("update_target_tag") == "v0.3.7"


# ---------------------------------------------------------------------------
# _report
# ---------------------------------------------------------------------------

class TestReport:
    def test_report_success_posts_embeddings(self, mock_backend):
        cfg = _make_cfg(mock_backend.base_url)
        assignment = {
            "job_id": "job-1",
            "subjob_id": "subjob-1-000",
            "chunk_index": 0,
            "texts": ["hello"],
            "callback_token": "tok-1",
        }
        ok = worker._report(
            cfg,
            assignment,
            embeddings=[[0.1, 0.2, 0.3]],
            gpu_seconds=0.5,
            duration_ms=500,
            error=None,
            model_sha_used="sha-test",
        )
        assert ok is True
        payload = mock_backend.calls("/report_result")[0]
        assert payload["status"] == "completed"
        assert payload["subjob_id"] == "subjob-1-000"
        assert payload["embeddings"] == [[0.1, 0.2, 0.3]]
        assert payload["model_sha_used"] == "sha-test"

    def test_report_failure_sets_status(self, mock_backend):
        cfg = _make_cfg(mock_backend.base_url)
        assignment = {
            "job_id": "job-1", "subjob_id": "subjob-1-000",
            "chunk_index": 0, "texts": ["x"], "callback_token": "tok-1",
        }
        worker._report(
            cfg, assignment, embeddings=[], gpu_seconds=0.0,
            duration_ms=100, error="encode_error:cuda OOM",
        )
        payload = mock_backend.calls("/report_result")[0]
        assert payload["status"] == "failed"
        assert "encode_error" in payload["error"]


# ---------------------------------------------------------------------------
# _attempt_signed_quote (Layer E.2 opportunistic path)
# ---------------------------------------------------------------------------

class TestAttemptSignedQuote:
    def test_signed_quote_no_op_when_tpm2_quote_missing(self, mock_backend):
        cfg = _make_cfg(mock_backend.base_url)
        # tpm_quote.quote() returns None when the binary isn't present.
        with patch("meshembed_node.tpm_quote.quote", return_value=None):
            worker._attempt_signed_quote(cfg)
        # The challenge was requested but no quote posted.
        assert mock_backend.call_count("/attestation/challenge") == 1
        assert mock_backend.call_count("/attestation/quote") == 0

    def test_signed_quote_posts_bundle_on_success(self, mock_backend):
        cfg = _make_cfg(mock_backend.base_url)
        with patch("meshembed_node.tpm_quote.quote",
                   return_value=("msg_b64", "sig_b64", "ek_b64")):
            worker._attempt_signed_quote(cfg)
        assert mock_backend.call_count("/attestation/challenge") == 1
        assert mock_backend.call_count("/attestation/quote") == 1
        payload = mock_backend.calls("/attestation/quote")[0]
        assert payload["quote_msg"] == "msg_b64"
        assert payload["quote_sig"] == "sig_b64"
        assert payload["ek_pub"] == "ek_b64"
        # The nonce from the mock challenge defaults to "aa"*32.
        assert payload["nonce"] == "aa" * 32
