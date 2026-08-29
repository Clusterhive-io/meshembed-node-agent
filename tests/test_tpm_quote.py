"""Unit tests for the daemon-side Layer E.2 helper.

The real tpm2_quote binary requires a TPM 2.0 device, so the tests
focus on the wrapper's behavior when the binary is missing, when it
fails, and on the base64 framing of a synthetic success. Actual
hardware tests live in T5 (installer fleet) on hosts with a TPM.
"""
from __future__ import annotations

import base64
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from meshembed_node import tpm_quote

pytestmark = pytest.mark.unit


class TestPrecondChecks:
    def test_has_binary_when_in_path(self):
        with patch("shutil.which", return_value="/usr/bin/tpm2_quote"):
            assert tpm_quote._has("tpm2_quote") is True

    def test_has_binary_when_missing(self):
        with patch("shutil.which", return_value=None):
            assert tpm_quote._has("tpm2_quote") is False


class TestQuoteDegradation:
    """Verify the daemon never crashes when the toolchain is missing."""

    def test_returns_none_when_tpm2_quote_missing(self):
        with patch("shutil.which", return_value=None):
            assert tpm_quote.quote("ab" * 32) is None

    def test_returns_none_on_nonzero_exit(self):
        # tpm2_quote present, but returns rc=1 (no TPM device)
        mock_proc = MagicMock(returncode=1, stdout="", stderr="no device")
        with patch("shutil.which", return_value="/usr/bin/tpm2_quote"), \
             patch("subprocess.run", return_value=mock_proc):
            assert tpm_quote.quote("ab" * 32) is None

    def test_returns_none_on_timeout(self):
        import subprocess
        with patch("shutil.which", return_value="/usr/bin/tpm2_quote"), \
             patch("subprocess.run",
                   side_effect=subprocess.TimeoutExpired(cmd=["x"], timeout=20)):
            assert tpm_quote.quote("ab" * 32) is None

    def test_returns_none_when_binary_disappears_mid_call(self):
        with patch("shutil.which", return_value="/usr/bin/tpm2_quote"), \
             patch("subprocess.run", side_effect=FileNotFoundError):
            assert tpm_quote.quote("ab" * 32) is None


class TestQuoteSuccessFraming:
    """Success path: a restricted SIGNING key is resolved (real hw / swtpm does
    this for real; mocked here), then tpm2_quote writes msg/sig which the wrapper
    base64-encodes into the 3-tuple. Includes the regression that the signer is
    NEVER the EK handle -- the EK is a decryption key and cannot sign a quote."""

    def test_success_returns_base64_tuple(self):
        def fake_run(cmd, **kw):
            for i, a in enumerate(cmd):
                if a == "-m":
                    Path(cmd[i + 1]).write_bytes(b"fake-quote-msg")
                elif a == "-s":
                    Path(cmd[i + 1]).write_bytes(b"fake-quote-sig")
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch("shutil.which", return_value="/usr/bin/tpm2_quote"), \
             patch.object(tpm_quote, "_resolve_signer",
                          return_value=("signer.ctx", b"fake-signer-pub")), \
             patch("subprocess.run", side_effect=fake_run):
            result = tpm_quote.quote("ab" * 32)

        assert result is not None
        msg_b64, sig_b64, pub_b64 = result
        assert base64.b64decode(msg_b64) == b"fake-quote-msg"
        assert base64.b64decode(sig_b64) == b"fake-quote-sig"
        assert base64.b64decode(pub_b64) == b"fake-signer-pub"

    def test_quote_uses_nonce_and_not_the_ek_as_signer(self):
        captured = {}

        def fake_run(cmd, **kw):
            if cmd and cmd[0] == "tpm2_quote":
                for i, a in enumerate(cmd):
                    if a == "-q":
                        captured["nonce"] = cmd[i + 1]
                    if a == "-c":
                        captured["signer"] = cmd[i + 1]
                    if a in ("-m", "-s"):
                        Path(cmd[i + 1]).write_bytes(b"x")
            return MagicMock(returncode=0)

        with patch("shutil.which", return_value="/usr/bin/tpm2_quote"), \
             patch.object(tpm_quote, "_resolve_signer",
                          return_value=("signer.ctx", b"pub")), \
             patch("subprocess.run", side_effect=fake_run):
            tpm_quote.quote("deadbeef" * 8)

        assert captured["nonce"] == "deadbeef" * 8
        # Regression (2026-08-20): the quote signer must not be the EK handle.
        assert captured["signer"] != tpm_quote._DEFAULT_EK_HANDLE
