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
    def test_have_tpm2_quote_when_in_path(self):
        with patch("shutil.which", return_value="/usr/bin/tpm2_quote"):
            assert tpm_quote._have_tpm2_quote() is True

    def test_have_tpm2_quote_when_missing(self):
        with patch("shutil.which", return_value=None):
            assert tpm_quote._have_tpm2_quote() is False


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
    """Synthetic success path: subprocess.run writes fake files; the
    wrapper should base64-encode them and return the 3-tuple."""

    def test_success_returns_base64_tuple(self, tmp_path, monkeypatch):
        # Capture the cmd so we can write the expected output files.
        def fake_run(cmd, capture_output, text, timeout, **kwargs):
            # Parse -m, -s, -o paths from the command and write fixtures.
            for i, arg in enumerate(cmd):
                if arg == "-m":
                    Path(cmd[i + 1]).write_bytes(b"fake-quote-msg")
                elif arg == "-s":
                    Path(cmd[i + 1]).write_bytes(b"fake-quote-sig")
                elif arg == "-o":
                    Path(cmd[i + 1]).write_bytes(b"fake-pcrs")
            return MagicMock(returncode=0, stdout="", stderr="")

        def fake_readpublic_run(cmd, capture_output, text, timeout, **kwargs):
            # tpm2_readpublic writes the EK pub to its -o arg.
            for i, arg in enumerate(cmd):
                if arg == "-o":
                    Path(cmd[i + 1]).write_bytes(b"fake-ek-pub-bytes")
            return MagicMock(returncode=0, stdout="", stderr="")

        call_count = {"n": 0}

        def dispatch(cmd, **kw):
            call_count["n"] += 1
            if cmd[0] == "tpm2_quote":
                return fake_run(cmd, **kw)
            if cmd[0] == "tpm2_readpublic":
                return fake_readpublic_run(cmd, **kw)
            return MagicMock(returncode=1)

        with patch("shutil.which", return_value="/usr/bin/tpm2_quote"), \
             patch("subprocess.run", side_effect=dispatch):
            result = tpm_quote.quote("ab" * 32)

        assert result is not None
        msg_b64, sig_b64, ek_b64 = result
        assert base64.b64decode(msg_b64) == b"fake-quote-msg"
        assert base64.b64decode(sig_b64) == b"fake-quote-sig"
        assert base64.b64decode(ek_b64) == b"fake-ek-pub-bytes"

    def test_quote_includes_nonce_in_command(self):
        captured = {}

        def fake_run(cmd, capture_output, text, timeout, **kwargs):
            for i, arg in enumerate(cmd):
                if arg == "-q":
                    captured["nonce"] = cmd[i + 1]
                if arg == "-m":
                    Path(cmd[i + 1]).write_bytes(b"x")
                if arg == "-s":
                    Path(cmd[i + 1]).write_bytes(b"x")
                if arg == "-o":
                    Path(cmd[i + 1]).write_bytes(b"x")
            return MagicMock(returncode=0)

        with patch("shutil.which", return_value="/usr/bin/tpm2_quote"), \
             patch("subprocess.run", side_effect=fake_run):
            tpm_quote.quote("deadbeef" * 8)

        assert captured["nonce"] == "deadbeef" * 8

    def test_custom_ek_handle_env_var_respected(self):
        captured = {}

        def fake_run(cmd, capture_output, text, timeout, **kwargs):
            for i, arg in enumerate(cmd):
                if arg == "-c":
                    captured["handle"] = cmd[i + 1]
                if arg in ("-m", "-s", "-o"):
                    Path(cmd[i + 1]).write_bytes(b"x")
            return MagicMock(returncode=0)

        with patch.dict("os.environ", {"MESHEMBED_TPM_QUOTE_KEY_HANDLE": "0x81020001"}), \
             patch("shutil.which", return_value="/usr/bin/tpm2_quote"), \
             patch("subprocess.run", side_effect=fake_run):
            tpm_quote.quote("ab" * 32)

        assert captured["handle"] == "0x81020001"
