"""Each installer's SHA256SUMS signature check, RUN for real against the format we publish.

Found 2026-10-04: sign-release.py writes SHA256SUMS.sig as the release line
"meshembed-relsig-v1 <key_id> <signature hex>", but all three installers handed the whole
file to Ed25519 as a raw signature, so every check of a published SHA256SUMS failed
(v0.3.66 onwards: fresh installs everywhere and every Mac self-update). The other installer
tests stub python3 to print "ok", and release audits used the daemon's verifier, so nothing
ever ran this code against a real signature. These tests do, with no stub.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

from meshembed_node.release_verify import key_id, sign_blob

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
REAL = Path(__file__).resolve().parent / "fixtures" / "release_v0.3.69"
INSTALLERS = ["install.sh", "install-mac.sh", "install.ps1"]


def _snippet(name: str) -> str:
    src = (ROOT / name).read_text()
    if name.endswith(".ps1"):
        m = re.search(r"@'\n(import sys, hashlib\n.*?)'@", src, re.S)
    else:
        m = re.search(r"<<'PYEOF'.*?\n(import sys, hashlib\n.*?)PYEOF\n", src, re.S)
    assert m, f"{name}: verification snippet not found"
    return m.group(1)


def _pinned_key(name: str) -> str:
    m = re.search(r"\b([0-9a-f]{64})\b", (ROOT / name).read_text())
    assert m, name
    return m.group(1)


def _run(name: str, tmp: Path, sums: bytes, sig: str, pub_hex: str) -> subprocess.CompletedProcess:
    (tmp / "verify.py").write_text(_snippet(name))
    (tmp / "SHA256SUMS").write_bytes(sums)
    (tmp / "SHA256SUMS.sig").write_text(sig)
    return subprocess.run(
        [sys.executable, str(tmp / "verify.py"), str(tmp / "SHA256SUMS"),
         str(tmp / "SHA256SUMS.sig"), pub_hex],
        capture_output=True, text=True, timeout=60,
    )


def _keypair() -> tuple[str, str]:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, NoEncryption, PrivateFormat, PublicFormat,
    )
    k = Ed25519PrivateKey.generate()
    priv = k.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()
    pub = k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    return priv, pub


SUMS = b"0" * 64 + b"  install.sh\n" + b"1" * 64 + b"  v9.9.9.tar.gz\n"


@pytest.mark.parametrize("name", INSTALLERS)
def test_accepts_what_the_signer_writes(name, tmp_path):
    priv, pub = _keypair()
    p = _run(name, tmp_path, SUMS, sign_blob(priv, SUMS) + "\n", pub)
    assert p.returncode == 0 and p.stdout.strip() == "ok", p.stderr


@pytest.mark.parametrize("name", INSTALLERS)
def test_rejects_tampered_sums(name, tmp_path):
    priv, pub = _keypair()
    p = _run(name, tmp_path, SUMS.replace(b"0", b"2", 1), sign_blob(priv, SUMS), pub)
    assert p.returncode == 1 and "INVALID" in p.stderr


@pytest.mark.parametrize("name", INSTALLERS)
def test_rejects_another_key(name, tmp_path):
    priv, _ = _keypair()
    _, other_pub = _keypair()
    p = _run(name, tmp_path, SUMS, sign_blob(priv, SUMS), other_pub)
    assert p.returncode == 1 and "INVALID" in p.stderr


@pytest.mark.parametrize("name", INSTALLERS)
def test_rejects_a_line_whose_key_id_is_not_the_pinned_key(name, tmp_path):
    """Same signature bytes, key id swapped: the line must name the pinned key."""
    priv, pub = _keypair()
    fmt, _kid, sig_hex = sign_blob(priv, SUMS).split()
    p = _run(name, tmp_path, SUMS, f"{fmt} {'0' * 16} {sig_hex}", pub)
    assert p.returncode == 1 and "INVALID" in p.stderr


@pytest.mark.parametrize("name", INSTALLERS)
def test_rejects_garbage(name, tmp_path):
    _, pub = _keypair()
    for junk in ("", "meshembed-relsig-v1", f"meshembed-relsig-v1 {key_id(pub)} zz"):
        p = _run(name, tmp_path, SUMS, junk, pub)
        assert p.returncode == 1, (junk, p.stdout, p.stderr)


@pytest.mark.parametrize("name", INSTALLERS)
def test_the_real_v0369_release_verifies_with_the_pinned_key(name, tmp_path):
    """The published v0.3.69 SHA256SUMS + .sig (fetched 2026-10-04, fleet key a138d7d0cf3d361a)."""
    pub = _pinned_key(name)
    assert key_id(pub) == "a138d7d0cf3d361a"
    p = _run(name, tmp_path, (REAL / "published-SHA256SUMS").read_bytes(),
             (REAL / "published-SHA256SUMS.sig").read_text(), pub)
    assert p.returncode == 0 and p.stdout.strip() == "ok", p.stderr
