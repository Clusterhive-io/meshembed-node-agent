"""auditor 2026-10-23 18:39Z: MESHEMBED_RELEASE_PUBKEY_OVERRIDE is a trust-root TEST hook, honoured only under
MESHEMBED_INSTALLER_TEST_MODE=1, in all three installers (K-2: no such hook in the default path)."""
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
REAL = "110ca603f1b4d850b5a956fbe34a9f4ba21e271afd10cb02baef6cf242236408 6c25a6c5349bf71046b575e75fabaa220ab3e67a0706963896093b0eef11b248"
EVIL = "ab" * 32


def _block(name):
    s = (ROOT / name).read_text()
    a = s.index('if [ "${MESHEMBED_INSTALLER_TEST_MODE:-}" = 1 ] && [ -n "${MESHEMBED_RELEASE_PUBKEY_OVERRIDE:-}" ]; then')
    return s[a:s.index("\nfi\n", a) + 4]


@pytest.mark.parametrize("name", ["install.sh", "install-mac.sh"])
@pytest.mark.parametrize("env,want", [
    ({}, REAL),
    ({"MESHEMBED_RELEASE_PUBKEY_OVERRIDE": EVIL}, REAL),                                   # ignored on a real install
    ({"MESHEMBED_RELEASE_PUBKEY_OVERRIDE": EVIL, "MESHEMBED_INSTALLER_TEST_MODE": "0"}, REAL),
    ({"MESHEMBED_RELEASE_PUBKEY_OVERRIDE": EVIL, "MESHEMBED_INSTALLER_TEST_MODE": "1"}, EVIL),   # the harnesses
    ({"MESHEMBED_INSTALLER_TEST_MODE": "1"}, REAL),
])
def test_the_override_only_in_test_mode(name, env, want):
    out = subprocess.run(["bash", "-c", _block(name) + 'printf "%s" "$RELEASE_PUBKEY_HEX"'],
                         env=dict({"PATH": "/usr/bin:/bin"}, **env), capture_output=True, text=True)
    assert out.stdout == want


def test_no_unconditional_override_left_anywhere():
    for name in ("install.sh", "install-mac.sh"):
        assert "${MESHEMBED_RELEASE_PUBKEY_OVERRIDE:-110ca" not in (ROOT / name).read_text()   # the old unconditional default
    ps1 = (ROOT / "install.ps1").read_text()
    assert "$ReleasePubKeyHex = if ($env:MESHEMBED_INSTALLER_TEST_MODE -eq '1' -and $env:MESHEMBED_RELEASE_PUBKEY_OVERRIDE)" in ps1
    assert not re.search(r"\$ReleasePubKeyHex = if \(\$env:MESHEMBED_RELEASE_PUBKEY_OVERRIDE\)", ps1)
