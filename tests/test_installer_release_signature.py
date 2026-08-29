"""First-install signature verification must never abort on a MISSING artifact.

Measured 2026-08-08: `SHA256SUMS` is not published -- 404 at both the release
asset URL and raw@tag, for v0.3.49 and v0.3.50.

`install-mac.sh` verified `SHA256SUMS` and called `fail` when the download did
not succeed, while the pubkey defaulted to empty so the block was skipped
entirely. The combination meant that setting
`MESHEMBED_RELEASE_PUBKEY_OVERRIDE` -- the hardening step COUNTERMEASURES.md
tells an operator to take -- did not enable verification. It aborted every macOS
install. The variable being unset was the only reason installs worked.

`install.sh` and `install.ps1` had no verification code at all.

The contract these tests pin:

* the release pubkey is PINNED in all three installers (not defaulted to empty,
  which silently disables the check);
* a MISSING SHA256SUMS warns and continues -- otherwise this turns into a fleet
  outage the day it ships, since the artifact is not published;
* a PRESENT SHA256SUMS with a missing or invalid signature ABORTS -- so the
  moment the release process starts publishing it, enforcement begins with no
  further installer change.

See docs/RELEASE_SIGNING_STATE.md for the required fix order.
"""
from __future__ import annotations

from pathlib import Path

import pytest

AGENT = Path(__file__).resolve().parents[1]
PUBKEY = "110ca603f1b4d850b5a956fbe34a9f4ba21e271afd10cb02baef6cf242236408"
INSTALLERS = ["install.sh", "install-mac.sh", "install.ps1"]


def _read(name: str) -> str:
    return (AGENT / name).read_text(encoding="utf-8")


@pytest.mark.parametrize("name", INSTALLERS)
def test_release_pubkey_is_pinned(name):
    """An empty default silently disables verification -- the macOS bug."""
    body = _read(name)
    assert PUBKEY in body, f"{name} must pin the release public key"


@pytest.mark.parametrize("name", INSTALLERS)
def test_override_is_still_possible(name):
    """Key rotation and testing against a throwaway key both need this."""
    assert "MESHEMBED_RELEASE_PUBKEY_OVERRIDE" in _read(name)


@pytest.mark.parametrize("name", ["install.sh", "install-mac.sh"])
def test_missing_sums_does_not_abort(name):
    """THE regression. A `fail` on the SHA256SUMS download is what bricked macOS
    installs for anyone who followed the documented hardening advice."""
    lines = _read(name).splitlines()
    # Only the SHA256SUMS fetch itself. The NEXT line legitimately aborts when
    # the sums are published but the .sig is not -- checking a multi-line window
    # would flag that correct behaviour.
    fetches = [
        ln for ln in lines
        if "curl" in ln and "SHA256SUMS" in ln and ".sig" not in ln
    ]
    assert fetches, f"{name}: expected a SHA256SUMS fetch"
    for ln in fetches:
        assert "|| fail" not in ln, (
            f"{name}: downloading SHA256SUMS must not `fail` -- it is not "
            f"published, so this aborts every install. Offending line: {ln.strip()}"
        )
        assert ln.lstrip().startswith("if ") or "if " in ln, (
            f"{name}: the fetch must be guarded so a 404 is a branch, not an error"
        )


@pytest.mark.parametrize("name", INSTALLERS)
def test_present_sums_with_missing_sig_aborts(name):
    """Fail-closed once published: having the sums but not the signature is an
    attack shape, not a soft state. install.ps1 joined the other two once it
    grew real verification (before that it only printed 'verification enforced')."""
    body = _read(name)
    assert "SHA256SUMS.sig" in body or "${SUMS_URL}.sig" in body
    assert "refusing to install unverified code" in body, (
        f"{name}: a published SHA256SUMS without its .sig must abort"
    )


@pytest.mark.parametrize("name", INSTALLERS)
def test_invalid_signature_aborts(name):
    assert "release signature verification FAILED" in _read(name), (
        f"{name}: an invalid signature must abort, not warn"
    )


@pytest.mark.parametrize("name", INSTALLERS)
def test_pip_tarball_is_bound_to_the_signed_sums(name):
    """Verifying the SHA256SUMS signature proves only that the LIST is authentic.
    The archive pip installs must ALSO match a hash IN it, or a signature-verified
    installer still fetches an unchecked tarball -- the gap the binding closes.
    All three download it, hash it, compare to its SHA256SUMS entry, and abort on
    a mismatch (install.ps1 was the last to gain this; see commit 58b7eee)."""
    body = _read(name)
    assert "release tarball verified against SHA256SUMS" in body, (
        f"{name}: the pip tarball is not bound to the signed SHA256SUMS"
    )
    assert "release TARBALL sha256 mismatch" in body, (
        f"{name}: a tarball whose hash is not in SHA256SUMS must abort the install"
    )


@pytest.mark.parametrize("name", INSTALLERS)
def test_skip_is_reported_honestly(name):
    """A skipped check that prints nothing is indistinguishable from a passed
    one -- the failure mode this whole line of work keeps finding."""
    body = _read(name)
    assert "SKIPPED" in body, f"{name} must say so when it does not verify"
