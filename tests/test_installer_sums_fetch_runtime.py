"""The SUMS fetch block, actually EXECUTED — not just grepped.

test_installer_release_signature.py pins the source (asset URL present, tried
before the tree URL). That catches deletion, not breakage: a typo in a
variable name, a quoting slip, or an `elif` that never fires all survive a
source grep and then fail on a real operator's first install.

So this runs the block under `bash -euo pipefail` with `curl` stubbed, and
asserts the CONTROL FLOW for the four cases that matter:

  1. asset published        -> asset URL used, tree never tried
  2. asset 404, tree has it -> falls back (pre-asset tags keep working)
  3. both 404               -> loud skip, install CONTINUES (the fleet-wide
                               outage this ordering exists to avoid)
  4. SUMS present, .sig 404 -> ABORT (a published-but-unsigned SUMS is an
                               attack, not a degradation)

Runtime-only concerns; the signature/hash crypto is covered elsewhere.
"""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

NODE_AGENT = Path(__file__).resolve().parents[1]
SHELL_INSTALLERS = ["install.sh", "install-mac.sh"]


# Sliced from the real installers so the test cannot drift from shipped code.
# The markers differ because the two files genuinely differ in shape: in
# install.sh the whole verification lives in ONE top-level `if`, while
# install-mac.sh splits it across TWO consecutive `if [ -n "$RELEASE_PUBKEY_HEX" ]`
# blocks (fetch, then verify). Slicing must land on balanced boundaries, so the
# markers are explicit rather than clever.
_SLICE = {
    "install.sh": (
        "SUMS_ASSET_URL=",
        'rm -rf "$TMPSIG"\nfi\n',
    ),
    "install-mac.sh": (
        'if [ -n "$RELEASE_PUBKEY_HEX" ]; then\n'
        '    info "Verifying release signature for $RELEASE_TAG..."',
        'info "release signature verification SKIPPED (RELEASE_PUBKEY_HEX unset)"\nfi\n',
    ),
}


def _helper(name: str) -> str:
    src = (NODE_AGENT / name).read_text()
    start = src.index('SUMS_REQUIRED_FROM="v0.3.66"')
    return src[start:src.index("\n}\n", start) + 3]


def _extract_block(name: str) -> str:
    src = (NODE_AGENT / name).read_text()
    start_marker, end_marker = _SLICE[name]
    start = src.index(start_marker)
    end = src.index(end_marker, start) + len(end_marker)
    block = src[start:end]
    # A slice that does not balance would fail as a confusing "syntax error"
    # inside the harness; catch it here with a message that names the cause.
    assert block.count("\nfi\n") + block.count("\n    fi\n") > 0, name
    return block


HARNESS = r"""
set -euo pipefail

# --- stubs -------------------------------------------------------------------
ATTEMPTS="$ATTEMPT_LOG"
info() { echo "INFO: $*"; }
ok()   { echo "OK: $*"; }
warn() { echo "WARN: $*"; }
fail() { echo "FAIL: $*"; exit 42; }

# curl stub: logs every URL, serves only those listed in $SERVE (space-sep).
curl() {
    local url="" out="" prev=""
    for a in "$@"; do
        case "$prev" in -o) out="$a" ;; esac
        case "$a" in http*) url="$a" ;; esac
        prev="$a"
    done
    echo "$url" >> "$ATTEMPTS"
    # the release tarball is always there (the hash stub decides whether it "matches")
    case "$url" in *.tar.gz) [ -n "$out" ] && echo tarball > "$out"; return 0 ;; esac
    case " $SERVE " in
        *" $url "*)
            if [ -n "$out" ]; then
                case "$url" in
                    # a SUMS that lists the tarball, with the hash the sha256sum stub returns
                    */SHA256SUMS) echo "deadbeef  ${RELEASE_TAG}.tar.gz" > "$out" ;;
                    */SHA256SUMS-unlisted) echo "0000  something-else.tar.gz" > "$out" ;;
                    *) echo "stub-body-for $url" > "$out" ;;
                esac
            fi
            return 0 ;;
    esac
    return 22   # curl's "HTTP error" exit, as -f gives on a 404
}
# signature + hash verification are covered by their own tests; here they pass
# so the control flow can be observed past them.
python3() { cat > /dev/null 2>&1 || true; echo ok; return 0; }
# install.sh picks its verifier from executable paths (MESHEMBED_DAEMON_PYTHON, the parent
# daemon's interpreter, python3 on PATH), so the stub is also a file for it to find.
FAKEPY="$(mktemp)"
printf '#!/bin/sh\n[ "${1:-}" = "-" ] && cat >/dev/null\necho ok\n' > "$FAKEPY"
chmod +x "$FAKEPY"
MESHEMBED_DAEMON_PYTHON="$FAKEPY"
_parent_python() { :; }
sha256sum() { echo "deadbeef  $1"; }
shasum()    { echo "deadbeef  $1"; }

# --- inputs the block reads --------------------------------------------------
REPO="Clusterhive-io/meshembed-node-agent"
RELEASE_TAG="${HARNESS_TAG:-v9.9.9}"
RELEASE_PUBKEY_HEX="aa"
# install-mac.sh runs the check on PYTHON_BIN (not a bare python3); the stub above serves it
PYTHON_BIN="python3"
PIP_EXTRA=""
PACKAGE_URL="https://github.com/${REPO}/archive/refs/tags/${RELEASE_TAG}.tar.gz"
TMPSIG=$(mktemp -d)
trap 'rm -rf "$TMPSIG"' EXIT
"""

ASSET_SUMS = "https://github.com/Clusterhive-io/meshembed-node-agent/releases/download/v9.9.9/SHA256SUMS"
TREE_SUMS = "https://raw.githubusercontent.com/Clusterhive-io/meshembed-node-agent/refs/tags/v9.9.9/SHA256SUMS"


def _run(name: str, serve: list[str], ota: bool = False, tag: str = "v9.9.9") -> tuple[int, str, list[str]]:
    block = _helper(name) + _extract_block(name)
    serve = [u.replace("v9.9.9", tag) for u in serve]
    with tempfile.TemporaryDirectory() as td:
        log = Path(td) / "attempts"
        log.touch()
        script = Path(td) / "harness.sh"
        script.write_text(HARNESS + "\n" + block + "\n")
        env = {
            **os.environ,
            "SERVE": " ".join(serve),
            "ATTEMPT_LOG": str(log),
            "HARNESS_TAG": tag,
        }
        env.pop("MESHEMBED_PACKAGE_URL", None)
        if ota:   # what worker._perform_self_update sets for the installer
            env["MESHEMBED_PACKAGE_URL"] = "https://github.com/Clusterhive-io/meshembed-node-agent/archive/refs/tags/v9.9.9.tar.gz"
        p = subprocess.run(
            ["bash", str(script)], capture_output=True, text=True, env=env, timeout=60
        )
        return p.returncode, p.stdout + p.stderr, log.read_text().split()


@pytest.mark.parametrize("name", SHELL_INSTALLERS)
def test_published_asset_is_used_and_tree_not_tried(name):
    rc, out, attempts = _run(name, [ASSET_SUMS, ASSET_SUMS + ".sig"])
    assert rc == 0, out
    assert attempts and attempts[0] == ASSET_SUMS, attempts
    assert TREE_SUMS not in attempts, (
        f"{name}: fell through to the tag tree even though the asset served"
    )
    assert f"{ASSET_SUMS}.sig" in attempts, "the .sig must come from the same source"


@pytest.mark.parametrize("name", SHELL_INSTALLERS)
def test_falls_back_to_the_tag_tree_for_pre_asset_tags(name):
    rc, out, attempts = _run(name, [TREE_SUMS, TREE_SUMS + ".sig"])
    assert rc == 0, out
    assert attempts[0] == ASSET_SUMS, "asset must still be tried FIRST"
    assert TREE_SUMS in attempts, "no fallback to the tag tree"
    assert f"{TREE_SUMS}.sig" in attempts, (
        f"{name}: fetched SUMS from the tree but the .sig from somewhere else"
    )


@pytest.mark.parametrize("name", SHELL_INSTALLERS)
def test_both_missing_aborts_for_a_tag_that_publishes_sums(name):
    """From v0.3.66 every release publishes a signed SHA256SUMS: none at all means attack
    or outage, never 'install unverified' (auditor 2026-10-04, reachable on self-updates)."""
    rc, out, attempts = _run(name, [])
    assert rc == 42, f"{name}: a missing SHA256SUMS did not abort\n{out}"
    assert "refusing to install unverified code" in out
    assert ASSET_SUMS in attempts and TREE_SUMS in attempts, attempts


@pytest.mark.parametrize("name", SHELL_INSTALLERS)
def test_both_missing_still_skips_for_an_explicitly_older_tag(name):
    rc, out, attempts = _run(name, [], tag="v0.3.65")
    assert rc == 0, f"{name}: a pre-v0.3.66 tag without SHA256SUMS aborted\n{out}"
    assert "SKIPPED" in out, out


def test_unlisted_tarball_aborts_for_a_new_tag():
    """install.sh binds the tarball inside this block: a SUMS that does not list it aborts."""
    unlisted = ASSET_SUMS + "-unlisted"
    block = _helper("install.sh") + _extract_block("install.sh").replace(
        'SUMS_ASSET_URL="https://github.com/${REPO}/releases/download/${RELEASE_TAG}/SHA256SUMS"',
        'SUMS_ASSET_URL="https://github.com/${REPO}/releases/download/${RELEASE_TAG}/SHA256SUMS-unlisted"')
    for tag, want_rc in (("v9.9.9", 42), ("v0.3.65", 0)):
        with tempfile.TemporaryDirectory() as td:
            log = Path(td) / "attempts"; log.touch()
            script = Path(td) / "harness.sh"
            script.write_text(HARNESS + "\n" + block + "\n")
            serve = [u.replace("v9.9.9", tag) for u in (unlisted, unlisted + ".sig")]
            env = {**os.environ, "SERVE": " ".join(serve), "ATTEMPT_LOG": str(log), "HARNESS_TAG": tag}
            p = subprocess.run(["bash", str(script)], capture_output=True, text=True, env=env, timeout=60)
            assert p.returncode == want_rc, (tag, p.stdout + p.stderr)
            if want_rc:
                assert "does not list" in p.stdout and "refusing to install unverified code" in p.stdout


@pytest.mark.parametrize("name", SHELL_INSTALLERS)
def test_published_sums_with_missing_signature_aborts(name):
    """Published-but-unsigned is tampering, not a degradation."""
    rc, out, _ = _run(name, [ASSET_SUMS])  # SUMS serves, .sig 404s
    assert rc == 42, f"{name}: an unsigned SHA256SUMS did not abort\n{out}"
    assert "refusing to install unverified code" in out



@pytest.mark.parametrize("name", SHELL_INSTALLERS)
def test_a_self_update_verifies_the_signed_sums_too(name):
    """Auditor 2026-10-04: install.sh skipped this block during a self-update, so the code a
    node updated itself to was never bound to the signed SHA256SUMS. It runs now."""
    rc, out, attempts = _run(name, [ASSET_SUMS, ASSET_SUMS + ".sig"], ota=True)
    assert rc == 0, out
    assert attempts and attempts[0] == ASSET_SUMS, attempts
