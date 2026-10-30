#!/bin/bash
# MeshEmbed Node - macOS installer (Apple Silicon and Intel)
set -euo pipefail

# The operator dashboard pipes `curl ... | INVITE='token' BACKEND='url' bash`
# so honor those env vars first; fall back to positional $1 + the
# MESHEMBED_* env vars that older docs reference.
BACKEND_URL="${BACKEND:-${MESHEMBED_BACKEND:-https://meshembed.clusterhive.io}}"

# --- Production guard rail (ROGUE_LAB ISSUE A) ------------------------------
# BACKEND defaults to production when unset, which is correct for the
# documented operator one-liner but dangerous for test/lab installs: a
# forgotten BACKEND silently enrolls the box onto PRODUCTION. Test harnesses
# export MESHEMBED_REFUSE_PROD=1 once, and any install that would land on prod
# then aborts instead of quietly succeeding.
case "$BACKEND_URL" in
    *meshembed.clusterhive.io*)
        case "$BACKEND_URL" in
            *sandbox*) IS_PROD_BACKEND=0 ;;
            *)         IS_PROD_BACKEND=1 ;;
        esac ;;
    *) IS_PROD_BACKEND=0 ;;
esac
if [ "${MESHEMBED_REFUSE_PROD:-0}" = "1" ] && [ "$IS_PROD_BACKEND" = "1" ]; then
    echo "REFUSING TO INSTALL: backend resolves to PRODUCTION ($BACKEND_URL)" >&2
    echo "  MESHEMBED_REFUSE_PROD=1 is set, so this looks like a test install." >&2
    echo "  Set BACKEND explicitly, e.g." >&2
    echo "    BACKEND='https://sandbox-meshembed.clusterhive.io'" >&2
    exit 2
fi

INVITE_TOKEN="${1:-${INVITE:-${MESHEMBED_INVITE:-}}}"
NODE_ID="${MESHEMBED_NODE_ID:-}"
PLIST="$HOME/Library/LaunchAgents/io.clusterhive.meshembed-node.plist"

# ── colors ───────────────────────────────────────────────────────────────────
bold=$(tput bold 2>/dev/null || true)
reset=$(tput sgr0 2>/dev/null || true)
green='\033[0;32m'; red='\033[0;31m'; nc='\033[0m'

info()  { echo "${bold}[meshembed]${reset} $*"; }
ok()    { echo -e "${green}✓${nc} $*"; }
fail()  { echo -e "${red}✗${nc} $*"; exit 1; }
# ── The REAL pause (DESIGN_H1 blocker 0.1; auditor P-a..P-c) ── an admin marker the daemon honours; P-b: this
# installer never removes or rewrites it, and while it exists it never bootstraps (starts) the node.
PAUSE_MARKER="/Library/Application Support/MeshEmbed/paused"
node_paused() { [ -e "$PAUSE_MARKER" ] || [ -L "$PAUSE_MARKER" ]; }
install_pause_tool() {
    sudo -n true 2>/dev/null || { info "pause tool not installed (needs sudo): re-run with sudo available to get meshembed-node-pause"; return 0; }
    sudo -n mkdir -p /usr/local/sbin
    sudo -n tee /usr/local/sbin/meshembed-node-pause >/dev/null << 'PAUSE'
#!/bin/sh
# MeshEmbed node (macOS): the REAL pause (DESIGN_H1 blocker 0.1). Run with sudo.
#   meshembed-node-pause pause <code> | resume | status
set -eu
M="/Library/Application Support/MeshEmbed/paused"
L=io.clusterhive.meshembed-node
[ "$(id -u)" -eq 0 ] || { echo "refused: run with sudo"; exit 2; }
U="${SUDO_UID:-}"; [ -n "$U" ] || { echo "refused: run with sudo from the node user's account"; exit 2; }
P="$(dscl . -read "/Users/$(id -un "$U")" NFSHomeDirectory 2>/dev/null | awk '{print $2}')/Library/LaunchAgents/$L.plist"
case "${1:-status}" in
  pause)
    code="${2:-}"
    printf '%s' "$code" | grep -qE '^[a-z_]{1,40}$' || { echo "usage: meshembed-node-pause pause <code: a-z and _>"; exit 2; }
    mkdir -p "/Library/Application Support/MeshEmbed"; chown root:wheel "/Library/Application Support/MeshEmbed"
    chmod 0755 "/Library/Application Support/MeshEmbed"
    umask 022; printf 'code=%s\nat=%s\n' "$code" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$M.tmp"
    chown root:wheel "$M.tmp"; chmod 0644 "$M.tmp"; mv -f "$M.tmp" "$M"
    launchctl bootout "gui/$U/$L" >/dev/null 2>&1 || true
    i=0; while pgrep -u "$U" -f meshembed_node >/dev/null && [ "$i" -lt 60 ]; do sleep 1; i=$((i+1)); done
    if pgrep -u "$U" -f meshembed_node >/dev/null; then echo "pause_incomplete (marker set, a node process remains)"; exit 1; fi
    echo paused ;;
  resume)
    rm -f "$M"
    launchctl bootstrap "gui/$U" "$P" 2>/dev/null && echo running || { echo "resume_failed"; exit 1; } ;;
  status)
    if [ -e "$M" ] || [ -L "$M" ]; then
      if [ "$(stat -f %u "$M" 2>/dev/null || echo x)" = 0 ] && [ ! -L "$M" ]; then echo paused; else echo "paused (marker NOT admin-owned)"; fi
    elif pgrep -u "$U" -f meshembed_node >/dev/null; then echo running; else echo stopped; fi ;;
  *) echo "usage: meshembed-node-pause pause <code> | resume | status"; exit 2 ;;
esac
PAUSE
    sudo -n chown root:wheel /usr/local/sbin/meshembed-node-pause; sudo -n chmod 0755 /usr/local/sbin/meshembed-node-pause
}
# AR1 phase 0: the agent host is Linux only (DESIGN_AR1 section 12); a designation here is refused, the node installs
if [ "${MESHEMBED_AGENT_HOST:-0}" = "1" ]; then info "agent host: Linux only in phase 0 (agent_host_linux_only); installing the node without it"; fi
if [ "${MESHEMBED_ENABLE_SERVE:-0}" = "1" ]; then info "serve: Linux root installs only (serve_linux_only); installing the node without it"; fi

# ── requirements ─────────────────────────────────────────────────────────────
info "Checking requirements..."
command -v python3 >/dev/null || fail "python3 not found. Install Python 3.10+ from https://python.org"

# Resolve to a *real* python interpreter, not the Apple stub that opens
# the Command Line Tools installer dialog. The stub lives at
# /usr/bin/python3 and exits with code 0 even when the CLT aren't
# actually installed (it just shows a GUI). We detect the stub by
# running a trivial import; if it succeeds we're real.
ARCH=$(uname -m)

# Build the candidate list. On Intel macOS we MUST avoid Python 3.13
# because PyTorch doesn't ship Intel-mac 3.13 wheels yet -- the pip
# resolver bails with "ResolutionImpossible". Prefer the versioned
# Homebrew binaries before falling back to the bare python3.
if [ "$ARCH" = "arm64" ]; then
    # Apple Silicon: any 3.10+ works.
    CANDIDATES=(
        /opt/homebrew/bin/python3.12
        /opt/homebrew/bin/python3.11
        /opt/homebrew/bin/python3.13
        /opt/homebrew/bin/python3
        /usr/local/bin/python3
        "$(command -v python3 2>/dev/null)"
    )
    REQUIRED_HINT="3.10+"
else
    # Intel: pin to 3.11/3.12. 3.13 has no torch wheel on Intel mac.
    CANDIDATES=(
        /usr/local/bin/python3.12
        /usr/local/bin/python3.11
        /opt/homebrew/bin/python3.12
        /opt/homebrew/bin/python3.11
        /opt/local/bin/python3.12
        /opt/local/bin/python3.11
    )
    REQUIRED_HINT="3.11 or 3.12 (3.13 has no PyTorch wheel for Intel Mac yet)"
fi

# A self-update passes the daemon's OWN interpreter (MESHEMBED_DAEMON_PYTHON, set by
# worker._perform_self_update): install into -- and verify with -- the Python that
# actually runs the node, or pip upgrades another interpreter and the daemon stays on the
# old version (auditor 2026-10-04). It still has to pass the checks below.
#
# Daemons before vN do not pass it (operator 2026-10-04: updates need zero user steps), so
# during a self-update find the daemon's interpreter here: the LaunchAgent's program, or
# the process that launched this script (worker._perform_self_update runs `bash
# <installer>`). A candidate counts only if it imports meshembed_node -- i.e. it IS the
# node's Python -- so a stray interpreter is never picked over the list below.
_node_python() {
    local c="$1" d
    [ -n "$c" ] || return 0
    case "$c" in /*) ;; *) return 0 ;; esac
    # a console script (…/bin/meshembed-node) -> the python next to it
    case "${c##*/}" in
        python*) ;;
        *) d="${c%/*}"; for c in "$d/python3" "$d/python"; do [ -x "$c" ] && break; done ;;
    esac
    [ -x "$c" ] && "$c" -c 'import meshembed_node' >/dev/null 2>&1 && printf '%s' "$c"
    return 0
}
DAEMON_PY_FOUND=""
if [ -z "${MESHEMBED_DAEMON_PYTHON:-}" ] && [ -n "${MESHEMBED_PACKAGE_URL:-}" ]; then
    if [ -f "$PLIST" ]; then
        DAEMON_PY_FOUND=$(_node_python "$(/usr/libexec/PlistBuddy -c "Print :ProgramArguments:0" "$PLIST" 2>/dev/null || true)")
    fi
    if [ -z "$DAEMON_PY_FOUND" ]; then
        DAEMON_PY_FOUND=$(_node_python "$(ps -o command= -p "$PPID" 2>/dev/null | awk '{print $1}')")
    fi
    [ -n "$DAEMON_PY_FOUND" ] && info "Self-update: the daemon runs $DAEMON_PY_FOUND"
fi
CANDIDATES=("${MESHEMBED_DAEMON_PYTHON:-}" "$DAEMON_PY_FOUND" "${CANDIDATES[@]}")

PYTHON_BIN=""
for cand in "${CANDIDATES[@]}"; do
    [ -z "$cand" ] && continue
    [ -x "$cand" ] || continue
    "$cand" -c 'import ssl, json, sys' >/dev/null 2>&1 || continue
    pyver=$("$cand" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    # Intel: reject 3.13+ explicitly.
    if [ "$ARCH" != "arm64" ] && [ "$pyver" = "3.13" -o "$pyver" = "3.14" ]; then
        continue
    fi
    PYTHON_BIN="$cand"
    break
done

if [ -z "$PYTHON_BIN" ]; then
    if [ "$ARCH" != "arm64" ]; then
        fail "no compatible Python found on this Intel Mac. PyTorch doesn't ship Python 3.13 wheels for Intel macOS; install Python 3.12: brew install python@3.12"
    else
        fail "no compatible Python found. Install Python ${REQUIRED_HINT} via Homebrew: brew install python@3.12"
    fi
fi
PY_MINOR=$("$PYTHON_BIN" -c 'import sys; print(sys.version_info.minor)')
[ "$PY_MINOR" -ge 10 ] || fail "Python ${REQUIRED_HINT} required at $PYTHON_BIN. Found: 3.$PY_MINOR"
ok "Python $($PYTHON_BIN --version) at $PYTHON_BIN"

if [ "$ARCH" = "arm64" ]; then
    ok "Apple Silicon detected - MPS acceleration will be used"
else
    ok "Intel Mac detected - CPU mode will be used"
fi

# ── upgrade-vs-fresh-install detection ───────────────────────────────────────
# When the daemon's auto-update channel fires, _perform_self_update execs
# this script with the daemon's env (which has MESHEMBED_NODE_API_KEY +
# MESHEMBED_NODE_ID) but no INVITE token. Detect that case and short-
# circuit to "pip install --upgrade then exit"; skip the invite prompt,
# the register call, the .env write, and the LaunchAgent reinstall (all
# already in place from the original enrollment).
EXISTING_ENV="$HOME/.meshembed/.env"
UPGRADE_ONLY=0
if [ -f "$EXISTING_ENV" ] && grep -q '^MESHEMBED_NODE_API_KEY=' "$EXISTING_ENV"; then
    UPGRADE_ONLY=1
elif [ -n "${MESHEMBED_NODE_API_KEY:-}" ] && [ -n "${MESHEMBED_NODE_ID:-}" ]; then
    UPGRADE_ONLY=1
fi

# ── invite token ─────────────────────────────────────────────────────────────
if [ "$UPGRADE_ONLY" -eq 1 ]; then
    info "Existing enrollment detected -- running in UPGRADE-ONLY mode (no re-register)."
elif [ -z "$INVITE_TOKEN" ]; then
    if [ -t 0 ]; then
        echo ""
        read -rp "Invite token (get one from the operator dashboard): " INVITE_TOKEN
    else
        # Piped from curl with no TTY: prompting silently hangs. Bail
        # with a clear message instead.
        fail "Invite token required. Use: curl ... | INVITE='your_token' bash    or pass it as arg 1."
    fi
fi
if [ "$UPGRADE_ONLY" -ne 1 ]; then
    [ -n "$INVITE_TOKEN" ] || fail "Invite token required"
fi

# ── Verify release signature (binary signing, 2026-05-22) ────────────────────
# Same protocol as install.sh; see that file for the rationale.
# Pinned release public key. Its private half signs releases; only the PUBLIC
# half is ever distributed. Overridable for key rotation and for testing against
# a throwaway key.
# Pinned release keys, space-separated (H6 rotation 2026-10-05: a138d7d0cf3d361a = old, f36c830ffd678cf4 = new).
# The release keys (auditor 2026-10-23 18:39Z): MESHEMBED_RELEASE_PUBKEY_OVERRIDE is a TEST hook, honoured ONLY under
# MESHEMBED_INSTALLER_TEST_MODE=1 (the e2e harnesses); on a real install it is ignored (K-2: no trust-root hook in the
# default path).
if [ "${MESHEMBED_INSTALLER_TEST_MODE:-}" = 1 ] && [ -n "${MESHEMBED_RELEASE_PUBKEY_OVERRIDE:-}" ]; then
    RELEASE_PUBKEY_HEX="$MESHEMBED_RELEASE_PUBKEY_OVERRIDE"
    echo "[meshembed] TEST MODE: release key override in use (never on a real install)" >&2
else
    [ -z "${MESHEMBED_RELEASE_PUBKEY_OVERRIDE:-}" ] \
        || echo "[meshembed] MESHEMBED_RELEASE_PUBKEY_OVERRIDE ignored (honoured only with MESHEMBED_INSTALLER_TEST_MODE=1)" >&2
    RELEASE_PUBKEY_HEX="110ca603f1b4d850b5a956fbe34a9f4ba21e271afd10cb02baef6cf242236408 6c25a6c5349bf71046b575e75fabaa220ab3e67a0706963896093b0eef11b248"
fi
# Fallback only for a bare `curl | bash`; OTA passes MESHEMBED_RELEASE_TAG.
# A stale literal here silently broke self-update (see install.sh).
RELEASE_TAG="${MESHEMBED_RELEASE_TAG:-v0.3.80rc1}"
REPO="Clusterhive-io/meshembed-node-agent"

# PEP 668 (moved above the signature check, which now pip-installs into PYTHON_BIN too): Homebrew Python (and python.org Python via brew) now ships
# with an EXTERNALLY-MANAGED marker on newer macOS that blocks pip
# outside a venv. Detect that and add --break-system-packages.
PYTHON_LIB=$("$PYTHON_BIN" -c 'import sysconfig; print(sysconfig.get_paths()["stdlib"])' 2>/dev/null || true)
PIP_EXTRA=""
if [ -n "$PYTHON_LIB" ] && [ -f "$PYTHON_LIB/EXTERNALLY-MANAGED" ]; then
    info "  (PEP 668 EXTERNALLY-MANAGED Python detected -- using --break-system-packages)"
    PIP_EXTRA="--break-system-packages"
fi

# Releases from v0.3.66 on publish a signed SHA256SUMS that lists the tarball. For those, a
# missing SHA256SUMS or an unlisted tarball is an attack or an outage -- never a reason to
# install unverified code (auditor 2026-10-04: reachable on every self-update since the
# block runs there too). Only an explicitly older MESHEMBED_RELEASE_TAG keeps the old
# warn-and-continue behaviour. An unparseable tag counts as new (fails closed).
SUMS_REQUIRED_FROM="v0.3.66"
_tag_at_least() {  # _tag_at_least vA.B.C vX.Y.Z -> true when A.B.C >= X.Y.Z
    local IFS=. i p q
    local -a x y
    x=(${1#v}); y=(${2#v})
    for i in 0 1 2; do
        p="${x[$i]:-0}"; q="${y[$i]:-0}"
        case "$p$q" in ''|*[!0-9]*) return 0 ;; esac
        if [ "$((10#$p))" -gt "$((10#$q))" ]; then return 0; fi
        if [ "$((10#$p))" -lt "$((10#$q))" ]; then return 1; fi
    done
    return 0
}

if [ -n "$RELEASE_PUBKEY_HEX" ]; then
    info "Verifying release signature for $RELEASE_TAG..."
    TMPSIG=$(mktemp -d)
    trap 'rm -rf "$TMPSIG"' EXIT
    # Measured 2026-08-08: SHA256SUMS is NOT published (404 at both the release
    # asset URL and raw@tag, for v0.3.49 and v0.3.50). This block used to `fail`
    # on that download, and the pubkey above used to default to empty -- so
    # setting MESHEMBED_RELEASE_PUBKEY_OVERRIDE, the documented hardening step,
    # aborted every macOS install instead of enabling verification. The variable
    # being unset was the only reason installs worked.
    #
    # Fail-closed ONCE PUBLISHED: a missing SHA256SUMS warns, a present-but-bad
    # one still aborts. When the release process starts publishing it, every
    # installer begins enforcing with no further installer change.
    #
    # Residual weakness, stated plainly: someone who can suppress SHA256SUMS
    # downgrades this to a warning. Publishing it is the prerequisite, not an
    # alternative. See docs/RELEASE_SIGNING_STATE.md.
    # SHA256SUMS lives in the tag's RELEASE ASSETS (attached after tagging --
    # a file in the tag's tree would change the very tarball bytes it hashes,
    # the circularity that kept it unpublished; docs/RELEASE_SIGNING_STATE.md).
    # Asset mutability doesn't matter: trust is the ed25519 signature over the
    # SUMS, never the URL. Tag-tree URL kept as fallback for pre-asset tags.
    SUMS_ASSET_URL="https://github.com/${REPO}/releases/download/${RELEASE_TAG}/SHA256SUMS"
    SUMS_URL="https://raw.githubusercontent.com/${REPO}/refs/tags/${RELEASE_TAG}/SHA256SUMS"
    _SUMS_SRC=""
    if curl -fsSL "$SUMS_ASSET_URL" -o "$TMPSIG/SHA256SUMS" 2>/dev/null; then
        _SUMS_SRC="$SUMS_ASSET_URL"
    elif curl -fsSL "$SUMS_URL" -o "$TMPSIG/SHA256SUMS" 2>/dev/null; then
        _SUMS_SRC="$SUMS_URL"
    elif _tag_at_least "$RELEASE_TAG" "$SUMS_REQUIRED_FROM"; then
        fail "SHA256SUMS for ${RELEASE_TAG} could not be fetched -- refusing to install unverified code"
    else
        info "release signature verification SKIPPED: no SHA256SUMS for ${RELEASE_TAG} (pre-${SUMS_REQUIRED_FROM} tag)"
        RELEASE_PUBKEY_HEX=""
    fi
fi
if [ -n "$RELEASE_PUBKEY_HEX" ]; then
    curl -fsSL "${_SUMS_SRC}.sig" -o "$TMPSIG/SHA256SUMS.sig" \
        || fail "SHA256SUMS is published but SHA256SUMS.sig is missing -- refusing to install unverified code"
    # The check runs on PYTHON_BIN, the interpreter this install targets -- not a bare
    # `python3`. On an Intel Mac the first python3 on PATH is often another one (Homebrew's
    # default, a uv Python) without `cryptography`: the import failed, the check "FAILED",
    # and every self-update of N-118037 (Mac mini 2014) aborted for days after signed
    # SHA256SUMS started being published (v0.3.66). Make sure the module is there first.
    if ! "$PYTHON_BIN" -c 'import cryptography' >/dev/null 2>&1; then
        info "  installing 'cryptography' into $PYTHON_BIN for the signature check..."
        # Wheels only (no sdist build running before anything is verified) and a bounded
        # range (auditor 2026-10-04).
        "$PYTHON_BIN" -m pip install --quiet $PIP_EXTRA --only-binary=:all: "cryptography>=42,<47" \
            || fail "cannot install 'cryptography' into $PYTHON_BIN -- refusing to install unverified code"
    fi
    "$PYTHON_BIN" - "$TMPSIG/SHA256SUMS" "$TMPSIG/SHA256SUMS.sig" "$RELEASE_PUBKEY_HEX" <<'PYEOF' || fail "release signature verification FAILED -- aborting install"
import sys, hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
sums, sig, pub_hex = sys.argv[1], sys.argv[2], sys.argv[3]
# SHA256SUMS.sig is the line sign-release.py writes (meshembed_node.release_verify):
# "meshembed-relsig-v1 <key_id> <signature hex>", key_id = sha256(pubkey)[:16]. Reading
# the file as a raw signature could never verify (found 2026-10-04: every installer check
# of a published SHA256SUMS failed since v0.3.66).
# Several pinned keys (H6 rotation, 2026-10-05): space- or comma-separated hex; the
# line's key_id picks which one must verify. An unknown key_id is refused.
pubs = [bytes.fromhex(h) for h in pub_hex.replace(",", " ").split()]
parts = open(sig).read().split()
match = [p for p in pubs if len(parts) == 3 and parts[1] == hashlib.sha256(p).hexdigest()[:16]]
if len(parts) != 3 or parts[0] != "meshembed-relsig-v1" or not match:
    print("INVALID: not a meshembed-relsig-v1 line for a pinned key", file=sys.stderr); sys.exit(1)
pub_raw = match[0]
try:
    Ed25519PublicKey.from_public_bytes(pub_raw).verify(bytes.fromhex(parts[2]), open(sums, "rb").read())
    print("ok")
except (InvalidSignature, ValueError):
    print("INVALID", file=sys.stderr); sys.exit(1)
PYEOF
    ok "release signature valid"
else
    info "release signature verification SKIPPED (RELEASE_PUBKEY_HEX unset)"
fi

# ── install package ──────────────────────────────────────────────────────────
info "Installing meshembed-node..."
info "  Downloads PyTorch (~600 MB on Apple Silicon, ~800 MB on Intel),"
info "  sentence-transformers and a few small deps. First-time install"
info "  takes 2-5 minutes; pip prints progress."
PACKAGE_URL="${MESHEMBED_PACKAGE_URL:-https://github.com/${REPO}/archive/refs/tags/${RELEASE_TAG}.tar.gz}"

# Bind the pip TARBALL to the verified SHA256SUMS (parity with install.sh): the
# SUMS signature only authenticates the LIST; the artifact we install must match
# a hash in it, or a signature-verified installer still pulls an unchecked
# archive. Active only when SHA256SUMS was published + verified above
# (TMPSIG/SHA256SUMS present) -- on a self-update too: the 31f7e6d fix missed this
# condition, so a Mac self-update still installed GitHub's archive unbound (found
# 2026-10-04 while proving zero-step updates). macOS ships `shasum`, not `sha256sum`.
_BOUND_TAR=0
if [ -f "${TMPSIG:-/nonexistent}/SHA256SUMS" ]; then
    _TARBALL_NAME="${RELEASE_TAG}.tar.gz"
    _WANT_SHA=$(awk -v f="$_TARBALL_NAME" '$2==f {print $1}' "$TMPSIG/SHA256SUMS" | head -1)
    if [ -n "$_WANT_SHA" ]; then
        _VTMP=$(mktemp -d)
        # Prefer the frozen release-asset tarball over GitHub's on-demand
        # archive (regenerable bytes would make this hash check an outage);
        # fall back for tags without the asset. Parity with install.sh.
        _TARBALL_ASSET_URL="https://github.com/${REPO}/releases/download/${RELEASE_TAG}/${_TARBALL_NAME}"
        curl -fsSL "$_TARBALL_ASSET_URL" -o "$_VTMP/$_TARBALL_NAME" 2>/dev/null \
            || curl -fsSL "$PACKAGE_URL" -o "$_VTMP/$_TARBALL_NAME" \
            || fail "could not download the release tarball to verify it"
        _GOT_SHA=$(shasum -a 256 "$_VTMP/$_TARBALL_NAME" | awk '{print $1}')
        [ "$_GOT_SHA" = "$_WANT_SHA" ] \
            || fail "release TARBALL sha256 mismatch -- refusing to install tampered code (expected $_WANT_SHA, got $_GOT_SHA)"
        ok "release tarball verified against SHA256SUMS"
        PACKAGE_URL="file://$_VTMP/$_TARBALL_NAME"
        _BOUND_TAR=1
    elif _tag_at_least "$RELEASE_TAG" "$SUMS_REQUIRED_FROM"; then
        fail "SHA256SUMS for ${RELEASE_TAG} does not list ${_TARBALL_NAME} -- refusing to install unverified code"
    else
        info "SHA256SUMS does not list ${_TARBALL_NAME}; tarball hash NOT verified (pre-${SUMS_REQUIRED_FROM} tag)"
    fi
fi

# Always maintainable (docs/DESIGN_NODE_MAINTENANCE_2026-10-14.md): pip must work in the
# node's interpreter -- it is this installer's tool and maintenance's fallback.
if ! "$PYTHON_BIN" -m pip --version >/dev/null 2>&1; then
    "$PYTHON_BIN" -m ensurepip --upgrade >/dev/null 2>&1 && ok "pip seeded into $PYTHON_BIN" \
        || echo "  ! could not seed pip into $PYTHON_BIN (no ensurepip)"
fi

# No --quiet: we want pip's per-package progress so the user sees activity.
# --prefer-binary: never trade an available wheel for an sdist build (no compiler toolchain on
# most Macs; cryptography >= 49 has no Intel-Mac wheel -- pinned in pyproject, this is the backstop).
"$PYTHON_BIN" -m pip install --upgrade --prefer-binary --progress-bar on $PIP_EXTRA "meshembed-node @ ${PACKAGE_URL}"

# CPU-feature guard (docs/DESIGN_CPU_FEATURE_GUARD_2026-10-14.md): the x86 runtime needs
# AVX2/FMA/F16C (Intel Macs before 2013 lack them; Apple Silicon is unaffected). Without
# them its import dies with an illegal instruction and takes embeddings down too.
LLM_SKIPPED=""
_LLM_IDX=""
if [ "$(uname -m)" = "x86_64" ]; then
    _cpuf=" $(sysctl -n machdep.cpu.features machdep.cpu.leaf7_features 2>/dev/null | tr '[:upper:]\n' '[:lower:] ') "
    _miss=""
    if [ "$_cpuf" != "  " ]; then
        for _x in avx2 fma f16c; do case "$_cpuf" in *" $_x "*) ;; *) _miss="$_miss $_x" ;; esac; done
    fi
    if [ -n "$_miss" ]; then
        LLM_SKIPPED="cpu_unsupported:$(echo $_miss | tr ' ' ',')"
        [ "${MESHEMBED_ENABLE_LLM:-0}" = "1" ] && echo "  ! This CPU lacks${_miss} -- it cannot run the inference runtime. Embeddings only."
        MESHEMBED_ENABLE_LLM=0
        if "$PYTHON_BIN" -c "import importlib.util,sys; sys.exit(0 if importlib.util.find_spec('llama_cpp') else 1)" 2>/dev/null; then
            "$PYTHON_BIN" -m pip uninstall -y $PIP_EXTRA llama-cpp-python >/dev/null 2>&1 \
                && ok "removed the inference runtime: this CPU cannot run it" \
                || echo "  ! could not remove llama-cpp-python"
        fi
        _nenv="$HOME/.meshembed/.env"
        [ -f "$_nenv" ] && grep -q '^MESHEMBED_ENABLE_LLM=' "$_nenv" \
            && sed -i '' 's/^MESHEMBED_ENABLE_LLM=.*/MESHEMBED_ENABLE_LLM=0/' "$_nenv" 2>/dev/null || true
    fi
fi

# Optional batch-inference runtime, OFF unless the operator asks for it. A
# Python wheel is executable code, unlike model weights, which are data pinned
# by SHA-256 -- so this is the operator's decision, taken in the signed
# installer, not something the daemon does at runtime. A node without it
# advertises no LLM models and is never routed generation.
# Prebuilt py3-none wheels live on the project's own index, not PyPI.
# Pinned: the fleet's LLM canaries carry answers generated on this exact
# runtime version (docs/LLM_DETERMINISM.md). A node on a different point
# release could produce a different token and be scored for it.
# Intel Macs: llama-cpp-python 0.3.35 publishes no x86_64 macOS wheel, so we build our own
# (scripts/rc/mac_build_llama_x86_64.sh: pinned sdist, portable AVX2/FMA/F16C, reproducible) and ship it
# as an asset of this release, listed in the operator-signed SHA256SUMS. It is installed ONLY when its
# bytes match BOTH the pin below and the signed SUMS entry -- never a bare pip fetch.
# EMPTY pin = inert: until the auditor's per-build GO on the binary, Intel Macs stay embeddings-only.
INTEL_MAC_LLAMA_WHEEL="llama_cpp_python-0.3.35-py3-none-macosx_11_0_x86_64.whl"
INTEL_MAC_LLAMA_SHA="${MESHEMBED_TEST_INTEL_MAC_LLAMA_SHA:-}"
_intel_mac_runtime() {   # 0 = our wheel installed and verified; 1 = not used (caller falls back)
  [ "$(uname -m)" = "x86_64" ] && [ -n "$INTEL_MAC_LLAMA_SHA" ] || return 1
  [ -f "${TMPSIG:-/nonexistent}/SHA256SUMS" ] || { echo "  ! no verified SHA256SUMS -- not using the Intel-Mac runtime wheel"; return 1; }
  local _want _dir
  _want=$(awk -v f="$INTEL_MAC_LLAMA_WHEEL" '$2==f {print $1}' "$TMPSIG/SHA256SUMS" | head -1)
  [ -n "$_want" ] && [ "$_want" = "$INTEL_MAC_LLAMA_SHA" ] \
      || { echo "  ! the signed SHA256SUMS does not list the pinned Intel-Mac runtime wheel -- not used"; return 1; }
  _dir=$(mktemp -d)
  curl -fsSL -o "$_dir/$INTEL_MAC_LLAMA_WHEEL" "https://github.com/${REPO}/releases/download/${RELEASE_TAG}/${INTEL_MAC_LLAMA_WHEEL}" \
      || { rm -rf "$_dir"; echo "  ! Intel-Mac runtime wheel download failed"; return 1; }
  if [ "$(shasum -a 256 "$_dir/$INTEL_MAC_LLAMA_WHEEL" | cut -d' ' -f1)" != "$INTEL_MAC_LLAMA_SHA" ]; then
    rm -rf "$_dir"; echo "  ! Intel-Mac runtime wheel sha mismatch -- refusing it (embeddings only)"; return 1
  fi
  "$PYTHON_BIN" -m pip install --prefer-binary $PIP_EXTRA "$_dir/$INTEL_MAC_LLAMA_WHEEL" "jinja2>=3.1.6" \
      || { rm -rf "$_dir"; echo "  ! Intel-Mac runtime wheel install failed"; return 1; }
  rm -rf "$_dir"
  ok "inference runtime: our verified Intel-Mac build of llama-cpp-python 0.3.35"
  return 0
}

if [ "${MESHEMBED_ENABLE_LLM:-0}" = "1" ] && _intel_mac_runtime; then
  _LLM_IDX="cpu-x86_64-self"
elif [ "${MESHEMBED_ENABLE_LLM:-0}" = "1" ]; then
  echo "  Installing the batch-inference runtime (operator opted in)."
  # Apple Silicon gets the Metal build (GPU offload); Intel Macs the CPU one.
  # MESHEMBED_LLM_BACKEND=cpu forces CPU. Falls back to CPU if Metal fails.
  _LLM_IDX="cpu"
  if [ "${MESHEMBED_LLM_BACKEND:-auto}" != "cpu" ] && [ "$(uname -m)" = "arm64" ]; then _LLM_IDX="metal"; fi
  echo "  Installing the batch-inference runtime: ${_LLM_IDX} build."
  if ! "$PYTHON_BIN" -m pip install --only-binary :all: \
    --extra-index-url "https://abetlen.github.io/llama-cpp-python/whl/${_LLM_IDX}" "llama-cpp-python==0.3.35" "jinja2>=3.1.6"; then
    if [ "$_LLM_IDX" != "cpu" ]; then
      echo "  ! ${_LLM_IDX} runtime install failed -- falling back to the CPU build."
      "$PYTHON_BIN" -m pip install --only-binary :all: \
        --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/cpu "llama-cpp-python==0.3.35" "jinja2>=3.1.6" \
        || echo "  ! llama-cpp-python install failed -- this node will serve embeddings only."
    else
      echo "  ! llama-cpp-python install failed -- this node will serve embeddings only."
    fi
  fi
  # The manifest says WHY there is no runtime (Intel Macs: llama-cpp-python 0.3.35 publishes no
  # x86_64 macOS wheel -- Mac side-by-side run 2026-10-15).
  if ! "$PYTHON_BIN" -c "import importlib.util,sys; sys.exit(0 if importlib.util.find_spec('llama_cpp') else 1)" 2>/dev/null; then
    LLM_SKIPPED="runtime_install_failed:no_wheel_for_$(uname -m)_macos"
    _LLM_IDX=""
  fi
fi
ok "meshembed-node installed"

# Install manifest (docs/DESIGN_NODE_MAINTENANCE_2026-10-14.md): where this node's Python
# and pip are and what was installed; read by `meshembed-node maintenance`. No secrets.
write_install_manifest() {   # <kind>
    mkdir -p "$HOME/.meshembed"
    "$PYTHON_BIN" -I -m meshembed_node.install_manifest --dir "$HOME/.meshembed" --kind "$1" \
        --tag "$RELEASE_TAG" --base existing --llm-build "${_LLM_IDX:-}" --llm-skipped "$LLM_SKIPPED" \
        --uv "$(command -v uv 2>/dev/null || true)" >/dev/null 2>&1 \
        && ok "install manifest: $HOME/.meshembed/install.json" \
        || echo "  ! could not write the install manifest"
}

# pip exiting 0 does NOT mean the upgrade landed: an already-satisfied
# requirement is "success", and PYTHON_BIN must be the same interpreter the
# LaunchAgent runs. Without this, a no-op upgrade still lets the daemon re-exec
# and report the OLD version to the backend -- the silent failure that kept the
# fleet on v0.3.40 (install.sh has had this guard since v0.3.45).
# The expected version is derived from the URL actually used, so a custom
# MESHEMBED_PACKAGE_URL (local wheel, branch tarball) skips the check instead of
# failing it against a stale literal.
_WANT=$(printf '%s' "$PACKAGE_URL" | sed -n 's#.*/tags/v\([0-9][0-9A-Za-z.]*\)\.tar\.gz$#\1#p')   # pre-releases too (RC-2)
# A bound install reads from file://…/<tag>.tar.gz, which the pattern above never matched:
# the check was silently skipped exactly when the release had been verified.
[ "$_BOUND_TAR" -eq 1 ] && _WANT="${RELEASE_TAG#v}"
if [ -n "$_WANT" ]; then
    _GOT=$("$PYTHON_BIN" -c 'import importlib.metadata as m; print(m.version("meshembed-node"))' 2>/dev/null || echo "")
    if [ "$_GOT" != "$_WANT" ]; then
        fail "post-install check: $PYTHON_BIN reports meshembed-node ${_GOT:-<none>}, expected $_WANT. The upgrade did not land in the daemon's interpreter -- not restarting."
    fi
    ok "post-install check: meshembed-node $_GOT"
fi

# ── D-4 / PB-V (v0.3.80): the INSTALLED package must be able to START (as install.sh) ──
# Imports every module + the start guards with the daemon's interpreter, isolated (-I); no network, key, file or thread.
# A failure stops the install HERE: nothing registered, the LaunchAgent not (re)loaded on it.
_SC=$("$PYTHON_BIN" -I -m meshembed_node selfcheck 2>&1 | tail -n 1) \
    || fail "post-install selfcheck: ${_SC:-no output} -- the installed node cannot start; not restarting it."
ok "$_SC"

# ── self-register (skipped on UPGRADE_ONLY) ──────────────────────────────────
if [ "$UPGRADE_ONLY" -eq 1 ]; then
    info "Skipping register: reusing credentials from $EXISTING_ENV"
    # Pull values we still need downstream (LaunchAgent label refresh
    # etc.) from the existing .env. This keeps the rest of the script
    # logic uniform.
    # `|| true`: under `set -euo pipefail` a line missing from .env made grep's exit status
    # kill the script silently here, before the fallback below could apply (found by the
    # self-repair harness, 2026-10-04).
    NODE_ID=$(grep '^MESHEMBED_NODE_ID='        "$EXISTING_ENV" | cut -d= -f2- || true)
    API_KEY=$(grep '^MESHEMBED_NODE_API_KEY='   "$EXISTING_ENV" | cut -d= -f2- || true)
    PRIVKEY=$(grep '^MESHEMBED_NODE_PRIVKEY='   "$EXISTING_ENV" | cut -d= -f2- || true)
    # Fall back to env vars (set by LaunchAgent + daemon auto-update) if
    # the file didn't have one of these (older installs).
    NODE_ID="${NODE_ID:-${MESHEMBED_NODE_ID:-}}"
    API_KEY="${API_KEY:-${MESHEMBED_NODE_API_KEY:-}}"
    PRIVKEY="${PRIVKEY:-${MESHEMBED_NODE_PRIVKEY:-}}"
    NODE_NUM=0  # Unknown in upgrade mode; the dashboard already shows it.
    ok "Reusing N-${NODE_ID:0:8}... ($EXISTING_ENV)"
else
    info "Registering node with the backend..."
    # Capture stdout (the --json payload) and stderr (logs, errors) separately.
    # Mixing them with `2>&1` was breaking the json.load below whenever
    # any module on the import path emitted a deprecation warning, log line,
    # or `print(..., file=sys.stderr)` before the JSON payload was written.
    REG_ERR=$(mktemp -t meshembed-register-err.XXXXXX)
    trap 'rm -f "$REG_ERR"' EXIT
    FRESH_FLAG=""
    if [ "${FRESH_NODE:-0}" = "1" ]; then
        FRESH_FLAG="--fresh"
        info "FRESH_NODE=1 -- enrolling a NEW node; existing reputation on this hardware is discarded."
    fi
    if ! REGISTER_OUT=$("$PYTHON_BIN" -m meshembed_node register \
            --backend "$BACKEND_URL" \
            --invite  "$INVITE_TOKEN" \
            $FRESH_FLAG \
            --json 2>"$REG_ERR"); then
        fail "Registration failed:\n$(cat "$REG_ERR")"
    fi
    # Defensive guard: register exited 0 but produced no JSON on stdout.
    if [ -z "$REGISTER_OUT" ]; then
        fail "Registration produced no output. Stderr was:\n$(cat "$REG_ERR")"
    fi

    PRIVKEY=$("$PYTHON_BIN" -c "from meshembed_node.crypto import generate_keypair; print(generate_keypair()[0])")
    NODE_ID=$(printf '%s' "$REGISTER_OUT"  | "$PYTHON_BIN" -c "import sys,json; d=json.load(sys.stdin); print(d['node_id'])")
    API_KEY=$(printf '%s' "$REGISTER_OUT"  | "$PYTHON_BIN" -c "import sys,json; d=json.load(sys.stdin); print(d['api_key'])")
    NODE_NUM=$(printf '%s' "$REGISTER_OUT" | "$PYTHON_BIN" -c "import sys,json; d=json.load(sys.stdin); print(d['node_number'])")
    ok "Node registered - N-$(printf '%04d' $NODE_NUM)"

    # ── data directory ───────────────────────────────────────────────────────
    CONFIG_DIR="$HOME/.meshembed"
    mkdir -p "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR"

    ENV_FILE="$CONFIG_DIR/.env"
    cat > "$ENV_FILE" << EOF
MESHEMBED_BACKEND=$BACKEND_URL
MESHEMBED_NODE_API_KEY=$API_KEY
MESHEMBED_NODE_ID=$NODE_ID
MESHEMBED_NODE_PRIVKEY=$PRIVKEY
EOF
    chmod 600 "$ENV_FILE"
    ok "Credentials saved to $ENV_FILE"
fi

# ── LaunchAgent (UPGRADE_ONLY: refresh the definition, then restart) ─────────
if [ "$UPGRADE_ONLY" -eq 1 ]; then
    LABEL=io.clusterhive.meshembed-node
    TARGET="gui/$(id -u)/$LABEL"

    # An upgrade used to update the CODE and leave the SERVICE DEFINITION
    # untouched ("Skipping LaunchAgent setup"). That made v0.3.48 nearly inert:
    # its whole point was KeepAlive, and every node that needed it was by
    # definition an existing install. Nodes had to be patched by hand.
    #
    # We patch the specific keys rather than rewriting the plist. A rewrite
    # would have to reproduce MESHEMBED_NODE_API_KEY / NODE_ID / NODE_PRIVKEY
    # from whatever this script happens to have loaded, and getting that wrong
    # silently breaks the node's identity. PlistBuddy edits in place and cannot
    # lose credentials it never touches.
    PLIST_CHANGED=0
    if [ -f "$PLIST" ]; then
        # KeepAlive must be plain `true`. The old value was a dict with
        # SuccessfulExit=false, i.e. "stay dead if it exited cleanly" -- and the
        # drain handler exits 0 on SIGTERM, so a clean stop was permanent.
        if ! /usr/libexec/PlistBuddy -c "Print :KeepAlive" "$PLIST" 2>/dev/null \
             | head -1 | grep -qx "true"; then
            /usr/libexec/PlistBuddy -c "Delete :KeepAlive" "$PLIST" >/dev/null 2>&1 || true
            if /usr/libexec/PlistBuddy -c "Add :KeepAlive bool true" "$PLIST" >/dev/null 2>&1; then
                PLIST_CHANGED=1
                ok "LaunchAgent refreshed: KeepAlive now restarts on ANY exit."
            else
                info "Could not update KeepAlive in $PLIST -- leaving it as-is."
            fi
        fi
        # Without a throttle, KeepAlive=true turns a boot loop into a hot loop.
        if ! /usr/libexec/PlistBuddy -c "Print :ThrottleInterval" "$PLIST" >/dev/null 2>&1; then
            /usr/libexec/PlistBuddy -c "Add :ThrottleInterval integer 30" "$PLIST" >/dev/null 2>&1 \
                && PLIST_CHANGED=1
        fi
    fi
    [ "$PLIST_CHANGED" -eq 0 ] && info "LaunchAgent definition already current."

    if [ -n "${MESHEMBED_PACKAGE_URL:-}" ]; then
        # OTA self-update: the DAEMON launched this installer and will re-exec
        # itself (os.execv) in place after we return. We must NOT touch the
        # LaunchAgent here -- unloading it would terminate the daemon (our own
        # parent) before it can re-exec. Patching the plist above is safe: it
        # edits a file, it does not signal the job. launchd reads the new
        # definition on the next load.
        info "Auto-update: the daemon will re-exec itself on the new code."
    elif node_paused; then
        info "the node is PAUSED ($PAUSE_MARKER): upgraded, NOT restarted (resume: sudo meshembed-node-pause resume)"
    elif launchctl print "$TARGET" >/dev/null 2>&1; then
        info "Restarting LaunchAgent so the new code takes effect now..."
        # MANUAL run only (we are NOT the daemon's child).
        #
        # `kickstart` is deliberately NOT used. `-k` SIGTERMs and BLOCKS waiting
        # for the old instance to exit, which hangs if that process is stuck in
        # a native call -- and plain `kickstart` was observed hanging too, on a
        # real operator machine, in both forms. bootout/bootstrap is the modern
        # pair, does not wait on the old instance, and has the side benefit of
        # making launchd re-read the plist we just patched.
        launchctl bootout "$TARGET" >/dev/null 2>&1 || true
        pkill -9 -f "meshembed_node" 2>/dev/null || true
        sleep 1
        if launchctl bootstrap "gui/$(id -u)" "$PLIST" 2>/dev/null; then
            ok "Daemon restarted -- reports new version on next poll (~30s)."
        else
            # Legacy fallback for older macOS where bootstrap is unavailable.
            launchctl load -w "$PLIST" >/dev/null 2>&1 \
                && ok "Daemon restarted (legacy load)." \
                || echo "  (relaunch failed; daemon will pick up the new code on next login)"
        fi
    else
        info "Daemon not currently loaded; it will load with new code on next login or reboot."
    fi
    declare -F write_install_manifest >/dev/null && write_install_manifest upgrade
    echo ""
    echo "${bold}Upgrade complete.${reset}"
    exit 0
fi

info "Installing LaunchAgent for autostart..."
mkdir -p "$(dirname "$PLIST")"

# Detect the user's homebrew prefix so we can extend PATH to include
# any required binaries (xcrun-shimmed tools etc). Without this the
# LaunchAgent runs with a minimal PATH and torch imports can fail to
# find libomp / similar.
BREW_PREFIX=""
if [ -x /opt/homebrew/bin/brew ]; then BREW_PREFIX="/opt/homebrew"; fi
if [ -x /usr/local/bin/brew ]; then BREW_PREFIX="${BREW_PREFIX:-/usr/local}"; fi
EXTRA_PATH=""
if [ -n "$BREW_PREFIX" ]; then EXTRA_PATH="$BREW_PREFIX/bin:$BREW_PREFIX/sbin:"; fi

cat > "$PLIST" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>io.clusterhive.meshembed-node</string>
    <key>ProgramArguments</key>
    <array>
        <string>$PYTHON_BIN</string>
        <string>-m</string>
        <string>meshembed_node</string>
        <string>run</string>
    </array>
    <key>WorkingDirectory</key>
    <string>$HOME/.meshembed</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>                    <string>${EXTRA_PATH}/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
        <key>HOME</key>                    <string>$HOME</string>
        <key>MESHEMBED_BACKEND</key>       <string>$BACKEND_URL</string>
        <key>MESHEMBED_NODE_API_KEY</key>  <string>$API_KEY</string>
        <key>MESHEMBED_NODE_ID</key>       <string>$NODE_ID</string>
        <key>MESHEMBED_NODE_PRIVKEY</key>  <string>$PRIVKEY</string>
    </dict>
    <key>RunAtLoad</key>       <true/>
    <!-- Restart on ANY exit, not just a crash.
         This used to be a dict with SuccessfulExit=false, which tells launchd
         to leave the daemon dead whenever it exits 0. The daemon's drain
         handler exits 0 on SIGTERM, so a clean stop was permanent: the node
         went silent and stayed silent until the operator next logged in. An
         unattended node must come back on its own, and the only exit that
         should stick is one the operator asked for (launchctl bootout, which
         unloads the job and is unaffected by KeepAlive).
         ThrottleInterval below still caps a crash loop at one start / 30s. -->
    <key>KeepAlive</key>            <true/>
    <key>ThrottleInterval</key>     <integer>30</integer>
    <key>StandardOutPath</key>      <string>$HOME/.meshembed/node.log</string>
    <key>StandardErrorPath</key>    <string>$HOME/.meshembed/node.log</string>
</dict>
</plist>
EOF

# Modern macOS (12+) prefers bootstrap/bootout over load/unload. Fall
# back to the legacy commands on older macOS or if bootstrap fails.
LAUNCHCTL_TARGET="gui/$(id -u)"
install_pause_tool
if node_paused; then
    info "the node is PAUSED ($PAUSE_MARKER): installed, NOT started (resume: sudo meshembed-node-pause resume)"
else
launchctl bootout "$LAUNCHCTL_TARGET" "$PLIST" >/dev/null 2>&1 || true
if launchctl bootstrap "$LAUNCHCTL_TARGET" "$PLIST" 2>/dev/null; then
    ok "LaunchAgent bootstrapped"
else
    launchctl unload "$PLIST" >/dev/null 2>&1 || true
    launchctl load -w "$PLIST" || fail "launchctl load failed -- check $HOME/.meshembed/node.log"
    ok "LaunchAgent loaded (legacy mode)"
fi
fi

# ── verify ───────────────────────────────────────────────────────────────────
# The daemon spends 30-60s loading the embedding model before it
# starts polling. Don't conclude "failed" too quickly.
DAEMON_OK=0
node_paused || info "Waiting for daemon to start (up to 90s for model load)..."
for _ in $(seq 1 18); do
    node_paused && break
    sleep 5
    # `launchctl print gui/<uid>/<label>` reports PID + last exit status.
    if launchctl print "$LAUNCHCTL_TARGET/io.clusterhive.meshembed-node" 2>/dev/null \
        | grep -E "state = running|pid = [0-9]+" >/dev/null; then
        DAEMON_OK=1
        break
    fi
    # Fall back to the legacy `launchctl list` for older macOS.
    if launchctl list | awk '$3 == "io.clusterhive.meshembed-node" {print $1}' \
        | grep -qE '^[0-9]+$'; then
        DAEMON_OK=1
        break
    fi
done
if node_paused; then
    info "Daemon not started: the node is paused"
elif [ "$DAEMON_OK" = 1 ]; then
    ok "Daemon running"
else
    echo "⚠ Daemon did not start within 90s."
    echo "  Last log lines:"
    tail -n 30 "$HOME/.meshembed/node.log" 2>/dev/null | sed 's/^/    /' || true
    echo "  Full log: $HOME/.meshembed/node.log"
    echo "  Status:   launchctl print $LAUNCHCTL_TARGET/io.clusterhive.meshembed-node"
fi

write_install_manifest fresh
echo ""
echo "${bold}Installation complete.${reset}"
echo "  Node:    N-$(printf '%04d' $NODE_NUM) ($NODE_ID)"
echo "  Logs:    tail -f $HOME/.meshembed/node.log"
echo "  Stop:    launchctl unload $PLIST"
echo "  Start:   launchctl load -w $PLIST"
