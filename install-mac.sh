#!/bin/bash
# MeshEmbed Node - macOS installer (Apple Silicon and Intel)
set -euo pipefail

# The operator dashboard pipes `curl ... | INVITE='token' BACKEND='url' bash`
# so honor those env vars first; fall back to positional $1 + the
# MESHEMBED_* env vars that older docs reference.
BACKEND_URL="${BACKEND:-${MESHEMBED_BACKEND:-https://meshembed.clusterhive.io}}"
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
RELEASE_PUBKEY_HEX="${MESHEMBED_RELEASE_PUBKEY_OVERRIDE:-}"
RELEASE_TAG="${MESHEMBED_RELEASE_TAG:-v0.3.15}"
REPO="Clusterhive-io/meshembed-node-agent"

if [ -n "$RELEASE_PUBKEY_HEX" ]; then
    info "Verifying release signature for $RELEASE_TAG..."
    TMPSIG=$(mktemp -d)
    trap 'rm -rf "$TMPSIG"' EXIT
    curl -fsSL "https://github.com/${REPO}/releases/download/${RELEASE_TAG}/SHA256SUMS" \
        -o "$TMPSIG/SHA256SUMS" || fail "could not download SHA256SUMS"
    curl -fsSL "https://github.com/${REPO}/releases/download/${RELEASE_TAG}/SHA256SUMS.sig" \
        -o "$TMPSIG/SHA256SUMS.sig" || fail "could not download SHA256SUMS.sig"
    python3 - "$TMPSIG/SHA256SUMS" "$TMPSIG/SHA256SUMS.sig" "$RELEASE_PUBKEY_HEX" <<'PYEOF' || fail "release signature verification FAILED -- aborting install"
import sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
sums_path, sig_path, pub_hex = sys.argv[1], sys.argv[2], sys.argv[3]
pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
with open(sums_path, 'rb') as f: sums = f.read()
with open(sig_path, 'rb') as f: sig = f.read()
try:
    pub.verify(sig, sums); print('ok')
except InvalidSignature:
    print('INVALID', file=sys.stderr); sys.exit(1)
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
# No --quiet: we want pip's per-package progress so the user sees activity.
"$PYTHON_BIN" -m pip install --upgrade --progress-bar on "meshembed-node @ ${PACKAGE_URL}"
ok "meshembed-node installed"

# ── self-register (skipped on UPGRADE_ONLY) ──────────────────────────────────
if [ "$UPGRADE_ONLY" -eq 1 ]; then
    info "Skipping register: reusing credentials from $EXISTING_ENV"
    # Pull values we still need downstream (LaunchAgent label refresh
    # etc.) from the existing .env. This keeps the rest of the script
    # logic uniform.
    NODE_ID=$(grep '^MESHEMBED_NODE_ID='        "$EXISTING_ENV" | cut -d= -f2-)
    API_KEY=$(grep '^MESHEMBED_NODE_API_KEY='   "$EXISTING_ENV" | cut -d= -f2-)
    PRIVKEY=$(grep '^MESHEMBED_NODE_PRIVKEY='   "$EXISTING_ENV" | cut -d= -f2-)
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
    if ! REGISTER_OUT=$("$PYTHON_BIN" -m meshembed_node register \
            --backend "$BACKEND_URL" \
            --invite  "$INVITE_TOKEN" \
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

# ── LaunchAgent (skipped on UPGRADE_ONLY, but daemon is kickstarted) ─────────
if [ "$UPGRADE_ONLY" -eq 1 ]; then
    info "Skipping LaunchAgent setup (existing plist already in place)."
    # The pip package was just upgraded on disk, but the long-lived
    # daemon process is still holding the OLD code in memory. When the
    # daemon's auto-update channel calls us, the daemon itself sys.exits
    # after this script returns and launchd respawns it. When the
    # operator runs this script manually, nothing else terminates the
    # daemon -- so kickstart it ourselves. -k = stop the running
    # instance first, then start a new one.
    LABEL=io.clusterhive.meshembed-node
    TARGET="gui/$(id -u)/$LABEL"
    if launchctl print "$TARGET" >/dev/null 2>&1; then
        info "Kickstarting LaunchAgent so the new code takes effect now..."
        if launchctl kickstart -k "$TARGET" 2>/dev/null; then
            ok "Daemon restarted -- reports new version on next poll (~30s)."
        else
            echo "  (kickstart returned non-zero; daemon will pick up the new code on next natural restart)"
        fi
    else
        info "Daemon not currently loaded; it will load with new code on next login or reboot."
    fi
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
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>   <false/>
        <key>Crashed</key>          <true/>
    </dict>
    <key>ThrottleInterval</key>     <integer>30</integer>
    <key>StandardOutPath</key>      <string>$HOME/.meshembed/node.log</string>
    <key>StandardErrorPath</key>    <string>$HOME/.meshembed/node.log</string>
</dict>
</plist>
EOF

# Modern macOS (12+) prefers bootstrap/bootout over load/unload. Fall
# back to the legacy commands on older macOS or if bootstrap fails.
LAUNCHCTL_TARGET="gui/$(id -u)"
launchctl bootout "$LAUNCHCTL_TARGET" "$PLIST" >/dev/null 2>&1 || true
if launchctl bootstrap "$LAUNCHCTL_TARGET" "$PLIST" 2>/dev/null; then
    ok "LaunchAgent bootstrapped"
else
    launchctl unload "$PLIST" >/dev/null 2>&1 || true
    launchctl load -w "$PLIST" || fail "launchctl load failed -- check $HOME/.meshembed/node.log"
    ok "LaunchAgent loaded (legacy mode)"
fi

# ── verify ───────────────────────────────────────────────────────────────────
# The daemon spends 30-60s loading the embedding model before it
# starts polling. Don't conclude "failed" too quickly.
info "Waiting for daemon to start (up to 90s for model load)..."
DAEMON_OK=0
for _ in $(seq 1 18); do
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
if [ "$DAEMON_OK" = 1 ]; then
    ok "Daemon running"
else
    echo "⚠ Daemon did not start within 90s."
    echo "  Last log lines:"
    tail -n 30 "$HOME/.meshembed/node.log" 2>/dev/null | sed 's/^/    /' || true
    echo "  Full log: $HOME/.meshembed/node.log"
    echo "  Status:   launchctl print $LAUNCHCTL_TARGET/io.clusterhive.meshembed-node"
fi

echo ""
echo "${bold}Installation complete.${reset}"
echo "  Node:    N-$(printf '%04d' $NODE_NUM) ($NODE_ID)"
echo "  Logs:    tail -f $HOME/.meshembed/node.log"
echo "  Stop:    launchctl unload $PLIST"
echo "  Start:   launchctl load -w $PLIST"
