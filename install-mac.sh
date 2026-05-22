#!/bin/bash
# MeshEmbed Node - macOS installer (Apple Silicon and Intel)
set -euo pipefail

BACKEND_URL="${MESHEMBED_BACKEND:-https://meshembed.clusterhive.io}"
INVITE_TOKEN="${1:-}"
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
PY_MINOR=$(python3 -c 'import sys; print(sys.version_info.minor)')
[ "$PY_MINOR" -ge 10 ] || fail "Python 3.10+ required. Found: 3.$PY_MINOR"
ok "Python $(python3 --version)"

ARCH=$(uname -m)
if [ "$ARCH" = "arm64" ]; then
    ok "Apple Silicon detected - MPS acceleration will be used"
else
    ok "Intel Mac detected - CPU mode will be used"
fi

# ── invite token ─────────────────────────────────────────────────────────────
if [ -z "$INVITE_TOKEN" ]; then
    echo ""
    read -rp "Invite token (get one from the operator dashboard): " INVITE_TOKEN
fi
[ -n "$INVITE_TOKEN" ] || fail "Invite token required"

# ── Verify release signature (binary signing, 2026-05-22) ────────────────────
# Same protocol as install.sh; see that file for the rationale.
RELEASE_PUBKEY_HEX="${MESHEMBED_RELEASE_PUBKEY_OVERRIDE:-}"
RELEASE_TAG="${MESHEMBED_RELEASE_TAG:-v0.3.2}"
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
python3 -m pip install --upgrade --progress-bar on "meshembed-node @ ${PACKAGE_URL}"
ok "meshembed-node installed"

# ── self-register ────────────────────────────────────────────────────────────
info "Registering node with the backend..."
REGISTER_OUT=$(python3 -m meshembed_node register \
    --backend "$BACKEND_URL" \
    --invite  "$INVITE_TOKEN" \
    --json 2>&1) || fail "Registration failed:\n$REGISTER_OUT"

PRIVKEY=$(python3 -c "from meshembed_node.crypto import generate_keypair; print(generate_keypair()[0])")
NODE_ID=$(echo "$REGISTER_OUT"  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['node_id'])")
API_KEY=$(echo "$REGISTER_OUT"  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['api_key'])")
NODE_NUM=$(echo "$REGISTER_OUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['node_number'])")
ok "Node registered - N-$(printf '%04d' $NODE_NUM)"

# ── data directory ───────────────────────────────────────────────────────────
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

# ── LaunchAgent (autostart on login) ─────────────────────────────────────────
info "Installing LaunchAgent for autostart..."
mkdir -p "$(dirname "$PLIST")"

PYTHON_BIN=$(command -v python3)
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
    <key>EnvironmentVariables</key>
    <dict>
        <key>MESHEMBED_BACKEND</key>       <string>$BACKEND_URL</string>
        <key>MESHEMBED_NODE_API_KEY</key>  <string>$API_KEY</string>
        <key>MESHEMBED_NODE_ID</key>       <string>$NODE_ID</string>
    </dict>
    <key>RunAtLoad</key>       <true/>
    <key>KeepAlive</key>       <true/>
    <key>StandardOutPath</key> <string>$HOME/.meshembed/node.log</string>
    <key>StandardErrorPath</key><string>$HOME/.meshembed/node.log</string>
</dict>
</plist>
EOF

launchctl unload "$PLIST" 2>/dev/null || true
launchctl load -w "$PLIST"
ok "LaunchAgent installed and started"

# ── verify ───────────────────────────────────────────────────────────────────
sleep 2
if launchctl list | grep -q "io.clusterhive.meshembed-node"; then
    ok "Daemon running"
else
    echo "⚠ Daemon did not appear in launchctl. Check $HOME/.meshembed/node.log"
fi

echo ""
echo "${bold}Installation complete.${reset}"
echo "  Node:    N-$(printf '%04d' $NODE_NUM) ($NODE_ID)"
echo "  Logs:    tail -f $HOME/.meshembed/node.log"
echo "  Stop:    launchctl unload $PLIST"
echo "  Start:   launchctl load -w $PLIST"
