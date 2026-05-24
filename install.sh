#!/usr/bin/env bash
# MeshEmbed Node - Linux installer (Ubuntu, Debian, RHEL, Arch...)
# Usage: bash install.sh [invite_token]
# Requirements: Python 3.10+, systemd, NVIDIA GPU optional
set -euo pipefail

# ── OS check ─────────────────────────────────────────────────────────────────
if [[ "$(uname -s)" != "Linux" ]]; then
    echo "This script is Linux-only."
    echo "  macOS:   bash install-mac.sh"
    echo "  Windows: .\\install.ps1"
    exit 1
fi

# The operator dashboard pipes `curl ... | INVITE='token' BACKEND='url' bash`
# so honor those env vars first; fall back to positional $1 + the
# MESHEMBED_* env vars that older docs reference.
BACKEND_URL="${BACKEND:-${MESHEMBED_BACKEND:-https://meshembed.clusterhive.io}}"
INVITE_TOKEN="${1:-${INVITE:-${MESHEMBED_INVITE:-}}}"

bold=$(tput bold 2>/dev/null || true)
reset=$(tput sgr0 2>/dev/null || true)
green='\033[0;32m'; red='\033[0;31m'; nc='\033[0m'

info() { echo "${bold}[meshembed]${reset} $*"; }
ok()   { echo -e "${green}✓${nc} $*"; }
fail() { echo -e "${red}✗${nc} $*"; exit 1; }

# ── Requirements ──────────────────────────────────────────────────────────────
info "Checking requirements..."
command -v python3 >/dev/null || fail "python3 not found. Install Python 3.10+."
PY_MINOR=$(python3 -c 'import sys; print(sys.version_info.minor)')
[ "$PY_MINOR" -ge 10 ] || fail "Python 3.10+ required. Found: 3.$PY_MINOR"
ok "Python $(python3 --version)"

if command -v nvidia-smi &>/dev/null; then
    GPU=$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | head -1 || echo "NVIDIA")
    ok "NVIDIA GPU detected: $GPU"
    INSTALL_EXTRAS="[gpu]"
else
    info "No NVIDIA GPU detected - CPU mode will be used"
    INSTALL_EXTRAS=""
fi

# ── Invite token ──────────────────────────────────────────────────────────────
if [ -z "$INVITE_TOKEN" ]; then
    if [ -t 0 ]; then
        echo ""
        read -rp "Invite token (get one from the operator dashboard): " INVITE_TOKEN
    else
        fail "Invite token required. Use: curl ... | INVITE='your_token' bash    or pass it as arg 1."
    fi
fi
[ -n "$INVITE_TOKEN" ] || fail "Invite token required"

# ── Verify release signature (binary signing, 2026-05-22) ─────────────────────
# Pinned ed25519 public key for the MeshEmbed release-signing key. To
# rotate: run scripts/generate-release-key.py on a trusted machine,
# update this constant + the GH Actions secret, and cut the next
# release. Empty string = no verification (rolling back the change
# without a redeploy if needed).
RELEASE_PUBKEY_HEX="${MESHEMBED_RELEASE_PUBKEY_OVERRIDE:-}"
RELEASE_TAG="${MESHEMBED_RELEASE_TAG:-v0.3.4}"
REPO="Clusterhive-io/meshembed-node-agent"

if [ -n "$RELEASE_PUBKEY_HEX" ]; then
    info "Verifying release signature for $RELEASE_TAG..."
    TMPSIG=$(mktemp -d)
    trap 'rm -rf "$TMPSIG"' EXIT
    curl -fsSL "https://github.com/${REPO}/releases/download/${RELEASE_TAG}/SHA256SUMS" \
        -o "$TMPSIG/SHA256SUMS" || fail "could not download SHA256SUMS"
    curl -fsSL "https://github.com/${REPO}/releases/download/${RELEASE_TAG}/SHA256SUMS.sig" \
        -o "$TMPSIG/SHA256SUMS.sig" || fail "could not download SHA256SUMS.sig (release may predate signing)"
    python3 - "$TMPSIG/SHA256SUMS" "$TMPSIG/SHA256SUMS.sig" "$RELEASE_PUBKEY_HEX" <<'PYEOF' || fail "release signature verification FAILED -- aborting install"
import sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
sums_path, sig_path, pub_hex = sys.argv[1], sys.argv[2], sys.argv[3]
pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
with open(sums_path, 'rb') as f: sums = f.read()
with open(sig_path, 'rb') as f: sig = f.read()
try:
    pub.verify(sig, sums)
    print('ok')
except InvalidSignature:
    print('INVALID', file=sys.stderr)
    sys.exit(1)
PYEOF
    ok "release signature valid"
else
    info "release signature verification SKIPPED (RELEASE_PUBKEY_HEX unset)"
fi

# ── Install package ───────────────────────────────────────────────────────────
# Install from GitHub until the package is published to PyPI. The
# repository is public so no token is needed.
info "Installing meshembed-node from GitHub..."
info "  Downloads PyTorch (~800 MB), sentence-transformers and a few small"
info "  deps. First-time install takes 2-5 minutes; pip prints progress."
# PEP 508 form: "name[extras] @ url" works with pip and supports extras.
PACKAGE_URL="${MESHEMBED_PACKAGE_URL:-https://github.com/${REPO}/archive/refs/tags/${RELEASE_TAG}.tar.gz}"
# No --quiet: we want pip's per-package progress so the user sees activity.
python3 -m pip install --upgrade --progress-bar on "meshembed-node${INSTALL_EXTRAS} @ ${PACKAGE_URL}"
ok "meshembed-node installed"

# ── Self-register ─────────────────────────────────────────────────────────────
info "Registering node with the backend..."
REGISTER_OUT=$(python3 -m meshembed_node register \
    --backend "$BACKEND_URL" \
    --invite  "$INVITE_TOKEN" \
    --json 2>&1) || fail "Registration failed:\n$REGISTER_OUT"

PRIVKEY=$(python3 -c "from meshembed_node.crypto import generate_keypair; print(generate_keypair()[0])")
NODE_ID=$(echo "$REGISTER_OUT"  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['node_id'])")
API_KEY=$(echo "$REGISTER_OUT"  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['api_key'])")
NODE_NUM=$(echo "$REGISTER_OUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['node_number'])")
ok "Node registered - N-$(printf '%04d' "$NODE_NUM")"

# ── Data directory ────────────────────────────────────────────────────────────
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

# ── Systemd service ───────────────────────────────────────────────────────────
PYTHON_BIN=$(command -v python3)
SERVICE_FILE="/etc/systemd/system/meshembed-node.service"

if command -v systemctl &>/dev/null; then
    info "Installing systemd service..."
    cat > /tmp/meshembed-node.service << EOF
[Unit]
Description=MeshEmbed Node daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$USER
Environment=MESHEMBED_BACKEND=$BACKEND_URL
Environment=MESHEMBED_NODE_API_KEY=$API_KEY
Environment=MESHEMBED_NODE_ID=$NODE_ID
ExecStart=$PYTHON_BIN -m meshembed_node run
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    if [ "$EUID" -eq 0 ]; then
        mv /tmp/meshembed-node.service "$SERVICE_FILE"
        systemctl daemon-reload
        systemctl enable --now meshembed-node.service
        ok "systemd service installed and started"
    else
        echo ""
        echo "To install as a systemd service (requires sudo):"
        echo "  sudo mv /tmp/meshembed-node.service $SERVICE_FILE"
        echo "  sudo systemctl daemon-reload && sudo systemctl enable --now meshembed-node"
        echo ""
        echo "Or start manually now:"
        echo "  python3 -m meshembed_node run"
    fi
else
    info "systemd not available - start manually:"
    echo "  python3 -m meshembed_node run"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "${bold}Installation complete.${reset}"
echo "  Node:    N-$(printf '%04d' "$NODE_NUM") ($NODE_ID)"
echo "  Logs:    journalctl -u meshembed-node -f"
echo "  Stop:    sudo systemctl stop meshembed-node"
