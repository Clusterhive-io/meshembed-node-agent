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

# ── Upgrade-vs-fresh-install detection ───────────────────────────────────────
# When the daemon's auto-update channel fires, _perform_self_update execs
# this script with the daemon's env (which has MESHEMBED_NODE_API_KEY +
# MESHEMBED_NODE_ID) but no INVITE token. Detect that case and short-
# circuit to "pip install --upgrade then exit"; skip the invite prompt,
# the register call, the .env write, and the systemd unit reinstall
# (all already in place from the original enrollment).
EXISTING_ENV="$HOME/.meshembed/.env"
UPGRADE_ONLY=0
if [ -f "$EXISTING_ENV" ] && grep -q '^MESHEMBED_NODE_API_KEY=' "$EXISTING_ENV"; then
    UPGRADE_ONLY=1
elif [ -n "${MESHEMBED_NODE_API_KEY:-}" ] && [ -n "${MESHEMBED_NODE_ID:-}" ]; then
    UPGRADE_ONLY=1
fi

# ── Invite token ──────────────────────────────────────────────────────────────
if [ "$UPGRADE_ONLY" -eq 1 ]; then
    info "Existing enrollment detected -- running in UPGRADE-ONLY mode (no re-register)."
elif [ -z "$INVITE_TOKEN" ]; then
    if [ -t 0 ]; then
        echo ""
        read -rp "Invite token (get one from the operator dashboard): " INVITE_TOKEN
    else
        fail "Invite token required. Use: curl ... | INVITE='your_token' bash    or pass it as arg 1."
    fi
fi
if [ "$UPGRADE_ONLY" -ne 1 ]; then
    [ -n "$INVITE_TOKEN" ] || fail "Invite token required"
fi

# ── Verify release signature (binary signing, 2026-05-22) ─────────────────────
# Pinned ed25519 public key for the MeshEmbed release-signing key. To
# rotate: run scripts/generate-release-key.py on a trusted machine,
# update this constant + the GH Actions secret, and cut the next
# release. Empty string = no verification (rolling back the change
# without a redeploy if needed).
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

# ── Self-register (skipped on UPGRADE_ONLY) ───────────────────────────────────
if [ "$UPGRADE_ONLY" -eq 1 ]; then
    info "Skipping register / .env write / systemd unit reinstall: existing enrollment in $EXISTING_ENV"
    # The pip package was just upgraded on disk, but the long-lived
    # daemon process is still holding the OLD code in memory. When the
    # daemon's auto-update channel calls us, the daemon sys.exits after
    # this script returns and systemd respawns it. When the operator
    # runs this script manually, we restart the unit ourselves --
    # otherwise the dashboard keeps showing the old agent_version even
    # though the pip package on disk is current.
    if command -v systemctl >/dev/null 2>&1 && systemctl cat meshembed-node.service >/dev/null 2>&1; then
        info "Restarting meshembed-node.service so the new code takes effect..."
        if [ "$EUID" -eq 0 ]; then
            systemctl restart meshembed-node.service && ok "Daemon restarted -- reports new version on next poll (~30s)."
        elif sudo -n systemctl restart meshembed-node.service 2>/dev/null; then
            ok "Daemon restarted (via passwordless sudo)."
        else
            echo "  (passwordless sudo not available; run 'sudo systemctl restart meshembed-node.service' to apply the upgrade now)"
        fi
    fi
    echo ""
    echo "${bold}Upgrade complete.${reset}"
    exit 0
fi

info "Registering node with the backend..."
# Capture stdout (--json payload) and stderr (logs, warnings) separately;
# `2>&1` was poisoning the JSON whenever any import-time log line leaked
# to stderr.
REG_ERR=$(mktemp -t meshembed-register-err.XXXXXX)
trap 'rm -f "$REG_ERR"' EXIT
if ! REGISTER_OUT=$(python3 -m meshembed_node register \
        --backend "$BACKEND_URL" \
        --invite  "$INVITE_TOKEN" \
        --json 2>"$REG_ERR"); then
    fail "Registration failed:\n$(cat "$REG_ERR")"
fi
if [ -z "$REGISTER_OUT" ]; then
    fail "Registration produced no output. Stderr was:\n$(cat "$REG_ERR")"
fi

PRIVKEY=$(python3 -c "from meshembed_node.crypto import generate_keypair; print(generate_keypair()[0])")
NODE_ID=$(printf '%s' "$REGISTER_OUT"  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['node_id'])")
API_KEY=$(printf '%s' "$REGISTER_OUT"  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['api_key'])")
NODE_NUM=$(printf '%s' "$REGISTER_OUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['node_number'])")
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
