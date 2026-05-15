#!/usr/bin/env bash
# MeshEmbed Node — Linux installer (Ubuntu, Debian, RHEL, Arch…)
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

BACKEND_URL="${MESHEMBED_BACKEND:-https://meshembed.clusterhive.io}"
INVITE_TOKEN="${1:-}"

bold=$(tput bold 2>/dev/null || true)
reset=$(tput sgr0 2>/dev/null || true)
green='\033[0;32m'; red='\033[0;31m'; nc='\033[0m'

info() { echo "${bold}[meshembed]${reset} $*"; }
ok()   { echo -e "${green}✓${nc} $*"; }
fail() { echo -e "${red}✗${nc} $*"; exit 1; }

# ── Requirements ──────────────────────────────────────────────────────────────
info "Checking requirements…"
command -v python3 >/dev/null || fail "python3 not found. Install Python 3.10+."
PY_MINOR=$(python3 -c 'import sys; print(sys.version_info.minor)')
[ "$PY_MINOR" -ge 10 ] || fail "Python 3.10+ required. Found: 3.$PY_MINOR"
ok "Python $(python3 --version)"

if command -v nvidia-smi &>/dev/null; then
    GPU=$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | head -1 || echo "NVIDIA")
    ok "NVIDIA GPU detected: $GPU"
    INSTALL_EXTRAS="[gpu]"
else
    info "No NVIDIA GPU detected — CPU mode will be used"
    INSTALL_EXTRAS=""
fi

# ── Invite token ──────────────────────────────────────────────────────────────
if [ -z "$INVITE_TOKEN" ]; then
    echo ""
    read -rp "Invite token (get one from the operator dashboard): " INVITE_TOKEN
fi
[ -n "$INVITE_TOKEN" ] || fail "Invite token required"

# ── Install package ───────────────────────────────────────────────────────────
info "Installing meshembed-node…"
python3 -m pip install --quiet --upgrade "meshembed-node${INSTALL_EXTRAS}"
ok "meshembed-node installed"

# ── Self-register ─────────────────────────────────────────────────────────────
info "Registering node with the backend…"
REGISTER_OUT=$(python3 -m meshembed_node register \
    --backend "$BACKEND_URL" \
    --invite  "$INVITE_TOKEN" \
    --json 2>&1) || fail "Registration failed:\n$REGISTER_OUT"

NODE_ID=$(echo "$REGISTER_OUT"  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['node_id'])")
API_KEY=$(echo "$REGISTER_OUT"  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['api_key'])")
NODE_NUM=$(echo "$REGISTER_OUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['node_number'])")
ok "Node registered — N-$(printf '%04d' "$NODE_NUM")"

# ── Data directory ────────────────────────────────────────────────────────────
CONFIG_DIR="$HOME/.meshembed"
mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

ENV_FILE="$CONFIG_DIR/.env"
cat > "$ENV_FILE" << EOF
MESHEMBED_BACKEND=$BACKEND_URL
MESHEMBED_NODE_API_KEY=$API_KEY
MESHEMBED_NODE_ID=$NODE_ID
EOF
chmod 600 "$ENV_FILE"
ok "Credentials saved to $ENV_FILE"

# ── Systemd service ───────────────────────────────────────────────────────────
PYTHON_BIN=$(command -v python3)
SERVICE_FILE="/etc/systemd/system/meshembed-node.service"

if command -v systemctl &>/dev/null; then
    info "Installing systemd service…"
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
    info "systemd not available — start manually:"
    echo "  python3 -m meshembed_node run"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "${bold}Installation complete.${reset}"
echo "  Node:    N-$(printf '%04d' "$NODE_NUM") ($NODE_ID)"
echo "  Logs:    journalctl -u meshembed-node -f"
echo "  Stop:    sudo systemctl stop meshembed-node"
