#!/bin/sh
# Post-install hook for the .deb / .rpm packages. Idempotent — safe to
# re-run on upgrade. Doesn't start the daemon; the operator opens
# `meshembed-node run` manually (or via the systemd unit) which will
# then open the browser at 127.0.0.1:7842 for the invite-token step.

set -eu

USER_NAME="meshembed"
HOME_DIR="/var/lib/meshembed-node"

# Create the unprivileged user the daemon runs under.
if ! getent passwd "$USER_NAME" >/dev/null; then
    useradd --system \
        --home-dir "$HOME_DIR" \
        --shell /usr/sbin/nologin \
        --comment "MeshEmbed Node daemon" \
        "$USER_NAME"
fi

# Ensure state dir exists with the right perms.
mkdir -p "$HOME_DIR"
chown "$USER_NAME:$USER_NAME" "$HOME_DIR"
chmod 0750 "$HOME_DIR"

# Enable the systemd unit but do NOT start it — the daemon needs a
# token before it can do anything useful. Operator does:
#
#   sudo systemctl start meshembed-node     # opens setup browser
#   sudo systemctl enable meshembed-node    # auto-start on boot
#
# Note: starting it auto here would race the operator and confuse the
# browser-open behavior.
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi

echo ""
echo "MeshEmbed Node installed."
echo ""
echo "To enroll this host:"
echo "  sudo systemctl start meshembed-node"
echo ""
echo "On first start the daemon opens http://127.0.0.1:7842/ in your"
echo "browser. Paste your invite token from"
echo "https://meshembed.clusterhive.io/operator."
echo ""
echo "To make it auto-start on boot once enrolled:"
echo "  sudo systemctl enable meshembed-node"
echo ""

exit 0
