#!/bin/sh
# Pre-uninstall hook. Stops the service. Does NOT delete the
# `meshembed` user or `/var/lib/meshembed-node` (which holds the
# credentials) so reinstalls don't trigger a new enrollment by accident.

set -eu

if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet meshembed-node; then
        systemctl stop meshembed-node || true
    fi
    if systemctl is-enabled --quiet meshembed-node 2>/dev/null; then
        systemctl disable meshembed-node || true
    fi
    # PATH-LIMIT HT-4: the heal timer goes with the node (it would otherwise restart .path units of a removed node)
    systemctl disable --now meshembed-path-heal.timer >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/meshembed-path-heal.timer /etc/systemd/system/meshembed-path-heal.service
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

exit 0
