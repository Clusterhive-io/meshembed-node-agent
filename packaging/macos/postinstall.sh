#!/bin/bash
# Self-contained macOS postinstall for the MeshEmbed Node .pkg.
#
# Runs as root during the .pkg install. Responsibilities:
#   1. Resolve the **GUI user** who launched the installer (robust against
#      sudo-from-SSH and macOS-Installer-from-non-console contexts).
#   2. Create a venv via the bundled `uv` binary (Astral's portable
#      Python installer). uv downloads + installs Python 3.12 if not
#      already cached, so no system Python dependency.
#   3. Install the bundled meshembed_node wheel + CPU-only torch into
#      that venv. Torch CPU is hard-pinned so the daemon works on any
#      Mac (Intel or Apple Silicon) without GPU surprises.
#   4. Move the LaunchAgent plist to the GUI user's ~/Library/LaunchAgents
#      and `launchctl bootstrap` it (loads immediately, no logout/login).
#   5. After a grace period, open http://127.0.0.1:7842 in the user's
#      default browser so the operator pastes their invite token.
#
# Anything that goes wrong here is fatal -- the operator sees the
# Installer.app failure dialog and can read /tmp/meshembed-node-postinstall.log.
set -uo pipefail

LOG=/tmp/meshembed-node-postinstall.log
exec >>"$LOG" 2>&1
echo
echo "================================================================"
echo "=== meshembed postinstall $(date) ==="
echo "================================================================"

DIR=/usr/local/libexec/meshembed-node
PLIST_SRC=/Library/LaunchAgents/io.clusterhive.meshembed-node.plist
PLIST_LABEL=io.clusterhive.meshembed-node

# ─────────────────────────────────────────────────────────────────────
# 1. Resolve the GUI user
# ─────────────────────────────────────────────────────────────────────
#
# Strategy in priority order:
#   a. macOS sets $USER to root and $INSTALLER_USER to the GUI user
#      when the Installer.app runs the postinstall. Use it if present.
#   b. The login shell of /dev/console is reliable in GUI sessions.
#   c. Walk /Users/ for a single non-system account (most home macs
#      have exactly one). Skip Shared, Guest, _* accounts and root.
#   d. Use stat to find the most-recently-modified Library directory
#      under /Users/* -- last logged-in user.
#
# If we still can't resolve, fail with a clear error.

resolve_invoker() {
    local candidate
    # (a) Installer-set env var
    if [ -n "${INSTALLER_USER:-}" ] && [ "$INSTALLER_USER" != "root" ]; then
        candidate="$INSTALLER_USER"
        if id "$candidate" >/dev/null 2>&1; then
            echo "$candidate"; return 0
        fi
    fi
    # (b) Console user (works in GUI installs)
    candidate=$(stat -f %Su /dev/console 2>/dev/null || true)
    if [ -n "$candidate" ] && [ "$candidate" != "root" ] && id "$candidate" >/dev/null 2>&1; then
        echo "$candidate"; return 0
    fi
    # (c) Single non-system user in /Users/
    local users
    users=$(ls -1 /Users/ 2>/dev/null | grep -vE '^(Shared|Guest|root|_|\.)' || true)
    if [ "$(echo "$users" | wc -l | tr -d ' ')" = "1" ] && [ -n "$users" ]; then
        candidate="$users"
        if id "$candidate" >/dev/null 2>&1; then
            echo "$candidate"; return 0
        fi
    fi
    # (d) Most-recently-modified user home (best-effort)
    candidate=$(ls -t /Users/ 2>/dev/null \
        | grep -vE '^(Shared|Guest|root|_|\.)' \
        | head -1)
    if [ -n "$candidate" ] && id "$candidate" >/dev/null 2>&1; then
        echo "$candidate"; return 0
    fi
    return 1
}

INVOKER=$(resolve_invoker || true)
if [ -z "$INVOKER" ]; then
    echo "FATAL: cannot resolve GUI user. The MeshEmbed daemon needs a"
    echo "       per-user LaunchAgent and a user home for credentials."
    echo "       /Users/ contents:"
    ls -la /Users/ 2>&1 | sed 's/^/  /'
    exit 1
fi
INVOKER_HOME=$(eval echo "~$INVOKER")
INVOKER_UID=$(id -u "$INVOKER")
echo "[ok] invoker=$INVOKER home=$INVOKER_HOME uid=$INVOKER_UID"

# ─────────────────────────────────────────────────────────────────────
# 2. Locate the bundled uv binary
# ─────────────────────────────────────────────────────────────────────
UV="$DIR/uv"
if [ ! -x "$UV" ]; then
    echo "FATAL: bundled uv binary missing at $UV -- .pkg payload broken"
    ls -la "$DIR" 2>&1 | sed 's/^/  /'
    exit 1
fi
echo "[ok] uv at $UV ($("$UV" --version 2>&1 | head -1))"

# ─────────────────────────────────────────────────────────────────────
# 3. Create venv + install meshembed-node + torch CPU
# ─────────────────────────────────────────────────────────────────────
#
# All under $DIR/.venv. uv downloads python-build-standalone 3.12 on
# the first run (~30 MB) into $DIR/uv-cache/. We pin the torch index
# to the CPU-only wheels so Intel + Apple Silicon both work without
# GPU dependencies. The bundled wheel ships with the .pkg.

WHEEL=$(ls "$DIR"/meshembed_node-*.whl 2>/dev/null | head -1)
if [ -z "$WHEEL" ]; then
    echo "FATAL: bundled wheel missing in $DIR"
    exit 1
fi
echo "[ok] wheel: $WHEEL"

export UV_CACHE_DIR="$DIR/uv-cache"
export UV_PYTHON_INSTALL_DIR="$DIR/uv-python"

if [ ! -x "$DIR/.venv/bin/python" ]; then
    echo "[..] creating venv with bundled Python 3.12 (uv downloads if first run)"
    "$UV" venv --python 3.12 "$DIR/.venv" || {
        echo "FATAL: uv venv failed"
        exit 1
    }
fi
echo "[ok] venv ready"

echo "[..] installing torch CPU (this is the heavy step on first install)"
"$UV" pip install --python "$DIR/.venv/bin/python" \
    --index-url https://download.pytorch.org/whl/cpu \
    torch || {
    echo "FATAL: torch CPU install failed"
    exit 1
}
echo "[ok] torch installed"

echo "[..] installing meshembed-node + deps"
"$UV" pip install --python "$DIR/.venv/bin/python" "$WHEEL" || {
    echo "FATAL: meshembed-node wheel install failed"
    exit 1
}
echo "[ok] meshembed-node installed"

# ─────────────────────────────────────────────────────────────────────
# 4. Sanity check: can the daemon entry-point import + run --help?
# ─────────────────────────────────────────────────────────────────────
if ! "$DIR/.venv/bin/meshembed-node" --help >/dev/null 2>&1; then
    if ! "$DIR/.venv/bin/python" -m meshembed_node --help >/dev/null 2>&1; then
        echo "FATAL: meshembed-node failed sanity check (cannot import)"
        exit 1
    fi
fi
echo "[ok] daemon entry-point sanity-check passes"

# ─────────────────────────────────────────────────────────────────────
# 5. Move LaunchAgent to user's ~/Library/LaunchAgents + bootstrap
# ─────────────────────────────────────────────────────────────────────
PLIST_DST="$INVOKER_HOME/Library/LaunchAgents/$(basename "$PLIST_SRC")"
mkdir -p "$(dirname "$PLIST_DST")"
chown "$INVOKER:staff" "$(dirname "$PLIST_DST")"
cp "$PLIST_SRC" "$PLIST_DST"
chown "$INVOKER:staff" "$PLIST_DST"
rm -f "$PLIST_SRC"
echo "[ok] LaunchAgent installed at $PLIST_DST"

# Unload any prior instance, then bootstrap (loads NOW, not on next login).
launchctl bootout "gui/$INVOKER_UID" "$PLIST_DST" >/dev/null 2>&1 || true
if sudo -u "$INVOKER" launchctl bootstrap "gui/$INVOKER_UID" "$PLIST_DST" 2>>"$LOG"; then
    echo "[ok] launchctl bootstrap succeeded"
else
    echo "WARNING: launchctl bootstrap returned non-zero (may already be loaded)"
fi

# ─────────────────────────────────────────────────────────────────────
# 6. Wait ~20s for the daemon to bind 127.0.0.1:7842, then open browser
# ─────────────────────────────────────────────────────────────────────
( sleep 20 && sudo -u "$INVOKER" open 'http://127.0.0.1:7842' >/dev/null 2>&1 ) &

echo "================================================================"
echo "=== postinstall ok @ $(date) ==="
echo "================================================================"
exit 0
