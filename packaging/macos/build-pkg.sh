#!/bin/bash
# Build the macOS .pkg installer. Runs on a macOS runner.
# Usage: build-pkg.sh <version>
#
# Produces MeshEmbedNode-<version>.pkg in the current directory.
# The pkg ships the Python wheel + a LaunchAgent plist + scripts that
# pip-install the wheel into a venv at /usr/local/libexec/meshembed-node/.

set -euxo pipefail

VERSION="${1:?version required}"
IDENTIFIER="io.clusterhive.meshembed-node"
INSTALL_ROOT="/usr/local/libexec/meshembed-node"
PKG_NAME="MeshEmbedNode-${VERSION}"

cd "$(dirname "$0")/../.."   # repo root

# Stage the payload.
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage${INSTALL_ROOT}"
mkdir -p "$stage/Library/LaunchAgents"

# Locate the wheel. The pkg --version comes from $VERSION (the tag),
# but the wheel filename comes from pyproject.toml's version, which
# may not match — pick whichever wheel exists.
wheel="$(ls dist/meshembed_node-*-py3-none-any.whl 2>/dev/null | head -1)"
if [ -z "$wheel" ] || [ ! -f "$wheel" ]; then
    echo "ERROR: no meshembed_node wheel found in dist/ (looking for version ${VERSION})" >&2
    ls -la dist/ >&2 || true
    exit 1
fi
cp "$wheel" "$stage${INSTALL_ROOT}/"
cat > "$stage${INSTALL_ROOT}/bootstrap.sh" <<'BS'
#!/bin/bash
# Wrapper invoked by the LaunchAgent. By the time we get called the
# postinstall script should have already created the venv -- but we
# keep a fallback path for the "user replaced files" case.
set -euo pipefail
dir="$(cd "$(dirname "$0")" && pwd)"

# Resolve a real Python interpreter. The Apple stub at /usr/bin/python3
# can't write into our libexec dir even with sudo on some setups;
# prefer Homebrew Python when available.
pick_python() {
    for cand in \
        /opt/homebrew/bin/python3 \
        /usr/local/bin/python3 \
        /opt/local/bin/python3 \
        "$(command -v python3 2>/dev/null)"; do
        if [ -n "$cand" ] && [ -x "$cand" ] \
           && "$cand" -c 'import ssl, json, venv, sys' >/dev/null 2>&1; then
            echo "$cand"
            return 0
        fi
    done
    echo "ERROR: no usable python3 found" >&2
    return 1
}

if [ ! -d "$dir/.venv" ]; then
    PY=$(pick_python)
    "$PY" -m venv "$dir/.venv"
    "$dir/.venv/bin/pip" install --upgrade pip
    "$dir/.venv/bin/pip" install "$dir"/meshembed_node-*.whl
fi
exec "$dir/.venv/bin/meshembed-node" "$@"
BS
chmod +x "$stage${INSTALL_ROOT}/bootstrap.sh"

# LaunchAgent plist. Runs in the user's session so the daemon can
# open `127.0.0.1:7842` in the user's default browser for the
# first-run setup.
cat > "$stage/Library/LaunchAgents/${IDENTIFIER}.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>             <string>${IDENTIFIER}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${INSTALL_ROOT}/bootstrap.sh</string>
    <string>run</string>
  </array>
  <key>RunAtLoad</key>         <true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>  <false/>
  </dict>
  <key>StandardOutPath</key>   <string>/tmp/meshembed-node.out.log</string>
  <key>StandardErrorPath</key> <string>/tmp/meshembed-node.err.log</string>
</dict>
</plist>
EOF

# Postinstall script: creates the venv synchronously (so install
# failures surface in Installer.app instead of silently via launchd),
# installs the LaunchAgent into the **invoking** user's
# ~/Library/LaunchAgents/, bootstraps it now, and opens the setup
# page in their browser. Without this the user has to log out + log
# in for the system-wide LaunchAgent to load.
scripts_dir="$(mktemp -d)"
trap 'rm -rf "$stage" "$scripts_dir"' EXIT
cat > "$scripts_dir/postinstall" <<'POSTINSTALL'
#!/bin/bash
# pkg postinstall: run as root, but we need to set up things for the
# user who launched the installer. $USER is set by macOS Installer to
# the logged-in user; fall back to USER_NAME or stat the home dir.
set -uo pipefail
LOG=/tmp/meshembed-node-postinstall.log
exec >>"$LOG" 2>&1
echo "=== meshembed postinstall $(date) ==="

INVOKER="${USER:-${INSTALLER_USER:-$(stat -f %Su /dev/console 2>/dev/null)}}"
if [ -z "$INVOKER" ] || [ "$INVOKER" = "root" ]; then
    echo "WARNING: could not resolve invoking user; LaunchAgent install skipped"
    exit 0
fi
INVOKER_HOME="$(eval echo "~$INVOKER")"
INVOKER_UID="$(id -u "$INVOKER")"
echo "invoker=$INVOKER home=$INVOKER_HOME uid=$INVOKER_UID"

DIR="/usr/local/libexec/meshembed-node"

# Synchronous venv creation -- bail out clearly if it fails.
if [ ! -d "$DIR/.venv" ]; then
    bash "$DIR/bootstrap.sh" --version >/dev/null 2>&1 || true
    # First exec of bootstrap creates the venv; run a no-op to trigger it.
    bash "$DIR/bootstrap.sh" register --help >/dev/null 2>&1 || true
fi
if [ ! -x "$DIR/.venv/bin/meshembed-node" ]; then
    echo "ERROR: venv creation failed -- see $LOG and try running manually:"
    echo "  $DIR/bootstrap.sh run"
    exit 1
fi

# Move the LaunchAgent from /Library/LaunchAgents (system-wide, won't
# load until next login) to the user's ~/Library/LaunchAgents (loads
# immediately via launchctl bootstrap below).
SRC=/Library/LaunchAgents/io.clusterhive.meshembed-node.plist
DST="$INVOKER_HOME/Library/LaunchAgents/io.clusterhive.meshembed-node.plist"
mkdir -p "$(dirname "$DST")"
chown "$INVOKER" "$(dirname "$DST")"
cp "$SRC" "$DST"
chown "$INVOKER" "$DST"
rm -f "$SRC"   # don't leave the system-wide copy around

# Bootstrap as the invoking user, not root.
launchctl bootout "gui/$INVOKER_UID" "$DST" 2>/dev/null || true
sudo -u "$INVOKER" launchctl bootstrap "gui/$INVOKER_UID" "$DST" \
    && echo "LaunchAgent loaded" \
    || echo "launchctl bootstrap returned non-zero (may already be loaded)"

# Give the daemon ~15s to bind 127.0.0.1:7842 before opening browser.
( sleep 15 && sudo -u "$INVOKER" open 'http://127.0.0.1:7842' ) &

echo "=== postinstall ok ==="
exit 0
POSTINSTALL
chmod +x "$scripts_dir/postinstall"

# Build component pkg with the postinstall script attached.
pkgbuild --root "$stage" \
         --scripts "$scripts_dir" \
         --identifier "$IDENTIFIER" \
         --version "$VERSION" \
         --install-location / \
         "${PKG_NAME}-component.pkg"

# Wrap with a distribution xml so it looks like a real installer.
cat > "$stage/distribution.xml" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
  <title>MeshEmbed Node ${VERSION}</title>
  <organization>io.clusterhive</organization>
  <domains enable_localSystem="true"/>
  <welcome file="welcome.html" mime-type="text/html"/>
  <conclusion file="conclusion.html" mime-type="text/html"/>
  <pkg-ref id="${IDENTIFIER}"/>
  <choices-outline>
    <line choice="default"><line choice="${IDENTIFIER}"/></line>
  </choices-outline>
  <choice id="default"/>
  <choice id="${IDENTIFIER}" visible="false">
    <pkg-ref id="${IDENTIFIER}"/>
  </choice>
  <pkg-ref id="${IDENTIFIER}" version="${VERSION}" auth="root">${PKG_NAME}-component.pkg</pkg-ref>
</installer-gui-script>
EOF

productbuild --distribution "$stage/distribution.xml" \
             --package-path . \
             --resources packaging/macos/resources \
             "${PKG_NAME}.pkg"

rm -f "${PKG_NAME}-component.pkg"
echo "Built ${PKG_NAME}.pkg"

# TODO when signing is enabled:
# productsign --sign "Developer ID Installer: ClusterHive (TEAMID)" \
#             "${PKG_NAME}.pkg" "${PKG_NAME}-signed.pkg"
# xcrun notarytool submit "${PKG_NAME}-signed.pkg" \
#             --keychain-profile "AC_NOTARY" --wait
# mv "${PKG_NAME}-signed.pkg" "${PKG_NAME}.pkg"
