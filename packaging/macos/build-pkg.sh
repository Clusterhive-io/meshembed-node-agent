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
set -euo pipefail
dir="$(cd "$(dirname "$0")" && pwd)"
if [ ! -d "$dir/.venv" ]; then
    python3 -m venv "$dir/.venv"
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

# Build component pkg.
# We don't ship pre/post-install scripts at the pkg level - the
# bootstrap.sh inside the payload handles venv creation on first run.
# Keeps the pkg simpler and avoids signing scope creep.
pkgbuild --root "$stage" \
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
