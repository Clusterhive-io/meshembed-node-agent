#!/bin/bash
# Build the macOS .pkg installer -- self-contained edition.
#
# Bundles:
#   * The meshembed_node wheel (built from this checkout).
#   * The `uv` binary (Astral's universal Python installer + venv tool).
#   * postinstall.sh (does the actual setup on the operator's machine).
#   * LaunchAgent plist (Label io.clusterhive.meshembed-node).
#
# The .pkg is therefore self-contained: no system Python required, no
# brew install steps for the operator, no manual setup. The postinstall
# creates a venv via uv (which downloads + installs Python 3.12 the
# first time), installs the wheel + torch CPU into that venv, moves
# the LaunchAgent to the GUI user's ~/Library/LaunchAgents, and
# bootstraps it so the daemon starts NOW.
#
# Usage:  build-pkg.sh <version>     # produces MeshEmbedNode-<version>.pkg
set -euxo pipefail

VERSION="${1:?version required}"
IDENTIFIER="io.clusterhive.meshembed-node"
INSTALL_ROOT="/usr/local/libexec/meshembed-node"
PKG_NAME="MeshEmbedNode-${VERSION}"

cd "$(dirname "$0")/../.."   # repo root

# Detect host arch (this runs on a macOS-13 / macOS-14 GitHub runner).
ARCH=$(uname -m)
case "$ARCH" in
    arm64)  UV_ASSET="uv-aarch64-apple-darwin" ;;
    x86_64) UV_ASSET="uv-x86_64-apple-darwin" ;;
    *)      echo "ERROR: unsupported arch: $ARCH" >&2; exit 1 ;;
esac
UV_VERSION="${UV_VERSION:-0.5.11}"   # pin for reproducibility

# ── 1. Stage the payload ─────────────────────────────────────────────
stage="$(mktemp -d)"
scripts_dir="$(mktemp -d)"
trap 'rm -rf "$stage" "$scripts_dir"' EXIT
mkdir -p "$stage${INSTALL_ROOT}"
mkdir -p "$stage/Library/LaunchAgents"

# Locate the wheel built before this step.
wheel="$(ls dist/meshembed_node-*-py3-none-any.whl 2>/dev/null | head -1)"
if [ -z "$wheel" ] || [ ! -f "$wheel" ]; then
    echo "ERROR: no meshembed_node wheel found in dist/ (version ${VERSION})" >&2
    ls -la dist/ >&2 || true
    exit 1
fi
cp "$wheel" "$stage${INSTALL_ROOT}/"

# ── 2. Download + bundle the uv binary ───────────────────────────────
# uv is distributed as a single static binary. Pinning the version makes
# the build reproducible. The tarball is tiny (~20MB) -- well under any
# reasonable .pkg size budget.
echo "Downloading uv ${UV_VERSION} for ${UV_ASSET}"
curl -fsSL -o /tmp/uv.tar.gz \
    "https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/${UV_ASSET}.tar.gz"
mkdir -p /tmp/uv-extract
tar -xzf /tmp/uv.tar.gz -C /tmp/uv-extract
# The tarball expands to ${UV_ASSET}/uv (and uvx).
cp "/tmp/uv-extract/${UV_ASSET}/uv" "$stage${INSTALL_ROOT}/uv"
chmod +x "$stage${INSTALL_ROOT}/uv"
rm -rf /tmp/uv.tar.gz /tmp/uv-extract

# ── 3. LaunchAgent plist ─────────────────────────────────────────────
# Points at the venv's meshembed-node entry-point. Postinstall moves
# this file from /Library/LaunchAgents to ~/Library/LaunchAgents at
# install time so it loads per-user (no logout/login required).
cat > "$stage/Library/LaunchAgents/${IDENTIFIER}.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>             <string>${IDENTIFIER}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${INSTALL_ROOT}/.venv/bin/meshembed-node</string>
    <string>run</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key>            <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    <key>PYTHONUNBUFFERED</key><string>1</string>
  </dict>
  <key>WorkingDirectory</key>  <string>${INSTALL_ROOT}</string>
  <key>RunAtLoad</key>         <true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>  <false/>
    <key>Crashed</key>         <true/>
  </dict>
  <key>ThrottleInterval</key>  <integer>30</integer>
  <key>StandardOutPath</key>   <string>/tmp/meshembed-node.out.log</string>
  <key>StandardErrorPath</key> <string>/tmp/meshembed-node.err.log</string>
</dict>
</plist>
EOF

# ── 4. Postinstall script (shipped beside, not inside the payload) ───
cp packaging/macos/postinstall.sh "$scripts_dir/postinstall"
chmod +x "$scripts_dir/postinstall"

# ── 5. Build the component pkg ───────────────────────────────────────
pkgbuild --root "$stage" \
         --scripts "$scripts_dir" \
         --identifier "$IDENTIFIER" \
         --version "$VERSION" \
         --install-location / \
         "${PKG_NAME}-component.pkg"

# ── 6. Wrap with a distribution.xml so it looks like a real installer ──
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
ls -la "${PKG_NAME}.pkg"

# Notes for future hardening:
#  * productsign + notarytool when we have a Developer ID.
#  * Bake the torch + sentence-transformers wheels into the .pkg so the
#    first install doesn't need network for the heavy step. The current
#    flow downloads them at install time via uv pip install.
