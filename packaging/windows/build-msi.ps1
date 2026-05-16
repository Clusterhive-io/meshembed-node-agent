# Build the Windows .msi installer. Runs on a windows-latest GH runner.
# Requires WiX 4 (installed in the workflow via `dotnet tool install`).
# Usage: build-msi.ps1 -Version 0.2.0

param([Parameter(Mandatory)][string]$Version)

$ErrorActionPreference = "Stop"
$ROOT  = Resolve-Path "$PSScriptRoot\..\.."   # repo root
Set-Location $ROOT

# 1. Freeze the daemon to a single .exe with PyInstaller. WiX then
#    just ships that .exe - no runtime Python dependency on the
#    target Windows host.
pyinstaller --onefile `
            --name meshembed-node `
            --paths . `
            --hidden-import meshembed_node `
            --hidden-import meshembed_node.setup_server `
            --hidden-import meshembed_node.fingerprint `
            --hidden-import meshembed_node.worker `
            --collect-all sentence_transformers `
            meshembed_node\__main__.py

if (-not (Test-Path "dist\meshembed-node.exe")) {
    throw "PyInstaller failed: dist\meshembed-node.exe not found"
}

# 2. Pull the WiX UI extension (needed for the standard wizard pages
#    referenced in product.wxs as WixUI_InstallDir). Pin to the SAME
#    version as the wix CLI installed by the workflow - without the pin
#    `wix extension add` grabs the latest (7.x), wix 4 can't load it,
#    and we get WIX0144 "extension could not be found".
wix extension add WixToolset.UI.wixext/4.0.5

# 3. Build the .msi from product.wxs.
$msi = "MeshEmbedNode-$Version.msi"
wix build packaging\windows\product.wxs `
    -arch x64 `
    -ext WixToolset.UI.wixext `
    -d Version=$Version `
    -d BinaryPath="$ROOT\dist\meshembed-node.exe" `
    -o $msi

Write-Host "Built $msi"

# TODO when Authenticode signing is enabled:
# signtool sign /fd SHA256 /a /tr http://timestamp.digicert.com /td SHA256 $msi
