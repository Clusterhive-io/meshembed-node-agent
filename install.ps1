# MeshEmbed Node - Windows installer (PowerShell 5.1+)
# Usage: .\install.ps1 -InviteToken <token>
# Requirements: Python 3.10+, pip, NVIDIA GPU optional
#
# Autostart: creates a Windows Task Scheduler task that starts the
# daemon on login.

param(
    # Accept either `-InviteToken` or `-Invite` (parameter abbreviation is
    # automatic in PowerShell as long as the prefix is unambiguous).
    [string]$InviteToken  = $env:INVITE_TOKEN,
    # `??` (null-coalescing) requires PowerShell 7+. Use if() for PS 5.1
    # compatibility - that's what ships by default on Windows 10/11.
    [string]$BackendUrl   = $(if ($env:MESHEMBED_BACKEND) { $env:MESHEMBED_BACKEND } else { "https://meshembed.clusterhive.io" }),
    [string]$NodeId       = $env:MESHEMBED_NODE_ID
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Info  { Write-Host "[meshembed] $args" -ForegroundColor Cyan }
function Ok    { Write-Host "  OK  $args" -ForegroundColor Green }
function Fail  { Write-Host "  ERR $args" -ForegroundColor Red; exit 1 }

# ── Requirements ──────────────────────────────────────────────────────────────
Info "Checking requirements..."

try { $pyver = & python --version 2>&1 } catch { Fail "Python not found. Install from https://python.org" }
if ($pyver -notmatch "3\.(1[0-9]|[2-9]\d)") { Fail "Python 3.10+ required. Found: $pyver" }
Ok $pyver

# Detect NVIDIA GPU
$hasNvidia = $false
try {
    $gpu = (Get-CimInstance Win32_VideoController | Where-Object { $_.Name -match "NVIDIA" } | Select-Object -First 1).Name
    if ($gpu) { Ok "GPU detected: $gpu"; $hasNvidia = $true }
} catch {}
if (-not $hasNvidia) { Info "No NVIDIA GPU detected - CPU mode will be used" }

# ── Invite token ──────────────────────────────────────────────────────────────
if (-not $InviteToken) {
    $InviteToken = Read-Host "Invite token (get one from the operator dashboard)"
}
if (-not $InviteToken) { Fail "Invite token required" }

# ── Install package ───────────────────────────────────────────────────────────
# Install from GitHub until the package is published to PyPI. The
# repository is public so no token is required.
Info "Installing meshembed-node from GitHub..."
$PackageSource = if ($env:MESHEMBED_PACKAGE_SOURCE) {
    $env:MESHEMBED_PACKAGE_SOURCE
} else {
    "git+https://github.com/Clusterhive-io/meshembed-node-agent.git@v0.2.0"
}
& python -m pip install --quiet --upgrade $PackageSource
if ($LASTEXITCODE -ne 0) { Fail "pip install failed" }
Ok "meshembed-node installed"

# ── Self-register ─────────────────────────────────────────────────────────────
Info "Registering node with the backend..."
$registerJson = & python -m meshembed_node register `
    --backend $BackendUrl `
    --invite  $InviteToken `
    --json 2>&1

if ($LASTEXITCODE -ne 0) { Fail "Registration failed:`n$registerJson" }

$reg     = $registerJson | ConvertFrom-Json
$NodeId  = $reg.node_id
$ApiKey  = $reg.api_key
$NodeNum = $reg.node_number
Ok ("Node registered - N-{0:D4}" -f $NodeNum)

# ── Data directory ────────────────────────────────────────────────────────────
$configDir = "$env:USERPROFILE\.meshembed"
New-Item -ItemType Directory -Force -Path $configDir | Out-Null

$envFile = "$configDir\.env"
@"
MESHEMBED_BACKEND=$BackendUrl
MESHEMBED_NODE_API_KEY=$ApiKey
MESHEMBED_NODE_ID=$NodeId
"@ | Set-Content -Path $envFile -Encoding UTF8

# Lock down file permissions to the current user only.
$acl = Get-Acl $envFile
$acl.SetAccessRuleProtection($true, $false)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $env:USERNAME, "FullControl", "Allow"
)
$acl.AddAccessRule($rule)
Set-Acl $envFile $acl

Ok "Credentials saved to $envFile"

# ── Scheduled task (autostart at login) ───────────────────────────────────────
Info "Creating Task Scheduler entry..."

$pythonPath = (& python -c "import sys; print(sys.executable)").Trim()
$taskName   = "MeshEmbed Node"

$action  = New-ScheduledTaskAction `
    -Execute $pythonPath `
    -Argument "-m meshembed_node" `
    -WorkingDirectory $configDir

$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME

$settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit (New-TimeSpan -Hours 0) `
    -RestartCount 999 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -StartWhenAvailable

$envVars = @(
    "MESHEMBED_BACKEND=$BackendUrl",
    "MESHEMBED_NODE_API_KEY=$ApiKey",
    "MESHEMBED_NODE_ID=$NodeId"
)

$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive

$task = New-ScheduledTask `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -Principal $principal

# Unregister if a previous task with the same name exists.
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

Register-ScheduledTask -TaskName $taskName -InputObject $task | Out-Null
Ok "Task registered: '$taskName'"

# Start the daemon now.
Start-ScheduledTask -TaskName $taskName
Ok "Daemon started"

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "Installation complete." -ForegroundColor Green
Write-Host ("  Node:    N-{0:D4} ({1})" -f $NodeNum, $NodeId)
Write-Host "  Logs:    $configDir\node.log  (stdout from the task)"
Write-Host "  Stop:    Stop-ScheduledTask  -TaskName '$taskName'"
Write-Host "  Start:   Start-ScheduledTask -TaskName '$taskName'"
Write-Host "  Uninstall: Unregister-ScheduledTask -TaskName '$taskName' -Confirm:`$false"
