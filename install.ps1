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
Info "  This downloads PyTorch (~800 MB), sentence-transformers and a few"
Info "  small deps. First-time install takes 2-5 minutes on a typical"
Info "  broadband connection; pip will print progress lines as it goes."
$PackageSource = if ($env:MESHEMBED_PACKAGE_SOURCE) {
    $env:MESHEMBED_PACKAGE_SOURCE
} else {
    "git+https://github.com/Clusterhive-io/meshembed-node-agent.git@v0.2.0"
}
# No --quiet: we want pip's per-package progress so the user can see
# the install is alive (downloading torch can easily take 2+ min).
& python -m pip install --upgrade --progress-bar on $PackageSource
if ($LASTEXITCODE -ne 0) { Fail "pip install failed" }
Ok "meshembed-node installed"

# ── Self-register ─────────────────────────────────────────────────────────────
# Capture stdout and stderr to SEPARATE temp files so any Python
# warnings on stderr don't trip PowerShell's strict-mode error
# handling. `--no-save` keeps Python out of file-creation territory
# (different POSIX vs Windows perm models) - we write the .env from
# PowerShell below where we control the ACL precisely.
Info "Registering node with the backend..."
$stdoutTmp = New-TemporaryFile
$stderrTmp = New-TemporaryFile
$proc = Start-Process -FilePath python `
    -ArgumentList @("-m", "meshembed_node", "register",
                    "--backend", $BackendUrl,
                    "--invite", $InviteToken,
                    "--json", "--no-save") `
    -NoNewWindow -Wait -PassThru `
    -RedirectStandardOutput $stdoutTmp `
    -RedirectStandardError  $stderrTmp

$registerJson = Get-Content $stdoutTmp -Raw -ErrorAction SilentlyContinue
$registerErr  = Get-Content $stderrTmp -Raw -ErrorAction SilentlyContinue
Remove-Item $stdoutTmp, $stderrTmp -ErrorAction SilentlyContinue

if ($proc.ExitCode -ne 0) {
    Write-Host ""
    Write-Host "  stderr:" -ForegroundColor Yellow
    Write-Host $registerErr
    Fail "Registration failed (python exit $($proc.ExitCode))"
}

# Defensive: if Python printed any stderr on the success path (e.g. a
# DeprecationWarning), surface it as info rather than treating as fatal.
if ($registerErr) {
    Info "  python stderr (non-fatal):"
    $registerErr.TrimEnd() -split "`n" | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
}

try {
    $reg = $registerJson | ConvertFrom-Json
} catch {
    Fail "Could not parse registration response as JSON:`n$registerJson"
}
$NodeId  = $reg.node_id
$ApiKey  = $reg.api_key
$NodeNum = $reg.node_number
if (-not $ApiKey) { Fail "Registration response is missing api_key. Full response:`n$registerJson" }
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
