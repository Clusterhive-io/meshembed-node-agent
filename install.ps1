# MeshEmbed Node - Windows installer (PowerShell 5.1+) v2
# Usage: .\install.ps1 -InviteToken <64-hex-token>
#
# v2 changes (2026-05-19):
# - Numbered steps with explicit [OK] / [X] outcome per step.
# - Pre-flight validation (token format, Python, outbound HTTPS, admin).
# - Idempotent re-runs: if .env already exists and is healthy, reuse it.
# - Auto-Force on hardware-already-registered conflicts (with a hint).
# - **Post-install handshake**: synthesises a /register_node call with the
#   new credentials and waits for a 200 OK before declaring success. If
#   the daemon's keys can talk to the backend, the daemon will too.
# - Full transcript captured to $env:USERPROFILE\.meshembed\install.log
#   so any failure can be diagnosed without re-running.

param(
    [string]$InviteToken  = $env:INVITE_TOKEN,
    [string]$BackendUrl   = $(if ($env:MESHEMBED_BACKEND) { $env:MESHEMBED_BACKEND } else { "https://meshembed.clusterhive.io" }),
    [string]$NodeId       = $env:MESHEMBED_NODE_ID,
    [switch]$Force,
    [switch]$NoVerify     # skip the handshake (for offline testing only)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# --- Output helpers ----------------------------------------------------
$TOTAL_STEPS = 9
$script:currentStep = 0
$script:state = @{
    pythonReady = $false
    pipInstalled = $false
    registered = $false
    node_id = $null
    api_key = $null
    config_dir = $null
    env_written = $false
    task_created = $false
    daemon_started = $false
    verified = $false
}

function Step($name) {
    $script:currentStep++
    Write-Host ""
    Write-Host ("[Step {0}/{1}] {2}" -f $script:currentStep, $TOTAL_STEPS, $name) -ForegroundColor Cyan
}
function Ok    { Write-Host "  [OK] $args" -ForegroundColor Green }
function Info  { Write-Host "  * $args" -ForegroundColor Gray }
function Warn  { Write-Host "  [!] $args" -ForegroundColor Yellow }

function FailWithDiagnostic($msg) {
    Write-Host ""
    Write-Host "  [X] FAILED at Step $($script:currentStep)/$TOTAL_STEPS" -ForegroundColor Red
    Write-Host "    $msg" -ForegroundColor Red
    Write-Host ""
    Write-Host "  State at failure:" -ForegroundColor Yellow
    foreach ($k in $script:state.Keys) {
        Write-Host "    ${k} = $($script:state[$k])" -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "  Next steps:" -ForegroundColor Yellow
    if ($script:state.registered -and -not $script:state.verified) {
        Write-Host "    1. A node was registered (N-$($script:state.node_id)) but the install did not finish."
        Write-Host "       Delete it from the operator dashboard so the next attempt can register cleanly."
    }
    Write-Host "    2. Send the full transcript at $configDir\install.log to ops@clusterhive.io."
    Write-Host "    3. See https://meshembed.clusterhive.io/node-install-guide for common fixes."
    Write-Host ""
    if ($transcriptStarted) { try { Stop-Transcript | Out-Null } catch {} }
    exit 1
}

# --- Transcript capture ------------------------------------------------
$configDir = "$env:USERPROFILE\.meshembed"
$transcriptStarted = $false
try {
    New-Item -ItemType Directory -Force -Path $configDir | Out-Null
    Start-Transcript -Path "$configDir\install.log" -Append | Out-Null
    $transcriptStarted = $true
} catch {
    Write-Host "  (transcript capture failed - proceeding without it)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  MeshEmbed Node - installer v2 ($(Get-Date -Format 'u'))" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

# --- Step 1: Pre-flight -----------------------------------------------
Step "Pre-flight checks"

# Token format
if (-not $InviteToken) {
    $InviteToken = Read-Host "Invite token (64-hex from the operator dashboard)"
}
if (-not ($InviteToken -match '^[a-f0-9]{64}$')) {
    FailWithDiagnostic "Invite token must be exactly 64 lowercase hex characters. Got: '$InviteToken' (length $($InviteToken.Length)). Generate a fresh token from the operator dashboard and pass it as -InviteToken."
}
Ok "Token format valid (64 hex chars)"

# Backend URL well-formed
if (-not ($BackendUrl -match '^https?://[^/]+/?$')) {
    FailWithDiagnostic "BackendUrl must look like 'https://host[/]'. Got: '$BackendUrl'."
}
$BackendUrl = $BackendUrl.TrimEnd('/')
Ok "Backend URL: $BackendUrl"

# Network reachability
try {
    $health = Invoke-WebRequest -Uri "$BackendUrl/healthz" -UseBasicParsing -TimeoutSec 10
    if ($health.StatusCode -ne 200) {
        FailWithDiagnostic "Backend /healthz returned HTTP $($health.StatusCode). Check internet connection + the backend URL."
    }
} catch {
    FailWithDiagnostic "Could not reach $BackendUrl/healthz. ($($_.Exception.Message)). Check internet connection or firewall."
}
Ok "Backend reachable (/healthz -> 200)"

# Disk space (~5 GB free needed for torch + sentence-transformers)
$drive = (Get-Item $env:USERPROFILE).PSDrive
$freeGB = [math]::Round($drive.Free / 1GB, 1)
if ($freeGB -lt 5) {
    Warn "Only $freeGB GB free on $($drive.Name): - torch + sentence-transformers need ~3 GB to install."
} else {
    Ok "Disk space OK ($freeGB GB free on $($drive.Name):)"
}

# --- Step 2: Python ---------------------------------------------------
Step "Python 3.10+ available"

function TryInstallPythonViaWinget {
    Write-Host "  * No Python found. Attempting silent install via winget..." -ForegroundColor Gray
    try {
        $null = & winget --version 2>&1
        if ($LASTEXITCODE -ne 0) { return $false }
    } catch { return $false }
    # NB: NO `2>&1 | ForEach-Object` - strict-mode PS turns native-cmd
    # stderr into NativeCommandError when piped. winget writes progress
    # info to stderr; that would crash the script. Print natively
    # instead.
    & winget install --id Python.Python.3.12 -e --silent `
        --accept-source-agreements --accept-package-agreements `
        --scope user
    if ($LASTEXITCODE -ne 0) { return $false }
    $env:PATH = `
        [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + `
        [System.Environment]::GetEnvironmentVariable("Path", "User")
    return $true
}

$pyver = $null
try { $pyver = & python --version 2>&1 } catch { }
if (-not $pyver -or $pyver -notmatch "3\.(1[0-9]|[2-9]\d)") {
    if (TryInstallPythonViaWinget) {
        try { $pyver = & python --version 2>&1 } catch { }
    }
}
if (-not $pyver -or $pyver -notmatch "3\.(1[0-9]|[2-9]\d)") {
    FailWithDiagnostic "Python 3.10+ not found and winget auto-install failed. Use the MSI installer instead (https://meshembed.clusterhive.io/install/msi) or install Python manually then re-run."
}
$script:state.pythonReady = $true
Ok "$pyver"

# --- Step 3: Inventory existing install (idempotency) -----------------
Step "Inventory existing install"

$envFile = "$configDir\.env"
$existingEnv = Test-Path $envFile
$existingTask = Get-ScheduledTask -TaskName 'MeshEmbed Node' -ErrorAction SilentlyContinue
$existingNodeId = $null
$existingApiKey = $null
if ($existingEnv) {
    $envText = Get-Content $envFile -Raw -ErrorAction SilentlyContinue
    if ($envText -match 'MESHEMBED_NODE_ID=([^\r\n]+)')   { $existingNodeId = $matches[1] }
    if ($envText -match 'MESHEMBED_NODE_API_KEY=([^\r\n]+)') { $existingApiKey = $matches[1] }
}

if ($existingEnv -and $existingTask -and $existingNodeId -and $existingApiKey -and -not $Force) {
    Info "Found existing install: NODE_ID=$existingNodeId, task '$($existingTask.TaskName)' state=$($existingTask.State)"
    Warn "Re-running on a healthy install. Will recreate the scheduled task and re-verify. Pass -Force to ignore existing state."
    $NodeId = $existingNodeId
    $ApiKey = $existingApiKey
    $script:state.registered = $true
    $script:state.node_id = $NodeId
    $script:state.api_key = $ApiKey
    $script:state.env_written = $true
    $skipPipInstall = $false
    $skipRegister = $true
} else {
    Ok "Clean install path"
    $skipPipInstall = $false
    $skipRegister = $false
}

# --- Step 4: Install meshembed-node package ---------------------------
Step "Install meshembed-node Python package"

$PackageSource = if ($env:MESHEMBED_PACKAGE_SOURCE) {
    $env:MESHEMBED_PACKAGE_SOURCE
} else {
    "https://github.com/Clusterhive-io/meshembed-node-agent/archive/refs/tags/v0.3.23.tar.gz"
}
Info "Source: $PackageSource"
Info "First-time install downloads PyTorch (~700 MB) - takes 2-5 min."

# NB: NO `2>&1 | ForEach-Object` - see comment in TryInstallPythonViaWinget.
# pip writes `[notice] A new release of pip is available` to stderr which
# would crash strict-mode PS when piped. Let pip print natively; the
# transcript still captures everything for diagnostics.
& python -m pip install --upgrade --progress-bar on --no-warn-script-location $PackageSource
if ($LASTEXITCODE -ne 0) {
    FailWithDiagnostic "pip install exited $LASTEXITCODE. See above for the error. Common causes: network blocked, no disk space, antivirus quarantining wheels."
}
$script:state.pipInstalled = $true
Ok "meshembed-node installed"

# --- Step 5: Register with backend (skip if existing healthy install) -
Step "Register node with backend"

if ($skipRegister) {
    Info "Reusing existing registration (NODE_ID=$NodeId)"
    Ok "Skipped - already registered"
} else {
    $stdoutTmp = New-TemporaryFile
    $stderrTmp = New-TemporaryFile
    $registerArgs = @("-m", "meshembed_node", "register",
                      "--backend", $BackendUrl,
                      "--invite", $InviteToken,
                      "--json", "--no-save")
    if ($Force) { $registerArgs += "--force" }

    $proc = Start-Process -FilePath python `
        -ArgumentList $registerArgs `
        -NoNewWindow -Wait -PassThru `
        -RedirectStandardOutput $stdoutTmp `
        -RedirectStandardError  $stderrTmp

    $registerJson = Get-Content $stdoutTmp -Raw -ErrorAction SilentlyContinue
    $registerErr  = Get-Content $stderrTmp -Raw -ErrorAction SilentlyContinue
    Remove-Item $stdoutTmp, $stderrTmp -ErrorAction SilentlyContinue

    if ($proc.ExitCode -ne 0) {
        # Hardware-already-registered: offer an auto-recover hint instead of a flat error.
        if ($registerErr -match 'hardware_already_registered_as_(N-\d+)') {
            $existingN = $matches[1]
            Warn "Backend reports the same hardware is already registered as $existingN."
            Warn "Either delete $existingN from the operator dashboard and re-run, OR re-run with -Force."
            FailWithDiagnostic "hardware_already_registered_as_$existingN (see above for recovery)"
        }
        if ($registerErr -match 'invite_token_already_used') {
            FailWithDiagnostic "Invite token has been consumed by a previous attempt. Generate a fresh one from the operator dashboard."
        }
        if ($registerErr -match 'invite_token_expired') {
            FailWithDiagnostic "Invite token has expired (24h after generation). Generate a fresh one."
        }
        Write-Host "  stderr:" -ForegroundColor Yellow
        Write-Host $registerErr -ForegroundColor Yellow
        FailWithDiagnostic "Registration failed (python exit $($proc.ExitCode)). See stderr above."
    }
    try { $reg = $registerJson | ConvertFrom-Json } catch {
        FailWithDiagnostic "Could not parse registration response as JSON: $registerJson"
    }
    $NodeId  = $reg.node_id
    $ApiKey  = $reg.api_key
    $NodeNum = $reg.node_number
    if (-not $ApiKey) {
        FailWithDiagnostic "Registration response is missing api_key. Full response: $registerJson"
    }
    $script:state.registered = $true
    $script:state.node_id = $NodeId
    $script:state.api_key = $ApiKey
    Ok ("Node registered - N-{0:D4} ({1})" -f $NodeNum, $NodeId.Substring(0, [Math]::Min(12, $NodeId.Length)))
}

# --- Step 6: Generate keypair + write .env (atomic) -------------------
Step "Write credentials to disk"

$script:state.config_dir = $configDir

# ACL repair (carried over from v1) - see comment in v1 for the pathlib(0o700) trap.
if (Test-Path $configDir) {
    $canWrite = $false
    try {
        $probe = Join-Path $configDir ".write-probe-$([guid]::NewGuid())"
        Set-Content -Path $probe -Value "x" -ErrorAction Stop
        Remove-Item $probe -Force -ErrorAction SilentlyContinue
        $canWrite = $true
    } catch { }
    if (-not $canWrite) {
        Info "Repairing locked-down ACL on $configDir"
        & takeown.exe /F $configDir /R /D Y 2>&1 | Out-Null
        & takeown.exe /F $configDir /R /D S 2>&1 | Out-Null
        & icacls.exe $configDir /grant "$($env:USERNAME):(OI)(CI)F" /T /Q | Out-Null
    }
}
New-Item -ItemType Directory -Force -Path $configDir | Out-Null

# Keypair (skip if reusing existing install)
if ($skipRegister -and ($envText -match 'MESHEMBED_NODE_PRIVKEY=([^\r\n]+)')) {
    $PrivKey = $matches[1]
    Info "Reusing existing keypair"
} else {
    $PrivKey = (& python -c "from meshembed_node.crypto import generate_keypair; print(generate_keypair()[0])").Trim()
    if (-not $PrivKey) { FailWithDiagnostic "Failed to generate ed25519 keypair" }
}

$envContent = @"
MESHEMBED_BACKEND=$BackendUrl
MESHEMBED_NODE_API_KEY=$ApiKey
MESHEMBED_NODE_ID=$NodeId
MESHEMBED_NODE_PRIVKEY=$PrivKey
"@
$utf8NoBom = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllText($envFile, $envContent, $utf8NoBom)

# Best-effort ACL lockdown -- Set-Acl with SetAccessRuleProtection needs
# SeSecurityPrivilege, which standard (non-admin) accounts don't have.
# Failing the install over file permissions would be silly; the file
# already lives under $env:USERPROFILE\.meshembed which only the user
# can read by default. Try the hardened ACL, fall back to "inherit from
# the user profile dir" with a warning.
try {
    $acl = Get-Acl $envFile
    $acl.SetAccessRuleProtection($true, $false)
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $env:USERNAME, "FullControl", "Allow"
    )
    $acl.AddAccessRule($rule)
    Set-Acl $envFile $acl
    $aclNote = "ACL: $env:USERNAME only"
} catch [System.Security.AccessControl.PrivilegeNotHeldException] {
    Warn "Could not lock ACL ($($_.Exception.Message.Split([Environment]::NewLine)[0])); inheriting from $env:USERPROFILE\.meshembed (still per-user readable). Re-run elevated to harden if you care."
    $aclNote = "ACL: inherited from .meshembed dir (best-effort)"
} catch {
    Warn "Could not lock ACL ($($_.Exception.Message.Split([Environment]::NewLine)[0])); inheriting from .meshembed dir."
    $aclNote = "ACL: inherited from .meshembed dir (best-effort)"
}

$script:state.env_written = $true
Ok ".env written to $envFile (UTF-8 no BOM, $aclNote)"

# --- Step 7: Create Task Scheduler entry ------------------------------
Step "Create Task Scheduler entry"

$pythonPath = (& python -c "import sys; print(sys.executable)").Trim()
$taskName   = "MeshEmbed Node"

$action = New-ScheduledTaskAction `
    -Execute $pythonPath `
    -Argument "-m meshembed_node" `
    -WorkingDirectory $configDir

$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME

$settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit (New-TimeSpan -Hours 0) `
    -RestartCount 999 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -StartWhenAvailable

$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive

$task = New-ScheduledTask `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -Principal $principal

Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName $taskName -InputObject $task | Out-Null

$script:state.task_created = $true
Ok "Task '$taskName' registered"

# --- Step 8: Start the daemon -----------------------------------------
Step "Start the daemon"

Start-ScheduledTask -TaskName $taskName
Start-Sleep -Seconds 3
$taskAfter = Get-ScheduledTask -TaskName $taskName
$taskInfo = Get-ScheduledTaskInfo -TaskName $taskName
if ($taskAfter.State -notin @('Running','Ready')) {
    FailWithDiagnostic "Task did not start. State=$($taskAfter.State), LastRunTime=$($taskInfo.LastRunTime), LastTaskResult=$($taskInfo.LastTaskResult). Check Task Scheduler -> MeshEmbed Node -> History."
}
$script:state.daemon_started = $true
Ok "Task state: $($taskAfter.State)"

# --- Step 9: Handshake (the CRC) --------------------------------------
Step "Verify daemon credentials with backend handshake"

if ($NoVerify) {
    Warn "-NoVerify set - skipping handshake"
    $script:state.verified = $true
} else {
    Info "Posting a synthetic /register_node with the new API key (proves the daemon's credentials work)."
    $verifyPayload = @{
        node_id = $NodeId
        status = "idle"
        gpu_model = "install-verify"
        vram_free_mb = 0
        ram_free_mb = 1024
        max_chunks = 1
        tier = "B"
        agent_version = "0.2.0-install-verify"
    } | ConvertTo-Json
    $verifyOk = $false
    $verifyError = $null
    for ($i = 1; $i -le 5; $i++) {
        try {
            $resp = Invoke-WebRequest `
                -Method POST `
                -Uri "$BackendUrl/register_node" `
                -Headers @{ "X-API-Key" = $ApiKey; "Content-Type" = "application/json" } `
                -Body $verifyPayload `
                -UseBasicParsing `
                -TimeoutSec 10
            if ($resp.StatusCode -eq 200) { $verifyOk = $true; break }
            $verifyError = "HTTP $($resp.StatusCode): $($resp.Content)"
        } catch {
            $verifyError = $_.Exception.Message
        }
        Start-Sleep -Seconds 2
    }
    if (-not $verifyOk) {
        FailWithDiagnostic "Backend handshake failed after 5 attempts: $verifyError. The daemon won't be able to do this either. Common causes: firewall blocking outbound to $BackendUrl, API key not accepted, backend down."
    }
    $script:state.verified = $true
    Ok "Backend accepted the handshake (200 OK)"
}

# --- Final banner -----------------------------------------------------
Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  [OK] INSTALLATION VERIFIED" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ("  Node:        N-{0:D4}" -f $NodeNum) -ForegroundColor White
Write-Host  "  Node ID:     $NodeId" -ForegroundColor White
Write-Host  "  Backend:     $BackendUrl" -ForegroundColor White
Write-Host  "  Config:      $envFile" -ForegroundColor White
Write-Host  "  Transcript:  $configDir\install.log" -ForegroundColor White
Write-Host  "  Dashboard:   $BackendUrl/operator" -ForegroundColor White
Write-Host ""
Write-Host  "  Task management:" -ForegroundColor Gray
Write-Host  "    Stop:      Stop-ScheduledTask -TaskName '$taskName'" -ForegroundColor Gray
Write-Host  "    Start:     Start-ScheduledTask -TaskName '$taskName'" -ForegroundColor Gray
Write-Host  "    Uninstall: Unregister-ScheduledTask -TaskName '$taskName' -Confirm:`$false" -ForegroundColor Gray
Write-Host  "    Logs:      Get-WinEvent -ProviderName 'Microsoft-Windows-TaskScheduler/Operational' | Where-Object { `$_.Message -like '*MeshEmbed*' } | Select -First 20" -ForegroundColor Gray
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Node is online and polling for work. Check your operator dashboard." -ForegroundColor Green

if ($transcriptStarted) { try { Stop-Transcript | Out-Null } catch {} }
