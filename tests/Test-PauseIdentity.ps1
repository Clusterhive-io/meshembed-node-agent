#requires -Version 5.1
<#
  Windows check for v0.3.78 final (manual, Windows PowerShell 5.1): the pause tool's daemon identity (P2-F2/P2-F3,
  FX-1), the task Arguments rewrite on upgrade (FX-2) and the task principal check (FX-4).

  It runs the functions extracted from the given install.ps1 -- never copied -- against MOCKED Get-ScheduledTask and
  Get-CimInstance (script functions shadow the cmdlets). It reads no real task or process, registers nothing,
  installs nothing and writes no file: an installed node on this machine is never touched.

  Usage:
      powershell -NoProfile -ExecutionPolicy Bypass -File .\Test-PauseIdentity.ps1 -Installer .\install.ps1
  Output is content-free: "PASS|FAIL <case>" lines and a total. Exit code = number of failures.
#>
param([Parameter(Mandatory = $true)][string]$Installer)
$ErrorActionPreference = "Stop"
$script:pass = 0; $script:fail = 0
function Check($name, [scriptblock]$body) {
    try { & $body; Write-Host "PASS  $name"; $script:pass++ }
    catch { Write-Host "FAIL  $name -- $($_.Exception.Message)"; $script:fail++ }
}
function Want($cond, $what) { if (-not $cond) { throw $what } }

$src = [IO.File]::ReadAllText((Resolve-Path $Installer))
$tool = [regex]::Match($src, "(?s)(function TaskAction \{.*?)\r?\nif \(\`$Action -ne 'Status'")
$main = [regex]::Match($src, "(?s)(function Test-NodeTaskPrincipal\(.*?)\r?\n\`$useS4U = Test-Elevated")
if (-not $tool.Success -or -not $main.Success) { Write-Host "FAIL  functions not found in install.ps1"; exit 1 }
. ([scriptblock]::Create($tool.Groups[1].Value))
. ([scriptblock]::Create($main.Groups[1].Value))

# --- mocks: the only "task" and "processes" these functions can see -------------------------------------------------
$task = 'MeshEmbed Node'
$script:mockTask = $null
$script:mockProcs = @()
function Get-ScheduledTask { param($TaskName, $ErrorAction) $script:mockTask }
function Get-CimInstance { param($ClassName) $script:mockProcs }
$script:calls = @()
function Unregister-ScheduledTask { param($TaskName, $Confirm, $ErrorAction) $script:calls += 'unregister'; if ($script:unregisterFails) { throw 'denied' } }
function Disable-ScheduledTask { param($TaskName, $ErrorAction) $script:calls += 'disable' }
function Start-ScheduledTask { param($TaskName, $ErrorAction) $script:calls += 'start' }
function FailWithDiagnostic($msg) { $script:calls += 'fail'; throw 'FailWithDiagnostic' }   # the real one exits 1

$py = 'C:\Users\nodeuser\AppData\Local\Programs\Python\Python312'
function T($exe, $argv, $state = 'Running') {
    $script:mockTask = [pscustomobject]@{ Actions = @([pscustomobject]@{ Execute = $exe; Arguments = $argv }); State = $state }
}
function P($path, $cmd, $name = $null) {
    if (-not $name) { $name = [IO.Path]::GetFileName($path) }
    [pscustomobject]@{ ExecutablePath = $path; Name = $name; CommandLine = $cmd }
}
$daemonLegacy = P "$py\pythonw.exe" "`"$py\pythonw.exe`" -m meshembed_node"
$daemonRun    = P "$py\pythonw.exe" "`"$py\pythonw.exe`"  -m  meshembed_node run"
$bridge       = P "$py\python.exe" "`"$py\python.exe`" C:\Users\nodeuser\mcp_ssh.py --port 2222"
$pwPass       = P "$py\pythonw.exe" "`"$py\pythonw.exe`" -c pass"
$maint        = P "$py\pythonw.exe" "`"$py\pythonw.exe`" -m meshembed_node maintenance status"
$manifest     = P "$py\pythonw.exe" "`"$py\pythonw.exe`" -m meshembed_node.install_manifest --dir x"
$otherDir     = P "C:\Python312x\pythonw.exe" "`"C:\Python312x\pythonw.exe`" -m meshembed_node"

# --- P2-F3: the task's own Arguments, whatever they are --------------------------------------------------------------
Check "legacy task '-m meshembed_node' (no run): its daemon IS counted" {
    T "$py\pythonw.exe" '-m meshembed_node'; $script:mockProcs = @($daemonLegacy, $bridge, $pwPass)
    $p = NodeProcs; Want ($null -ne $p -and $p.Count -eq 1) "count=$($p.Count)"
}
Check "current task '-m meshembed_node run': its daemon IS counted (whitespace normalised)" {
    T "$py\pythonw.exe" '-m meshembed_node run'; $script:mockProcs = @($daemonRun, $bridge)
    $p = NodeProcs; Want ($null -ne $p -and $p.Count -eq 1) "count=$($p.Count)"
}
Check "changed Arguments still match: no hard-coded command line" {
    T "$py\pythonw.exe" '-m meshembed_node run --x'
    $script:mockProcs = @((P "$py\pythonw.exe" "`"$py\pythonw.exe`" -m meshembed_node run --x"), $maint, $pwPass)
    $p = NodeProcs; Want ($p.Count -eq 1) "count=$($p.Count)"
}
# --- P2-F2: bystanders from the same global Python are NOT the daemon ------------------------------------------------
Check "bystanders (mcp bridge, -c pass, maintenance, install_manifest, a lookalike dir) are NOT counted" {
    T "$py\pythonw.exe" '-m meshembed_node'; $script:mockProcs = @($bridge, $pwPass, $maint, $manifest, $otherDir)
    $p = NodeProcs; Want ($null -ne $p -and $p.Count -eq 0) "count=$($p.Count)"
}
Check "R-1: a daemon in the OTHER module form of the same exe IS counted; other args are not" {
    T "$py\pythonw.exe" '-m meshembed_node run'; $script:mockProcs = @($daemonLegacy, $maint, $manifest)
    $p = NodeProcs; Want ($p.Count -eq 1) "run task, legacy daemon: count=$($p.Count)"
    T "$py\pythonw.exe" '-m meshembed_node'; $script:mockProcs = @($daemonRun, $maint)
    $p = NodeProcs; Want ($p.Count -eq 1) "legacy task, run daemon: count=$($p.Count)"
}
# --- FX-1: cannot tell -> never "stopped" ----------------------------------------------------------------------------
Check "no task: NodeProcs is null (unknown), NodeStopped false" {
    $script:mockTask = $null; $script:mockProcs = @()
    Want ($null -eq (NodeProcs)) "not null"; Want (-not (NodeStopped)) "stopped"
}
Check "unrooted Execute or empty Arguments: unknown" {
    T 'pythonw.exe' '-m meshembed_node'; Want ($null -eq (NodeProcs)) "unrooted not null"
    T "$py\pythonw.exe" '   '; Want ($null -eq (NodeProcs)) "empty args not null"
    Want (-not (NodeStopped)) "stopped"
}
Check "unreadable ExecutablePath: matched on the image name" {
    T "$py\pythonw.exe" '-m meshembed_node'
    $script:mockProcs = @((P $null "`"$py\pythonw.exe`" -m meshembed_node" 'pythonw.exe'), (P $null 'x -m meshembed_node' 'python.exe'))
    $p = NodeProcs; Want ($p.Count -eq 1) "count=$($p.Count)"
}
Check "unreadable CommandLine of the same exe: a possible daemon, counted" {
    T "$py\pythonw.exe" '-m meshembed_node'; $script:mockProcs = @((P "$py\pythonw.exe" $null))
    $p = NodeProcs; Want ($p.Count -eq 1) "count=$($p.Count)"
}
Check "none left: an EMPTY ARRAY (not null); stopped only when the task is not Running" {
    T "$py\pythonw.exe" '-m meshembed_node' 'Disabled'; $script:mockProcs = @($bridge)
    $p = NodeProcs; Want ($null -ne $p -and $p.Count -eq 0) "null or non-empty"; Want (NodeStopped) "not stopped"
    T "$py\pythonw.exe" '-m meshembed_node' 'Running'; Want (-not (NodeStopped)) "stopped while Running"
}
Check "env-var Execute is expanded the way the Task Scheduler would" {
    $env:MESHEMBED_TEST_PY = $py
    T '%MESHEMBED_TEST_PY%\pythonw.exe' '-m meshembed_node'; $script:mockProcs = @($daemonLegacy)
    $p = NodeProcs; Remove-Item Env:\MESHEMBED_TEST_PY; Want ($p.Count -eq 1) "count=$($p.Count)"
}
# --- FX-2 ------------------------------------------------------------------------------------------------------------
Check "FX-2: only the exact legacy form is rewritten" {
    Want ((Resolve-NodeTaskArguments '-m meshembed_node') -eq 'rewrite') "legacy"
    Want ((Resolve-NodeTaskArguments ' -m  meshembed_node ') -eq 'rewrite') "legacy, spaces"
    Want ((Resolve-NodeTaskArguments '-m meshembed_node run') -eq 'keep') "current"
    foreach ($o in '-m MESHEMBED_NODE', '-m meshembed_node --debug', '', '-m other') {
        Want ((Resolve-NodeTaskArguments $o) -eq 'warn') "warn: '$o'"
    }
}
# --- FX-4 ------------------------------------------------------------------------------------------------------------
Check "FX-4: only the user's own account, RunLevel Limited, no group" {
    $me = $env:USERNAME
    $mySid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    function Pr($u, $rl = 'Limited', $g = $null) { [pscustomobject]@{ UserId = $u; RunLevel = $rl; GroupId = $g } }
    Want (Test-NodeTaskPrincipal (Pr $me)) "own"
    $tokDomain, $tokUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name -split '\\', 2
    Want (Test-NodeTaskPrincipal (Pr "$tokDomain\$tokUser")) "own, domain\user from the TOKEN"
    # 160 under OpenSSH (2026-10-27): USERDOMAIN is WORKGROUP while the token's domain is MINIPC. An environment
    # domain that disagrees with the token must be REFUSED (C-2: judged by the token, never by $env:).
    if ($env:USERDOMAIN -and -not [string]::Equals($env:USERDOMAIN, $tokDomain, 'OrdinalIgnoreCase')) {
        Want (-not (Test-NodeTaskPrincipal (Pr "$env:USERDOMAIN\$me"))) "accepted the ENVIRONMENT's domain"
    } else {
        Write-Host "      (note: USERDOMAIN equals the token's domain here; the environment-domain refusal is not exercised)"
    }
    Want (Test-NodeTaskPrincipal (Pr $mySid)) "own SID"
    Want (-not (Test-NodeTaskPrincipal (Pr $me 'Highest'))) "Highest accepted"
    foreach ($s in 'S-1-5-18', 'S-1-5-19', 'S-1-5-20') { Want (-not (Test-NodeTaskPrincipal (Pr $s))) "accepted $s" }
    $localSystemName = ([Security.Principal.SecurityIdentifier]'S-1-5-18').Translate([Security.Principal.NTAccount]).Value
    Want (-not (Test-NodeTaskPrincipal (Pr $localSystemName))) "accepted the local system account by its (local-language) name"
    Want (-not (Test-NodeTaskPrincipal (Pr $me 'Limited' 'S-1-5-32-545'))) "group accepted"
    Want (-not (Test-NodeTaskPrincipal (Pr 'someone-else'))) "other user accepted"
    Want (-not (Test-NodeTaskPrincipal $null)) "null accepted"
}
Check "FX-4 C-2: judged by the token, not the environment; a domain must match too" {
    $tok = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $leaf = ($tok -split '\\', 2)[-1]
    function Pr($u) { [pscustomobject]@{ UserId = $u; RunLevel = 'Limited'; GroupId = $null } }
    Want (Test-NodeTaskPrincipal (Pr $tok)) "the token's own domain\user"
    Want (-not (Test-NodeTaskPrincipal (Pr "OTHERDOMAIN-X\$leaf"))) "same user, another domain accepted"
    $saved = $env:USERNAME
    try {
        $env:USERNAME = 'someone-else'
        Want (Test-NodeTaskPrincipal (Pr $leaf)) "the token's user rejected after USERNAME changed"
        Want (-not (Test-NodeTaskPrincipal (Pr 'someone-else'))) "the environment's USERNAME vouched"
    } finally { $env:USERNAME = $saved }
}
Check "FX-4 C-1: a wrong principal on a fresh install is REMOVED, never started, and the install fails" {
    $script:mockTask = [pscustomobject]@{ Principal = [pscustomobject]@{ UserId = 'S-1-5-18'; RunLevel = 'Limited'; GroupId = $null } }
    $script:calls = @(); $script:unregisterFails = $false
    try { Assert-RegisteredNodeTaskPrincipal 'MeshEmbed Node' } catch {}
    Want (($script:calls -join ',') -eq 'unregister,fail') "calls=$($script:calls -join ',')"
    $script:calls = @(); $script:unregisterFails = $true
    try { Assert-RegisteredNodeTaskPrincipal 'MeshEmbed Node' } catch {}
    Want (($script:calls -join ',') -eq 'unregister,disable,fail') "fallback calls=$($script:calls -join ',')"
    $script:calls = @(); $script:unregisterFails = $false
    $script:mockTask = [pscustomobject]@{ Principal = [pscustomobject]@{ UserId = [Security.Principal.WindowsIdentity]::GetCurrent().Name; RunLevel = 'Limited'; GroupId = $null } }
    Assert-RegisteredNodeTaskPrincipal 'MeshEmbed Node'
    Want ($script:calls.Count -eq 0) "a correct principal touched the task: $($script:calls -join ',')"
}

Write-Host ""
Write-Host "TOTAL pass=$($script:pass) fail=$($script:fail)"
exit $script:fail
