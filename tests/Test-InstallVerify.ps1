#requires -Version 5.1
<#
  Windows check for a PUBLISHED release (manual, Windows PowerShell 5.1). It runs pieces of
  the release's OWN install.ps1 -- extracted from the file, never copied -- against the
  release's published assets. It installs nothing, registers nothing, and reads or writes
  nothing outside -Dir: an installed node on this machine (its .meshembed folder, its
  scheduled task, its Python packages) is never touched.

  Replaces Test-InstallBinding.ps1, which carried a copy of the old verify snippet and
  generated a RAW signature -- so it "proved" the format that could never verify a real
  release (found 2026-10-04).

  Usage (after downloading install.ps1, SHA256SUMS, SHA256SUMS.sig and <tag>.tar.gz into -Dir):
      powershell -NoProfile -ExecutionPolicy Bypass -File .\Test-InstallVerify.ps1 -Dir <dir> -Tag vX.Y.Z
  Needs `python` (3.10+) with `cryptography` on PATH. Expected: "6 passed, 0 failed".
  Exit code = number of failures.
#>
param([Parameter(Mandatory = $true)][string]$Dir, [Parameter(Mandatory = $true)][string]$Tag)
$ErrorActionPreference = "Stop"
$script:pass = 0; $script:fail = 0
function Check($name, [scriptblock]$body) {
    try { & $body; Write-Host "PASS  $name"; $script:pass++ }
    catch { Write-Host "FAIL  $name -- $($_.Exception.Message)"; $script:fail++ }
}
$inst = Join-Path $Dir "install.ps1"
$src = [IO.File]::ReadAllText($inst)
$sums = Join-Path $Dir "SHA256SUMS"; $sig = Join-Path $Dir "SHA256SUMS.sig"
$tar = Join-Path $Dir "$Tag.tar.gz"

# 1. The installer parses on this PowerShell (a syntax error breaks every Windows install/update).
Check "install.ps1 parses with no errors" {
    $tok = $null; $err = $null
    [System.Management.Automation.Language.Parser]::ParseFile($inst, [ref]$tok, [ref]$err) | Out-Null
    if ($err.Count -ne 0) { throw ($err | ForEach-Object { "line $($_.Extent.StartLineNumber): $($_.Message)" }) -join "; " }
}

# 2+3. The installer's own signature snippet, against the published SUMS and a tampered copy.
$m = [regex]::Match($src, "(?s)@'\r?\n(import sys, hashlib\r?\n.*?)'@")
$pub = [regex]::Match($src, '\b[0-9a-f]{64}\b').Value
$py = Join-Path $Dir "verify_snippet.py"
Check "own verify snippet accepts the published SHA256SUMS (pinned key)" {
    if (-not $m.Success) { throw "verify snippet not found in install.ps1" }
    Set-Content -Path $py -Value $m.Groups[1].Value -Encoding ASCII
    $out = & python $py $sums $sig $pub
    if ($LASTEXITCODE -ne 0 -or "$out".Trim() -ne "ok") { throw "rc=$LASTEXITCODE out=$out" }
}
Check "own verify snippet rejects a tampered SHA256SUMS" {
    $bad = Join-Path $Dir "SHA256SUMS.tampered"
    [IO.File]::WriteAllBytes($bad, [IO.File]::ReadAllBytes($sums) + [byte[]](0x0a))
    $prev = $ErrorActionPreference; $ErrorActionPreference = "Continue"
    & python $py $bad $sig $pub 2>$null | Out-Null
    $rc = $LASTEXITCODE; $ErrorActionPreference = $prev
    if ($rc -eq 0) { throw "a tampered SHA256SUMS verified" }
}

# 4. The published tarball is the one SHA256SUMS lists.
Check "tarball sha256 matches its SHA256SUMS entry" {
    $want = $null
    foreach ($ln in [IO.File]::ReadAllLines($sums)) {
        $c = $ln.Trim() -split '\s+', 2
        if ($c.Count -eq 2 -and $c[1].Trim() -eq "$Tag.tar.gz") { $want = $c[0].ToLower() }
    }
    if (-not $want) { throw "$Tag.tar.gz not listed" }
    $got = (Get-FileHash -Algorithm SHA256 -Path $tar).Hash.ToLower()
    if ($got -ne $want) { throw "got $got want $want" }
}

# 5. Fail-closed decision for tags that publish SHA256SUMS (v0.3.66+), from the installer's own lines.
Check "SHA256SUMS required for v0.3.66+ / garbage, optional for an older tag" {
    $lines = ($src -split "\r?\n") | Where-Object { $_ -match '^\$SumsRequired = |^try \{ \$SumsRequired' }
    if (@($lines).Count -ne 2) { throw "SumsRequired lines not found" }
    $code = $lines -join "`n"
    foreach ($case in @(@("v0.3.65", $false), @($Tag, $true), @("garbage", $true))) {
        $ReleaseTag = $case[0]; Invoke-Expression $code
        if ($SumsRequired -ne $case[1]) { throw "$($case[0]) -> $SumsRequired" }
    }
}

# 6. An OLD daemon (no MESHEMBED_DAEMON_PYTHON) launches the installer: the installer's own
#    discovery block finds the parent interpreter. A stand-in meshembed_node on PYTHONPATH (an
#    empty package in -Dir) makes the gate pass without installing anything anywhere.
Check "self-update finds the daemon's interpreter from its parent process" {
    $dm = [regex]::Match($src, '(?s)(\$NodePython = "python"\r?\n.*?\r?\nif \(\$NodePython -ne "python"\)[^\r\n]*)')
    if (-not $dm.Success) { throw "discovery block not found" }
    $disc = Join-Path $Dir "discovery.ps1"
    Set-Content -Path $disc -Encoding ASCII -Value ("function Info(`$m) { }`n" + $dm.Groups[1].Value + "`nWrite-Output `"NODEPY=`$NodePython`"")
    $pkg = Join-Path $Dir "fakepkg\meshembed_node"
    New-Item -ItemType Directory -Force -Path $pkg | Out-Null
    Set-Content -Path (Join-Path $pkg "__init__.py") -Value "" -Encoding ASCII
    $launch = Join-Path $Dir "launch.py"
@'
import os, subprocess, sys
disc, pkgroot, ota = sys.argv[1], sys.argv[2], sys.argv[3] == "1"
env = dict(os.environ, PYTHONPATH=pkgroot)
env.pop("MESHEMBED_DAEMON_PYTHON", None)
env.pop("MESHEMBED_PACKAGE_URL", None)
if ota:
    env["MESHEMBED_PACKAGE_URL"] = "https://example.invalid/v9.9.9.tar.gz"
out = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", disc],
                     env=env, capture_output=True, text=True).stdout
print(out.strip().splitlines()[-1] if out.strip() else "NODEPY=<none>")
'@ | Set-Content -Path $launch -Encoding ASCII
    $exe = "$(& python -c "import sys; print(sys.executable)")".Trim()
    $ota = "$(& python $launch $disc (Split-Path $pkg) 1)".Trim()
    $manual = "$(& python $launch $disc (Split-Path $pkg) 0)".Trim()
    if ($manual -ne "NODEPY=python") { throw "without a self-update it must stay 'python', got $manual" }
    if ($ota -eq "NODEPY=python") {
        throw "during a self-update the parent interpreter was not found (python.exe is $exe; a venv/Store launcher can hide it -- report this line)"
    }
    Write-Host "      found $ota (python.exe on PATH: $exe)"
}

Remove-Item -Recurse -Force (Join-Path $Dir "fakepkg"), $py, (Join-Path $Dir "discovery.ps1"), (Join-Path $Dir "launch.py"), (Join-Path $Dir "SHA256SUMS.tampered") -ErrorAction SilentlyContinue
Write-Host "$($script:pass) passed, $($script:fail) failed"
exit $script:fail
