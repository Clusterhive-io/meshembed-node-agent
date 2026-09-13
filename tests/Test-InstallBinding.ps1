#requires -Version 5.1
<#
  Windows installer regression guard (MANUAL, Windows-only) for the release-
  signature verification + pip-tarball binding in ../install.ps1 (commit 58b7eee).

  The Python guards in this folder (test_installer_release_signature.py,
  test_installer_platform_parity.py) statically pin that the logic EXISTS in the
  script; they run in Linux CI. This harness proves the logic actually WORKS on a
  real Windows PowerShell 5.1 (.NET Framework) runtime -- the one thing CI cannot
  exercise. It generates its own throwaway ed25519 key + signed fixtures, then
  runs the EXACT verify+bind block from install.ps1 against them. No network, no
  real install; the only footprint is a transient `pip install cryptography`
  (which install.ps1 needs anyway) and a temp dir that is deleted at the end.

  KEEP IN SYNC: the Invoke-VerifyAndBind body below is copied verbatim from
  install.ps1. If you change the verify/bind logic there, mirror it here.

  Validated on 192.168.30.160 / MINIPC (user moises), Windows PowerShell 5.1 --
  the fleet's Windows test host. (Not to be confused with the fleet node named
  "PAPA" / 77458, which is unrelated.)

  Run:
      python --version    # need Python 3.10+; else: winget install -e --id Python.Python.3.12
      powershell -ExecutionPolicy Bypass -File .\Test-InstallBinding.ps1
  Expected: 4 passed, 0 failed. Exit code = failure count.
#>
$ErrorActionPreference = "Stop"
$Work = Join-Path $env:TEMP ("meshembed-bindtest-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $Work -Force | Out-Null
try {
    Write-Host "[setup] ensuring cryptography is importable..."
    & python -m pip install --quiet --disable-pip-version-check cryptography
    if ($LASTEXITCODE -ne 0) { throw "could not install cryptography for the harness" }
    $genPy = Join-Path $Work "gen.py"
@'
import sys, hashlib, os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
d = sys.argv[1]
priv = Ed25519PrivateKey.generate()
pub_hex = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
tar = b"MESHEMBED-FAKE-RELEASE-TARBALL-v0.3.50\n" * 64
open(os.path.join(d, "v0.3.50.tar.gz"), "wb").write(tar)
sha = hashlib.sha256(tar).hexdigest()
sums = (sha + "  v0.3.50.tar.gz\n").encode() + b"0" * 64 + b"  install.ps1\n"
open(os.path.join(d, "SHA256SUMS"), "wb").write(sums)
open(os.path.join(d, "SHA256SUMS.sig"), "wb").write(priv.sign(sums))
open(os.path.join(d, "v0.3.50.tar.gz.TAMPERED"), "wb").write(tar + b"EVIL")
open(os.path.join(d, "SHA256SUMS.FORGED"), "wb").write(sums.replace(sha.encode(), b"f" * 64))
open(os.path.join(d, "pubkey.hex"), "w").write(pub_hex)
print("ok")
'@ | Set-Content -Path $genPy -Encoding ASCII
    & python $genPy $Work
    if ($LASTEXITCODE -ne 0) { throw "fixture generation failed" }
    $PubKeyHex = (Get-Content -Raw (Join-Path $Work "pubkey.hex")).Trim()

    # --- verbatim from install.ps1, parameterised to local paths (see KEEP IN SYNC) ---
    function Invoke-VerifyAndBind {
        param($SumsPath, $SigPath, $ReleasePubKeyHex, $TarballName, $TarballLocalSource)
        $verifyPy = Join-Path $env:TEMP "meshembed_verify_sums.py"
@'
import sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
sums, sig, pub_hex = sys.argv[1], sys.argv[2], sys.argv[3]
pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
try:
    pub.verify(open(sig, "rb").read(), open(sums, "rb").read()); print("ok")
except InvalidSignature:
    print("INVALID", file=sys.stderr); sys.exit(1)
'@ | Set-Content -Path $verifyPy -Encoding ASCII
        & python $verifyPy $SumsPath $SigPath $ReleasePubKeyHex
        $sigRc = $LASTEXITCODE
        Remove-Item $verifyPy -ErrorAction SilentlyContinue
        if ($sigRc -ne 0) { throw "release signature verification FAILED - aborting install" }
        $WantSha = $null
        foreach ($ln in [IO.File]::ReadAllLines($SumsPath)) {
            $cols = $ln.Trim() -split '\s+', 2
            if ($cols.Count -eq 2 -and $cols[1].Trim() -eq $TarballName) { $WantSha = $cols[0].Trim().ToLower(); break }
        }
        if ($WantSha) {
            $TarPath = Join-Path $env:TEMP $TarballName
            Copy-Item -Path $TarballLocalSource -Destination $TarPath -Force   # stands in for Invoke-WebRequest
            $GotSha = (Get-FileHash -Algorithm SHA256 -Path $TarPath).Hash.ToLower()
            if ($GotSha -ne $WantSha) { throw "release TARBALL sha256 mismatch - refusing to install tampered code (expected $WantSha, got $GotSha)" }
            return @{ SigOk = $true; Bound = $true; BoundPath = $TarPath }
        } else { return @{ SigOk = $true; Bound = $false; BoundPath = $null } }
    }

    $sums=Join-Path $Work "SHA256SUMS"; $sig=Join-Path $Work "SHA256SUMS.sig"
    $forged=Join-Path $Work "SHA256SUMS.FORGED"; $tar=Join-Path $Work "v0.3.50.tar.gz"
    $tamper=Join-Path $Work "v0.3.50.tar.gz.TAMPERED"; $pass=0; $fail=0
    function Check($name,$ok){ if($ok){Write-Host ("  [PASS] "+$name) -ForegroundColor Green;$script:pass++}else{Write-Host ("  [FAIL] "+$name) -ForegroundColor Red;$script:fail++} }
    Write-Host "`n== install.ps1 verify+bind, real PowerShell $($PSVersionTable.PSVersion) =="
    try { $r=Invoke-VerifyAndBind $sums $sig $PubKeyHex "v0.3.50.tar.gz" $tar; Check "valid signature + matching tarball binds to local copy" ($r.SigOk -and $r.Bound -and (Test-Path $r.BoundPath)) } catch { Check "valid signature + matching tarball binds" $false; Write-Host "    $($_.Exception.Message)" }
    try { Invoke-VerifyAndBind $sums $sig $PubKeyHex "v0.3.50.tar.gz" $tamper | Out-Null; Check "tampered tarball aborts" $false } catch { Check "tampered tarball aborts (sha mismatch)" ($_.Exception.Message -like "*sha256 mismatch*") }
    try { Invoke-VerifyAndBind $forged $sig $PubKeyHex "v0.3.50.tar.gz" $tar | Out-Null; Check "forged SHA256SUMS aborts" $false } catch { Check "forged SHA256SUMS aborts at signature verify" ($_.Exception.Message -like "*signature verification FAILED*") }
    try { $r=Invoke-VerifyAndBind $sums $sig $PubKeyHex "v9.9.9.tar.gz" $tar; Check "unlisted tarball -> graceful skip (no bind, no abort)" ($r.SigOk -and (-not $r.Bound)) } catch { Check "unlisted tarball -> graceful skip" $false; Write-Host "    $($_.Exception.Message)" }
    Write-Host ("`n== $pass passed, $fail failed ==") -ForegroundColor $(if($fail){"Red"}else{"Green"})
    exit $fail
} finally { Remove-Item -Recurse -Force $Work -ErrorAction SilentlyContinue }
