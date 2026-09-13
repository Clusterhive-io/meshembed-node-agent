# Cross-platform generation determinism check — run on a Windows node.
#
# docs/LLM_DETERMINISM.md. Answers one question: does this machine produce the
# SAME tokens as the reference host for our real canary prompts? If it does not,
# an honest Windows node would fail our canaries, and the verdict bands need
# widening before generation is offered on Windows at all.
#
# Windows matters here beyond the CPU: llama.cpp is built with a different
# compiler (MSVC rather than GCC), which can select different instructions for
# the same arithmetic. That is a different "dispatch" in exactly the sense the
# cross-vendor test on Linux could not cover.
#
# Leaves nothing installed: the runtime is unpacked into a temp folder and the
# whole folder is deleted at the end.
#
#   powershell -ExecutionPolicy Bypass -File check_determinism.ps1 -Canaries canaries.json
#
# Then send back determinism-result.json.

param(
  [Parameter(Mandatory=$true)][string]$Canaries,
  [string]$Out = "determinism-result.json"
)

$ErrorActionPreference = "Stop"
$work = Join-Path $env:TEMP "meshembed-determinism"
if (Test-Path $work) { Remove-Item -Recurse -Force $work }
New-Item -ItemType Directory -Path $work | Out-Null

try {
    $py = (Get-Command python -ErrorAction SilentlyContinue)
    if (-not $py) { throw "python not found on PATH" }
    Write-Host "  python: $(python -V 2>&1)"

    Write-Host "  installing the runtime into $work (nothing is installed system-wide)"
    python -m pip install --quiet --only-binary :all: --target "$work\lib" `
        --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/cpu `
        llama-cpp-python==0.3.35
    if ($LASTEXITCODE -ne 0) { throw "runtime install failed" }

    $model = Join-Path $work "qwen.gguf"
    Write-Host "  downloading the pinned artifact (469 MB)"
    Invoke-WebRequest -UseBasicParsing -Uri `
      "https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/resolve/main/qwen2.5-0.5b-instruct-q4_k_m.gguf" `
      -OutFile $model
    $sha = (Get-FileHash $model -Algorithm SHA256).Hash.ToLower()
    $want = "74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db"
    if ($sha -ne $want) { throw "artifact digest mismatch: got $sha" }
    Write-Host "  digest verified"

    $runner = Join-Path $work "run.py"
@'
import json, platform, sys
from llama_cpp import Llama, __version__
cat = json.load(open(sys.argv[1], encoding="utf-8"))["canaries"]
m = Llama(model_path=sys.argv[2], n_ctx=4096, verbose=False, n_threads=2)
try:
    raw = __import__("llama_cpp").llama_print_system_info()
    simd = raw.decode() if isinstance(raw, bytes) else str(raw)
except Exception:
    simd = None
out = []
for c in cat:
    r = m.create_chat_completion(
        messages=[{"role": "user", "content": c["prompt"]}], **c["model_params"])
    out.append({"prompt": c["prompt"],
                "got": r["choices"][0]["message"]["content"],
                "reference": c["ground_truth_text"]})
json.dump({"host": platform.node(), "os": platform.platform(),
           "cpu": platform.processor(), "llama_cpp": __version__,
           "simd": simd, "results": out},
          open(sys.argv[3], "w", encoding="utf-8"), ensure_ascii=False, indent=2)
'@ | Set-Content -Encoding UTF8 $runner

    Write-Host "  generating"
    $env:PYTHONPATH = "$work\lib"
    python $runner (Resolve-Path $Canaries) $model $Out
    if ($LASTEXITCODE -ne 0) { throw "generation failed" }

    $r = Get-Content $Out -Raw | ConvertFrom-Json
    $same = 0
    foreach ($x in $r.results) { if ($x.got -ceq $x.reference) { $same++ } }
    Write-Host ""
    Write-Host "  $same of $($r.results.Count) byte-identical to the reference host"
    Write-Host "  result written to $Out -- send this file back"
}
finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
    Write-Host "  temp folder removed"
}
