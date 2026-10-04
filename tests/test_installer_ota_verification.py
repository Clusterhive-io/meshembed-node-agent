"""Self-updates verify the release like first installs (auditor 2026-10-04).

Before: install.sh and install.ps1 skipped the SHA256SUMS block when the daemon ran them
(MESHEMBED_PACKAGE_URL set), so a self-update pip-installed GitHub's archive with no hash
binding; install-mac.sh ran the check on a bare python3 without `cryptography` and every
Mac self-update failed. Now every installer runs the block, verifies with the daemon's
own interpreter (MESHEMBED_DAEMON_PYTHON) when given, and fetches `cryptography` as
wheels only, within a bounded range, and only when it is missing.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _src(name: str) -> str:
    return (ROOT / name).read_text()


def test_no_installer_skips_verification_on_a_self_update():
    assert '[ -n "$RELEASE_PUBKEY_HEX" ] && [ -z "${MESHEMBED_PACKAGE_URL:-}" ]' not in _src("install.sh")
    assert 'if [ -z "${MESHEMBED_PACKAGE_URL:-}" ]; then\n            _TARBALL_NAME' not in _src("install.sh")
    assert "-not $env:MESHEMBED_PACKAGE_URL" not in _src("install.ps1")


def test_verification_prefers_the_daemons_own_interpreter():
    sh = _src("install.sh")
    assert 'for _c in "${MESHEMBED_DAEMON_PYTHON:-}" "$(_parent_python)"' in sh
    assert '"$_VERIFY_PY" - "$TMPSIG/SHA256SUMS"' in sh
    assert 'CANDIDATES=("${MESHEMBED_DAEMON_PYTHON:-}" "$DAEMON_PY_FOUND" "${CANDIDATES[@]}")' in _src("install-mac.sh")
    ps = _src("install.ps1")
    assert "$env:MESHEMBED_DAEMON_PYTHON" in ps and "& $VerifyPython $verifyPy" in ps
    worker = (ROOT / "meshembed_node" / "worker.py").read_text()
    assert 'env["MESHEMBED_DAEMON_PYTHON"] = _sys.executable' in worker


def test_cryptography_is_fetched_as_wheels_in_a_bounded_range():
    for name in ("install-mac.sh", "install.ps1"):
        src = _src(name)
        assert '--only-binary=:all: "cryptography>=42,<47"' in src, name
    region = _src("install.sh").split('_VERIFY_PY=""')[1].split("PYEOF")[0]
    pips = [l for l in region.splitlines() if "pip install" in l]
    assert pips and all('--python "$TMPSIG/verify-venv/bin/python"' in l for l in pips), \
        "Linux never pip-installs into the system or the daemon's Python before verifying"
    assert all('--only-binary :all: "cryptography>=42,<47"' in l for l in pips)


def test_linux_finds_the_daemons_python_from_its_parent_process(tmp_path):
    """An old daemon (no MESHEMBED_DAEMON_PYTHON) runs `bash <installer>`: the installer's
    parent is the daemon, whose interpreter has `cryptography`. A python3 on PATH without it
    must not be chosen -- the case that would have stranded Linux nodes."""
    import subprocess
    import sys
    src = _src("install.sh")
    helpers = src[src.index("_parent_python() {"):src.index("# ── Verify release signature")]
    select = src[src.index('        _VERIFY_PY=""'):src.index('        info "  verifying with $_VERIFY_PY"')]
    (tmp_path / "bin").mkdir()
    fake = tmp_path / "bin" / "python3"   # a python3 that has no `cryptography`
    fake.write_text("#!/bin/sh\nexit 1\n")
    fake.chmod(0o755)
    script = tmp_path / "sel.sh"
    script.write_text(
        "set -euo pipefail\ninfo() { :; }\nfail() { echo FAIL; exit 42; }\n"
        "ensure_uv() { echo NEEDED_UV; exit 43; }\nTMPSIG=/nonexistent\n"
        + helpers + select + 'echo "VERIFY_PY=$_VERIFY_PY"\n'
    )
    env = {"PATH": f"{tmp_path / 'bin'}:/usr/bin:/bin",
           "MESHEMBED_PACKAGE_URL": "https://example.invalid/v9.9.9.tar.gz"}
    # The "daemon": an absolute interpreter path that has cryptography, running bash.
    p = subprocess.run(
        [sys.executable, "-c", f"import subprocess,sys; sys.exit(subprocess.run(['bash', {str(script)!r}]).returncode)"],
        capture_output=True, text=True, env=env, timeout=60,
    )
    assert p.returncode == 0, p.stdout + p.stderr
    assert f"VERIFY_PY={sys.executable}" in p.stdout, p.stdout
    # Not a self-update (no MESHEMBED_PACKAGE_URL): the parent is never trusted.
    env.pop("MESHEMBED_PACKAGE_URL")
    p = subprocess.run(
        [sys.executable, "-c", f"import subprocess,sys; sys.exit(subprocess.run(['bash', {str(script)!r}]).returncode)"],
        capture_output=True, text=True, env=env, timeout=60,
    )
    assert "NEEDED_UV" in p.stdout, p.stdout


def test_mac_upgrade_tolerates_a_line_missing_from_env():
    """A missing .env line must reach the env fallback, not end the script under pipefail."""
    src = _src("install-mac.sh")
    for var in ("MESHEMBED_NODE_ID", "MESHEMBED_NODE_API_KEY", "MESHEMBED_NODE_PRIVKEY"):
        line = next(l for l in src.splitlines() if f"grep '^{var}='" in l and '"$EXISTING_ENV"' in l)
        assert line.rstrip().endswith("|| true)"), line
