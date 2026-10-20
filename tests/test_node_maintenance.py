"""Install manifest + `meshembed-node maintenance` + installer contract (v0.3.75).

docs/DESIGN_NODE_MAINTENANCE_2026-10-14.md and DESIGN_CPU_FEATURE_GUARD (B). The auditor's
build-time conditions (2026-10-14 21:31Z) are pinned here: no bare pip/uv install of a wheel
in maintenance; llm-enable only through the signed installer; never loosen permissions;
manifest 0600 without secrets; the same contract in all three installers.
"""
import json
import os
import re
import stat
import subprocess
import sys
import types
from pathlib import Path

import pytest

from meshembed_node import cpu_guard, install_manifest, maintenance

_ROOT = Path(__file__).resolve().parents[1]
_INSTALLERS = ("install.sh", "install-mac.sh", "install.ps1")


@pytest.fixture(autouse=True)
def _home(monkeypatch, tmp_path):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setattr(cpu_guard, "_VERDICT", None)
    yield tmp_path


# ── manifest ─────────────────────────────────────────────────────────────────
def test_manifest_written_owner_only_without_secrets(tmp_path, monkeypatch):
    monkeypatch.setenv("MESHEMBED_NODE_API_KEY", "sk-should-never-appear")
    doc = install_manifest.build(kind="fresh", tag="v0.3.75", base="uv", llm_build=None,
                                 llm_skipped="cpu_unsupported:avx2", uv=None)
    path = install_manifest.write(tmp_path / ".meshembed", doc)
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    text = path.read_text()
    assert "sk-should-never-appear" not in text
    back = install_manifest.read()
    assert back["schema"] == 1 and back["installer"]["tag"] == "v0.3.75"
    assert back["extras"]["llm_runtime"]["skipped_reason"] == "cpu_unsupported:avx2"
    s = install_manifest.summary()
    assert s["llm_skipped"] == "cpu_unsupported:avx2"
    assert all(isinstance(v, (str, bool, type(None))) for v in s.values())


def test_manifest_cli(tmp_path):
    rc = install_manifest.main(["--dir", str(tmp_path / "cfg"), "--kind", "upgrade", "--tag", "v0.3.75",
                                "--llm-build", "", "--llm-skipped", "", "--uv", ""])
    assert rc == 0
    doc = json.loads((tmp_path / "cfg" / "install.json").read_text())
    assert doc["installer"]["kind"] == "upgrade" and doc["tools"]["uv"] is None


def test_manifest_never_imports_the_runtime(monkeypatch):
    import builtins
    real = builtins.__import__
    monkeypatch.setattr(builtins, "__import__", lambda n, *a, **k: (_ for _ in ()).throw(
        AssertionError("imported llama_cpp")) if n.startswith("llama_cpp") else real(n, *a, **k))
    install_manifest.build(kind="fresh", tag=None, base=None, llm_build=None, llm_skipped=None, uv=None)


# ── maintenance ──────────────────────────────────────────────────────────────
class _Runs:
    def __init__(self, rc=0):
        self.cmds, self.rc = [], rc

    def __call__(self, cmd, timeout=120):
        self.cmds.append(cmd)
        return types.SimpleNamespace(returncode=self.rc, stdout="", stderr="")


def test_llm_enable_refused_on_an_unsupported_cpu(monkeypatch):
    monkeypatch.setattr(cpu_guard, "cpu_flags", lambda *a, **k: {"sse4_2"})
    monkeypatch.setattr(cpu_guard, "_is_x86", lambda m=None: True)
    called = []
    assert maintenance.llm_enable(perform=lambda *a, **k: called.append(1)) == maintenance.EXIT_REFUSED
    assert not called


def test_llm_enable_goes_through_the_signed_installer_without_reexec(monkeypatch):
    monkeypatch.setattr(cpu_guard, "cpu_flags", lambda *a, **k: {"avx2", "fma", "f16c"})
    monkeypatch.setattr(maintenance, "_needs_root", lambda: False)
    seen = {}
    assert maintenance.llm_enable(perform=lambda tag, **kw: seen.update(tag=tag, **kw)) == 0
    assert seen["enable_llm"] is True and seen["reexec"] is False and seen["tag"].startswith("v")


def test_root_owned_install_asks_for_sudo_and_changes_nothing(monkeypatch):
    monkeypatch.setattr(maintenance, "_needs_root", lambda: True)
    monkeypatch.setattr(cpu_guard, "cpu_flags", lambda *a, **k: {"avx2", "fma", "f16c"})
    runs = _Runs()
    assert maintenance.llm_disable(run=runs) == maintenance.EXIT_NEED_ROOT
    assert maintenance.repair_venv(run=runs) == maintenance.EXIT_NEED_ROOT
    assert maintenance.llm_enable(perform=lambda *a, **k: pytest.fail("ran")) == maintenance.EXIT_NEED_ROOT
    assert runs.cmds == []


def test_llm_disable_uninstalls_with_the_recorded_tool_and_saves_the_flag(monkeypatch, tmp_path):
    monkeypatch.setattr(maintenance, "_needs_root", lambda: False)
    monkeypatch.setattr(cpu_guard, "runtime_installed", lambda: True)
    uv = tmp_path / "uv"
    uv.write_text("#!/bin/sh\n")
    uv.chmod(0o755)
    doc = install_manifest.build(kind="fresh", tag="v0.3.75", base="uv", llm_build="cpu",
                                 llm_skipped=None, uv=None)
    doc["tools"]["uv"] = {"path": str(uv), "version": "0.11.19"}
    install_manifest.write(tmp_path / ".meshembed", doc)
    runs = _Runs()
    assert maintenance.llm_disable(run=runs) == 0
    assert runs.cmds == [[str(uv), "pip", "uninstall", "--python", sys.executable, "llama-cpp-python"]]
    assert "MESHEMBED_ENABLE_LLM=0" in (tmp_path / ".meshembed" / ".env").read_text()
    assert install_manifest.read()["extras"]["llm_runtime"]["installed"] is False


def test_llm_disable_falls_back_to_pip(monkeypatch):
    monkeypatch.setattr(maintenance, "_needs_root", lambda: False)
    monkeypatch.setattr(cpu_guard, "runtime_installed", lambda: True)
    monkeypatch.setattr(maintenance.shutil, "which", lambda name: None)
    runs = _Runs()
    assert maintenance.llm_disable(run=runs) == 0
    assert runs.cmds == [[sys.executable, "-m", "pip", "uninstall", "-y", "llama-cpp-python"]]


def test_repair_venv_uses_ensurepip_only(monkeypatch):
    monkeypatch.setattr(maintenance, "_needs_root", lambda: False)
    state = {"pip": False}

    def run(cmd, timeout=120):
        if cmd[1:3] == ["-m", "ensurepip"]:
            state["pip"] = True
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")
        if cmd[1:4] == ["-m", "pip", "--version"]:
            return types.SimpleNamespace(returncode=0 if state["pip"] else 1, stdout="", stderr="")
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")
    assert maintenance.repair_venv(run=run) == 0
    assert state["pip"]


def test_maintenance_never_pip_installs_a_wheel():
    """Auditor condition: removal is allowed, installation only via the signed installer."""
    src = (_ROOT / "meshembed_node" / "maintenance.py").read_text()
    assert not re.search(r'"pip",\s*"install"', src)
    assert not re.search(r"pip install", src.replace("never a bare pip\n  install", ""))
    assert "chmod" not in src and "chown" not in src


# ── installers ───────────────────────────────────────────────────────────────
@pytest.mark.parametrize("name", _INSTALLERS)
def test_every_installer_guards_the_cpu_seeds_pip_and_writes_the_manifest(name):
    body = (_ROOT / name).read_text()
    assert "DESIGN_CPU_FEATURE_GUARD_2026-10-14" in body
    assert "cpu_unsupported:" in body
    assert "ensurepip" in body
    assert "meshembed_node.install_manifest" in body
    assert "MESHEMBED_ENABLE_LLM=0" in body                     # the decision is remembered


def test_linux_venv_is_seeded_and_uv_has_a_fixed_path():
    body = (_ROOT / "install.sh").read_text()
    assert "uv venv --seed" in body
    assert 'UV_FIXED_DIR="${MESHEMBED_UV_DIR:-$HOME/.meshembed/bin}"' in body


def test_uv_is_sha256_pinned_and_fail_closed():
    """Auditor 2026-10-14 22:00Z: uv is executable code fetched from outside."""
    body = (_ROOT / "install.sh").read_text()
    assert "astral.sh" not in body                                    # no curl | sh any more
    fn = re.search(r"^ensure_uv\(\) \{.*?^\}", body, re.S | re.M).group(0)
    assert 'uv_pinned_sha "$_t"' in fn and "sha256sum" in fn
    assert fn.index("sha256sum") < fn.index("tar -xzf")            # verified before unpacking
    assert "refusing to run it" in fn
    pins = re.search(r"^uv_pinned_sha\(\) \{.*?^\}", body, re.S | re.M).group(0)
    assert re.search(r"x86_64-unknown-linux-gnu\)\s+echo [0-9a-f]{64}", pins)
    assert re.search(r"aarch64-unknown-linux-gnu\)\s+echo [0-9a-f]{64}", pins)


def _cpu_missing(cpuinfo: str, tmp_path) -> str:
    fn = re.search(r"^_llm_cpu_missing\(\) \{.*?^\}", (_ROOT / "install.sh").read_text(), re.S | re.M).group(0)
    f = tmp_path / "cpuinfo"
    f.write_text(cpuinfo)
    out = subprocess.run(["bash", "-c", fn + "\n_llm_cpu_missing"], capture_output=True, text=True,
                         env={**os.environ, "MESHEMBED_TEST_CPUINFO": str(f)})
    return out.stdout.strip()


@pytest.mark.skipif(os.name == "nt", reason="bash")
def test_install_sh_cpu_check(tmp_path):
    if os.uname().machine not in ("x86_64",):
        pytest.skip("the check only applies on x86")
    assert _cpu_missing("flags\t: fpu sse4_2 popcnt\n", tmp_path) == "avx2 fma f16c"
    assert _cpu_missing("flags\t: fpu avx avx2 fma f16c\n", tmp_path) == ""
    assert _cpu_missing("", tmp_path) == ""                    # unknown: never blocks


# ── F1/F4 rotation check (orchestrator 2026-10-16 06:00Z): labels only, never key material ──
def _status_json(capsys, run=None):
    maintenance.status(as_json=True, run=run or (lambda *a, **k: types.SimpleNamespace(returncode=1)))
    return json.loads(capsys.readouterr().out)


def _env(tmp_path, text):
    (tmp_path / ".meshembed").mkdir(exist_ok=True)
    (tmp_path / ".meshembed" / ".env").write_text(text)


@pytest.fixture
def _no_service(monkeypatch):
    monkeypatch.setattr(maintenance, "_service_present", lambda run=None: False)
    monkeypatch.delenv("MESHEMBED_NODE_PRIVKEY", raising=False)
    monkeypatch.delenv("MESHEMBED_NODE_API_KEY", raising=False)


def test_signing_key_source_labels(tmp_path, monkeypatch, capsys, _no_service):
    assert _status_json(capsys)["signing_key"] == "none"
    (tmp_path / ".meshembed").mkdir()
    (tmp_path / ".meshembed" / "node_key").write_text("ab" * 32)
    assert _status_json(capsys)["signing_key"] == "node_key file"
    _env(tmp_path, "MESHEMBED_NODE_PRIVKEY=\n")                       # empty value does not count
    assert _status_json(capsys)["signing_key"] == "node_key file"
    _env(tmp_path, "MESHEMBED_NODE_PRIVKEY=" + "cd" * 32 + "\n")
    assert _status_json(capsys)["signing_key"] == ".env"
    monkeypatch.setenv("MESHEMBED_NODE_PRIVKEY", "ef" * 32)
    assert _status_json(capsys)["signing_key"] == "environment"


def test_enrolment_evidence(tmp_path, monkeypatch, capsys, _no_service):
    assert _status_json(capsys)["enrolment"] == "not enrolled"
    _env(tmp_path, "MESHEMBED_NODE_API_KEY=msh_node_SECRET\nMESHEMBED_NODE_ID=x\n")
    assert _status_json(capsys)["enrolment"] == "manual"
    monkeypatch.setattr(maintenance, "_service_present", lambda run=None: True)
    assert _status_json(capsys)["enrolment"] == "installer (service, before v0.3.75)"
    install_manifest.write(tmp_path / ".meshembed", {"schema": 1})
    assert _status_json(capsys)["enrolment"] == "installer (manifest)"


def test_status_never_prints_key_material(tmp_path, monkeypatch, capsys, _no_service):
    priv, api = "9f" * 32, "msh_node_TOPSECRET"
    _env(tmp_path, f"MESHEMBED_NODE_API_KEY={api}\nMESHEMBED_NODE_PRIVKEY={priv}\n")
    (tmp_path / ".meshembed" / "node_key").write_text("aa" * 32)
    maintenance.status(as_json=False, run=lambda *a, **k: types.SimpleNamespace(returncode=1))
    text = capsys.readouterr().out
    maintenance.status(as_json=True, run=lambda *a, **k: types.SimpleNamespace(returncode=1))
    text += capsys.readouterr().out
    assert priv not in text and api not in text and "aa" * 32 not in text
    assert "signing key   .env" in text and "enrolment     manual" in text and "rotate" in text


def test_windows_service_check_uses_the_installer_task_name(monkeypatch):
    monkeypatch.setattr(maintenance.platform, "system", lambda: "Windows")
    seen = []
    def run(cmd, timeout=0):
        seen.append(cmd)
        return types.SimpleNamespace(returncode=0)
    assert maintenance._service_present(run) is True
    assert seen == [["schtasks", "/Query", "/TN", "MeshEmbed Node"]]
    assert "'MeshEmbed Node'" in (_ROOT / "install.ps1").read_text(encoding="utf-8")
