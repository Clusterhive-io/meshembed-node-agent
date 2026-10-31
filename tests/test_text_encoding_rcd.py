"""RC-d (auditor 2026-10-30 08:19Z): on Windows the default text encoding is the code page (cp1252), so a text read
or write with no explicit encoding can fail at RUN time, past the first poll the start smoke reaches. Every such call
in the package is listed below with the reason it is safe; a new one fails this test until it is listed or fixed."""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit
PKG = Path(__file__).resolve().parents[1] / "meshembed_node"

# (module, kind) -> why no explicit encoding is needed. kind: read_text / write_text / open / fdopen / run.
ALLOWED = {
    ("agent_host", "fdopen"): "Linux-only (agent host); JSON written by us, ASCII",
    ("agent_host", "read_text"): "Linux-only (agent host); JSON written by us, ASCII",
    ("cpu_guard", "read_text"): "Linux /proc files, ASCII",
    ("cpu_guard", "run"): "macOS sysctl output, ASCII",
    ("encoder", "run"): "macOS sysctl / nvidia-smi output, ASCII",
    ("fingerprint", "open"): "Linux /proc and /sys files, ASCII",
    ("install_manifest", "read_text"): "Linux /proc/cpuinfo, ASCII",
    ("install_manifest", "run"): "uv --version / macOS sysctl output, ASCII",
    ("llm", "run"): "nvidia-smi output, ASCII",
    ("power", "open"): "Linux RAPL /sys files, ASCII",
    ("power", "run"): "nvidia-smi output, ASCII",
    ("resources", "run"): "ioreg (macOS), xprintidle / nmcli (Linux), a fixed powershell word (metered/unmetered/unknown)",
    ("runtime_anomalies", "open"): "Linux /proc/self files, ASCII",
    ("selfcheck", "open"): "os.devnull, written to and discarded",
    ("serve_launch", "read_text"): "Linux-only root launcher; /proc and /sys, ASCII",
    ("split_handoff", "run"): "Linux-only (split stages)",
    ("split_launch", "run"): "Linux-only root launcher",
    ("split_overlay_node", "write_text"): "Linux-only (split overlay); WireGuard config, ASCII",
    ("tpm_quote", "run"): "Linux tpm2 tools, ASCII",
    ("unit_check", "run"): "systemctl, Linux-only",
    ("updater", "run"): "Linux-only root updater",
    ("worker", "open"): "Linux /sys chassis_type, ASCII",
    ("worker", "run"): "the installed version printed by importlib.metadata, ASCII",
}


def _sites():
    out = set()
    for f in sorted(PKG.glob("*.py")):
        for n in ast.walk(ast.parse(f.read_text(encoding="utf-8"))):
            if not isinstance(n, ast.Call) or "encoding" in {k.arg for k in n.keywords}:
                continue
            fn = n.func
            name = fn.attr if isinstance(fn, ast.Attribute) else (fn.id if isinstance(fn, ast.Name) else "")
            if name in ("read_text", "write_text"):
                out.add((f.stem, name))
            elif name in ("open", "fdopen") and not (isinstance(fn, ast.Attribute) and getattr(fn.value, "id", "") == "os"
                                                    and name == "open"):
                mode = next((a.value for a in n.args if isinstance(a, ast.Constant) and isinstance(a.value, str)
                             and set(a.value) <= set("rwabxt+")), None)
                mode = next((k.value.value for k in n.keywords if k.arg == "mode" and isinstance(k.value, ast.Constant)),
                            mode)
                if mode is None or "b" not in mode:
                    out.add((f.stem, name))
            elif name in ("run", "Popen", "check_output") and any(k.arg in ("text", "universal_newlines")
                                                                for k in n.keywords):
                out.add((f.stem, "run"))
    return out


def test_every_text_io_without_an_encoding_is_listed_with_its_reason():
    unlisted = sorted(_sites() - set(ALLOWED))
    assert unlisted == [], f"add encoding='utf-8' (or list it with a reason): {unlisted}"


def test_the_allow_list_has_no_stale_entries():
    assert sorted(set(ALLOWED) - _sites()) == []


def test_the_windows_relevant_calls_are_explicit():
    w = (PKG / "worker.py").read_text(encoding="utf-8")
    i = w.index("interp + [path], env=env, check=False,")
    assert 'encoding="utf-8", errors="replace"' in w[i:i + 200]          # the OTA installer's output
    m = (PKG / "maintenance.py").read_text(encoding="utf-8")
    assert 'encoding="utf-8", errors="replace"' in m


@pytest.mark.parametrize("writer", ["main", "setup"])
def test_both_env_writers_write_utf8_that_config_reads(tmp_path, monkeypatch, writer):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    url = "https://nóde.example"                                    # a non-ASCII value
    if writer == "main":
        from meshembed_node import __main__ as M
        env_file = tmp_path / ".meshembed" / ".env"
        env_file.parent.mkdir(parents=True)
        M._save_credentials(url, "node-1", "key-1")
    else:
        from meshembed_node import setup_server as SS
        SS._save_credentials(url, "node-1", "key-1")
        env_file = tmp_path / ".meshembed" / ".env"
    assert url.encode("utf-8") in env_file.read_bytes()
    assert env_file.read_text(encoding="utf-8-sig").splitlines()[0] == f"MESHEMBED_BACKEND={url}"
