"""F1 + F2 from the 160 side-by-side run (2026-10-15).

F1: with MESHEMBED_NODE_PRIVKEY unset, the daemon logged the generated PRIVATE signing key at WARNING
("Add this line to your .env ...") on every start; a console with it was pasted into chat. The key must
be stored 0600, reused, and never appear in any log record.
F2: re-running `register` with an already-used invite printed an error although this machine was enrolled.
"""
import logging
import os
import stat
import sys
import types
from pathlib import Path

import pytest

from meshembed_node import config as cfgmod


@pytest.fixture(autouse=True)
def _home(monkeypatch, tmp_path):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.delenv("MESHEMBED_NODE_PRIVKEY", raising=False)
    yield tmp_path


def _new():
    obj = cfgmod.Config.__new__(cfgmod.Config)
    obj._autogenerate_keypair()
    return obj


def test_generated_key_is_stored_0600_and_reused(tmp_path):
    a = _new()
    p = tmp_path / ".meshembed" / "node_key"
    assert p.is_file()
    if os.name != "nt":
        assert stat.S_IMODE(p.stat().st_mode) == 0o600
    b = _new()
    assert (b.node_privkey, b.node_pubkey) == (a.node_privkey, a.node_pubkey)


def test_private_key_never_reaches_a_log_record(caplog):
    with caplog.at_level(logging.DEBUG):
        a = _new()
        _new()                                  # the reload path logs too
    assert a.node_privkey not in caplog.text
    assert "MESHEMBED_NODE_PRIVKEY=" not in caplog.text
    assert a.node_pubkey not in caplog.text     # only a short fingerprint of it


def test_env_key_still_wins(monkeypatch, tmp_path):
    from meshembed_node.crypto import generate_keypair
    priv, pub = generate_keypair()
    monkeypatch.setenv("MESHEMBED_NODE_PRIVKEY", priv)
    src = Path(cfgmod.__file__).read_text()
    assert 'privkey_env = os.environ.get("MESHEMBED_NODE_PRIVKEY", "").strip()' in src
    assert not (tmp_path / ".meshembed" / "node_key").exists()


def test_no_code_path_formats_the_private_key_into_a_message():
    src = Path(cfgmod.__file__).read_text()
    assert "MESHEMBED_NODE_PRIVKEY=%s" not in src


# ── F2 ───────────────────────────────────────────────────────────────────────
def _run_register(monkeypatch, tmp_path, env_text):
    from meshembed_node import __main__ as m
    if env_text is not None:
        (tmp_path / ".meshembed").mkdir(exist_ok=True)
        (tmp_path / ".meshembed" / ".env").write_text(env_text)

    class Resp:
        status_code = 409
        def json(self):
            return {"detail": "invite_token_already_used"}
        def raise_for_status(self):
            import requests
            raise requests.HTTPError("409 Conflict", response=self)
    monkeypatch.setattr("requests.post", lambda *a, **k: Resp())
    monkeypatch.setitem(sys.modules, "meshembed_node.fingerprint",
                        types.SimpleNamespace(collect_fingerprint=lambda: ("fp", None, False)))
    args = types.SimpleNamespace(backend="http://sbx:28080", invite="a" * 64, node_id=None, json=False,
                                 no_save=False, force=False, fresh=False)
    with pytest.raises(SystemExit) as e:
        m._cmd_register(args)
    return e.value.code


def test_reused_invite_on_an_enrolled_machine_is_success(monkeypatch, tmp_path, capsys):
    code = _run_register(monkeypatch, tmp_path,
                         "MESHEMBED_BACKEND=http://sbx:28080\nMESHEMBED_NODE_API_KEY=k\nMESHEMBED_NODE_ID=abc123\n")
    assert code == 0
    assert "already enrolled" in capsys.readouterr().out


def test_reused_invite_elsewhere_is_still_an_error(monkeypatch, tmp_path):
    assert _run_register(monkeypatch, tmp_path, None) == 1
    assert _run_register(monkeypatch, tmp_path,
                         "MESHEMBED_BACKEND=https://prod\nMESHEMBED_NODE_API_KEY=k\nMESHEMBED_NODE_ID=x\n") == 1


# ── F4 ───────────────────────────────────────────────────────────────────────
def _register_ok(monkeypatch, *, json_out, no_save):
    from meshembed_node import __main__ as m

    class Resp:
        status_code = 200
        def raise_for_status(self):
            pass
        def json(self):
            return {"node_id": "nid", "node_number": 7, "api_key": "msh_node_SECRETKEY"}
    monkeypatch.setattr("requests.post", lambda *a, **k: Resp())
    monkeypatch.setitem(sys.modules, "meshembed_node.fingerprint",
                        types.SimpleNamespace(collect_fingerprint=lambda: ("fp", None, False)))
    args = types.SimpleNamespace(backend="http://sbx:28080", invite="a" * 64, node_id=None, json=json_out,
                                 no_save=no_save, force=False, fresh=False)
    m._cmd_register(args)


def test_register_never_prints_the_api_key_when_it_saves_it(monkeypatch, tmp_path, capsys):
    _register_ok(monkeypatch, json_out=False, no_save=False)
    out = capsys.readouterr().out
    assert "msh_node_SECRETKEY" not in out and "N-0007" in out and "Credentials saved" in out
    env = tmp_path / ".meshembed" / ".env"
    assert "MESHEMBED_NODE_API_KEY=msh_node_SECRETKEY" in env.read_text()
    if os.name != "nt":
        assert stat.S_IMODE(env.stat().st_mode) == 0o600


def test_register_no_save_must_show_the_only_copy(monkeypatch, capsys):
    _register_ok(monkeypatch, json_out=False, no_save=True)
    out = capsys.readouterr().out
    assert "msh_node_SECRETKEY" in out and "ONLY copy" in out


def test_register_json_is_unchanged_for_the_installers(monkeypatch, capsys):
    _register_ok(monkeypatch, json_out=True, no_save=True)
    assert '"api_key": "msh_node_SECRETKEY"' in capsys.readouterr().out
