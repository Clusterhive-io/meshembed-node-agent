"""INS-1 (auditor 2026-11-02 08:20:10Z): the single-use invite never goes on the register command line, where every
local user can read it (ps, /proc/<pid>/cmdline) for the seconds the registration takes. The installers pass it in
MESHEMBED_REGISTER_INVITE; `register` reads it from there when --invite is absent and removes it from its own
environment. --invite still works for a person running the command by hand."""
import re
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _register(monkeypatch, tmp_path, invite=None, env=None):
    """Run _cmd_register up to the backend call; returns (exit code or None, the invite sent, env left)."""
    from meshembed_node import __main__ as m
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.delenv("MESHEMBED_REGISTER_INVITE", raising=False)
    if env is not None:
        monkeypatch.setenv("MESHEMBED_REGISTER_INVITE", env)
    sent = {}

    class Resp:
        status_code = 409
        def json(self):
            return {"detail": "invite_token_already_used"}
        def raise_for_status(self):
            import requests
            raise requests.HTTPError("409 Conflict", response=self)

    def post(url, json=None, **k):
        sent["invite"] = (json or {}).get("invite_token")
        return Resp()
    monkeypatch.setattr("requests.post", post)
    monkeypatch.setitem(sys.modules, "meshembed_node.fingerprint",
                        types.SimpleNamespace(collect_fingerprint=lambda: ("fp", None, False)))
    args = types.SimpleNamespace(backend="http://sbx:28080", invite=invite, node_id=None, json=False,
                                 no_save=False, force=False, fresh=False)
    with pytest.raises(SystemExit) as e:
        m._cmd_register(args)
    import os
    return e.value.code, sent.get("invite"), os.environ.get("MESHEMBED_REGISTER_INVITE")


def test_the_invite_is_read_from_the_environment_and_removed(monkeypatch, tmp_path):
    code, sent, left = _register(monkeypatch, tmp_path, env="b" * 64)
    assert sent == "b" * 64            # it reached the backend call
    assert left is None                # and no longer sits in the process environment


def test_an_explicit_invite_still_wins(monkeypatch, tmp_path):
    code, sent, left = _register(monkeypatch, tmp_path, invite="c" * 64, env="b" * 64)
    assert sent == "c" * 64


def test_no_invite_anywhere_is_a_format_error(monkeypatch, tmp_path, capsys):
    code, sent, _ = _register(monkeypatch, tmp_path)
    assert code == 2 and sent is None and "invite token format invalid" in capsys.readouterr().err


def test_a_malformed_env_invite_is_refused_before_any_call(monkeypatch, tmp_path):
    code, sent, _ = _register(monkeypatch, tmp_path, env="not-hex")
    assert code == 2 and sent is None


@pytest.mark.parametrize("name", ["install.sh", "install-mac.sh", "install.ps1"])
def test_no_installer_puts_the_invite_on_the_register_command_line(name):
    src = (ROOT / name).read_text()
    assert "MESHEMBED_REGISTER_INVITE" in src
    # the register invocation itself never carries --invite (the token)
    blocks = re.findall(r"meshembed_node[\"']?,?\s*[\"']?register[\s\S]{0,400}?(?:--json|\))", src)
    assert blocks, name
    for b in blocks:
        assert "--invite" not in b, (name, b[:200])


def test_the_windows_installer_clears_the_variable_after_the_call():
    src = (ROOT / "install.ps1").read_text()
    i = src.index("$env:MESHEMBED_REGISTER_INVITE = $InviteToken")
    assert "Remove-Item Env:MESHEMBED_REGISTER_INVITE" in src[i:i + 600] and "finally" in src[i:i + 600]
