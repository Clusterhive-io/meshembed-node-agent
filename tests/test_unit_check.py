"""The daemon warns at start when its unit carries the node API key inline -- and never logs the value."""
import logging
import types

from meshembed_node import unit_check as U


def _run(stdout):
    return lambda *a, **k: types.SimpleNamespace(stdout=stdout)


def test_a_key_in_the_unit_is_reported_without_its_value(monkeypatch, caplog):
    monkeypatch.setattr(U.platform, "system", lambda: "Linux")
    monkeypatch.setattr(U.shutil, "which", lambda n: "/usr/bin/systemctl")
    with caplog.at_level(logging.WARNING):
        assert U.warn_if_key_in_unit(_run("HOME=/home/a MESHEMBED_NODE_API_KEY=msh_node_SECRET MESHEMBED_NODE_ID=x"))
    assert "inline" in caplog.text and "msh_node_SECRET" not in caplog.text


def test_a_clean_unit_says_nothing(monkeypatch, caplog):
    monkeypatch.setattr(U.platform, "system", lambda: "Linux")
    monkeypatch.setattr(U.shutil, "which", lambda n: "/usr/bin/systemctl")
    with caplog.at_level(logging.WARNING):
        assert not U.warn_if_key_in_unit(_run("HOME=/home/a PATH=/usr/bin"))
    assert caplog.text == ""


def test_not_linux_or_no_systemctl_or_an_error_is_false(monkeypatch):
    monkeypatch.setattr(U.platform, "system", lambda: "Darwin")
    assert not U.key_in_unit(_run("MESHEMBED_NODE_API_KEY=x"))
    monkeypatch.setattr(U.platform, "system", lambda: "Linux")
    monkeypatch.setattr(U.shutil, "which", lambda n: None)
    assert not U.key_in_unit(_run("MESHEMBED_NODE_API_KEY=x"))
    monkeypatch.setattr(U.shutil, "which", lambda n: "/usr/bin/systemctl")
    def boom(*a, **k):
        raise OSError("no dbus")
    assert not U.key_in_unit(boom)


def test_the_daemon_calls_it_at_start():
    from pathlib import Path
    src = (Path(U.__file__).parent / "worker.py").read_text()
    i = src.index("def run(cfg: Config)")
    assert "_unit_check.warn_if_key_in_unit()" in src[i:i + 2000]
