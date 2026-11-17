"""OLDVENV-1 F4 (v0.3.85; design rev 1 03f77e2d): the venvs a root install moved aside are listed in the install manifest
(carried over across rewrites) and printed by `meshembed-node maintenance status`, so the owner can delete them. The
installer never deletes one."""
import json
import types
from pathlib import Path

import pytest

from meshembed_node import cpu_guard, install_manifest, maintenance

pytestmark = pytest.mark.unit
ROOT = Path(__file__).resolve().parents[1]
INSTALL = (ROOT / "install.sh").read_text()


@pytest.fixture(autouse=True)
def _home(monkeypatch, tmp_path):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setattr(cpu_guard, "_VERDICT", None)
    yield tmp_path


def _build(**kw):
    return install_manifest.build(kind="upgrade", tag="v0.3.85", base="existing", llm_build=None,
                                  llm_skipped=None, uv=None, **kw)


def test_a_fresh_manifest_lists_no_retired_venv():
    assert _build()["retired_venvs"] == []


def test_the_retired_venv_is_appended_once_and_carried_over():
    a = "/home/automation/.meshembed/.venv.retired-20261111"
    doc = _build(retired=a)
    assert doc["retired_venvs"] == [a]
    again = _build(retired=a, previous=doc)                     # the same path twice: listed once
    assert again["retired_venvs"] == [a]
    later = _build(previous=again)                              # a later rewrite with nothing retired keeps it
    assert later["retired_venvs"] == [a]


def test_only_strings_are_kept_and_the_list_is_capped():
    prev = {"retired_venvs": [None, 3, "", {"x": 1}] + [f"/home/u/.v{i}" for i in range(25)]}
    out = _build(previous=prev)["retired_venvs"]
    assert len(out) == install_manifest.RETIRED_MAX and all(isinstance(x, str) and x for x in out)
    assert out[-1] == "/home/u/.v24"
    assert _build(previous={"retired_venvs": "not-a-list"})["retired_venvs"] == []


def test_the_cli_records_and_then_keeps_the_retired_venv(tmp_path):
    d = tmp_path / "cfg"
    a = "/home/automation/.meshembed/.venv.retired-20261111"
    assert install_manifest.main(["--dir", str(d), "--kind", "upgrade", "--retired", a]) == 0
    assert install_manifest.main(["--dir", str(d), "--kind", "upgrade", "--retired", ""]) == 0     # the installer's empty value
    doc = json.loads((d / install_manifest.FILENAME).read_text())
    assert doc["retired_venvs"] == [a]


def test_status_prints_the_retired_venvs(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(maintenance, "_service_present", lambda run: False, raising=False)
    a = "/home/automation/.meshembed/.venv.retired-20261111"
    install_manifest.write(tmp_path / ".meshembed", _build(retired=a))
    run = lambda *x, **k: types.SimpleNamespace(returncode=1)          # noqa: E731
    maintenance.status(as_json=True, run=run)
    assert json.loads(capsys.readouterr().out)["retired_venvs"] == [a]
    maintenance.status(as_json=False, run=run)
    text = capsys.readouterr().out
    assert "retired venvs " + a in text and "delete them" in text


def test_the_installer_records_the_retired_venv_in_the_manifest():
    assert INSTALL.count('--retired "${RETIRED_VENV:-}"') == 1
    init = INSTALL.index('RETIRED_VENV=""')
    assert init < INSTALL.index('retire_prev_venv "$PREV_VENV"') and init < INSTALL.index("write_install_manifest() {")
    case0 = INSTALL.index('        0) RETIRED_VENV="$parent/$new"')
    assert INSTALL.count('RETIRED_VENV="$parent/$new"') == 1 and case0 > INSTALL.index("retire_prev_venv() {")
