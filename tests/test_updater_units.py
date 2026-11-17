"""IC-3b F3 (v0.3.85): the root updater keeps the installer's MESHEMBED_UNITS lines (and ONLY those) in last-result.
On 2026-11-13 the v0.3.84 upgrade left the limits applier uninstalled on three hardened hosts and the one line that said why was
thrown away with the rest of the installer's output (capture_output, exit code only)."""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from meshembed_node import updater as U

pytestmark = pytest.mark.unit

UID = os.getuid()
INSTALLER = b"#!/bin/bash\n" + b"echo upgrading\n" * 10        # the updater refuses a stub that is too small


def _request(tmp_path: Path) -> Path:
    p = tmp_path / "update-request"
    p.write_bytes(b"v0.3.73\n")
    os.chmod(p, 0o600)
    return p


def _venv(tmp_path: Path) -> Path:
    v = tmp_path / "venv"
    (v / "lib" / "python3.12" / "site-packages" / "meshembed_node-0.3.72.dist-info").mkdir(parents=True, exist_ok=True)
    return v


def _site(inst=INSTALLER):
    return lambda url: (200, b"sig-line") if url.endswith(".sig") else (200, inst)


@pytest.fixture(autouse=True)
def _verify(monkeypatch):
    monkeypatch.setattr("meshembed_node.release_verify.verify_blob", lambda d, s: "a138d7d0cf3d361a")


def _run_with(stdout: str, rc: int = 0):
    return lambda argv, **kw: subprocess.CompletedProcess(argv, rc, stdout, "")


def _once(tmp_path, stdout, rc=0):
    st = tmp_path / "state"
    out = U.run_once(_request(tmp_path), UID, _venv(tmp_path), state_dir=st, now=1000.0, get=_site(), run=_run_with(stdout, rc))
    return out, json.loads((st / "last-result").read_text()), st


# ---- extract_units ----------------------------------------------------------------------------------------------------
def test_only_well_formed_tagged_lines_are_kept_in_order():
    text = ("\x1b[0;33m!\x1b[0m limits applier skipped (no regular request file at /x/limits-request)\n"
            "MESHEMBED_UNITS limits skipped:no_request_file\n"
            "OK updater installed\n"
            "MESHEMBED_UNITS updater installed\r\n")
    assert U.extract_units(text) == ["limits skipped:no_request_file", "updater installed"]


@pytest.mark.parametrize("bad", [
    "MESHEMBED_UNITS limits skipped:no_request_file extra",          # trailing junk
    "  MESHEMBED_UNITS limits installed",                           # indented
    "MESHEMBED_UNITS Limits installed",                             # upper case
    "MESHEMBED_UNITS limits ../../etc/passwd",                      # path
    "MESHEMBED_UNITS limits installed;rm -rf /",                    # shell metacharacters
    "MESHEMBED_UNITS limits " + "a" * 41,                           # state too long
    "MESHEMBED_UNITS limits skipped:" + "a" * 61,                   # reason too long
    "MESHEMBED_UNITS limits",                                       # no state
    "prefix MESHEMBED_UNITS limits installed",                      # not at the line start
    "MESHEMBED_UNITS limits skipped:Bad-Reason",                    # outside the closed [a-z_] vocabulary
])
def test_a_lookalike_or_malformed_line_is_rejected(bad):
    assert U.extract_units(bad + "\n") == []


def test_none_and_empty_output_give_no_units():
    assert U.extract_units(None) == [] and U.extract_units("") == []


def test_only_the_last_twenty_lines_are_kept():
    text = "".join(f"MESHEMBED_UNITS limits n{c}\n".replace("n" + str(c), "x" * 1 + "abcdefghijklmnopqrstuvwxyz"[c % 26]) for c in range(30))
    got = U.extract_units(text)
    assert len(got) == U.UNITS_MAX_LINES == 20 and got == [l.split(" ", 1)[1] for l in text.splitlines()[-20:]]


# ---- run_installer ----------------------------------------------------------------------------------------------------
def test_run_installer_keeps_its_int_return_and_fills_units_out_only_when_asked(tmp_path):
    run = _run_with("noise\nMESHEMBED_UNITS limits installed\n", rc=0)
    assert U.run_installer(INSTALLER, "v0.3.73", tmp_path / "venv", tmp_path, run=run) == 0          # the old call shape still works
    units = []
    assert U.run_installer(INSTALLER, "v0.3.73", tmp_path / "venv", tmp_path, run=run, units_out=units) == 0
    assert units == ["limits installed"]


# ---- run_once -> last-result --------------------------------------------------------------------------------------------
def test_last_result_carries_the_units_and_nothing_else_from_the_installers_output(tmp_path):
    secret = "MESHEMBED_NODE_API_KEY=sk-live-abc123 password prompt /home/user/doc.txt"
    out, res, st = _once(tmp_path, f"{secret}\nMESHEMBED_UNITS limits skipped:no_request_file\nMESHEMBED_UNITS updater installed\n")
    assert out == "ok"
    assert res == {"tag": "v0.3.73", "result": "ok", "code": "installer_exit_0", "at": 1000,
                   "units": ["limits skipped:no_request_file", "updater installed"]}
    text = (st / "last-result").read_text()
    assert "sk-live" not in text and "password" not in text and "doc.txt" not in text
    assert oct((st / "last-result").stat().st_mode & 0o777) == "0o644"


def test_a_failed_installer_still_records_why(tmp_path):
    out, res, _ = _once(tmp_path, "MESHEMBED_UNITS limits skipped:layout_not_recognised\n", rc=1)
    assert out == "failed:installer_exit_1" and res["result"] == "failed" and res["units"] == ["limits skipped:layout_not_recognised"]


def test_no_unit_lines_keeps_the_exact_old_result_shape(tmp_path):
    _, res, _ = _once(tmp_path, "upgrading\nOK done\n")
    assert res == {"tag": "v0.3.73", "result": "ok", "code": "installer_exit_0", "at": 1000}            # no "units" key at all


def test_the_units_in_last_result_stay_bounded(tmp_path):
    stdout = "".join(f"MESHEMBED_UNITS limits {c}\n" for c in "abcdefghijklmnopqrstuvwxyzabcdefghijklmnop")
    _, res, _ = _once(tmp_path, stdout)
    assert len(res["units"]) == 20 and all(len(u) <= 100 for u in res["units"])
