"""U1 (auditor GO 2026-11-21T10:23:55Z, design Rev 1 a12b90d1, U1R-a..U1R-g): the installer must work under the published 0.3.86 updater
unit, where root cannot change its uid by any tool (NoNewPrivileges + RestrictSUIDSGID: runuser rc 1, setpriv EPERM, the 11-20 row).

Root TESTS first and switches user only when something is MISSING; every switch goes through as_user; when no switch is possible root writes
NOTHING in the user's tree, prints ONE closed MESHEMBED_UNITS line and the install continues (rc 0). The harness runs the REAL functions of
install.sh under `set -euo pipefail` (U1-e: errexit is reproduced) with fake runuser/setpriv as shell functions that log their argv; the
files are real, owned by the test's own user, so stat/-L/-f/-h are the real tests."""
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = (ROOT / "install.sh").read_text()
ME = subprocess.run(["id", "-un"], capture_output=True, text=True).stdout.strip()


def _fn(name: str, text: str = INSTALL) -> str:
    start = text.index(f"\n{name}() {{") + 1
    return text[start:text.index("\n}\n", start) + 3]


def _helpers(text: str = INSTALL) -> str:
    a = text.index("AS_USER_DEFERRED=77")
    b = text.index("\nensure_user_dir() {")
    return text[a:b] + "\n" + "".join(_fn(n, text) for n in (
        "ensure_user_dir", "make_user_request_file", "append_node_env_flag"))


def _run(body: str, mode: str, text: str = INSTALL, extra: str = ""):
    """mode: runuser | setpriv | none | lie (runuser rc 0 but prints another uid). Returns (rc, stdout+stderr, argv log)."""
    with tempfile.TemporaryDirectory() as td:
        log = Path(td) / "argv.log"
        fakes = {
            "runuser": 'runuser(){ echo "runuser $*" >> "$LOG"; shift 3; "$@"; }',
            "setpriv": 'setpriv(){ echo "setpriv $*" >> "$LOG"; while [ "$1" != -- ]; do shift; done; shift; "$@"; }',
            "none": 'runuser(){ echo "runuser $*" >> "$LOG"; return 1; }\nsetpriv(){ echo "setpriv $*" >> "$LOG"; return 127; }',
            "lie": 'runuser(){ echo "runuser $*" >> "$LOG"; case " $* " in *" id "*) echo 0; return 0;; esac; return 1; }\n'
                   'setpriv(){ echo "setpriv $*" >> "$LOG"; return 127; }',
        }
        if mode == "runuser":
            fk = fakes["runuser"] + "\nsetpriv(){ echo \"setpriv $*\" >> \"$LOG\"; return 127; }"
        elif mode == "setpriv":
            fk = 'runuser(){ echo "runuser $*" >> "$LOG"; return 1; }\n' + fakes["setpriv"]
        else:
            fk = fakes[mode]
        script = ("set -euo pipefail\nexport LOG=" + str(log) + "\nwarn(){ echo \"WARN $*\"; }\nok(){ echo \"OK $*\"; }\n" + fk + "\n"
                  + _fn("units_note", text) + _helpers(text) + "\n" + extra + body + "\necho DONE\n")
        p = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
        return p.returncode, p.stdout + p.stderr, (log.read_text() if log.exists() else "")


def _tree(d: Path):
    return sorted((str(p.relative_to(d)), p.stat().st_mode, p.read_bytes() if p.is_file() else b"") for p in [d, *d.rglob("*")])


def _home(tmp_path):
    h = tmp_path / "home"
    (h / ".meshembed").mkdir(parents=True, mode=0o700)
    os.chmod(h / ".meshembed", 0o700)
    return h


def _req(h):
    f = h / ".meshembed" / "limits-request"
    f.write_text("")
    os.chmod(f, 0o600)
    return f


def test_request_file_present_as_required_does_no_switch_at_all(tmp_path):
    h = _home(tmp_path); f = _req(h)
    for mode in ("runuser", "none"):
        rc, out, log = _run(f'make_user_request_file {ME} "{f}"', mode)
        assert rc == 0 and out.endswith("DONE\n") and log == "" and "MESHEMBED_UNITS" not in out


def test_request_file_missing_is_made_as_the_user(tmp_path):
    h = _home(tmp_path); f = h / ".meshembed" / "limits-request"
    rc, out, log = _run(f'make_user_request_file {ME} "{f}"', "runuser")
    assert rc == 0 and f.is_file() and oct(f.stat().st_mode & 0o777) == "0o600"
    assert log.count("runuser -u") >= 2 and "deferred" not in out          # the probe, then the write


def test_request_file_missing_falls_back_to_setpriv(tmp_path):
    h = _home(tmp_path); f = h / ".meshembed" / "limits-request"
    rc, out, log = _run(f'make_user_request_file {ME} "{f}"', "setpriv")
    assert rc == 0 and f.is_file() and "setpriv --reuid" in log


def test_no_switch_possible_writes_nothing_and_defers_with_one_closed_line(tmp_path):
    h = _home(tmp_path); f = h / ".meshembed" / "limits-request"
    before = _tree(h)
    rc, out, log = _run(f'make_user_request_file {ME} "{f}"', "none")
    assert rc == 0 and out.endswith("DONE\n")
    assert out.count("MESHEMBED_UNITS") == 1 and "MESHEMBED_UNITS limits deferred:request_file\n" in out
    assert _tree(h) == before                                   # U1R-f: byte-identical, nothing created anywhere
    assert "chmod" not in log


def test_serve_request_names_its_own_set(tmp_path):
    h = _home(tmp_path); f = h / ".meshembed" / "serve-request"
    rc, out, _ = _run(f'make_user_request_file {ME} "{f}"', "none")
    assert rc == 0 and "MESHEMBED_UNITS serve deferred:request_file\n" in out


def test_missing_state_dir_with_no_switch_is_deferred_not_created(tmp_path):
    h = tmp_path / "home"; h.mkdir()
    f = h / ".meshembed" / "limits-request"
    before = _tree(h)
    rc, out, _ = _run(f'make_user_request_file {ME} "{f}"', "none")
    assert rc == 0 and "MESHEMBED_UNITS updater deferred:state_dir\n" in out and out.count("MESHEMBED_UNITS") == 1
    assert _tree(h) == before and not (h / ".meshembed").exists()


def test_a_wrong_mode_state_dir_with_no_switch_is_deferred(tmp_path):
    h = _home(tmp_path); os.chmod(h / ".meshembed", 0o755)
    f = h / ".meshembed" / "limits-request"
    rc, out, _ = _run(f'make_user_request_file {ME} "{f}"', "none")
    assert rc == 0 and "MESHEMBED_UNITS updater deferred:state_dir\n" in out
    assert oct((h / ".meshembed").stat().st_mode & 0o777) == "0o755"      # root did not chmod it


def test_a_symlink_or_fifo_at_the_request_file_is_refused_and_nothing_is_followed(tmp_path):
    h = _home(tmp_path); f = h / ".meshembed" / "limits-request"; target = tmp_path / "victim"; target.write_text("keep")
    f.symlink_to(target)
    rc, out, log = _run(f'make_user_request_file {ME} "{f}"', "runuser")
    assert rc == 0 and "is a symlink" in out and log == "" and target.read_text() == "keep"
    f.unlink(); os.mkfifo(f)
    rc, out, log = _run(f'make_user_request_file {ME} "{f}"', "runuser")        # would block a write: must not even try
    assert rc == 0 and "not a regular file" in out and log == ""


def test_a_functional_probe_rejects_a_switch_that_prints_the_wrong_uid(tmp_path):
    h = _home(tmp_path); f = h / ".meshembed" / "limits-request"            # U1R-e: rc 0 of the tool is not enough
    rc, out, _ = _run(f'make_user_request_file {ME} "{f}"', "lie")
    assert rc == 0 and not f.exists() and "MESHEMBED_UNITS limits deferred:request_file\n" in out


def _env(h, text="MESHEMBED_NODE_ID=x\n"):
    f = h / ".meshembed" / ".env"; f.write_text(text); os.chmod(f, 0o600); return f


def _flag(h, key="MESHEMBED_SERVE"):
    return f'VENV_PY={sys.executable}\nappend_node_env_flag {ME} "{h}" {key}'


def test_env_flag_already_present_does_no_switch(tmp_path):
    h = _home(tmp_path); f = _env(h, "MESHEMBED_NODE_ID=x\nMESHEMBED_SERVE=1\n")
    for mode in ("runuser", "none"):
        before = f.read_bytes()
        rc, out, log = _run(_flag(h), mode)
        assert rc == 0 and log == "" and f.read_bytes() == before and "MESHEMBED_UNITS" not in out


def test_env_flag_absent_is_appended_as_the_user(tmp_path):
    h = _home(tmp_path); f = _env(h)
    rc, out, log = _run(_flag(h), "runuser")
    assert rc == 0 and "MESHEMBED_SERVE=1\n" in f.read_text() and "runuser -u" in log


def test_env_flag_absent_with_no_switch_is_deferred_and_the_file_is_untouched(tmp_path):
    h = _home(tmp_path); f = _env(h)
    before = _tree(h)
    rc, out, _ = _run(_flag(h), "none")
    assert rc == 0 and out.count("MESHEMBED_UNITS") == 1 and "MESHEMBED_UNITS serve deferred:env_opt_in\n" in out
    assert _tree(h) == before
    rc, out, _ = _run(_flag(h, "MESHEMBED_ENABLE_SPLIT"), "none")
    assert "MESHEMBED_UNITS split deferred:env_opt_in\n" in out


def test_env_symlink_fifo_or_hardlink_is_refused_without_a_switch(tmp_path):
    h = _home(tmp_path); f = h / ".meshembed" / ".env"; target = tmp_path / "victim"; target.write_text("keep")
    f.symlink_to(target)
    rc, out, log = _run(_flag(h), "runuser")
    assert rc == 1 and "NOT written" in out and log == "" and target.read_text() == "keep"
    f.unlink(); os.mkfifo(f)
    rc, out, log = _run(_flag(h), "runuser")
    assert rc == 1 and log == ""
    f.unlink(); g = tmp_path / "other"; g.write_text("MESHEMBED_NODE_ID=x\n"); os.link(g, f)      # nlink 2: refused by the bounded read
    rc, out, log = _run(_flag(h), "runuser")
    assert rc == 1 and "could not be read safely" in out and log == ""


def test_manifest_is_written_as_the_user_or_deferred(tmp_path):
    # EUID is readonly in bash: the harness swaps the condition in the extracted text only (the function under test is otherwise unchanged).
    fn = _fn("write_install_manifest").replace('"$EUID" -eq 0', '"${FAKE_EUID:-$EUID}" -eq 0')
    d = tmp_path / ".meshembed"; d.mkdir()
    py = tmp_path / "fakepy"
    py.write_text('#!/bin/sh\necho "PY $*" >> "$(dirname "$0")/py.log"\n'); py.chmod(0o755)      # env -i drops $LOG: log beside the script
    extra = f'FAKE_EUID=0\nVENV_PY={py}\nRELEASE_TAG=v0\nLLM_SKIPPED=""\n' + fn + "\n"
    body = f'write_install_manifest "{d}" {ME} upgrade'
    rc, out, log = _run(body, "runuser", extra=extra)
    assert rc == 0 and "OK install manifest" in out and "runuser -u" in log
    assert "-I -m meshembed_node.install_manifest" in (tmp_path / "py.log").read_text()
    rc, out, log = _run(body, "none", extra=extra)
    assert rc == 0 and out.count("MESHEMBED_UNITS") == 1 and "MESHEMBED_UNITS manifest deferred:install_manifest\n" in out
    assert "install_manifest" not in log                                  # root ran nothing in the user's tree
    assert len((tmp_path / "py.log").read_text().splitlines()) == 1       # (only the run of the first call)


def test_grep_gate_no_bare_user_switch_outside_as_user():
    allowed = set()
    for name in ("as_user_probe", "as_user"):
        body = _fn(name)
        allowed.update(body.splitlines())
    bad = [l for l in INSTALL.splitlines()
           if re.search(r"\b(runuser -u|setpriv --)", l) and not l.lstrip().startswith("#") and l not in allowed]
    assert bad == [], bad


def test_negative_control_without_the_test_first_line_the_harness_sees_a_switch(tmp_path):
    h = _home(tmp_path); f = _req(h)
    mutated = INSTALL.replace(
        '''    if [ -f "$f" ] && [ "$(stat -c '%U %a %h' -- "$f" 2>/dev/null)" = "$u 600 1" ]; then return 0; fi\n''', "")
    assert mutated != INSTALL
    rc, out, log = _run(f'make_user_request_file {ME} "{f}"', "runuser", text=mutated)
    assert "runuser -u" in log                       # the 0.3.86 shape: it switches even though the file is already right
    rc, out, log = _run(f'make_user_request_file {ME} "{f}"', "none", text=mutated)
    assert "MESHEMBED_UNITS" in out                  # ...and under the published unit that switch is what failed (now a deferral line)


def test_u1b_the_user_command_runs_under_a_fixed_environment_in_both_modes(tmp_path):
    # auditor U1-b (10:49:41Z): root's environment (an interactive sudo install can carry tokens/keys) must NOT reach the node user's process.
    canary = 'export U1_CANARY=secret-canary ENROL_TOKEN=tok\n'
    for mode in ("runuser", "setpriv"):
        out_f = tmp_path / f"seen-{mode}"
        rc, out, _ = _run(f'as_user_probe {ME}\nas_user {ME} sh -c \'echo "${{U1_CANARY-unset}}/${{ENROL_TOKEN-unset}}/$HOME/$LANG" > "$1"\' sh "{out_f}"',
                          mode, extra=canary)
        assert rc == 0, (mode, out)
        seen = out_f.read_text().strip()
        assert seen.startswith("unset/unset/") and seen.endswith("/C.UTF-8"), (mode, seen)
