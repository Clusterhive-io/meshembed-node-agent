"""Privilege-separated updater for hardened installs (H1-a; auditor design GO 2026-10-12).

A hardened root install (PART75) runs the daemon as `meshembed` with /opt read-only,
so the daemon cannot update itself (docs/FINDING_2026-10-11_OTA_BLOCKED_ON_HARDENED_NODES.md).
The daemon only WRITES A TAG to its request file; this module, started as root by
meshembed-node-update.service (.path-triggered), decides and acts. Design and the
auditor's six criteria: docs/DESIGN_NODE_PRIVSEP_UPDATER.md.

Everything here is fail-closed. Nothing from the request file except a validated tag
and ONE optional fixed flag line ("runtime=1", INF-HARD C1) is used; nothing from the daemon's environment or .env is read (the unit has a fixed
Environment= and no EnvironmentFile=); ALLOW_UNSIGNED / ALLOW_DOWNGRADE are ignored.
Build conditions (auditor): B1 refuse when the installed version cannot be read;
B2 keys = the compiled-in trust list (a138d7d0 + f36c830f) and only tags whose
installer carries the fixed SHA256SUMS check (>= v0.3.70); B3 request dir 0700 /
file 0600, owned by the service user.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable, List, Optional, Tuple

TAG_RE = re.compile(r"^v\d+\.\d+\.\d+$")
REPO = "Clusterhive-io/meshembed-node-agent"          # constant: never from input
INSTALLER_URL = "https://raw.githubusercontent.com/" + REPO + "/refs/tags/{tag}/install.sh"
MIN_TAG = (0, 3, 70)            # first release whose installer verifies the signed SUMS correctly
MAX_REQUEST_BYTES = 64
# INF-HARD C1 (docs/DESIGN_INF_HARD_RUNTIME_OPT_IN_2026-11-07.md, auditor DESIGN GO 07:15:37Z): the owner's Inference
# opt-in reaches the root side as this exact second line and nothing else; it maps to MESHEMBED_ENABLE_LLM=1 only.
RUNTIME_FLAG_LINE = "runtime=1"
MIN_INTERVAL_S = 600
MAX_EQUAL_RETRIES = 2          # U3-a (auditor 16:32:51Z): a persistent installer failure must not re-run the full installer for ever
STATE_DIR = Path("/var/lib/meshembed-node-updater")


class Refused(Exception):
    """A request the updater will not act on. str() is a short code."""


def _version(v: str) -> Tuple[int, int, int, int]:
    """(major, minor, patch, final): a pre-release (0.3.78rc1) sorts BELOW its final (RC-2, auditor 18:39Z)."""
    m = re.match(r"^v?(\d+)\.(\d+)\.(\d+)([^+]*)", (v or "").strip())
    if not m:
        raise Refused("unparseable_version")
    rest = m.group(4)
    final = 1 if (rest == "" or rest.startswith(".post")) else 0
    return int(m.group(1)), int(m.group(2)), int(m.group(3)), final


def read_request(path: Path, owner_uid: int) -> Tuple[str, bool]:
    """(tag, runtime) from the request file, then truncate it. Refused unless it is a regular
    file (no symlink), owned by the service user, 0600-or-stricter, <= 64 bytes.
    Line 1 is the tag; an optional line 2 must be exactly RUNTIME_FLAG_LINE (INF-HARD C1). Any
    other second line, or a third line, is refused "request_bad_flag": no key=value parsing."""
    # 0.3.87 U4 (PATH-TRIGGER, as 0.3.86 #200 did for the split launcher): the request is CONSUMED BY UNLINK and the .path unit is
    # level-triggered (PathExists=). The daemon writes a request by tmp + rename, and a rename over an EXISTING watched file raises no
    # PathModified start on systemd 255 / 26.04 (host tests 11-19): the old "truncate and keep the name" protocol left the name present, so
    # the NEXT request never started the updater. One check-and-use: O_NOFOLLOW open, fstat the fd, read from that fd, then unlink the
    # name. Every outcome (refusal, empty leftover of the old protocol, symlink) removes the name too, or PathExists would start the
    # updater forever; a refusal is still returned to the caller (recorded in last-result), never a silent drop.
    # U4-a (auditor 16:35:58Z): root reads and unlinks the name through a descriptor of its PARENT directory, never by path: the directory
    # belongs to the daemon user, so a swap of ~/.meshembed for a symlink between check and use must not make root unlink or read a name in
    # another directory. Parent: O_DIRECTORY|O_NOFOLLOW, owned by the service user (or root), not group/other-writable; else refused and
    # NOTHING is unlinked. Then openat + unlinkat on that fd.
    parent, name = os.path.dirname(str(path)) or ".", os.path.basename(str(path))
    try:
        dfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except FileNotFoundError:
        raise Refused("no_request")
    except OSError as exc:
        raise Refused(f"request_dir_unreadable:{exc.errno}")
    try:
        dst = os.fstat(dfd)
        if dst.st_uid not in (owner_uid, 0) or dst.st_mode & 0o022:
            raise Refused("request_dir_untrusted")
        def _drop() -> None:
            try:
                os.unlink(name, dir_fd=dfd)
            except OSError:
                pass
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
        except FileNotFoundError:
            raise Refused("no_request")                 # a start with no request (boot, a race): nothing to do, no result written
        except OSError as exc:
            _drop()                                     # e.g. a symlink (ELOOP): the link goes, its target is never read
            raise Refused(f"request_unreadable:{exc.errno}")
        try:
            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                    raise Refused("request_not_a_regular_file")
                if st.st_uid != owner_uid:
                    raise Refused("request_wrong_owner")
                if st.st_mode & 0o077:
                    raise Refused("request_mode_too_open")
                if st.st_size == 0:
                    raise Refused("no_request")         # an empty leftover (the old protocol truncated): consumed below, "nothing to do"
                if st.st_size > MAX_REQUEST_BYTES:
                    raise Refused("request_too_large")
                raw = os.read(fd, MAX_REQUEST_BYTES + 1)
            finally:
                os.close(fd)
        finally:
            _drop()                                     # one action per request: the name is gone, whatever happened
    finally:
        os.close(dfd)
    text = raw.decode("ascii", errors="replace")
    if text.endswith("\n"):
        text = text[:-1]                        # the one newline the daemon writes after its last line
    lines = text.split("\n")
    tag = lines[0].strip()                      # line 1 as before: a tag-only file reads exactly as today
    if len(lines) == 1:
        runtime = False
    elif len(lines) == 2 and lines[1] == RUNTIME_FLAG_LINE:
        runtime = True
    else:
        raise Refused("request_bad_flag")
    if not TAG_RE.fullmatch(tag):
        raise Refused("request_bad_tag")
    return tag, runtime


def installed_version(venv: Path) -> str:
    """meshembed-node's version from the root-owned venv's dist-info, read without
    executing anything. B1: no readable version -> refuse (never default to allow)."""
    found = sorted(venv.glob("lib/python*/site-packages/meshembed_node-*.dist-info"))
    for d in found:
        m = re.match(r"meshembed_node-(\d+\.\d+\.\d+[A-Za-z0-9.]*?)\.dist-info$", d.name)   # keeps 'rc1' (RC-2)
        if m:
            return m.group(1)
    raise Refused("installed_version_unreadable")


def runtime_present(venv: Path) -> bool:
    """Whether the inference runtime (llama-cpp-python) is installed in the root-owned venv, from its dist-info,
    without executing anything (INF-HARD IH-Q2, the same way as installed_version)."""
    return any(venv.glob("lib/python*/site-packages/llama_cpp_python-*.dist-info"))


def check(tag: str, installed: str, last_run_at: Optional[float], now: float, *,
          runtime: bool = False, has_runtime: bool = False, retry_failed: bool = False, retry_exhausted: bool = False) -> None:
    """Raise Refused unless acting on `tag` is allowed.

    INF-HARD C1b (auditor IH-Q1 = YES): an EQUAL tag is allowed only for the owner's runtime opt-in
    (runtime=True) while the runtime is absent; equal with the runtime already there is refused
    "runtime_already_present" (no reinstall loop); a lower tag is refused in every case (anti-rollback).

    0.3.87 U3: an EQUAL tag is also allowed when the updater's own last-result says THIS tag's installer FAILED (retry_failed): a half-done
    install leaves the venv already at the new version (pip ran, a later step failed), so `want <= have` locked the node out of its own
    retry for ever (187 / dellpantalla, 2026-11-20: refused:not_newer_than_installed every ~10 min). Still never a lower tag; still
    rate-limited; a SUCCESSFUL run records ok and the equal tag is refused again."""
    if not TAG_RE.fullmatch(tag):
        raise Refused("bad_tag")
    want, have = _version(tag), _version(installed)
    if want[:3] < MIN_TAG:
        raise Refused("tag_below_minimum")
    if want == have and runtime:
        if has_runtime:
            raise Refused("runtime_already_present")
    elif want == have and retry_failed and retry_exhausted:
        raise Refused("retry_exhausted")                    # U3-a: at most MAX_EQUAL_RETRIES per tag, then refused until the tag changes
    elif want <= have and not (retry_failed and want == have):
        raise Refused("not_newer_than_installed")           # anti-rollback, also equal (except U3: the retry of a failed install)
    if last_run_at is not None and now - last_run_at < MIN_INTERVAL_S:
        raise Refused("rate_limited")


def fetch_verified_installer(tag: str, get: Callable[[str], Tuple[int, bytes]]) -> bytes:
    """install.sh for `tag` from the fixed repo, verified against the compiled-in keys."""
    from .release_verify import SIG_SUFFIX, verify_blob
    url = INSTALLER_URL.format(tag=tag)
    code, data = get(url)
    if code != 200 or not data or len(data) < 100:
        raise Refused(f"installer_unavailable:{code}")
    code, sig = get(url + SIG_SUFFIX)
    if code != 200 or not sig:
        raise Refused(f"installer_signature_unavailable:{code}")
    try:
        verify_blob(data, sig.decode("ascii", errors="replace"))
    except Exception:
        raise Refused("installer_signature_invalid")
    return data


def installer_env(tag: str, venv: Path, runtime: bool = False) -> dict:
    """A CLEAN environment, built from nothing (no inheritance). Not
    MESHEMBED_PACKAGE_URL: that tells install.sh 'the daemon will re-exec itself';
    here the installer's own upgrade path must restart the unit. MESHEMBED_ENABLE_LLM=1
    only for the validated runtime flag (INF-HARD C1); the installer still re-checks the
    CPU itself and pins the runtime by hash (IH-4)."""
    env = {
        "PATH": "/root/.local/bin:/root/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": "/root",
        "LANG": "C.UTF-8",
        "MESHEMBED_RELEASE_TAG": tag,
        "MESHEMBED_DAEMON_PYTHON": str(venv / "bin" / "python"),
    }
    if runtime is True:
        env["MESHEMBED_ENABLE_LLM"] = "1"
    return env


# IC-3b F3 (v0.3.85): the root updater used to throw the installer's output away (capture_output=True, only the exit code kept), so
# the one line that said WHY the limits applier was not installed on three hardened hosts (2026-11-13) was lost. The installer now
# prints ONE tagged line per unit-installer exit (MESHEMBED_UNITS <set> <state>[:<reason>], a closed [a-z_] vocabulary); only those
# lines are kept in last-result, bounded, nothing else from the installer's output.
_UNITS_LINE = re.compile(r"^MESHEMBED_UNITS ([a-z]{1,20}) ([a-z_]{1,40}(?::[a-z_]{1,60})?)$")
UNITS_MAX_LINES = 20


def extract_units(text: Optional[str]) -> List[str]:
    """'<set> <state>[:<reason>]' for each MESHEMBED_UNITS line of the installer's stdout; the LAST UNITS_MAX_LINES."""
    out: List[str] = []
    for line in (text or "").splitlines():
        m = _UNITS_LINE.match(line.rstrip("\r"))
        if m:
            out.append(f"{m.group(1)} {m.group(2)}")
    return out[-UNITS_MAX_LINES:]


# 0.3.87 U2 (operator 16:29Z; auditor 12:10Z): a FAILED installer left only "installer_exit_1": the fail() text that says why was thrown away
# (the 2026-11-20 hardened-updater failures on 187 / dellpantalla were diagnosed from a hand repro, not from the node). On a FAILED run only,
# the last TAIL_LINES lines of the installer's output (stdout, then stderr marked "E: ") are kept in its OWN root 0600 file last-failure-tail (auditor U2-a: last-result is 0644): ANSI stripped, control
# characters dropped, each line cut to TAIL_LINE_MAX, a line naming a secret-like word withheld, long token-like runs redacted. A successful run
# keeps no file (a stale one is removed). last-result is UNCHANGED; the operator reads the tail with sudo.
TAIL_LINES = 30
TAIL_LINE_MAX = 200
_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_SECRETISH = re.compile(r"(?i)key|token|secret|passw|priv|credential|invite|bearer|authoriz|cookie")
_LONGRUN = re.compile(r"[A-Za-z0-9+/_=-]{32,}")


def extract_tail(stdout: Optional[str], stderr: Optional[str] = None) -> List[str]:
    """The last TAIL_LINES lines of the installer's output, cleaned (see above). Never raises."""
    try:
        raw = [l for l in (stdout or "").splitlines()] + ["E: " + l for l in (stderr or "").splitlines()]
        out: List[str] = []
        for line in raw:
            line = _ANSI.sub("", line.rstrip("\r"))
            line = "".join(ch for ch in line if ch == "\t" or ch >= " ").strip()
            if not line or line.startswith("MESHEMBED_UNITS "):
                continue
            if _SECRETISH.search(line):
                line = "[line withheld: secret-like word]"
            else:
                line = _LONGRUN.sub("[redacted]", line)[:TAIL_LINE_MAX]
            out.append(line)
        return out[-TAIL_LINES:]
    except Exception:                                    # pragma: no cover - defensive
        return []


def run_installer(data: bytes, tag: str, venv: Path, state_dir: Path,
                  run: Callable[..., subprocess.CompletedProcess] = subprocess.run, runtime: bool = False,
                  units_out: Optional[List[str]] = None, tail_out: Optional[List[str]] = None) -> int:
    fd, path = tempfile.mkstemp(prefix="install-", suffix=".sh", dir=str(state_dir))
    try:
        os.write(fd, data)
        os.close(fd)
        os.chmod(path, 0o700)
        p = run(["bash", path], env=installer_env(tag, venv, runtime), shell=False,
                capture_output=True, text=True, timeout=900)
        if units_out is not None:
            units_out.extend(extract_units(getattr(p, "stdout", None)))
        if tail_out is not None:
            tail_out.extend(extract_tail(getattr(p, "stdout", None), getattr(p, "stderr", None)))
        return p.returncode
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _http_get(url: str) -> Tuple[int, bytes]:
    import requests
    r = requests.get(url, timeout=60)
    return r.status_code, r.content


def _write_result(state_dir: Path, tag: Optional[str], result: str, code: str, now: float,
                  units: Optional[List[str]] = None) -> None:
    state_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
    tmp = state_dir / "last-result.tmp"
    body = {"tag": tag, "result": result, "code": code, "at": int(now)}
    if units:
        body["units"] = list(units)[-UNITS_MAX_LINES:]
    tmp.write_text(json.dumps(body), encoding="utf-8")
    os.chmod(tmp, 0o644)
    os.replace(tmp, state_dir / "last-result")


def _write_failure_tail(state_dir: Path, tag: str, now: float, tail: Optional[List[str]]) -> None:
    """U2-a: the cleaned tail of a FAILED installer in last-failure-tail, root 0600 (created 0600 from the start, atomic); a successful run
    removes a stale one. Never raises into the updater."""
    path = state_dir / "last-failure-tail"
    try:
        if not tail:
            path.unlink(missing_ok=True)
            return
        tmp = state_dir / "last-failure-tail.tmp"
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"tag": tag, "at": int(now), "lines": list(tail)[-TAIL_LINES:]}) + "\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except OSError:
        pass


def _last_failed_for(state_dir: Path, tag: str) -> bool:
    """U3: True iff last-result records result == 'failed' for exactly this tag (an installer that ran and exited non-zero)."""
    try:
        r = json.loads((state_dir / "last-result").read_text(encoding="utf-8"))
        return r.get("result") == "failed" and r.get("tag") == tag and str(r.get("code", "")).startswith("installer_exit_")
    except Exception:
        return False


def _retries(state_dir: Path, tag: str) -> int:
    """Equal-tag retries already run for this tag (root state; another tag, or no file, = 0)."""
    try:
        r = json.loads((state_dir / "retry-count").read_text(encoding="utf-8"))
        return int(r["n"]) if r.get("tag") == tag else 0
    except Exception:
        return 0


def _set_retries(state_dir: Path, tag: str, n: int) -> None:
    try:
        tmp = state_dir / "retry-count.tmp"
        tmp.write_text(json.dumps({"tag": tag, "n": n}), encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, state_dir / "retry-count")
    except OSError:
        pass


def _last_run_at(state_dir: Path) -> Optional[float]:
    try:
        return float(json.loads((state_dir / "last-run").read_text(encoding="utf-8"))["at"])
    except Exception:
        return None


def run_once(request: Path, owner_uid: int, venv: Path, *, state_dir: Path = STATE_DIR,
             now: Optional[float] = None, get=_http_get, run=subprocess.run, venv_drift: Optional[str] = None) -> str:
    """One updater run. Returns 'ok' | 'refused:<code>' | 'failed:<code>'."""
    now = time.time() if now is None else now
    tag = None
    try:
        tag, runtime = read_request(request, owner_uid)
        if venv_drift:
            # CD-5 (auditor 2026-11-03 15:10:07Z): refused AFTER the tag is read, so the result names the tag and the
            # daemon reports it (last_update_error "<tag>: updater_refused:venv_drift"): this node can no longer
            # update itself, and a human has to look
            raise Refused("venv_drift")
        _have = installed_version(venv)
        _failed = _last_failed_for(state_dir, tag)
        _n = _retries(state_dir, tag)
        check(tag, _have, _last_run_at(state_dir), now,
              runtime=runtime, has_runtime=runtime and runtime_present(venv), retry_failed=_failed, retry_exhausted=_n >= MAX_EQUAL_RETRIES)
        _equal_retry = _failed and _version(tag) == _version(_have)
        state_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
        if _equal_retry:
            _set_retries(state_dir, tag, _n + 1)            # U3-a: counted BEFORE the installer runs (a crash mid-run still counts)
        (state_dir / "last-run").write_text(json.dumps({"at": int(now), "tag": tag}), encoding="utf-8")
        data = fetch_verified_installer(tag, get)
        units: List[str] = []
        tail: List[str] = []
        rc = run_installer(data, tag, venv, state_dir, run=run, runtime=runtime, units_out=units, tail_out=tail)
    except Refused as exc:
        if str(exc) == "no_request":
            return "none"
        _write_result(state_dir, tag, "refused", str(exc), now)
        return f"refused:{exc}"
    except Exception as exc:                                  # network etc.: safe, old version stays
        _write_result(state_dir, tag, "failed", type(exc).__name__, now)
        return f"failed:{type(exc).__name__}"
    result = "ok" if rc == 0 else "failed"
    if rc == 0:
        _set_retries(state_dir, tag, 0)                     # a success clears the count
    _write_result(state_dir, tag, result, f"installer_exit_{rc}", now, units)
    _write_failure_tail(state_dir, tag, now, tail if rc != 0 else None)                                   # U2: only when it failed
    return "ok" if rc == 0 else f"failed:installer_exit_{rc}"


def main(argv=None) -> int:
    """Entry point for meshembed-node-update.service. Every path comes from the
    root-owned unit's argv, never from the environment or the request."""
    ap = argparse.ArgumentParser(prog="meshembed_node.updater")
    ap.add_argument("--request", required=True)
    ap.add_argument("--owner", required=True, help="service user name owning the request")
    ap.add_argument("--venv", required=True)
    a = ap.parse_args(argv)
    if os.geteuid() != 0:
        print("refused: not root", file=sys.stderr)
        return 2
    import pwd
    try:
        uid = pwd.getpwnam(a.owner).pw_uid
    except KeyError:
        print("refused: unknown owner", file=sys.stderr)
        return 2
    # HT-5 at start (CD-5, auditor 2026-11-03 15:10:07Z): the fifth root entry point on the venv; the interpreter, this
    # module and the heal module it imports, with every parent, root-owned and not group/other-writable
    from . import path_heal
    bad = path_heal.drift([os.path.realpath(sys.executable), os.path.realpath(__file__),
                           os.path.realpath(path_heal.__file__)])
    out = run_once(Path(a.request), uid, Path(a.venv), venv_drift=bad)
    if bad:
        print(f"updater: refused venv_drift {bad} ({out})")
        return 3
    print(out)
    return 0 if out in ("ok", "none") else 1


if __name__ == "__main__":
    sys.exit(main())
