"""Privilege-separated updater for hardened installs (H1-a; auditor design GO 2026-10-12).

A hardened root install (PART75) runs the daemon as `meshembed` with /opt read-only,
so the daemon cannot update itself (docs/FINDING_2026-10-11_OTA_BLOCKED_ON_HARDENED_NODES.md).
The daemon only WRITES A TAG to its request file; this module, started as root by
meshembed-node-update.service (.path-triggered), decides and acts. Design and the
auditor's six criteria: docs/DESIGN_NODE_PRIVSEP_UPDATER.md.

Everything here is fail-closed. Nothing from the request file except a validated tag
is used; nothing from the daemon's environment or .env is read (the unit has a fixed
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
from typing import Callable, Optional, Tuple

TAG_RE = re.compile(r"^v\d+\.\d+\.\d+$")
REPO = "Clusterhive-io/meshembed-node-agent"          # constant: never from input
INSTALLER_URL = "https://raw.githubusercontent.com/" + REPO + "/refs/tags/{tag}/install.sh"
MIN_TAG = (0, 3, 70)            # first release whose installer verifies the signed SUMS correctly
MAX_REQUEST_BYTES = 64
MIN_INTERVAL_S = 600
STATE_DIR = Path("/var/lib/meshembed-node-updater")


class Refused(Exception):
    """A request the updater will not act on. str() is a short code."""


def _version(v: str) -> Tuple[int, int, int]:
    m = re.match(r"^v?(\d+)\.(\d+)\.(\d+)", (v or "").strip())
    if not m:
        raise Refused("unparseable_version")
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def read_request(path: Path, owner_uid: int) -> str:
    """The tag in the request file, then truncate it. Refused unless it is a regular
    file (no symlink), owned by the service user, 0600-or-stricter, <= 64 bytes."""
    try:
        fd = os.open(str(path), os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        raise Refused(f"request_unreadable:{exc.errno}")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise Refused("request_not_a_regular_file")
        if st.st_uid != owner_uid:
            raise Refused("request_wrong_owner")
        if st.st_mode & 0o077:
            raise Refused("request_mode_too_open")
        if st.st_size == 0:
            # Our own truncation re-triggers the .path unit (PathModified): an
            # empty request is "nothing to do", not an error -- no result written.
            raise Refused("no_request")
        if st.st_size > MAX_REQUEST_BYTES:
            raise Refused("request_too_large")
        raw = os.read(fd, MAX_REQUEST_BYTES + 1)
        os.ftruncate(fd, 0)                     # one action per request: never re-fires
    finally:
        os.close(fd)
    tag = raw.decode("ascii", errors="replace").strip()
    if not TAG_RE.fullmatch(tag):
        raise Refused("request_bad_tag")
    return tag


def installed_version(venv: Path) -> str:
    """meshembed-node's version from the root-owned venv's dist-info, read without
    executing anything. B1: no readable version -> refuse (never default to allow)."""
    found = sorted(venv.glob("lib/python*/site-packages/meshembed_node-*.dist-info"))
    for d in found:
        m = re.match(r"meshembed_node-(\d+\.\d+\.\d+)", d.name)
        if m:
            return m.group(1)
    raise Refused("installed_version_unreadable")


def check(tag: str, installed: str, last_run_at: Optional[float], now: float) -> None:
    """Raise Refused unless acting on `tag` is allowed."""
    if not TAG_RE.fullmatch(tag):
        raise Refused("bad_tag")
    want, have = _version(tag), _version(installed)
    if want < MIN_TAG:
        raise Refused("tag_below_minimum")
    if want <= have:
        raise Refused("not_newer_than_installed")           # anti-rollback, also equal
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


def installer_env(tag: str, venv: Path) -> dict:
    """A CLEAN environment, built from nothing (no inheritance). Not
    MESHEMBED_PACKAGE_URL: that tells install.sh 'the daemon will re-exec itself';
    here the installer's own upgrade path must restart the unit."""
    return {
        "PATH": "/root/.local/bin:/root/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": "/root",
        "LANG": "C.UTF-8",
        "MESHEMBED_RELEASE_TAG": tag,
        "MESHEMBED_DAEMON_PYTHON": str(venv / "bin" / "python"),
    }


def run_installer(data: bytes, tag: str, venv: Path, state_dir: Path,
                  run: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> int:
    fd, path = tempfile.mkstemp(prefix="install-", suffix=".sh", dir=str(state_dir))
    try:
        os.write(fd, data)
        os.close(fd)
        os.chmod(path, 0o700)
        p = run(["bash", path], env=installer_env(tag, venv), shell=False,
                capture_output=True, text=True, timeout=900)
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


def _write_result(state_dir: Path, tag: Optional[str], result: str, code: str, now: float) -> None:
    state_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
    tmp = state_dir / "last-result.tmp"
    tmp.write_text(json.dumps({"tag": tag, "result": result, "code": code, "at": int(now)}), encoding="utf-8")
    os.chmod(tmp, 0o644)
    os.replace(tmp, state_dir / "last-result")


def _last_run_at(state_dir: Path) -> Optional[float]:
    try:
        return float(json.loads((state_dir / "last-run").read_text(encoding="utf-8"))["at"])
    except Exception:
        return None


def run_once(request: Path, owner_uid: int, venv: Path, *, state_dir: Path = STATE_DIR,
             now: Optional[float] = None, get=_http_get, run=subprocess.run) -> str:
    """One updater run. Returns 'ok' | 'refused:<code>' | 'failed:<code>'."""
    now = time.time() if now is None else now
    tag = None
    try:
        tag = read_request(request, owner_uid)
        check(tag, installed_version(venv), _last_run_at(state_dir), now)
        state_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
        (state_dir / "last-run").write_text(json.dumps({"at": int(now), "tag": tag}), encoding="utf-8")
        data = fetch_verified_installer(tag, get)
        rc = run_installer(data, tag, venv, state_dir, run=run)
    except Refused as exc:
        if str(exc) == "no_request":
            return "none"
        _write_result(state_dir, tag, "refused", str(exc), now)
        return f"refused:{exc}"
    except Exception as exc:                                  # network etc.: safe, old version stays
        _write_result(state_dir, tag, "failed", type(exc).__name__, now)
        return f"failed:{type(exc).__name__}"
    result = "ok" if rc == 0 else "failed"
    _write_result(state_dir, tag, result, f"installer_exit_{rc}", now)
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
    out = run_once(Path(a.request), uid, Path(a.venv))
    print(out)
    return 0 if out in ("ok", "none") else 1


if __name__ == "__main__":
    sys.exit(main())
