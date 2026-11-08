"""MVP 1 (2026-10-21): the ROOT serve launcher -- start meshembed-serve on a verified serve plan, stop it on request.

Same privilege split as split_launch: the unprivileged daemon only REQUESTS, by writing JSON to
`$SVC_HOME/.meshembed/serve-request`; systemd (meshembed-serve-launch.path) runs this module as root with a fixed
argv. Nothing the daemon wrote is trusted:

  {"action": "stop", "reason": "<code>"}   -- always honoured: stopping can only protect the owner (pause, battery,
                                              owner active, memory pressure...). No plan needed.
  {"action": "start", "plan": {envelope}}  -- the serve plan is RE-VERIFIED here (serve_plan: closed schema,
                                              signature by a compiled-in plan key, for THIS node whose id comes from
                                              the root-owned /etc/meshembed-node/node-id, unexpired, unseen nonce).

On start, only these values reach the server, and none of the host settings come from the plan:
  - the two models by sha: /srv/mesh-di/models/<sha>.gguf, root-owned. When missing, it is copied from the
    daemon's staging dir `$SVC_HOME/.meshembed/serve-models/<sha>.gguf` (O_NOFOLLOW, a regular file owned by the
    service user) and kept ONLY if the bytes hash to the sha. G2 re-verifies both at every start.
  - ctx and slots from the plan (bounded by its schema);
  - threads = min(6, physical cores - 2), at least 1; --no-repack below 32 GB available (measured on 160: repack
    adds ~40 % on a Q4_K model). Computed here, from this host.
  - a drop-in 20-owner.conf: MemoryMax = min(available - 1 GiB, 3/4 of RAM), CPUQuota = threads x 100 %.
"""
from __future__ import annotations

import argparse
import grp
import hashlib
import json
import os
import pwd
import re
import stat
import subprocess
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from . import serve_plan as SP
from . import split_launch as _SLN
from .split_launch import NODE_ID_FILE, Refused, _ENV, _root_owned, _write, node_id, read_request
from .split_plan_verify import NonceStore, PlanRejected

UNIT = "meshembed-serve"
UNIT_NODRAFT = "meshembed-serve-nodraft"   # the SIGNED plan's draft_sha null selects it (auditor 19:22Z (b))
# DS-1: the serve split units (split_launch SERVE_PROBE_UNIT / SERVE_COORD_UNIT; not imported, a test pins them)
SPLIT_SERVE_UNITS = ("meshembed-di-serve-probe", "meshembed-di-serve-coord")
STATE_DIR = Path("/var/lib/meshembed-serve-launch")
ETC = Path("/etc/mesh-di")
MODELS = Path("/srv/mesh-di/models")
UNITS = Path("/etc/systemd/system")
REPACK_BELOW_MB = 32 * 1024
MIN_REMAINING_S = 60          # a plan with less left is refused, never RuntimeMaxSec=0 (auditor F2)
START_MIN_INTERVAL_S = 60     # SD-a (auditor 2026-10-27 19:53Z): at most one start per minute, enforced HERE (root),
                              # since the request file is user-writable; "stop" is never limited
PAUSE_MARKER = Path("/etc/meshembed-node/paused")   # SD-e3: presence alone (pause.py P-c) refuses a start
CHUNK = 1 << 20
MAX_ROUNDS = 8                # F-3a: a request rewritten without end cannot pin the root launcher
RATE_LIMITED = "refused:start_rate_limited"
# IO-CAP IOB-1 (auditor 2026-10-31 19:12Z, 20:28Z IOB-1a..IOB-1d): the limits reconcile runs in its OWN unit (the
# applier's confinement), never in-process here: this unit can write neither the applier's state nor
# meshembed-node.service.d, and ProtectHome hides the data disk it resolves.
LIMITS_RECONCILE_UNIT = "meshembed-limits-reconcile"
LIMITS_RESULT = Path("/var/lib/meshembed-limits-apply/result.json")
LIMITS_START_TIMEOUT_S = 180  # IOB-1b: above the reconcile unit's TimeoutStartSec=120, so a slow pass is not a crash
LIMITS_OK = ("applied", "no_request", "parked:loosen_rate_limited", "not_installed")
_REASON = re.compile(r"^[a-z_:]{1,40}$")


def physical_cores(sys_cpu: Path = Path("/sys/devices/system/cpu")) -> int:
    cores = set()
    for d in sys_cpu.glob("cpu[0-9]*"):
        try:
            cores.add(((d / "topology/physical_package_id").read_text().strip(),
                       (d / "topology/core_id").read_text().strip()))
        except OSError:
            continue
    return len(cores) or (os.cpu_count() or 1)


def meminfo_mb(path: Path = Path("/proc/meminfo")) -> Dict[str, int]:
    out = {}
    for line in path.read_text().splitlines():
        k, _, v = line.partition(":")
        if k in ("MemTotal", "MemAvailable"):
            out[k] = int(v.split()[0]) // 1024
    return out


def host_settings(cores: int, mem: Dict[str, int]) -> Dict[str, Any]:
    threads = max(1, min(6, cores - 2))
    avail, total = mem["MemAvailable"], mem["MemTotal"]
    return {"threads": threads,
            "repack_flag": "--no-repack" if avail < REPACK_BELOW_MB else "--repack",
            "memory_max_mb": max(512, min(avail - 1024, total * 3 // 4)),
            "cpu_quota_pct": threads * 100}


def place_model(sha: str, staging: Path, owner_uid: int, models: Path = MODELS) -> Path:
    """/srv/mesh-di/models/<sha>.gguf, root-owned; copied from staging only if the bytes hash to sha."""
    dst = models / f"{sha}.gguf"
    if dst.exists() and _root_owned(dst):
        return dst
    src = staging / f"{sha}.gguf"
    try:
        fd = os.open(str(src), os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise Refused("model_not_staged")
    tmp = dst.with_name(dst.name + ".part")
    installed = False
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != owner_uid or st.st_nlink != 1:   # SD-b: one link only
            raise Refused("model_staging_not_regular_or_not_owned")
        # ONE read loop feeds the hash AND the .part: the bytes installed are the bytes hashed, even if the staging
        # file (owned by a non-root user) changes during the copy (auditor 13:46Z TOCTOU condition).
        h = hashlib.sha256()
        with os.fdopen(os.dup(fd), "rb") as f, open(tmp, "wb") as out:
            for chunk in iter(lambda: f.read(CHUNK), b""):
                h.update(chunk)
                out.write(chunk)
            out.flush()
            os.fsync(out.fileno())
        if h.hexdigest() != sha:
            raise Refused("model_sha_mismatch")
        os.chmod(tmp, 0o644)
        os.replace(tmp, dst)
        installed = True
    finally:
        os.close(fd)
        if not installed:
            tmp.unlink(missing_ok=True)            # never leave a partial or unverified .part behind
    return dst


def env_text(model: Path, draft: Optional[Path], plan: Dict[str, Any], hs: Dict[str, Any], model_sha: str,
             draft_sha: Optional[str]) -> str:
    """The unit's env file. No draft -> NO draft key at all (the no-draft unit's G0 profile refuses any)."""
    d = (f"DRAFT_MODEL={draft}\nDRAFT_SHA_PIN={draft_sha}\nDRAFT_N_MAX=8\n" if draft_sha is not None else "")
    return (f"MODEL={model}\nMODEL_SHA_PIN={model_sha}\n{d}THREADS={hs['threads']}\nCTX={plan['ctx']}\n"
            f"SLOTS={plan['slots']}\nREPACK_FLAG={hs['repack_flag']}\n")


def unit_for(plan: Dict[str, Any]) -> str:
    """The unit comes from the SIGNED plan only: a draft_sha -> the draft unit, null -> the no-draft unit."""
    return UNIT if plan["draft_sha"] is not None else UNIT_NODRAFT


# RENEW-1 (2026-11-02, auditor 18:53:02Z + 18:53:23Z): a renewal of the RUNNING plan with EVERY signed field equal keeps
# the unit running. Any difference = a normal start (restart).
RENEW_FIELDS = ("node_id", "model_sha", "draft_sha", "ctx", "slots")


def renew_fields(plan: Dict[str, Any]) -> Dict[str, Any]:
    return {k: plan.get(k) for k in RENEW_FIELDS}


class _NoNonces:
    """The renewal PRE-check must not consume the nonce (a refused renewal falls back to a normal start of the same
    plan, which must still verify); the real store is used once the renewal is accepted."""

    def seen(self, nonce: str, now: float) -> bool:
        return False

    def remember(self, nonce: str, expires_at: int, now: float) -> None:
        return None


def _kept_lines(path: Path) -> Optional[List[str]]:
    """RN-4 (auditor 19:05:27Z): EVERY [Service] line of the running unit's drop-in except RuntimeMaxSec, byte-for-byte
    (MemoryMax / CPUQuota as set at the start, never recomputed: free memory is low once the model is loaded; plus any
    other cap a later head adds, e.g. IO-CAP or OOMScoreAdjust). None when the drop-in is unreadable or lacks its
    MemoryMax / CPUQuota (then the renewal is refused and the duty starts the plan normally)."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    kept = [l for l in lines if l and not l.startswith("#") and l != "[Service]" and not l.startswith("RuntimeMaxSec=")]
    keys = {l.partition("=")[0] for l in kept}
    if not {"MemoryMax", "CPUQuota"} <= keys or any("=" not in l for l in kept):
        return None
    return kept


def _active_enter_mono_s(unit: str) -> Optional[float]:
    """The unit's ActiveEnterTimestampMonotonic in seconds (RuntimeMaxSec counts from it), or None."""
    r = subprocess.run(["systemctl", "show", "-p", "ActiveEnterTimestampMonotonic", "--value", f"{unit}.service"],
                       env=_ENV, timeout=30, check=False, capture_output=True, encoding="utf-8")
    try:
        v = int((r.stdout or "").strip() or 0)
    except ValueError:
        return None
    return v / 1e6 if v > 0 else None


# MH-4 (auditor 2026-11-02 17:13:50Z, option (iii) accepted 19:12:27Z): if the owner's processes grow after the start,
# the kernel's OOM killer takes llama-server FIRST, never the owner's work. Written by this ROOT launcher only.
OOM_SCORE_ADJUST = 900


def dropin_text(plan_id: str, hs: Dict[str, Any], remaining_s: int) -> str:
    return (f"# serve plan {plan_id} (written by meshembed_node.serve_launch)\n[Service]\n"
            f"MemoryMax={hs['memory_max_mb']}M\nCPUQuota={hs['cpu_quota_pct']}%\nOOMScoreAdjust={OOM_SCORE_ADJUST}\n"
            f"RuntimeMaxSec={remaining_s}\n")


def _write_nf(path: Path, text: str, mode: int, gid: Optional[int] = None) -> None:
    """CD-1 (auditor 2026-10-27 20:08Z): like split_launch._write, but the temp file is created O_EXCL|O_NOFOLLOW
    (a planted symlink or file at the temp name is removed, never followed), then renamed over `path`."""
    tmp = path.with_name(path.name + ".tmp")
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.write(fd, text.encode("utf-8"))
        os.fchmod(fd, mode)
        if gid is not None:
            os.fchown(fd, _SLN.ROOT_UID, gid)
    finally:
        os.close(fd)
    os.replace(tmp, path)


def limits_reconcile_via_unit(unit: str, dropin: Path, text: str, *, units: Path = UNITS,
                              result: Optional[Path] = None, start: Optional[Callable[[], Any]] = None) -> str:
    """IOB-1: start meshembed-limits-reconcile.service (a oneshot: systemctl start returns when the pass ended) and
    return its result, but only from a pass that READ the 20-owner.conf just written (IOB-1a: its sha256 in the
    result's sources). A start can join a pass that began before the write, so a mismatch starts once more (that
    pass has ended, so this is a fresh one); a second mismatch is "unbound". A host without the applier installed
    (no reconcile unit file) has nothing to reconcile: "not_installed". Errors propagate to the caller (IOB-1b)."""
    if not (units / f"{LIMITS_RECONCILE_UNIT}.service").exists():
        return "not_installed"
    result = result or LIMITS_RESULT
    start = start or (lambda: subprocess.run(["systemctl", "start", f"{LIMITS_RECONCILE_UNIT}.service"], env=_ENV,
                                             timeout=LIMITS_START_TIMEOUT_S, check=True, capture_output=True))
    want = hashlib.sha256(text.encode("utf-8")).hexdigest()
    for _ in range(2):
        start()
        r = _read_json(result)
        seen = ((r.get("sources") or {}).get(unit) or {}) if isinstance(r.get("sources"), dict) else {}
        if isinstance(seen, dict) and seen.get(str(dropin)) == want:
            return str(r.get("result") or "")
    return "unbound"


def _start_rate_ok(state: Path, now: float, interval_s: int) -> None:
    """SD-a: refuse a start within interval_s of the last verified start attempt (root 0600 stamp)."""
    try:
        last = float((state / "last-start").read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        return
    if 0 <= now - last < interval_s:
        raise Refused("start_rate_limited")


def _start_stamp(state: Path, now: float) -> None:
    state.mkdir(mode=0o755, parents=True, exist_ok=True)
    _write(state / "last-start", f"{int(now)}\n", 0o600)


def run_once(request: Path, owner: str, *, state: Path = STATE_DIR, now: Optional[float] = None,
             etc: Path = ETC, models: Path = MODELS, units: Path = UNITS, systemctl: Optional[Callable] = None,
             nid: Optional[str] = None, settings: Optional[Dict[str, Any]] = None,
             trusted: Optional[Dict[str, str]] = None, gid_of: Optional[Callable[[str], int]] = None,
             pause_marker: Path = PAUSE_MARKER, start_interval_s: int = START_MIN_INTERVAL_S,
             req_obj: Optional[Dict[str, Any]] = None, unit_active: Optional[Callable[[str], bool]] = None,
             active_enter: Optional[Callable[[str], Optional[float]]] = None,
             mono_now: Optional[Callable[[], float]] = None,
             limits_reconcile: Optional[Callable[[], str]] = None) -> str:
    now = time.time() if now is None else now
    gid_of = gid_of or (lambda name: grp.getgrnam(name).gr_gid)
    systemctl = systemctl or (lambda *a: subprocess.run(["systemctl", *a], env=_ENV, timeout=120,
                                                        check=True, capture_output=True))
    pw = pwd.getpwnam(owner)
    req: Any = None
    try:
        req = read_request(request, pw.pw_uid) if req_obj is None else req_obj   # read_request truncates the file
        if req is None:
            return "no_request"
        if not isinstance(req, dict) or req.get("action") not in ("start", "stop", "renew"):
            raise Refused("request_action")
        if req["action"] == "stop":
            if set(req) != {"action", "reason"} or not isinstance(req["reason"], str) or not _REASON.match(req["reason"]):
                raise Refused("stop_reason")
            for u in (UNIT, UNIT_NODRAFT):                    # stop is honoured for either unit, no plan needed
                systemctl("stop", f"{u}.service")
            _set_running(state, None, None, now)
            code = f"stopped:{req['reason']}"
        elif req["action"] == "renew":
            code = _renew(req, state, now, etc=etc, units=units, systemctl=systemctl, nid=nid, trusted=trusted,
                          pause_marker=pause_marker, unit_active=unit_active or _unit_active,
                          active_enter=active_enter or _active_enter_mono_s, mono_now=mono_now or time.monotonic,
                          limits_reconcile=limits_reconcile)
        else:
            if set(req) != {"action", "plan"}:
                raise Refused("request_keys")
            if os.path.lexists(str(pause_marker)):           # SD-e3: a paused node never starts serving
                raise Refused("node_paused")
            # DS-1 (auditor 2026-11-02 21:13:50Z): a serve split coordinator or its probe owns serve.sock right now
            if _split_serve_active(units, unit_active or _unit_active):
                raise Refused("split_serve_active")
            _start_rate_ok(state, now, start_interval_s)     # SD-a: before any hashing or systemctl
            me = nid or node_id(NODE_ID_FILE)
            plan = SP.verify_serve_plan(req["plan"], me, now=now, trusted=trusted,
                                        nonces=NonceStore(state / "serve-plan-nonces.json"))
            _start_stamp(state, now)                         # a verified start attempt counts, whatever follows
            staging = Path(pw.pw_dir) / ".meshembed" / "serve-models"
            model = place_model(plan["model_sha"], staging, pw.pw_uid, models)
            draft = place_model(plan["draft_sha"], staging, pw.pw_uid, models) if plan["draft_sha"] else None
            unit, other = unit_for(plan), (UNIT_NODRAFT if plan["draft_sha"] else UNIT)
            remaining = int(plan["expires_at"] - now)
            if remaining < MIN_REMAINING_S:
                raise Refused("plan_expires_too_soon")
            hs = settings or host_settings(physical_cores(), meminfo_mb())
            # 0640 root:mesh-serve: G0 runs AS mesh-serve and reads this file itself (auditor F1: 0600 root made
            # every start fail); same pattern as split_launch's stage.env / engine.env
            _write_nf(etc / "serve.env", env_text(model, draft, plan, hs, plan["model_sha"], plan["draft_sha"]), 0o640,
                      gid_of("mesh-serve"))
            d = units / f"{unit}.service.d"
            d.mkdir(mode=0o755, exist_ok=True)
            owner_text = dropin_text(plan["plan_id"], hs, remaining)
            _write_nf(d / "20-owner.conf", owner_text, 0o644)   # never 10-node.conf
            # IO-CAP (auditor IC-1): the limits applier's runtime properties were computed against the OLD
            # 20-owner.conf; re-apply them against the new one BEFORE the restart, or a stale runtime value could
            # loosen this plan's host bound. A failed reconcile refuses the start rather than loosen (IOB-1b: a
            # timeout or an OS error is a failure too, never a crash of this run).
            if limits_reconcile is None:
                limits_reconcile = lambda: limits_reconcile_via_unit(unit, d / "20-owner.conf", owner_text,  # noqa: E731
                                                                     units=units)
            try:
                rec = limits_reconcile()
            except (subprocess.SubprocessError, OSError):
                rec = "start_failed"
            if rec not in LIMITS_OK:
                raise Refused("limits_reconcile_failed")
            systemctl("stop", f"{other}.service")             # never both: one socket, one server
            systemctl("daemon-reload")
            # LAUNCH-1 (2026-11-02, 187): never WAIT for the unit's start. Its ExecStartPre G2 re-hashes the whole model
            # (18.5 GB for the 30B: minutes under I/O pressure); a blocking restart hit the 120 s subprocess timeout,
            # the launcher died before recording the plan, and the plan could never become ready (F-3c). The record is
            # written only HERE, after every check above passed (LA-1), and cleared if the start cannot be queued.
            # The duty's health check and the backend's load deadline cover a slow start.
            _set_running(state, plan["plan_id"], unit, now, renew_fields(plan))
            try:
                systemctl("restart", "--no-block", f"{unit}.service")
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                _set_running(state, None, None, now)
                raise
            code = f"started:{plan['plan_id']}"
    except (Refused, PlanRejected) as exc:
        code = f"refused:{exc}"
    except subprocess.SubprocessError:                       # CalledProcessError, TimeoutExpired (IOB-1b)
        code = "systemctl_failed"
    state.mkdir(mode=0o755, parents=True, exist_ok=True)
    if code == RATE_LIMITED:
        # R1: the request file is already truncated; keep the START (root-only) for the next run instead of losing it
        _write_nf(state / "pending.json", json.dumps(req, sort_keys=True), 0o600)
    else:
        try:
            os.unlink(state / "pending.json")               # any newer request handled supersedes a parked START
        except FileNotFoundError:
            pass
    _write(state / "result.json", json.dumps({"result": code, "at": int(now)}, sort_keys=True), 0o644)
    return code


# --- F-3 (E3a-1 finding 2026-10-28; auditor design GO 16:26Z with R1-R3, P-1..P-3) ----------------------------------
# A request written while a run is in progress used to be LOST: the .path unit drops PathModified events while the
# oneshot service is active, so a STOP never ran and a revoked plan's unit kept serving. read_request truncates what
# it reads, so an EMPTY request file means "nothing pending": every run now loops until it is empty, a timer re-runs
# it every 30 s as a safety net, a rate-limited START is parked root-side (pending.json) instead of being lost, and
# running.json is the launcher's own record of which plan it started (result.json is overwritten by every run).

def _read_json(path: Path) -> Dict[str, Any]:
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return d if isinstance(d, dict) else {}


def _set_running(state: Path, plan_id: Optional[str], unit: Optional[str], now: float,
                 fields: Optional[Dict[str, Any]] = None) -> None:
    """R2/P-1: written ONLY after a successful start (the plan), a renewal (RENEW-1) or a stop (null); 0644 so the
    daemon can read it. `fields` = the started plan's signed RENEW_FIELDS (content-free: ids, shas, sizes)."""
    state.mkdir(mode=0o755, parents=True, exist_ok=True)
    _write_nf(state / "running.json", json.dumps({"plan_id": plan_id, "unit": unit, "at": int(now), "fields": fields},
                                                 sort_keys=True), 0o644)


def _renew(req: Dict[str, Any], state: Path, now: float, *, etc: Path, units: Path, systemctl: Callable,
           nid: Optional[str], trusted: Optional[Dict[str, str]], pause_marker: Path,
           unit_active: Callable[[str], bool], active_enter: Callable[[str], Optional[float]],
           mono_now: Callable[[], float], limits_reconcile: Optional[Callable[[], str]] = None) -> str:
    """RENEW-1: keep the RUNNING unit for a renewed plan whose every signed field equals the running one's.
    1. a pre-check that consumes NO nonce: signature, schema, for this node, not expired; the fields, the unit and the
       running record must match, the unit must be running, and its drop-in must exist (else Refused: the duty then
       sends a normal START of the same plan, which still verifies);
    2. the FULL verification with the root nonce store (a new nonce, never replayed);
    3. the drop-in keeps EVERY line but RuntimeMaxSec byte-for-byte (RN-4) and gets RuntimeMaxSec = the new expiry
       measured from the unit's activation; daemon-reload, NO restart; the running record switches to the new plan;
    4. RN-4 x IC-1 (auditor 2026-11-02 19:05:27Z): the limits reconcile against the NEW drop-in, as at a start. A failed
       reconcile restores the old drop-in byte-for-byte, daemon-reloads, reconciles once more on the restored text
       (CD-1a, best effort, logged) and refuses (renewal_limits_failed): the unit keeps the old plan's record and
       RuntimeMaxSec, so a renewal never loosens the owner's caps."""
    if set(req) != {"action", "plan"}:
        raise Refused("request_keys")
    if os.path.lexists(str(pause_marker)):
        raise Refused("node_paused")
    me = nid or node_id(NODE_ID_FILE)
    pre = SP.verify_serve_plan(req["plan"], me, now=now, trusted=trusted, nonces=_NoNonces())
    run = _read_json(state / "running.json")
    unit = unit_for(pre)
    if not run.get("plan_id") or run.get("plan_id") == pre["plan_id"] or run.get("unit") != unit \
            or run.get("fields") != renew_fields(pre):
        raise Refused("renewal_differs")
    if not unit_active(unit):
        raise Refused("renewal_unit_not_running")
    remaining = int(pre["expires_at"] - now)
    if remaining < MIN_REMAINING_S:
        raise Refused("plan_expires_too_soon")
    drop = units / f"{unit}.service.d" / "20-owner.conf"
    kept = _kept_lines(drop)
    if kept is None:
        raise Refused("renewal_no_dropin")
    enter = active_enter(unit)
    if enter is None:
        raise Refused("renewal_no_active_time")
    plan = SP.verify_serve_plan(req["plan"], me, now=now, trusted=trusted,
                                nonces=NonceStore(state / "serve-plan-nonces.json"))      # consumes the nonce
    runtime = int(remaining + max(0.0, mono_now() - enter))
    old_text = drop.read_text(encoding="utf-8")
    new_text = (f"# serve plan {plan['plan_id']} (renewal of {run['plan_id']}, written by meshembed_node.serve_launch)\n"
                "[Service]\n" + "".join(l + "\n" for l in kept) + f"RuntimeMaxSec={runtime}\n")
    _write_nf(drop, new_text, 0o644)
    systemctl("daemon-reload")
    if limits_reconcile is None:
        # bound to the drop-in's text AT THE CALL: the new text first, the restored one on the CD-1a pass
        limits_reconcile = lambda: limits_reconcile_via_unit(unit, drop, drop.read_text(encoding="utf-8"),  # noqa: E731
                                                             units=units)
    try:
        rec = limits_reconcile()
    except (subprocess.SubprocessError, OSError):
        rec = "start_failed"
    if rec not in LIMITS_OK:
        _write_nf(drop, old_text, 0o644)
        systemctl("daemon-reload")
        # CD-1a (auditor 2026-11-03 14:55:22Z): the applier writes 99-limits.conf FIRST (IC-2), so a pass that failed
        # after it may have written it from the new text; one more pass on the restored drop-in, best effort, logged
        try:
            again = limits_reconcile()
        except (subprocess.SubprocessError, OSError):
            again = "start_failed"
        print(f"serve_launch: renewal_limits_failed {rec}; reconcile on the restored drop-in: {again}")
        raise Refused("renewal_limits_failed")
    _set_running(state, plan["plan_id"], unit, now, renew_fields(plan))
    return f"renewed:{plan['plan_id']}"


def _split_serve_active(units: Path, active: Callable[[str], bool]) -> bool:
    """DS-1: a serve split unit INSTALLED here (the R3 kit) is active or starting. Cannot tell = active (fail closed:
    the whole-model start waits; it never kills a split coordinator through the Conflicts= of serve-coord)."""
    for u in SPLIT_SERVE_UNITS:
        if not (units / f"{u}.service").exists():
            continue
        try:
            if active(u):
                return True
        except (OSError, subprocess.SubprocessError):
            return True
    return False


def _unit_active(unit: str) -> bool:
    """Running for P-2: active, or still starting (LAUNCH-1: a --no-block start sits in "activating" while its
    ExecStartPre hashes the model). failed / inactive / deactivating = not running."""
    r = subprocess.run(["systemctl", "is-active", f"{unit}.service"], env=_ENV, timeout=30, check=False,
                       capture_output=True, encoding="utf-8")
    return (r.stdout or "").strip() in ("active", "activating", "reloading")


def run(request: Path, owner: str, *, state: Path = STATE_DIR, max_rounds: int = MAX_ROUNDS,
        unit_active: Optional[Callable[[str], bool]] = None, now: Optional[float] = None, **kw) -> str:
    """F-3a: handle requests until the request file is empty (at most max_rounds), then a parked START (R1). An empty
    file with nothing parked is a no-op: no systemctl call that changes anything, no write (P-3)."""
    unit_active = unit_active or _unit_active
    last = "no_request"                                      # the result of the last request actually handled
    for _ in range(max_rounds):
        code = run_once(request, owner, state=state, now=now, **kw)
        if code == "no_request":
            parked = _read_json(state / "pending.json")
            if not parked:
                break
            code = run_once(request, owner, state=state, now=now, req_obj=parked, **kw)
        last = code
        if code == RATE_LIMITED:
            break                                            # parked again; the timer retries after the 60 s
    # P-2: running.json records what the launcher did, not the unit's later fate (RuntimeMaxSec, BindsTo). A plan
    # whose unit is no longer active is cleared here; only a read (is-active) unless it changes something.
    rec = _read_json(state / "running.json")
    if rec.get("plan_id") and rec.get("unit") in (UNIT, UNIT_NODRAFT) and not unit_active(rec["unit"]):
        _set_running(state, None, None, time.time() if now is None else now)
    return last


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="meshembed_node.serve_launch")
    ap.add_argument("--request", required=True)
    ap.add_argument("--owner", required=True)
    a = ap.parse_args(argv)
    if os.geteuid() != 0:
        print("serve_launch: must run as root (meshembed-serve-launch.service)")
        return 2
    from .path_heal import drift
    bad = drift()                                        # HT-5 at start (auditor 2026-11-03 14:06:46Z), before systemctl
    if bad:
        print(f"serve_launch: refused venv_drift {bad}")
        return 3
    print(f"serve_launch: {run(Path(a.request), a.owner)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
