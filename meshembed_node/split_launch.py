"""M2 build #5a: the ROOT split launcher (docs/DESIGN_DI_CHAIN_FORMATION.md, build #5 plan D4/D6;
auditor DESIGN GO 2026-10-12; this build needs its per-build GO).

The unprivileged daemon can only REQUEST: it writes a signed plan envelope to
`$SVC_HOME/.meshembed/split-request`. systemd (meshembed-split-launch.path) starts this module
as root (meshembed-split-launch.service: fixed argv, fixed Environment=, no EnvironmentFile).
Nothing the daemon wrote is trusted:

  1. the request file: O_NOFOLLOW, regular file, owned by the service user, mode 0600-or-tighter,
     at most MAX_REQUEST_BYTES; read once, then truncated; JSON;
  2. the plan is RE-VERIFIED here with this root-owned code: closed schema, signature against
     the split-plan key compiled into the installed package, unexpired, lifetime <= 24 h,
     names THIS node -- whose id comes from the ROOT-owned /etc/meshembed-node/node-id, never
     from the daemon's own config -- and an unseen nonce in a ROOT-owned nonce store;
  3. only validated values are derived: role (coordinator if the plan names this node as
     coordinator, else stage), this node's /32 (must be configured on wg0), the other members'
     /32s, the model sha (a pre-placed /srv/mesh-di/models/<sha>.gguf must exist);
  4. the stage gets stage.env + a drop-in narrowing IPAddressAllow to the plan's members and
     RuntimeMaxSec = the plan's remaining lifetime; then it is (re)started. No plan text ever
     reaches an argv. The coordinator gets engine.env (model by sha, the plan's stages in layer
     order, slots/context/threads from fixed host settings) + the same kind of drop-in, and its
     ENGINE (meshembed-di-engine: llama-server on a UNIX socket, build #5b) is (re)started.

Every run also refreshes `ready.json` (D6): the runtime set verifies and the units exist. The
daemon advertises split capability only from that root-written file.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import hashlib
import os
import pwd
import re
import shutil
import stat
import subprocess
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import split_plan_verify as V

MAX_REQUEST_BYTES = 64 * 1024
STATE_DIR = Path("/var/lib/meshembed-split-launch")
NODE_ID_FILE = Path("/etc/meshembed-node/node-id")
SRV = Path("/srv/mesh-di")
ETC = Path("/etc/mesh-di")
UNITS = Path("/etc/systemd/system")
STAGE_UNIT = "meshembed-di-stage"
COORD_UNIT = "meshembed-di-coordinator"
ENGINE_UNIT = "meshembed-di-engine"                 # #5b: the coordinator's llama-server (UNIX socket)
ENGINE_SLOTS = 4                                    # parallel slots per plan (E1); host setting, never from a plan
ENGINE_CTX_PER_SLOT = 4096
ENGINE_VERIFY_S = 540                               # < the launcher unit's TimeoutStartSec=600; a slower load fails closed
RPC_PORT = 50052
# SPLIT-SERVE part B (auditor 2026-11-02 20:09:04Z, Q-B1..Q-B3, PB-1..PB-5): a serve split plan's coordinator. The
# one-shot PROBE (-lv 4, private socket, takes no request) verifies the placement; only then the serving unit starts.
SERVE_PROBE_UNIT = "meshembed-di-serve-probe"
SERVE_COORD_UNIT = "meshembed-di-serve-coord"
PROBE_SOCK = "/run/mesh-di-probe/probe.sock"
SERVE_SOCK = "/run/mesh-serve/serve.sock"
# the context and slots the backend sizes every member's signed share for (backend/app/serve_warmset.py SERVE_CTX,
# SERVE_SLOTS; a serve split plan signs no ctx or slots): host constants, never from a plan (a test pins both copies)
SERVE_COORD_CTX, SERVE_COORD_SLOTS = 8192, 2
SERVE_MIN_LIFE_S = 600                              # PB-3: serve-coord starts only with at least this much plan life left
WHOLE_SERVE_UNITS = ("meshembed-serve", "meshembed-serve-nodraft")   # DS-1: serve-coord Conflicts= them
PROBE_INV_WAIT_S = 20                               # LAUNCH-1: a --no-block start gets its InvocationID within seconds
IFACE = "meshdi0"                  # overlay automation step 3: the launcher's own interface (never wg0)
_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}
ROOT_UID = 0                       # the owner trusted files must have (tests substitute their uid)
# the stage's sha256-keyed weight cache (C.2 kit: --cache, LLAMA_CACHE=/var/lib/mesh-di-stage): purged on plan expiry,
# on revocation, and before a stage starts for a plan whose coordinator differs from the one that filled it (auditor
# 2026-10-21 15:04Z condition 4; the 64-bit key is accepted only for weights from the SAME coordinator)
STAGE_CACHE_ROOT = Path("/var/lib/mesh-di-stage")


class Refused(Exception):
    """A short code; the request is not acted on."""


# --- SPLIT-SERVE head 4-node (docs/DESIGN_SPLIT_SERVE_2026-11-02.md; auditor 19:38:48Z K4-1..K4-3) ----------------
# SD-6a: the two strings that mark a libggml-rpc whose cache READ path re-hashes every hit (our CVE-fix tree). A set
# without them (cf8716f7) is never given --cache.
_REHASH_MARKERS = (b"sha256t-%016", b"does not match its key")
STAGE_CACHE_USER = "mesh-di-stage"


def own_runtime_set(srv: Path = SRV) -> Optional[str]:
    """The digest of the runtime set this host verified: sha256 of its MANIFEST.runtime-set.sha256 (the auditor's
    definition, 18:41:37Z). None when the manifest is not root-owned or unreadable."""
    man = srv / "MANIFEST.runtime-set.sha256"
    if not _root_owned(man):
        return None
    try:
        return hashlib.sha256(man.read_bytes()).hexdigest()
    except OSError:
        return None


def rehash_cache_supported(srv: Path = SRV) -> bool:
    """K4-3 (ii): this set's libggml-rpc carries the re-hashing cache read path: EVERY real libggml-rpc.so* file in the
    set's bin has both markers, and there is at least one (auditor 19:42:29Z: never "any one of several")."""
    real = []
    for lib in sorted((srv / "bin").glob("libggml-rpc.so*")):
        try:
            if lib.is_symlink() or not lib.is_file():
                continue
            real.append(lib.read_bytes())
        except OSError:
            return False                                   # an unreadable library: no cache (fail closed)
    return bool(real) and all(all(m in data for m in _REHASH_MARKERS) for data in real)


def stage_cache_dir_ok(root: Optional[Path] = None, uid_of=None) -> bool:
    """K4-3 (iii) / SD-6: the cache dir is a real directory (no symlink) owned by the stage user, mode 0700 (so neither
    meshembed nor the owner's account can write it)."""
    p = root or STAGE_CACHE_ROOT
    uid_of = uid_of or (lambda name: pwd.getpwnam(name).pw_uid)
    try:
        st = os.lstat(p)
        want = uid_of(STAGE_CACHE_USER)
    except (OSError, KeyError):
        return False
    return stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode) and st.st_uid == want and (st.st_mode & 0o777) == 0o700


def stage_memory_max_mb(signed_mb: int, mem: Dict[str, int]) -> int:
    """CAP-2: a serve stage's MemoryMax = min(its SIGNED share, MemAvailable - 1 GiB, 3/4 MemTotal), never from a value
    the daemon could influence (the request file, the poll, its environment)."""
    return max(512, min(int(signed_mb), int(mem["MemAvailable"]) - 1024, int(mem["MemTotal"]) * 3 // 4))


def _meminfo_mb(path: Path = Path("/proc/meminfo")) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        k, _, v = line.partition(":")
        if k in ("MemTotal", "MemAvailable"):
            out[k] = int(v.split()[0]) // 1024
    return out


def _root_owned(path: Path, *, mode_mask: int = 0o022) -> bool:
    try:
        st = os.stat(path, follow_symlinks=False)
    except OSError:
        return False
    return stat.S_ISREG(st.st_mode) and st.st_uid == ROOT_UID and not (st.st_mode & mode_mask)


def node_id(path: Path = NODE_ID_FILE) -> str:
    """This node's id from the ROOT-owned file written by install.sh (not group/world writable)."""
    if not _root_owned(path):
        raise Refused("node_id_file_untrusted")
    nid = path.read_text(encoding="utf-8").strip()
    if not V._ID.fullmatch(nid or ""):
        raise Refused("node_id_invalid")
    return nid


def read_request(path: Path, owner_uid: int) -> Optional[Dict[str, Any]]:
    """The envelope, or None when there is no request. Truncates what it read."""
    try:
        fd = os.open(str(path), os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    except OSError:
        raise Refused("request_unreadable")              # e.g. a symlink (ELOOP)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise Refused("request_not_regular")
        if st.st_uid != owner_uid:
            raise Refused("request_wrong_owner")
        if st.st_mode & 0o077:
            raise Refused("request_mode_too_open")
        if st.st_size == 0:
            return None
        if st.st_size > MAX_REQUEST_BYTES:
            os.ftruncate(fd, 0)
            raise Refused("request_too_large")
        data = os.read(fd, MAX_REQUEST_BYTES + 1)
        os.ftruncate(fd, 0)
    finally:
        os.close(fd)
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise Refused("request_not_json")


def local_overlay_ips(iface: str = IFACE) -> set:
    """IPv4 addresses configured on the overlay interface (fixed argv, no shell)."""
    try:
        out = subprocess.run(["ip", "-4", "-o", "addr", "show", "dev", iface], capture_output=True,
                             text=True, timeout=10, env=_ENV, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return set()
    ips = set()
    for line in out.splitlines():
        parts = line.split()
        if "inet" in parts:
            ips.add(parts[parts.index("inet") + 1].split("/")[0])
    return ips


def derive(body: Dict[str, Any], me: str, local_ips: set, models_dir: Path,
           own_set: Optional[str] = None) -> Dict[str, Any]:
    """Validated launch parameters from a VERIFIED plan body. Refused on any mismatch.
    Kind serve (head 4-node): the SIGNED runtime_set must equal the set this host verified (SP-2 enforcement), and only
    the COORDINATOR needs the model file (section 3a: a stage receives its layers from the coordinator)."""
    if body["kind"] not in ("primary", "twin", "serve"):
        raise Refused("not_a_split_plan")
    serve = body["kind"] == "serve"
    if serve and (own_set is None or body.get("runtime_set") != own_set):
        raise Refused("runtime_set_mismatch")
    members = body["members"]
    mine = [m for m in members if m["node_id"] == me]
    if len(mine) != 1:
        raise Refused("not_a_member")
    own_ip = str(ipaddress.ip_address(mine[0]["overlay_ip"]))
    if own_ip not in local_ips:
        raise Refused("own_overlay_ip_not_on_overlay")
    peers = [str(ipaddress.ip_address(m["overlay_ip"])) for m in members if m["node_id"] != me]
    if not peers:
        raise Refused("no_peers")
    for ip in peers + [own_ip]:
        if ipaddress.ip_address(ip) not in V.OVERLAY_NET:
            raise Refused("ip_outside_overlay")
    model = models_dir / f"{body['model_sha']}.gguf"          # sha is ^[0-9a-f]{64}$ (schema)
    role = "coordinator" if body["coordinator"] == me else "stage"
    if (role == "coordinator" or not serve) and not _root_owned(model):
        raise Refused("model_not_preplaced")
    ordered = sorted((m for m in members if m["node_id"] != me), key=lambda m: m["layers"][0])
    return {"role": role, "plan_id": body["plan_id"], "own_ip": own_ip, "peers": peers,
            "coordinator": body["coordinator"],
            "stages": [f"{ipaddress.ip_address(m['overlay_ip'])}:{RPC_PORT}" for m in ordered],
            "layers": list(mine[0]["layers"]), "model": str(model), "model_sha": body["model_sha"],
            "expires_at": int(body["expires_at"]),
            # plan v3 (proposal A): the -ngl / --tensor-split the engine runs, from the VERIFIED body only
            # (split_plan_verify checked them against llama_assign); the --rpc order is the stages' order above
            "ngl": int(body["ngl"]), "ts": [int(x) for x in body["ts"]], "n_layer": int(body["n_layer"]),
            "kind": body["kind"], "runtime_set": body.get("runtime_set"),
            "memory_max_mb": int(mine[0]["memory_max_mb"]) if serve else None}


def _write(path: Path, text: str, mode: int, gid: Optional[int] = None) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.chmod(tmp, mode)
    if gid is not None:
        os.chown(tmp, ROOT_UID, gid)
    os.replace(tmp, path)


def apply(params: Dict[str, Any], now: float, *, etc: Path = ETC, units: Path = UNITS,
          systemctl=None, gid_of=None, state: Optional[Path] = None, cache_root: Optional[Path] = None,
          verifier=None, srv: Path = SRV, uid_of=None, meminfo=None, show=None, sleep=None) -> str:
    """Write env + plan drop-in; start the stage. Returns a result code."""
    gid_of = gid_of or (lambda name: pwd.getpwnam(name).pw_gid)
    systemctl = systemctl or (lambda *a: subprocess.run(["systemctl", *a], env=_ENV, timeout=60,
                                                        check=True, capture_output=True))
    remaining = int(params["expires_at"] - now)
    if remaining < 60:
        raise Refused("plan_expires_too_soon")
    allow = " ".join(f"{ip}/32" for ip in params["peers"]) + " 127.0.0.1"
    serve = params.get("kind") == "serve"
    if serve and params["role"] == "coordinator":
        return start_serve_probe(params, now, allow, etc=etc, units=units, systemctl=systemctl, gid_of=gid_of,
                                 state=state or STATE_DIR, meminfo=meminfo, show=show, sleep=sleep)
    unit = STAGE_UNIT if params["role"] == "stage" else ENGINE_UNIT
    d = units / f"{unit}.service.d"
    d.mkdir(mode=0o755, exist_ok=True)
    mem_line = ""
    if serve:                                              # CAP-2: the signed share, clamped by the host's floors
        mem_line = f"MemoryMax={stage_memory_max_mb(params['memory_max_mb'], (meminfo or _meminfo_mb)())}M\n"
        # STAGE-RESTART F-R1 (auditor 2026-11-04T21:38:23Z): a serve stage never restarts itself under a signed plan. A
        # restarted rpc-server comes back EMPTY and the coordinator aborts on it (bed run 2); a dead stage must be a
        # declared loss (the daemon's heartbeat, the backend's engine_down), never a silent repair.
        mem_line += "Restart=no\n"
    _write(d / "20-plan.conf", f"# plan {params['plan_id']}\n[Service]\nLimitCORE=0\nIPAddressAllow=\n"
           f"IPAddressAllow={allow}\nRuntimeMaxSec={remaining}\n{mem_line}", 0o644)
    if params["role"] == "stage":
        coord = str(params.get("coordinator") or "")
        owner = {"coordinator": coord, "model_sha": params.get("model_sha")}
        if _cache_record(state or STATE_DIR) != owner:     # SD-6: a coordinator OR model change purges
            purge_stage_cache(cache_root)
        _result(state or STATE_DIR, "stage-cache-coordinator.json", owner)                   # only after the purge
        # K4-3: the cache flag is ON only for a serve plan whose SIGNED set equals this host's verified set (checked in
        # derive), on a set whose libggml-rpc re-hashes hits, with a safe cache dir. Any miss = no cache, never a refusal.
        cache = (serve and params.get("runtime_set") is not None and params.get("runtime_set") == own_runtime_set(srv)
                 and rehash_cache_supported(srv) and stage_cache_dir_ok(cache_root, uid_of))
        gid = gid_of("mesh-di-stage")
        _write(etc / "stage.env", f"STAGE_BIND={params['own_ip']}\nRPC_PORT={RPC_PORT}\n"
               "CACHE_DIR=/var/lib/mesh-di-stage\n"
               f"STAGE_CACHE_FLAG={'--cache' if cache else ''}\n", 0o640, gid)
        systemctl("daemon-reload")
        systemctl("restart", f"{STAGE_UNIT}.service")
        return "stage_started"
    gid = gid_of("mesh-di-coord")
    threads = max(1, os.cpu_count() or 1)
    _write(etc / "engine.env", f"MODEL={params['model']}\nMODEL_SHA_PIN={params['model_sha']}\n"
           f"RPC_STAGES={','.join(params['stages'])}\nNGL={params['ngl']}\nTS={','.join(map(str, params['ts']))}\n"
           f"SLOTS={ENGINE_SLOTS}\n"
           f"CTX={ENGINE_SLOTS * ENGINE_CTX_PER_SLOT}\nTHREADS={threads}\n", 0o640, gid)
    systemctl("daemon-reload")
    # LAUNCH-2 (auditor 2026-11-02 21:37:00Z): never WAIT for the engine's start (its ExecStartPre G2 re-hashes the whole
    # model: minutes for a 14B/30B, past the 60 s subprocess timeout); wait for the NEW invocation instead, and read the
    # placement ONLY from that invocation's journal (a previous run's load lines never verify this one)
    show = show or _show
    prev = show(ENGINE_UNIT, "InvocationID")
    systemctl("restart", "--no-block", f"{ENGINE_UNIT}.service")
    inv = await_new_invocation(show, ENGINE_UNIT, prev, sleep or time.sleep)
    if inv is None:
        systemctl("stop", f"{ENGINE_UNIT}.service")
        raise Refused("engine_not_started")
    # blocks until the load lines are in (<= ENGINE_VERIFY_S): "engine_started" is only ever reported VERIFIED, so the
    # daemon's split_engine.status() (which needs engine_started) never routes to an unverified placement
    ok, code = (verifier(params) if verifier else
                verify_engine_placement(params, read=lambda: invocation_journal(ENGINE_UNIT, inv, show)))
    if not ok:                                         # execution != authorisation: stop, the plan is lost upstream
        systemctl("stop", f"{ENGINE_UNIT}.service")
        raise Refused(code)
    return "engine_started"


def _show(unit: str, prop: str) -> str:
    """One systemd property of a unit (root launcher; fixed argv, no shell)."""
    return subprocess.run(["systemctl", "show", "-p", prop, "--value", f"{unit}.service"], env=_ENV, timeout=30,
                          capture_output=True, text=True, check=False).stdout.strip()


def _sha256(path: Path) -> Optional[str]:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _physical_cores(sys_cpu: Path = Path("/sys/devices/system/cpu")) -> int:
    """As serve_launch.physical_cores (not imported: no package module imports a root launcher, test_start_guards)."""
    cores = set()
    for d in sys_cpu.glob("cpu[0-9]*"):
        try:
            cores.add(((d / "topology/physical_package_id").read_text(encoding="utf-8").strip(),
                       (d / "topology/core_id").read_text(encoding="utf-8").strip()))
        except OSError:
            continue
    return len(cores) or (os.cpu_count() or 1)


def serve_threads(cores: int) -> int:
    """serve_launch.host_settings' rule (owner first: two cores left to the owner, at most 6); a test pins the two."""
    return max(1, min(6, cores - 2))


def await_new_invocation(show, unit: str, prev: str, sleep) -> Optional[str]:
    """LAUNCH-1/2: after a --no-block restart, the unit's NEW InvocationID (32 hex, not `prev`), or None in time."""
    for _ in range(PROBE_INV_WAIT_S):
        inv = show(unit, "InvocationID")
        if re.fullmatch(r"[0-9a-f]{32}", inv or "") and inv != prev:
            return inv
        sleep(1)
    return None


def invocation_journal(unit: str, inv: str, show=None) -> Tuple[bool, List[str]]:
    """(that invocation still running, ITS log lines only): _SYSTEMD_INVOCATION_ID=<inv>."""
    show = show or _show
    active = show(unit, "InvocationID") == inv and show(unit, "ActiveState") in ("active", "activating")
    return active, _journal(inv)


def serve_coord_env(params: Dict[str, Any], hs: Dict[str, Any]) -> str:
    """serve-coord.env: exactly the keys of the kit's G0 ENGINE profile (the checker is a runtime-set file, so the serve
    units reuse it; --no-repack is a unit byte), from the VERIFIED plan + host settings."""
    return (f"MODEL={params['model']}\nMODEL_SHA_PIN={params['model_sha']}\nRPC_STAGES={','.join(params['stages'])}\n"
            f"NGL={params['ngl']}\nTS={','.join(map(str, params['ts']))}\nSLOTS={SERVE_COORD_SLOTS}\n"
            f"CTX={SERVE_COORD_CTX}\nTHREADS={hs['threads']}\n")


def _active(show, unit: str) -> bool:
    return show(unit, "ActiveState") in ("active", "activating", "reloading")


def start_serve_probe(params: Dict[str, Any], now: float, allow: str, *, etc: Path, units: Path, systemctl,
                      gid_of, state: Path, meminfo=None, show=None, sleep=None) -> str:
    """Q-B3 option (iii): write the env + the probe's drop-in, start the PROBE, record the pending state (PB-1: root-
    written, never daemon memory) and return. A later pass (serve_probe_step) reads the placement and decides."""
    show, sleep = show or _show, sleep or time.sleep
    if not all((units / f"{u}.service").exists() for u in (SERVE_PROBE_UNIT, SERVE_COORD_UNIT)):
        raise Refused("serve_units_absent")                  # a host without the R3 kit: never a half start
    if any(_active(show, u) for u in WHOLE_SERVE_UNITS):
        raise Refused("whole_serve_active")                  # DS-1: Conflicts= must never kill a live whole-model plan
    mem = (meminfo or _meminfo_mb)()
    hs = {"threads": serve_threads(_physical_cores())}
    mem_max = stage_memory_max_mb(params["memory_max_mb"], mem)   # CAP-2, as the stage
    env = serve_coord_env(params, hs)
    systemctl("stop", f"{SERVE_COORD_UNIT}.service")          # the previous plan's coordinator never overlaps a probe
    _write(etc / "serve-coord.env", env, 0o640, gid_of("mesh-di-coord"))
    d = units / f"{SERVE_PROBE_UNIT}.service.d"
    d.mkdir(mode=0o755, exist_ok=True)
    # PB-4: the probe's RuntimeMaxSec is a unit byte; its drop-in narrows the network and the memory only
    _write(d / "20-plan.conf", f"# plan {params['plan_id']}\n[Service]\nLimitCORE=0\nIPAddressAllow=\nIPAddressAllow={allow}\n"
           f"MemoryMax={mem_max}M\n", 0o644)
    _result(state, "serve-coord.json", {})                   # a new probe: no stale "coordinator started" record
    systemctl("daemon-reload")
    # LAUNCH-1: never WAIT for the start (G2 re-hashes the whole model in ExecStartPre: minutes for a large one); the
    # new invocation's id appears as soon as the start job runs
    prev = show(SERVE_PROBE_UNIT, "InvocationID")
    systemctl("restart", "--no-block", f"{SERVE_PROBE_UNIT}.service")
    inv = await_new_invocation(show, SERVE_PROBE_UNIT, prev, sleep)
    if inv is None:
        systemctl("stop", f"{SERVE_PROBE_UNIT}.service")
        raise Refused("probe_not_started")
    _result(state, "serve-probe.json", {
        "plan_id": params["plan_id"], "invocation": inv, "env_sha": hashlib.sha256(env.encode()).hexdigest(),
        "stage_invocation": show(STAGE_UNIT, "InvocationID"), "started_at": int(now),
        "expires_at": int(params["expires_at"]), "allow": allow, "memory_max_mb": mem_max,
        "n_layer": params["n_layer"], "ngl": params["ngl"], "ts": params["ts"], "stages": params["stages"]})
    return "serve_probe_started"


_VERBOSITY = ("-lv", "--log-verbosity", "--verbosity", "-v", "--verbose")


def _argv(execstart: str) -> Optional[List[str]]:
    """The argv systemd will run, from `systemctl show -p ExecStart --value` ("{ path=... ; argv[]=... ; ...}")."""
    m = re.search(r"argv\[\]=(.*?) ; ignore_errors=", execstart or "")
    return m.group(1).split() if m else None


def argv_pair_ok(probe: str, coord: str) -> bool:
    """Q-B2 (defence in depth): the two units' ExecStart differ ONLY in "--log-verbosity 4" (probe) and the socket."""
    p, c = _argv(probe), _argv(coord)
    if not p or not c or any(t in _VERBOSITY for t in c):
        return False
    if p.count("--log-verbosity") != 1 or p.count(PROBE_SOCK) != 1 or c.count(SERVE_SOCK) != 1:
        return False
    i = p.index("--log-verbosity")
    if i + 1 >= len(p) or p[i + 1] != "4":
        return False
    rest = p[:i] + p[i + 2:]
    if any(t in _VERBOSITY for t in rest):
        return False
    return [SERVE_SOCK if t == PROBE_SOCK else t for t in rest] == c


def _journal(inv: str) -> List[str]:
    out = subprocess.run(["journalctl", f"_SYSTEMD_INVOCATION_ID={inv}", "-o", "cat", "--no-pager"], env=_ENV,
                         timeout=30, capture_output=True, text=True, check=False).stdout
    return out.splitlines()


def _inactive(state_str: str) -> bool:
    return state_str in ("inactive", "failed")


PASSES_PER_START = 3                       # F-P1 passes per start; F-P2 kicks per probe
KICK_UNIT = "meshembed-split-launch-kick"   # SPLIT-PACE F-P2: ONE fixed transient name, so kicks never pile up
KICK_AFTER_S = 20
PROBE_WINDOW_S = 1500                      # = meshembed-di-serve-probe RuntimeMaxSec (the R3 kit; backend SERVE_PROBE_BOUND_S)


def schedule_kick(state: Path, pend: Dict[str, Any], now: float, *, runner=None) -> bool:
    """SPLIT-PACE F-P2 (auditor 2026-11-04T22:46:40Z, option (a)): while a serve probe is loading, the launcher schedules
    ITS OWN next pass in KICK_AFTER_S with a transient timer of a FIXED name (one pending kick at a time: a second
    systemd-run on the same name fails and is ignored), at most PASSES_PER_START times per probe and only inside the probe's
    RuntimeMaxSec. The static 5-min timer stays the safety net. Returns whether a kick was scheduled."""
    kicks = int(pend.get("kicks") or 0)
    if kicks >= PASSES_PER_START or now - int(pend.get("started_at") or now) > PROBE_WINDOW_S:
        return False
    run = runner or (lambda argv: subprocess.run(argv, env=_ENV, timeout=30, check=True, capture_output=True))
    try:
        run(["systemd-run", "--quiet", f"--unit={KICK_UNIT}", f"--on-active={KICK_AFTER_S}",
             "--timer-property=AccuracySec=1s",
             # PG-K1 (auditor 2026-11-04 wake run): a timer's RemainAfterElapse defaults to yes, so an ELAPSED kick timer
             # would stay loaded and the next kick of the same name would fail "unit exists"; it unloads once it fired
             "--timer-property=RemainAfterElapse=no", "/usr/bin/systemctl", "start", "--no-block",
             "meshembed-split-launch.service"])
    except Exception:                                         # already pending, or systemd-run absent: the timer covers it
        return False
    _result(state, "serve-probe.json", dict(pend, kicks=kicks + 1))
    return True


kick_runner = None                                            # tests replace it; None = the real systemd-run


def serve_probe_step(state: Path, now: float, *, units: Path = UNITS, etc: Path = ETC, systemctl=None, show=None,
                     journal=None) -> str:
    """One pass over a pending probe (PB-1..PB-3). "" = none pending; "serve_probe_loading" = keep waiting;
    "serve_coord_started"; or "refused:<code>" (the probe stopped, serve-coord not started, the code recorded)."""
    try:
        pend = json.loads((state / "serve-probe.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ""
    if not isinstance(pend, dict) or not pend.get("plan_id"):
        return ""
    systemctl = systemctl or (lambda *a: subprocess.run(["systemctl", *a], env=_ENV, timeout=60,
                                                        check=True, capture_output=True))
    show, journal = show or _show, journal or _journal

    def stop_probe() -> bool:
        try:
            systemctl("stop", f"{SERVE_PROBE_UNIT}.service")
        except Exception:
            pass
        return _inactive(show(SERVE_PROBE_UNIT, "ActiveState"))

    def end(code: str) -> str:
        stop_probe()
        _result(state, "serve-probe.json", {})
        _result(state, "last-result.json", {"plan_id": pend["plan_id"], "role": "coordinator", "result": "refused",
                                            "code": code, "at": int(now)})
        return f"refused:{code}"

    applied = _applied(state)
    if applied.get("plan_id") != pend["plan_id"] or int(pend.get("expires_at") or 0) - now < SERVE_MIN_LIFE_S:
        return end("serve_plan_not_current")                  # revoked, reclaimed, expired, superseded, or too short
    inv = str(pend.get("invocation") or "")
    if not re.fullmatch(r"[0-9a-f]{32}", inv):
        return end("probe_state_unreadable")
    running = show(SERVE_PROBE_UNIT, "InvocationID") == inv and show(SERVE_PROBE_UNIT, "ActiveState") in (
        "active", "activating")
    ok, code = placement_check(journal(inv), pend["n_layer"], pend["ngl"], pend["ts"], pend["stages"])   # PB-2
    if ok is None:
        if running:
            if kick_runner is not None or os.geteuid() == 0:   # the launcher (root) or a test's runner only
                schedule_kick(state, pend, now, runner=kick_runner)   # SPLIT-PACE F-P2: look again soon, not in 5 min
            return "serve_probe_loading"
        return end("placement_unverified")                    # PB-4: past the bound = fail closed
    if not ok:
        return end(code)
    if _sha256(etc / "serve-coord.env") != pend.get("env_sha"):
        return end("serve_env_changed")
    if show(STAGE_UNIT, "InvocationID") != pend.get("stage_invocation"):
        return end("stage_restarted")
    if not argv_pair_ok(show(SERVE_PROBE_UNIT, "ExecStart"), show(SERVE_COORD_UNIT, "ExecStart")):
        return end("serve_units_differ")
    if any(_active(show, u) for u in WHOLE_SERVE_UNITS):
        return end("whole_serve_active")                      # DS-1, also at the coordinator's start
    if not stop_probe():                                       # PB-3: stopped AND confirmed inactive first
        return end("probe_did_not_stop")
    d = units / f"{SERVE_COORD_UNIT}.service.d"
    d.mkdir(mode=0o755, exist_ok=True)
    _write(d / "20-plan.conf", f"# plan {pend['plan_id']}\n[Service]\nLimitCORE=0\nIPAddressAllow=\nIPAddressAllow={pend['allow']}\n"
           f"RuntimeMaxSec={int(pend['expires_at'] - now)}\nMemoryMax={int(pend['memory_max_mb'])}M\n", 0o644)
    systemctl("daemon-reload")
    systemctl("restart", "--no-block", f"{SERVE_COORD_UNIT}.service")   # LAUNCH-1: G2 again; the duty's health covers it
    _result(state, "serve-probe.json", {})
    rec = {"plan_id": pend["plan_id"], "role": "coordinator", "result": "ok", "code": "serve_coord_started",
           "at": int(now), "expires_at": int(pend["expires_at"])}
    _result(state, "last-result.json", rec)
    _result(state, "serve-coord.json", rec)                   # kept apart, as engine.json; the batch worker never reads it
    return "serve_coord_started"


# --- proposal A runtime check: what llama.cpp ASSIGNED == what the plan signed (auditor A1 (2), 13:23Z rule) -------
# Source: the engine's own load lines at --log-verbosity 4 (the unit fixes 4), measured 2026-10-21 on 189:
#   llama_kv_cache: RPC0[10.44.0.3:50052] KV buffer size =    36.00 MiB     (every RPC device is labelled RPC0:
#   llama_kv_cache:        CPU KV buffer size =    36.00 MiB                 the ENDPOINT is the key, never the name)
#   llama_kv_cache: size =  112.00 MiB (  1024 cells,  28 layers,  1/1 seqs) ...
# layers on a device = its KV / (size / layers). Expected: the coordinator holds [0, n_layer+1-ngl), each stage its
# llama_assign() range; block n_layer is the output head and carries no KV. A missing line fails.
_KV_DEV = re.compile(r"llama_kv_cache:\s+(?:CPU|RPC\d+\[([0-9.]+:\d+)\]) KV buffer size =\s*([0-9.]+) MiB")
_KV_TOTAL = re.compile(r"llama_kv_cache: size =\s*([0-9.]+) MiB \(\s*\d+ cells,\s*(\d+) layers")
_HYBRID = re.compile(r"llama_memory_recurrent|RS buffer size")


def expected_kv_layers(n_layer: int, ngl: int, ts: List[int], stages: List[str]) -> Dict[str, int]:
    """{"CPU": n, "<endpoint>": n, ...} KV-carrying layers per device for the signed placement."""
    kv = lambda a, b: max(0, min(b, n_layer) - a)             # ids >= n_layer are the output head (no KV)
    out = {"CPU": kv(0, n_layer + 1 - ngl)}
    for ep, (a, b) in zip(stages, V.llama_assign(n_layer, ngl, ts)):
        out[ep] = kv(a, b)
    return out


def placement_check(lines: List[str], n_layer: int, ngl: int, ts: List[int],
                    stages: List[str]) -> Tuple[Optional[bool], str]:
    """None = not loaded yet; (True, "placement_verified") or (False, <content-free code>)."""
    if any(_HYBRID.search(l) for l in lines):
        return False, "placement_hybrid_unsupported"          # line format not measured yet (M5b): fail closed
    total = next((m for m in map(_KV_TOTAL.search, lines) if m), None)
    if total is None:
        return None, "placement_loading"
    tot_mib, tot_layers = float(total.group(1)), int(total.group(2))
    if tot_layers <= 0 or tot_mib <= 0:
        return False, "placement_unreadable"
    per = tot_mib / tot_layers
    seen: Dict[str, int] = {}
    for m in filter(None, map(_KV_DEV.search, lines)):
        key = m.group(1) or "CPU"
        n = float(m.group(2)) / per
        if abs(n - round(n)) > 0.01 or key in seen:
            return False, "placement_unreadable"
        seen[key] = int(round(n))
    want = expected_kv_layers(n_layer, ngl, ts, stages)
    if set(seen) - set(want):
        return False, "placement_unknown_device"
    for dev, n in want.items():
        if seen.get(dev, 0) != n or (n > 0 and dev not in seen):
            return False, "placement_mismatch"
    if sum(seen.values()) != tot_layers:
        return False, "placement_mismatch"
    return True, "placement_verified"


def engine_journal(systemctl=None) -> Tuple[bool, List[str]]:
    """(active, the CURRENT engine invocation's log lines) -- filtered by its _SYSTEMD_INVOCATION_ID."""
    run = lambda *a: subprocess.run(list(a), env=_ENV, timeout=30, capture_output=True, text=True, check=False).stdout
    inv = run("systemctl", "show", "-p", "InvocationID", "--value", f"{ENGINE_UNIT}.service").strip()
    active = run("systemctl", "is-active", f"{ENGINE_UNIT}.service").strip() in ("active", "activating")
    if not re.fullmatch(r"[0-9a-f]{32}", inv):
        return active, []
    out = run("journalctl", f"_SYSTEMD_INVOCATION_ID={inv}", "-o", "cat", "--no-pager")
    return active, out.splitlines()


def verify_engine_placement(params: Dict[str, Any], *, read: Callable[[], Tuple[bool, List[str]]] = engine_journal,
                            clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep,
                            budget_s: float = ENGINE_VERIFY_S) -> Tuple[bool, str]:
    end = clock() + budget_s
    while True:
        active, lines = read()
        ok, code = placement_check(lines, params["n_layer"], params["ngl"], params["ts"], params["stages"])
        if ok is not None:
            return ok, code
        if not active:
            return False, "engine_exited_before_load"
        if clock() >= end:
            return False, "placement_unverified"              # no load lines in time: a missing line FAILS
        sleep(5)


def readiness(srv: Path = SRV, units: Path = UNITS) -> Tuple[bool, str]:
    """D6: the mesh-di runtime set verifies and both units are installed."""
    man = srv / "MANIFEST.runtime-set.sha256"
    if not all((units / f"{u}.service").exists() for u in (STAGE_UNIT, ENGINE_UNIT)):
        return False, "mesh_di_units_missing"
    if not _root_owned(man):
        return False, "runtime_manifest_missing"
    try:
        r = subprocess.run(["sha256sum", "-c", "--strict", "--quiet", str(man)], cwd=str(srv / "bin"),
                           env=_ENV, timeout=300, capture_output=True, check=False)
    except (OSError, subprocess.SubprocessError):
        return False, "runtime_verify_error"
    return (r.returncode == 0, "ok" if r.returncode == 0 else "runtime_set_mismatch")


def _result(state: Path, name: str, payload: Dict[str, Any]) -> None:
    state.mkdir(mode=0o755, exist_ok=True)
    _write(state / name, json.dumps(payload, sort_keys=True), 0o644)


def _applied(state: Path) -> Dict[str, Any]:
    try:
        return json.loads((state / "applied.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def purge_stage_cache(root: Optional[Path] = None) -> None:
    """Delete <root>/rpc (fixed path). A symlink there is removed itself, never followed."""
    p = (root or STAGE_CACHE_ROOT) / "rpc"
    if p.is_symlink():
        p.unlink()
    elif p.exists():
        shutil.rmtree(p)


def _cache_record(state: Path) -> Optional[Dict[str, Any]]:
    """{coordinator, model_sha} the cache was last filled for (None: nobody recorded; an older record without the sha
    never matches, so the first start after the upgrade purges). The caller records the new one only AFTER a
    successful purge, so a failed purge is retried at the next start (auditor 16:50Z nit)."""
    try:
        d = json.loads((state / "stage-cache-coordinator.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return {"coordinator": d.get("coordinator"), "model_sha": d.get("model_sha")} if isinstance(d, dict) else None


STOP_ORDER = (SERVE_COORD_UNIT, SERVE_PROBE_UNIT, ENGINE_UNIT, STAGE_UNIT)


def _stop_units(systemctl=None, show=None) -> None:
    """Teardown. The CONSUMERS first, while their RPC stage still answers: llama-server aborts (SIGABRT, status 6) on
    SIGTERM once its RPC peer is gone (the split-serve bed 2026-11-03; the ABRT-CORE clean-stop test reproduces it with
    the stage stopped first). Then the engine, then the stage. A coordinator that still ends with status 6 is the
    KNOWN exit (auditor 2026-11-03 13:58:00Z item 4), logged as such, never an incident."""
    real = systemctl is None
    systemctl = systemctl or (lambda *a: subprocess.run(["systemctl", *a], env=_ENV, timeout=60,
                                                        check=False, capture_output=True))
    show = show or (_show if real else (lambda u, p: ""))
    for u in STOP_ORDER:
        systemctl("stop", f"{u}.service")
    if show(SERVE_COORD_UNIT, "ExecMainStatus") == "6":
        print("split_launch: serve_coord_exit_6_known (llama-server on a lost RPC peer; not an incident)")


def clear_serve_coord_files(etc: Path = ETC, units: Path = UNITS) -> None:
    """Part B (auditor 21:04:05Z LOW, defence in depth): a torn-down plan leaves no serve-coord.env and no plan drop-in
    for the probe or the coordinator (fixed paths; a symlink there is removed itself, never followed)."""
    for p in (etc / "serve-coord.env", units / f"{SERVE_PROBE_UNIT}.service.d" / "20-plan.conf",
              units / f"{SERVE_COORD_UNIT}.service.d" / "20-plan.conf"):
        try:
            p.unlink()
        except FileNotFoundError:
            pass


LEASE_S = 180          # SO-2: about three daemon polls' worth plus margin; a stale lease = teardown


def read_keep(path: Path, owner_uid: int) -> Dict[str, Any]:
    """The daemon's lease file {plan_id: time}: the SAME trust checks as a request (regular, one link, the daemon user,
    0600, never a symlink), read WITHOUT truncating. Anything wrong = {} (no lease = stale)."""
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return {}
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid != owner_uid or st.st_mode & 0o077
                or st.st_size > MAX_REQUEST_BYTES):
            return {}
        d = json.loads(os.read(fd, MAX_REQUEST_BYTES + 1).decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return {}
    finally:
        os.close(fd)
    return d if isinstance(d, dict) else {}


def lease_fresh(keep: Path, owner_uid: int, plan_id: str, now: float) -> bool:
    at = read_keep(keep, owner_uid).get(plan_id)
    if not isinstance(at, (int, float)) or isinstance(at, bool):
        return False
    return -60 <= now - at <= LEASE_S                    # a marker from the future (clock skew > 60 s) does not count


def _teardown_plan(state: Path, ovl, systemctl, cache_root: Optional[Path], etc: Path, units: Path, *,
                   stop: bool) -> Optional[str]:
    """Tear the applied plan down and ALWAYS return to a clean state (STAGE-WEDGE F-W1, auditor 2026-11-04T21:04:13Z):
    whatever the unit stop, the overlay teardown or the cache purge does, applied.json and serve-coord.json are cleared in
    the finally, so the node can take the next plan. A purge that fails is reported as its own code
    (purge_failed:<errno name>), never folded into a catch-all "failed" that would leave the old plan applied."""
    purge_err: Optional[str] = None
    try:
        if stop:
            _stop_units(systemctl)
        ovl.teardown()
        try:
            purge_stage_cache(cache_root)
        except OSError as e:
            import errno as _errno
            purge_err = "purge_failed:" + (_errno.errorcode.get(e.errno or 0) or type(e).__name__)
            _result(state, "purge.json", {"result": "failed", "code": purge_err, "at": int(time.time())})
    finally:
        _result(state, "applied.json", {})
        _result(state, "serve-coord.json", {})
        clear_serve_coord_files(etc, units)
    return purge_err


def housekeeping(state: Path, revoke: Optional[Path], owner_uid: int, now: float, ovl, systemctl=None,
                 cache_root: Optional[Path] = None, etc: Path = ETC, units: Path = UNITS,
                 keep: Optional[Path] = None) -> str:
    """Tear the overlay down when the applied plan expired, or when the daemon relays a revocation
    of EXACTLY that plan (the revocation can only tear down, never bring anything up)."""
    applied = _applied(state)
    pid = applied.get("plan_id")
    code = ""
    if pid and int(applied.get("expires_at") or 0) <= now:
        code, err = "expired_torn_down", _teardown_plan(state, ovl, systemctl, cache_root, etc, units, stop=False)
    else:
        rv = None
        if revoke is not None:
            try:
                rv = read_request(revoke, owner_uid)
            except Refused:
                rv = None
        if pid and isinstance(rv, dict) and rv.get("plan_id") == pid:
            code, err = "revoked_torn_down", _teardown_plan(state, ovl, systemctl, cache_root, etc, units, stop=True)
        elif pid and keep is not None and not lease_fresh(keep, owner_uid, pid, now):
            # SO-2: the daemon no longer renews this plan (it was lost, the daemon is gated, crashed or cut off): stop it
            # now, not at its expiry. The lease can only shorten a plan, never extend it (the expiry branch always wins).
            code, err = "lease_expired_torn_down", _teardown_plan(state, ovl, systemctl, cache_root, etc, units, stop=True)
        elif pid and callable(getattr(ovl, "present", None)) and not ovl.present():
            # STAGE-WEDGE F-W3: a plan recorded as applied while its overlay is gone (a node wedged by an older build, or
            # meshdi0 removed by hand) cannot serve: heal to a clean state so the next plan can start.
            code, err = "healed_no_overlay", _teardown_plan(state, ovl, systemctl, cache_root, etc, units, stop=True)
        else:
            return ""
    return f"{code}:{err}" if err else code

def run_once(request: Path, owner: str, *, state: Path = STATE_DIR, now: Optional[float] = None,
             node_id_file: Path = NODE_ID_FILE, trusted=None, local_ips=None,
             models_dir: Path = SRV / "models", applier=None, ready=None, overlay=None,
             revoke: Optional[Path] = None, systemctl=None, cache_root: Optional[Path] = None,
             probe_step=None, keep: Optional[Path] = None) -> str:
    """One launcher pass. Overlay automation step 3: the WireGuard key is generated here (root) and
    its PUBLIC half published in ready.json; a verified plan v2 builds meshdi0 (own-key check first)
    and the mesh_di nft table before the units start; expiry / a revocation of the applied plan
    tears it down."""
    from . import split_overlay_node as _real_ovl
    ovl = overlay or _real_ovl
    now = time.time() if now is None else now
    ok, code = readiness() if ready is None else ready
    pub = None
    if ok:
        try:
            pub = ovl.ensure_key()
        except Exception as e:                      # e.g. wireguard-tools missing: not ready, say why
            ok, code = False, "wireguard_unavailable" if isinstance(e, (OSError, RuntimeError)) else str(e)[:40]
    ready_doc = {"ready": ok, "code": code, "at": int(now)}
    own_set = own_runtime_set() if ok else None
    if pub:
        ready_doc["wg_pubkey"] = pub
    if own_set:
        ready_doc["runtime_set"] = own_set                 # SS-4: a CLAIM for planning; derive enforces it
    _result(state, "ready.json", ready_doc)
    try:
        owner_uid = pwd.getpwnam(owner).pw_uid
        hk = housekeeping(state, revoke, owner_uid, now, ovl, systemctl, cache_root=cache_root, keep=keep)
        ps = serve_probe_step(state, now, systemctl=systemctl) if probe_step is None else probe_step(state, now)
        env = read_request(request, owner_uid)
        if env is None:
            return hk or ps or "no_request"
        if not ok:
            raise Refused(code)
        me = node_id(node_id_file)
        nonces = V.NonceStore(state / "nonces.json")
        try:
            body = V.verify_plan(env, me, now=now, nonces=nonces, trusted=trusted)
        except V.PlanRejected as e:
            raise Refused(str(e))
        try:
            cfg = ovl.configure(body, me, pub)          # own-key check, then meshdi0 from the plan
        except _real_ovl.Refused as e:
            raise Refused(str(e))
        ovl.firewall(cfg["peers"], listener=cfg["listener"], udp_sources=())
        _result(state, "applied.json", {"plan_id": body["plan_id"], "expires_at": int(body["expires_at"])})
        if body["kind"] == "probe":                     # a probe needs only the overlay (the daemon measures)
            _result(state, "last-result.json", {"plan_id": body["plan_id"], "role": "probe", "result": "ok",
                                                "code": "probe_overlay_up", "at": int(now),
                                                "expires_at": int(body["expires_at"])})
            return "probe_overlay_up"
        if local_ips is None:
            local_ips = {cfg["own_ip"]} | local_overlay_ips()
        params = derive(body, me, local_ips, models_dir, own_set=own_set)
        result = applier(params, now) if applier else apply(params, now, state=state, cache_root=cache_root)
        _result(state, "last-result.json", {"plan_id": params["plan_id"], "role": params["role"],
                                            "result": "ok", "code": result, "at": int(now),
                                            "expires_at": params["expires_at"]})
        if result == "engine_started":     # kept apart: later requests must not hide a running engine
            _result(state, "engine.json", {"plan_id": params["plan_id"], "role": "coordinator",
                                           "result": "ok", "code": result, "at": int(now),
                                           "expires_at": params["expires_at"]})
        return result
    except Refused as e:
        _result(state, "last-result.json", {"result": "refused", "code": str(e), "at": int(now)})
        return f"refused:{e}"
    except Exception as e:                                  # never leave a half-applied plan silent
        _result(state, "last-result.json", {"result": "failed", "code": type(e).__name__, "at": int(now)})
        return "failed"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="meshembed_node.split_launch")
    ap.add_argument("--request", required=True)
    ap.add_argument("--owner", required=True)
    ap.add_argument("--revoke", default=None)
    a = ap.parse_args(argv)
    if os.geteuid() != 0:
        print("split_launch: must run as root (meshembed-split-launch.service)")
        return 2
    from .path_heal import drift
    bad = drift()                                        # HT-5 at start (auditor 2026-11-03 14:06:46Z), before systemctl
    if bad:
        print(f"split_launch: refused venv_drift {bad}")
        return 3
    req = Path(a.request)
    # SPLIT-PACE F-P1 (auditor 2026-11-04T21:38:23Z): a handoff written WHILE a pass runs is coalesced by systemd into the
    # running activation (bed run 2, 19:33:06Z: the next start came from the 5-min timer). So after a pass, a request
    # file that is non-empty again is handled at once, a bounded number of times.
    for _ in range(PASSES_PER_START):
        print(f"split_launch: {run_once(req, a.owner, revoke=Path(a.revoke) if a.revoke else None, keep=req.parent / 'split-keep')}")
        if not request_pending(req):
            break
    return 0



def request_pending(req: Path) -> bool:
    """A non-empty request file (read_request truncates what it read; anything there now arrived after the read).
    A symlink, an unreadable or a missing file = not pending (the next trigger or the timer handles it)."""
    try:
        st = os.lstat(req)
    except OSError:
        return False
    return stat.S_ISREG(st.st_mode) and st.st_size > 0


if __name__ == "__main__":
    raise SystemExit(main())
