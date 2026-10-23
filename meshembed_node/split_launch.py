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
import os
import pwd
import shutil
import stat
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

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
RPC_PORT = 50052
IFACE = "meshdi0"                  # overlay automation step 3: the launcher's own interface (never wg0)
_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}
ROOT_UID = 0                       # the owner trusted files must have (tests substitute their uid)
# the stage's sha256-keyed weight cache (C.2 kit: --cache, LLAMA_CACHE=/var/lib/mesh-di-stage): purged on plan expiry,
# on revocation, and before a stage starts for a plan whose coordinator differs from the one that filled it (auditor
# 2026-10-21 15:04Z condition 4; the 64-bit key is accepted only for weights from the SAME coordinator)
STAGE_CACHE_ROOT = Path("/var/lib/mesh-di-stage")


class Refused(Exception):
    """A short code; the request is not acted on."""


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


def derive(body: Dict[str, Any], me: str, local_ips: set, models_dir: Path) -> Dict[str, Any]:
    """Validated launch parameters from a VERIFIED plan body. Refused on any mismatch."""
    if body["kind"] not in ("primary", "twin"):
        raise Refused("not_a_split_plan")
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
    if not _root_owned(model):
        raise Refused("model_not_preplaced")
    role = "coordinator" if body["coordinator"] == me else "stage"
    ordered = sorted((m for m in members if m["node_id"] != me), key=lambda m: m["layers"][0])
    return {"role": role, "plan_id": body["plan_id"], "own_ip": own_ip, "peers": peers,
            "coordinator": body["coordinator"],
            "stages": [f"{ipaddress.ip_address(m['overlay_ip'])}:{RPC_PORT}" for m in ordered],
            "layers": list(mine[0]["layers"]), "model": str(model), "model_sha": body["model_sha"],
            "expires_at": int(body["expires_at"])}


def _write(path: Path, text: str, mode: int, gid: Optional[int] = None) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.chmod(tmp, mode)
    if gid is not None:
        os.chown(tmp, ROOT_UID, gid)
    os.replace(tmp, path)


def apply(params: Dict[str, Any], now: float, *, etc: Path = ETC, units: Path = UNITS,
          systemctl=None, gid_of=None, state: Optional[Path] = None, cache_root: Optional[Path] = None) -> str:
    """Write env + plan drop-in; start the stage. Returns a result code."""
    gid_of = gid_of or (lambda name: pwd.getpwnam(name).pw_gid)
    systemctl = systemctl or (lambda *a: subprocess.run(["systemctl", *a], env=_ENV, timeout=60,
                                                        check=True, capture_output=True))
    remaining = int(params["expires_at"] - now)
    if remaining < 60:
        raise Refused("plan_expires_too_soon")
    allow = " ".join(f"{ip}/32" for ip in params["peers"]) + " 127.0.0.1"
    unit = STAGE_UNIT if params["role"] == "stage" else ENGINE_UNIT
    d = units / f"{unit}.service.d"
    d.mkdir(mode=0o755, exist_ok=True)
    _write(d / "20-plan.conf", f"# plan {params['plan_id']}\n[Service]\nIPAddressAllow=\n"
           f"IPAddressAllow={allow}\nRuntimeMaxSec={remaining}\n", 0o644)
    if params["role"] == "stage":
        coord = str(params.get("coordinator") or "")
        if _cache_owner(state or STATE_DIR) != coord:
            purge_stage_cache(cache_root)
        _result(state or STATE_DIR, "stage-cache-coordinator.json", {"coordinator": coord})   # only after the purge
        gid = gid_of("mesh-di-stage")
        _write(etc / "stage.env", f"STAGE_BIND={params['own_ip']}\nRPC_PORT={RPC_PORT}\n"
               "CACHE_DIR=/var/lib/mesh-di-stage\n", 0o640, gid)
        systemctl("daemon-reload")
        systemctl("restart", f"{STAGE_UNIT}.service")
        return "stage_started"
    gid = gid_of("mesh-di-coord")
    threads = max(1, os.cpu_count() or 1)
    _write(etc / "engine.env", f"MODEL={params['model']}\nMODEL_SHA_PIN={params['model_sha']}\n"
           f"RPC_STAGES={','.join(params['stages'])}\nSLOTS={ENGINE_SLOTS}\n"
           f"CTX={ENGINE_SLOTS * ENGINE_CTX_PER_SLOT}\nTHREADS={threads}\n", 0o640, gid)
    systemctl("daemon-reload")
    systemctl("restart", f"{ENGINE_UNIT}.service")
    return "engine_started"


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


def _cache_owner(state: Path) -> Optional[str]:
    """The coordinator the cache was last filled for (None: nobody recorded). The caller records the new one only
    AFTER a successful purge, so a failed purge is retried at the next start (auditor 16:50Z nit)."""
    try:
        return json.loads((state / "stage-cache-coordinator.json").read_text(encoding="utf-8")).get("coordinator")
    except (OSError, ValueError, AttributeError):
        return None


def _stop_units(systemctl=None) -> None:
    systemctl = systemctl or (lambda *a: subprocess.run(["systemctl", *a], env=_ENV, timeout=60,
                                                        check=False, capture_output=True))
    for u in (STAGE_UNIT, ENGINE_UNIT):
        systemctl("stop", f"{u}.service")


def housekeeping(state: Path, revoke: Optional[Path], owner_uid: int, now: float, ovl, systemctl=None,
                 cache_root: Optional[Path] = None) -> str:
    """Tear the overlay down when the applied plan expired, or when the daemon relays a revocation
    of EXACTLY that plan (the revocation can only tear down, never bring anything up)."""
    applied = _applied(state)
    pid = applied.get("plan_id")
    if pid and int(applied.get("expires_at") or 0) <= now:
        ovl.teardown()
        purge_stage_cache(cache_root)
        _result(state, "applied.json", {})
        return "expired_torn_down"
    if revoke is not None:
        try:
            rv = read_request(revoke, owner_uid)
        except Refused:
            rv = None
        if pid and isinstance(rv, dict) and rv.get("plan_id") == pid:
            _stop_units(systemctl)
            ovl.teardown()
            purge_stage_cache(cache_root)
            _result(state, "applied.json", {})
            return "revoked_torn_down"
    return ""


def run_once(request: Path, owner: str, *, state: Path = STATE_DIR, now: Optional[float] = None,
             node_id_file: Path = NODE_ID_FILE, trusted=None, local_ips=None,
             models_dir: Path = SRV / "models", applier=None, ready=None, overlay=None,
             revoke: Optional[Path] = None, systemctl=None, cache_root: Optional[Path] = None) -> str:
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
    if pub:
        ready_doc["wg_pubkey"] = pub
    _result(state, "ready.json", ready_doc)
    try:
        owner_uid = pwd.getpwnam(owner).pw_uid
        hk = housekeeping(state, revoke, owner_uid, now, ovl, systemctl, cache_root=cache_root)
        env = read_request(request, owner_uid)
        if env is None:
            return hk or "no_request"
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
        params = derive(body, me, local_ips, models_dir)
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
    print(f"split_launch: {run_once(Path(a.request), a.owner, revoke=Path(a.revoke) if a.revoke else None)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
