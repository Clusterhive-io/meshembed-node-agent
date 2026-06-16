"""Main daemon loop: register → poll → encode → report.

Exponential backoff when there is no work: 1s → 2s → 4s … → poll_max_s.
Resets to poll_min_s as soon as a job arrives.
"""
from __future__ import annotations

import json
import logging
import os
import platform
import threading
import time
from typing import Any, Dict, Optional

import psutil
import requests

from .config import Config
from .encoder import Encoder, GPU_MODEL, vram_free_mb

log = logging.getLogger(__name__)


def _hardware_info() -> Dict[str, Any]:
    """Best-effort, comprehensive machine inventory. Sent as a JSONB blob so we
    can collect as much as possible without a column per field. Every probe is
    wrapped so a failure on one platform never breaks register/poll."""
    hw: Dict[str, Any] = {}
    try:
        hw["os"] = platform.system()              # Linux | Darwin | Windows
        hw["os_version"] = platform.release()
        hw["os_pretty"] = platform.platform()
        hw["arch"] = platform.machine()           # x86_64 | arm64 | ...
        hw["hostname"] = platform.node()
        hw["python"] = platform.python_version()
    except Exception:
        pass
    try:
        hw["cpu_model"] = platform.processor() or platform.machine()
        hw["cpu_cores_physical"] = psutil.cpu_count(logical=False)
        hw["cpu_cores_logical"] = psutil.cpu_count(logical=True)
    except Exception:
        pass
    try:
        vm = psutil.virtual_memory()
        hw["ram_total_mb"] = int(vm.total / 1024 / 1024)
        hw["ram_free_mb"] = int(vm.available / 1024 / 1024)
    except Exception:
        pass
    # NOTE: we deliberately do NOT report disk usage. It's the operator's
    # machine -- MeshEmbed doesn't surveil their free space. The operator
    # declares the field of play explicitly (which models, how much, when);
    # disk capacity is theirs to manage when they pick the models a node serves.
    try:
        hw["gpu_model"] = GPU_MODEL
        hw["vram_free_mb"] = vram_free_mb()
    except Exception:
        pass
    return hw


def _should_pause(limits: Optional[Dict[str, Any]]) -> bool:
    """Reservation enforcement: True when the OWNER is actively using the box
    beyond the headroom they reserved, so the daemon should back off and NOT
    pull work this cycle. Driven by resource_limits.pause_when_busy +
    reserve_cpu_cores / reserve_ram_gb (best-effort via psutil)."""
    if not limits or not limits.get("pause_when_busy"):
        return False
    try:
        cpu_pct = psutil.cpu_percent(interval=0.3)          # whole-system %
        cores = psutil.cpu_count() or 1
        avail_gb = psutil.virtual_memory().available / 1024 ** 3
    except Exception:
        return False  # never block the loop on a metrics hiccup
    reserve_cores = limits.get("reserve_cpu_cores")
    reserve_ram = limits.get("reserve_ram_gb")
    idle_cores = (100.0 - cpu_pct) / 100.0 * cores
    if reserve_cores and idle_cores < float(reserve_cores):
        return True                                         # owner needs the CPU
    if reserve_ram and avail_gb < float(reserve_ram):
        return True                                         # owner needs the RAM
    # pause_when_busy with no explicit reserve -> generic high-load guard.
    if not reserve_cores and not reserve_ram and cpu_pct > 75.0:
        return True
    return False


def _headers(api_key: str) -> Dict[str, str]:
    return {"X-API-Key": api_key, "Content-Type": "application/json"}


def _post(base: str, path: str, payload: dict, api_key: str, timeout: int = 60) -> dict:
    resp = requests.post(
        f"{base}{path}", json=payload, headers=_headers(api_key), timeout=timeout
    )
    resp.raise_for_status()
    return resp.json()


def _compute_daemon_files_sha() -> str:
    """sha256 across the canonical files of THIS installed daemon.

    Walks the `meshembed_node` package directory, hashes every `.py`
    file's contents (sorted by path, NUL-delimited), and returns the
    overall digest. The backend cross-references against a "blessed"
    list per release tag; any modification to the package source ->
    sha mismatch -> backend ejects this node.

    What this catches: an operator who edits `encoder.py` to add a
    logging line. It does NOT catch sidecar inspection (strace, gdb,
    eBPF, /proc/<pid>/mem) -- that's documented in COUNTERMEASURES.md.
    """
    import hashlib
    import os
    here = os.path.dirname(os.path.abspath(__file__))
    h = hashlib.sha256()
    files = []
    for root, _dirs, names in os.walk(here):
        for n in names:
            if n.endswith(".py"):
                files.append(os.path.join(root, n))
    for path in sorted(files):
        rel = os.path.relpath(path, here).encode()
        h.update(rel + b"\x00")
        with open(path, "rb") as f:
            h.update(f.read())
        h.update(b"\x00")
    return h.hexdigest()


def _register(cfg: Config, installed_models: Optional[list] = None) -> Optional[int]:
    """Register the node and return the assigned node_number (or None on failure)."""
    payload = {
        "node_id":       cfg.node_id,
        "status":        "idle",
        "gpu_model":     GPU_MODEL,
        "vram_free_mb":  vram_free_mb(),
        "ram_free_mb":   int(psutil.virtual_memory().available / 1024 / 1024),
        "max_chunks":    cfg.max_chunks,
        "tier":          "B",
        "agent_version": cfg.agent_version,
        # OS reporting — "Linux" | "Darwin" | "Windows" + kernel/release.
        "os":            platform.system(),
        "os_version":    platform.release(),
        # Comprehensive machine inventory (JSONB blob; see _hardware_info).
        "hardware":      _hardware_info(),
        "node_pubkey":   cfg.node_pubkey,
        # Option B Phase 1A — X25519 encryption pubkey for end-to-end
        # client->daemon payload encryption (confidential + restricted
        # tiers). Phase 1B wires the pre-assignment flow that uses this.
        "encryption_pubkey": cfg.encryption_pubkey,
    }
    # Stage 1.5 multimodel: tell the backend exactly which models are
    # loaded. Sending this field (even as []) flips the node into strict
    # mode -- the scheduler will only route work for the listed models.
    if installed_models is not None:
        payload["installed_models"] = installed_models
    # Agent attestation (2026-05-22): sha256 across our own package
    # source. Backend cross-checks against the "blessed" list for this
    # agent_version and ejects on mismatch.
    payload["daemon_files_sha"] = _compute_daemon_files_sha()
    try:
        result = _post(cfg.backend_url, "/register_node", payload, cfg.api_key)
        node_number = result.get("node_number")
        log.info(
            "Registered: node_id=%s node_number=N-%04d pubkey=%s…",
            cfg.node_id,
            node_number or 0,
            cfg.node_pubkey[:16],
        )
        return node_number
    except Exception as exc:
        log.warning("register_node failed: %s", exc)
        return None


def _poll(
    cfg: Config,
    installed_models: Optional[list] = None,
    last_update_error: Optional[str] = None,
) -> Dict[str, Any]:
    """Request the next subjob. Returns the FULL response dict (so the
    caller can inspect update_now/update_target_tag alongside assignment).
    Returns {} on network error."""
    payload = {
        "node_id":       cfg.node_id,
        "status":        "idle",
        "gpu_model":     GPU_MODEL,
        "vram_free_mb":  vram_free_mb(),
        "ram_free_mb":   int(psutil.virtual_memory().available / 1024 / 1024),
        "max_chunks":    cfg.max_chunks,
        "tier":          "B",
        "agent_version": cfg.agent_version,
        "os":            platform.system(),
        "os_version":    platform.release(),
        "hardware":      _hardware_info(),
        # Hardware binding (2026-05-14 hardening). Backend compares with
        # the values stored at /nodes/register and 401s on mismatch.
        "machine_fingerprint": cfg.machine_fingerprint,
        "gpu_uuid":            cfg.gpu_uuid,
        "is_vm":               cfg.is_vm,
        # Option B Phase 1A — X25519 pubkey for end-to-end client->daemon
        # payload encryption (confidential + restricted tiers). Backend
        # stores on nodes.encryption_pubkey; Phase 1B uses it to wrap
        # confidential subjobs to this specific daemon.
        "encryption_pubkey":   cfg.encryption_pubkey,
    }
    # Stage 1.5 multimodel: same field as /register_node. Re-sent on every
    # poll so a node that hot-loads a new model is reflected by the backend
    # within one poll cycle.
    if installed_models is not None:
        payload["installed_models"] = installed_models
    # OTA observability: surface the last self-update failure so the backend can
    # log it + the dashboard can show why a node is stuck on an old version.
    if last_update_error:
        payload["last_update_error"] = last_update_error
    # Agent attestation: re-sent every poll so a daemon that mutates its
    # own files at runtime is detected within one cycle.
    payload["daemon_files_sha"] = _compute_daemon_files_sha()
    # Detection Layer A (2026-05-22): self-instrumentation signals.
    # Empty list = no anomalies. Non-empty = backend treats as
    # runtime_inspection_detected -> permanent eject.
    from .runtime_anomalies import collect as _collect_anomalies
    anomalies = _collect_anomalies()
    if anomalies:
        payload["runtime_anomalies"] = anomalies
        log.warning("runtime_anomalies reported to backend: %s", anomalies)

    # Detection Layer E.1 (2026-05-23): TPM 2.0 PCR snapshot. Backend
    # compares against MESHEMBED_TRUSTED_PCRS_JSON allowlist when set;
    # mismatch -> kernel_integrity_violation event -> permanent eject.
    # E.1 is unsigned (operator could lie); E.2 will add tpm2_quote.
    from .attestation import collect_tpm_state as _collect_tpm
    tpm_available, pcr_values = _collect_tpm()
    payload["tpm_available"] = tpm_available
    if pcr_values:
        payload["pcr_values"] = pcr_values

    # Phase 2 location enforcement: VPN-challenge side-channel. The
    # daemon resolves its own public-facing country via Cloudflare's
    # one.one.one.one trace endpoint (free, anycast'd everywhere) and
    # ships the value. Backend cross-checks against the country it
    # observed from cf-ipcountry / the IP geo lookup. A mismatch is a
    # VPN/proxy signal -- score drops on signal E (DNS resolver loc).
    # Cached for the daemon's lifetime since the result rarely changes;
    # `_cf_loc_cache` is module-scope.
    cf_loc = _resolve_cf_loc()
    if cf_loc:
        payload["dns_resolver_loc"] = cf_loc

    try:
        resp = _post(cfg.backend_url, "/get_job", payload, cfg.api_key)
        return resp or {}
    except Exception as exc:
        log.warning("get_job failed: %s", exc)
        return {}


_cf_loc_cache: Optional[str] = None


def _resolve_cf_loc() -> Optional[str]:
    """Hit Cloudflare's edge-trace endpoint to learn what country our
    outbound IP resolves to from CF's perspective. Cached for the
    daemon process lifetime; refreshes only on next restart.

    Returns ISO-3166 alpha-2 country code, or None on any failure
    (network down, CF down, parse error). Failure is always non-fatal
    -- the location score awards partial credit when this signal is
    absent.
    """
    global _cf_loc_cache
    if _cf_loc_cache is not None:
        return _cf_loc_cache
    try:
        resp = requests.get(
            "https://one.one.one.one/cdn-cgi/trace",
            timeout=5,
        )
        if resp.status_code != 200:
            return None
        # The trace format is a flat key=value newline list. `loc=XX`
        # is the country code Cloudflare's edge resolved.
        for line in resp.text.splitlines():
            if line.startswith("loc="):
                cc = line.split("=", 1)[1].strip().upper()
                if cc and len(cc) == 2:
                    _cf_loc_cache = cc
                    return cc
    except Exception:
        pass
    return None


def _report(cfg: Config, assignment: Dict[str, Any], embeddings: list,
            gpu_seconds: float, duration_ms: int, error: Optional[str],
            model_sha_used: Optional[str] = None) -> bool:
    payload = {
        "job_id":         assignment["job_id"],
        "subjob_id":      assignment["subjob_id"],
        "node_id":        cfg.node_id,
        "status":         "failed" if error else "completed",
        "chunk_index":    assignment["chunk_index"],
        "embeddings":     embeddings,
        "text_count":     len(assignment["texts"]),
        "duration_ms":    duration_ms,
        "gpu_seconds":    gpu_seconds,
        "error":          error,
        "callback_token": assignment["callback_token"],
        # Hardware binding (see _poll). Must match what register stored
        # or the backend rejects with 401 hardware_mismatch.
        "machine_fingerprint": cfg.machine_fingerprint,
        "gpu_uuid":            cfg.gpu_uuid,
    }
    # Stage 1.6 multimodel: tell the backend which model checkpoint
    # actually produced these embeddings. The backend cross-checks with
    # the job's requested model + supported_models registry; mismatches
    # fail_permanent with penalty. Omitting the field is currently
    # accepted (env-gated), but the backend logs it as a strict-mode
    # anomaly when present.
    if model_sha_used:
        payload["model_sha_used"] = model_sha_used
    headers = _headers(cfg.api_key)
    # ed25519 signature — only when there are valid embeddings (skip on error path).
    if cfg.node_privkey and not error:
        from .crypto import sign_result
        sig = sign_result(
            cfg.node_privkey,
            assignment["subjob_id"],
            assignment["callback_token"],
            embeddings,
        )
        headers["X-Node-Signature"] = sig
    try:
        resp = requests.post(
            f"{cfg.backend_url}/report_result",
            json=payload,
            headers=headers,
            timeout=60,
        )
        resp.raise_for_status()
        return True
    except Exception as exc:
        log.error("report_result failed: %s", exc)
        return False


def _perform_self_update(target_tag: str) -> None:
    """Download the platform installer for `target_tag` from the public
    daemon repo and exec it. The installer runs `pip install --upgrade`
    on the active venv; when it finishes, we sys.exit(0) so the
    supervisor (systemd / launchd) restarts us with the new code.

    Supports Linux and macOS. On Windows we just log -- PowerShell
    installer auto-exec via the daemon is intentionally deferred
    (operators on Windows re-run install.ps1 manually for now).

    Raises on download / exec failures so the caller can log and
    fall back to "try again next poll".
    """
    import os as _os
    import platform as _pf
    import subprocess as _sp
    import sys as _sys
    import tempfile

    repo = _os.environ.get(
        "MESHEMBED_INSTALLER_REPO", "Clusterhive-io/meshembed-node-agent",
    )
    system = _pf.system()
    if system == "Linux":
        script_name = "install.sh"
        interp = ["bash"]
        suffix = ".sh"
    elif system == "Darwin":
        script_name = "install-mac.sh"
        interp = ["bash"]
        suffix = ".sh"
    elif system == "Windows":
        # PowerShell installer; install.ps1's idempotency detects the
        # existing Task Scheduler entry + .env and runs in upgrade mode.
        script_name = "install.ps1"
        interp = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File"]
        suffix = ".ps1"
    else:
        raise RuntimeError(f"unsupported_os:{system}")

    url = f"https://raw.githubusercontent.com/{repo}/refs/tags/{target_tag}/{script_name}"
    log.info("Downloading installer: %s", url)
    fd, path = tempfile.mkstemp(prefix="meshembed-update-", suffix=suffix)
    try:
        # Use requests (bundles certifi) rather than urllib.request, because
        # python.org's macOS installer ships without a usable system CA
        # store -- urlopen() fails with SSL: CERTIFICATE_VERIFY_FAILED on
        # `raw.githubusercontent.com`, which is the entire auto-update path.
        # `requests` is already a hard dependency, so this swap is free.
        import requests as _requests
        resp = _requests.get(url, timeout=60)
        resp.raise_for_status()
        data = resp.content
        if not data or len(data) < 100:
            raise RuntimeError(
                f"installer_too_small: {len(data)} bytes (url={url})"
            )
        _os.write(fd, data)
        _os.close(fd)
        # chmod is a no-op on Windows; only meaningful for shell scripts.
        if system != "Windows":
            _os.chmod(path, 0o755)
        # Pin the target tag for the installer's pip install step too.
        env = dict(_os.environ)
        env["MESHEMBED_PACKAGE_URL"] = (
            f"https://github.com/{repo}/archive/refs/tags/{target_tag}.tar.gz"
        )
        # The daemon runs under systemd with a MINIMAL PATH (no ~/.local/bin),
        # but the installer needs `uv` -- which lives in ~/.local/bin or
        # ~/.cargo/bin on most nodes. Without this the installer's `command -v
        # uv` misses, and if the astral.sh re-install is flaky the whole update
        # silently fails. Prepend the usual tool locations so install.sh finds
        # uv directly. (Root of the chronic "updates don't flow" issue.)
        home = _os.path.expanduser("~")
        env["PATH"] = ":".join([
            f"{home}/.local/bin", f"{home}/.cargo/bin", "/usr/local/bin",
            env.get("PATH", "/usr/bin:/bin"),
        ])
        log.info("Executing installer (script=%s tag=%s)", script_name, target_tag)
        # Capture output so a failure is diagnosable (logged to the node journal
        # AND reported to the backend on the next poll) instead of vanishing.
        result = _sp.run(
            interp + [path], env=env, check=False,
            capture_output=True, text=True, timeout=900,
        )
        out_tail = ((result.stdout or "") + "\n" + (result.stderr or ""))[-2000:]
        if result.returncode != 0:
            log.error("Installer FAILED rc=%s. Output tail:\n%s",
                      result.returncode, out_tail)
            raise RuntimeError(
                f"installer_exit_{result.returncode}: {out_tail[-400:]}"
            )
        log.info("Installer finished rc=0. Output tail:\n%s", out_tail)
        # Confirm the on-disk package actually upgraded before we re-exec into
        # it -- a silent no-op (e.g. pip installed into the wrong venv) would
        # otherwise just loop us back onto the old code every cycle.
        want = target_tag.lstrip("v")
        try:
            ver = _sp.run(
                [_sys.executable, "-c",
                 "import importlib.metadata as m;print(m.version('meshembed-node'))"],
                capture_output=True, text=True, timeout=30,
            ).stdout.strip()
        except Exception:
            ver = ""
        if ver and want and ver != want:
            raise RuntimeError(
                f"version_unchanged_after_install: got {ver} want {want}"
            )
        try:
            _os.unlink(path)
        except Exception:
            pass
        # Re-exec the daemon IN PLACE with the freshly-installed code. This does
        # NOT depend on systemd/launchd restarting us -- the old path
        # (sys.exit(0) + Restart=on-failure) silently left non-root daemons that
        # couldn't `systemctl restart` themselves DOWN. os.execv replaces the
        # process image (same PID), so it works root/non-root, systemd or not.
        # Windows: keep the clean exit (os.execv semantics differ; the Task
        # Scheduler entry / manual restart applies the new code).
        if system == "Windows":
            # Exit NON-zero so the scheduled task's restart-on-failure
            # (RestartCount 999 / RestartInterval 1m) relaunches us on the new
            # code. A clean exit(0) reads as "task completed" -> no restart. This
            # keeps Windows self-update fully NON-admin: the upgrade installer
            # skips re-registering the task (the only step that needed elevation).
            log.info("Installer succeeded -- exiting non-zero so the task restarts us on the new code")
            _sys.exit(3)
        log.warning("Self-update applied (version=%s). Re-executing daemon in place.",
                    ver or "?")
        _os.execv(_sys.executable, [_sys.executable, "-m", "meshembed_node", "run"])
    finally:
        try:
            _os.unlink(path)
        except Exception:
            pass


def _attempt_signed_quote(cfg: Config) -> None:
    """Detection Layer E.2: ask backend for a nonce, call tpm2_quote,
    POST the bundle. All best-effort -- failures are logged at DEBUG
    so they don't spam the operator's syslog when there's no TPM."""
    from .tpm_quote import quote as _tpm_quote
    # 1. Get a fresh nonce.
    try:
        resp = _post(
            cfg.backend_url, "/attestation/challenge",
            {"node_id": cfg.node_id}, cfg.api_key,
        )
    except Exception as exc:
        log.debug("attestation_challenge.failed: %s", exc)
        return
    if not resp or "nonce" not in resp:
        return
    nonce_hex = resp["nonce"]
    # 2. Run tpm2_quote locally.
    bundle = _tpm_quote(nonce_hex)
    if bundle is None:
        log.debug("tpm2_quote unavailable -- staying at E.1 unsigned")
        return
    quote_msg_b64, quote_sig_b64, ek_pub_b64 = bundle
    # 3. Report the bundle. PCR values not re-collected here -- the
    # signed quote IS the authoritative source for those values once
    # E.2b backend verification lands.
    try:
        _post(
            cfg.backend_url, "/attestation/quote",
            {
                "node_id": cfg.node_id,
                "nonce": nonce_hex,
                "quote_msg": quote_msg_b64,
                "quote_sig": quote_sig_b64,
                "ek_pub": ek_pub_b64,
                "pcr_values": {},
            },
            cfg.api_key,
        )
        log.info("signed_quote_reported nonce=%s...", nonce_hex[:16])
    except Exception as exc:
        log.debug("attestation_quote.post_failed: %s", exc)


def _echo_landmark(host: str, port: int, node_id: str, nonce: str, timeout: float = 8.0) -> None:
    """Connect OUT to one landmark and echo its PINGs so it can measure our
    min-RTT. We report nothing ourselves — the landmark does (it's the
    trusted measurer). Bypasses Cloudflare by design (direct TCP)."""
    import socket as _socket
    with _socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall((json.dumps({"node_id": node_id, "nonce": nonce}) + "\n").encode("utf-8"))
        buf = b""
        while True:
            chunk = s.recv(256)
            if not chunk:
                return
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                txt = line.decode("utf-8", "ignore").strip()
                if txt.startswith("PING"):
                    parts = txt.split()
                    idx = parts[1] if len(parts) > 1 else "0"
                    s.sendall(f"PONG {idx}\n".encode("utf-8"))
                elif txt.startswith("BYE"):
                    return


def _attempt_location_probe(cfg: Config) -> None:
    """Latency-triangulation probe (docs/NODE_LOCATION_ENFORCEMENT.md).

    Ask the backend for a probe plan; for each EU landmark, connect out and
    echo PINGs so the landmark can measure (and report) our min-RTT. All
    best-effort — failures stay at DEBUG so a node behind a strict egress
    firewall doesn't spam syslog."""
    try:
        plan = _post(
            cfg.backend_url, "/location/probe-plan",
            {"node_id": cfg.node_id}, cfg.api_key,
        )
    except Exception as exc:
        log.debug("location_probe_plan.failed: %s", exc)
        return
    if not plan or not plan.get("due"):
        return
    nonce = plan.get("nonce")
    landmarks = plan.get("landmarks") or []
    if not nonce or not landmarks:
        return
    for lm in landmarks:
        try:
            _echo_landmark(lm["host"], int(lm["port"]), cfg.node_id, nonce)
        except Exception as exc:
            log.debug("landmark_echo.failed id=%s: %s", lm.get("id"), exc)


def run(cfg: Config) -> None:
    # preload=False: do NOT block startup on the (possibly multi-hundred-MB)
    # first-boot model download. We register + start polling immediately so the
    # node is visible to the backend within seconds, then load the default
    # model on a background thread. installed_models() is empty until that
    # finishes; the backend simply doesn't route work to us until the next poll
    # reports the loaded model. (Previously the eager __init__ load blocked
    # registration for minutes — nodes looked offline on first boot and the
    # installer-fleet poll assertion timed out.)
    encoder = Encoder(cfg.model, preload=False)
    threading.Thread(
        target=encoder.ensure_default_loaded,
        name="meshembed-model-preload",
        daemon=True,
    ).start()

    # Stage 1.5 multimodel: report installed_models on every register +
    # poll so the backend can route work appropriately. With the
    # 2026-05-23 hybrid lazy-load encoder this list now reflects the
    # *current cache contents* (not just the default model). Each poll
    # gets a fresh snapshot, so the default model shows up within one cycle
    # of the background preload finishing, and a lazy-loaded model that gets
    # evicted drops out of routing within one cycle.
    initial_installed = encoder.installed_models()
    _register(cfg, installed_models=initial_installed)

    backoff = cfg.poll_min_s
    jobs_done = 0
    # Reservation (resource_limits) cached from each /get_job response. Used to
    # honor pause_when_busy before pulling work (increment 2 enforcement).
    node_limits: Dict[str, Any] = {}
    # Last self-update failure, reported to the backend on the next poll so OTA
    # failures are visible in the dashboard/logs instead of vanishing silently.
    last_update_error: Optional[str] = None
    # Operator model allow-list currently applied to the encoder; re-applied
    # only when /get_job reports a different set.
    served_applied: frozenset = frozenset()
    # Layer E.2 cadence: every N polls, attempt a signed quote. Default
    # 60 polls (~30min at the default 30s poll); can be tuned via env.
    quote_cadence = max(1, int(os.environ.get("MESHEMBED_QUOTE_EVERY_N_POLLS", "60") or "60"))
    quote_counter = 0
    # Location triangulation cadence: every N polls, run the landmark RTT
    # probe (~20min at the default 30s poll). The backend only hands out a
    # plan when landmarks are configured, so on fleets without triangulation
    # this is a cheap no-op POST.
    probe_cadence = max(1, int(os.environ.get("MESHEMBED_PROBE_EVERY_N_POLLS", "40") or "40"))
    probe_counter = 0

    log.info(
        "Daemon started — backend=%s node_id=%s default_model=%s installed=%d",
        cfg.backend_url, cfg.node_id, cfg.model, len(initial_installed),
    )

    while True:
        # Layer E.2: signed TPM quote, opportunistic. We don't block
        # the job loop on attestation -- if it fails, we just stay at
        # E.1. The backend marks `quote_signature_status` accordingly.
        quote_counter += 1
        if quote_counter >= quote_cadence:
            quote_counter = 0
            try:
                _attempt_signed_quote(cfg)
            except Exception as exc:
                log.debug("signed_quote_attempt_failed: %s", exc)

        probe_counter += 1
        if probe_counter >= probe_cadence:
            probe_counter = 0
            try:
                _attempt_location_probe(cfg)
            except Exception as exc:
                log.debug("location_probe_attempt_failed: %s", exc)

        # Reservation enforcement: if the operator set pause_when_busy and the
        # owner is actively using the box (beyond their reserved headroom), back
        # off WITHOUT pulling work, so MeshEmbed never competes with the owner.
        # Recheck on a short fixed interval so we resume promptly when they stop.
        if _should_pause(node_limits):
            log.info("reservation: owner active -> pausing (no work pulled this cycle)")
            time.sleep(max(cfg.poll_min_s, 15))
            continue

        # Fresh installed_models snapshot per poll -- captures any
        # lazy-loaded models that came in during the last cycle.
        resp = _poll(
            cfg, installed_models=encoder.installed_models(),
            last_update_error=last_update_error,
        )
        last_update_error = None  # reported once; clear so we don't repeat it
        # Cache the operator's reservation for the next loop's pause check.
        node_limits = resp.get("resource_limits") or {}

        # Operator "field of play": serve ONLY the models the operator pinned.
        # Apply on change, on a background thread (preloading can be slow).
        pinned = frozenset(resp.get("pinned_models") or [])
        if pinned != served_applied:
            served_applied = pinned
            threading.Thread(
                target=encoder.set_served_models,
                args=(list(pinned),),
                name="meshembed-field-of-play",
                daemon=True,
            ).start()

        # Auto-update channel: operator clicked "Update now" in the
        # dashboard; backend signals us to upgrade. Exec the platform
        # installer for the target tag and exit so the supervisor
        # restarts us with the new code. The signal is one-shot --
        # backend already flipped update_started_at, so re-polling
        # won't repeat the install.
        if resp.get("update_now"):
            target = resp.get("update_target_tag") or "main"
            log.warning(
                "Operator requested self-update -> %s. Running installer and exiting.",
                target,
            )
            try:
                _perform_self_update(target)
            except Exception as exc:
                log.error("self-update failed: %s -- staying on current version", exc)
                last_update_error = f"{target}: {str(exc)[:440]}"
                time.sleep(backoff)
                backoff = min(backoff * 2, cfg.poll_max_s)
                continue
            # _perform_self_update sys.exits when the installer
            # succeeds; this line is only reached if it returns
            # (it shouldn't on success).
            log.warning("self-update returned without exiting -- exiting now")
            import sys as _sys
            _sys.exit(0)

        assignment = resp.get("assignment")

        if assignment is None:
            time.sleep(backoff)
            backoff = min(backoff * 2, cfg.poll_max_s)
            continue

        backoff = cfg.poll_min_s
        texts = assignment.get("texts", [])
        log.info(
            "Job received: job=%s subjob=%s texts=%d",
            assignment["job_id"], assignment["subjob_id"], len(texts),
        )

        t_wall = time.perf_counter()
        error: Optional[str] = None
        embeddings: list = []
        gpu_seconds: float = 0.0
        # Multimodel (2026-05-23): assignments now carry the model the
        # client requested. Hybrid lazy-load means the cache may miss
        # and load a new model on the fly. If load fails, encoder
        # returns sha="" and the backend handles it per its strict-sha
        # policy.
        assignment_model = assignment.get("model") or encoder.default_model_name
        model_sha_used: Optional[str] = None

        try:
            embeddings, gpu_seconds, model_sha_used = encoder.encode(
                texts, model_name=assignment_model,
            )
        except Exception as exc:
            error = f"encode_error:{exc}"
            log.error("Encode failed: %s", exc)

        duration_ms = int((time.perf_counter() - t_wall) * 1000)
        # Detection Layer A: record encode duration to track anomalies.
        # If this encode took 3x the established baseline, the next
        # /get_job will report encode_duration_anomaly. Suggests the
        # process was paused (debugger break) or someone hijacked the
        # CPU mid-encode.
        from .runtime_anomalies import record_encode_duration
        if error is None and gpu_seconds > 0:
            record_encode_duration(gpu_seconds)
        ok = _report(
            cfg, assignment, embeddings, gpu_seconds, duration_ms, error,
            model_sha_used=model_sha_used or None,
        )

        jobs_done += 1
        status = "OK" if ok and not error else "FAIL"
        log.info(
            "Subjob %s [%s] — %dms %.3fs GPU (total completed: %d)",
            assignment["subjob_id"], status, duration_ms, gpu_seconds, jobs_done,
        )
