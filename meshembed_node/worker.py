"""Main daemon loop: register → poll → encode → report.

Exponential backoff when there is no work: 1s → 2s → 4s … → poll_max_s.
Resets to poll_min_s as soon as a job arrives.
"""
from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, Optional

import psutil
import requests

from .config import Config
from .encoder import Encoder, GPU_MODEL, vram_free_mb

log = logging.getLogger(__name__)


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


def _poll(cfg: Config, installed_models: Optional[list] = None) -> Dict[str, Any]:
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
    elif system == "Darwin":
        script_name = "install-mac.sh"
        interp = ["bash"]
    elif system == "Windows":
        log.warning(
            "Windows auto-update via daemon not supported yet -- "
            "operator must re-run install.ps1 manually (target=%s).",
            target_tag,
        )
        return
    else:
        raise RuntimeError(f"unsupported_os:{system}")

    url = f"https://raw.githubusercontent.com/{repo}/refs/tags/{target_tag}/{script_name}"
    log.info("Downloading installer: %s", url)
    fd, path = tempfile.mkstemp(prefix="meshembed-update-", suffix=".sh")
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
        _os.chmod(path, 0o755)
        # Pin the target tag for the installer's pip install step too.
        env = dict(_os.environ)
        env["MESHEMBED_PACKAGE_URL"] = (
            f"https://github.com/{repo}/archive/refs/tags/{target_tag}.tar.gz"
        )
        log.info("Executing installer (script=%s tag=%s)", script_name, target_tag)
        result = _sp.run(interp + [path], env=env, check=False)
        if result.returncode != 0:
            raise RuntimeError(f"installer_exit_nonzero:{result.returncode}")
        log.info("Installer succeeded -- exiting so supervisor restarts us")
        _sys.exit(0)
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


def run(cfg: Config) -> None:
    encoder = Encoder(cfg.model)

    # Stage 1.5 multimodel: report installed_models on every register +
    # poll so the backend can route work appropriately. With the
    # 2026-05-23 hybrid lazy-load encoder this list now reflects the
    # *current cache contents* (not just the default model). Each poll
    # gets a fresh snapshot, so when a lazy-loaded model gets evicted
    # the backend stops routing work for it within one cycle.
    initial_installed = encoder.installed_models()
    _register(cfg, installed_models=initial_installed)

    backoff = cfg.poll_min_s
    jobs_done = 0
    # Layer E.2 cadence: every N polls, attempt a signed quote. Default
    # 60 polls (~30min at the default 30s poll); can be tuned via env.
    quote_cadence = max(1, int(os.environ.get("MESHEMBED_QUOTE_EVERY_N_POLLS", "60") or "60"))
    quote_counter = 0

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

        # Fresh installed_models snapshot per poll -- captures any
        # lazy-loaded models that came in during the last cycle.
        resp = _poll(cfg, installed_models=encoder.installed_models())

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
