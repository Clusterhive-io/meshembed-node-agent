"""Main daemon loop: register → poll → encode → report.

Exponential backoff when there is no work: 1s → 2s → 4s … → poll_max_s.
Resets to poll_min_s as soon as a job arrives.
"""
from __future__ import annotations

import logging
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


def _register(cfg: Config) -> Optional[int]:
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
    }
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


def _poll(cfg: Config) -> Optional[Dict[str, Any]]:
    """Request the next subjob. Returns the assignment or None."""
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
    }
    try:
        resp = _post(cfg.backend_url, "/get_job", payload, cfg.api_key)
        return resp.get("assignment")
    except Exception as exc:
        log.warning("get_job failed: %s", exc)
        return None


def _report(cfg: Config, assignment: Dict[str, Any], embeddings: list,
            gpu_seconds: float, duration_ms: int, error: Optional[str]) -> bool:
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


def run(cfg: Config) -> None:
    encoder = Encoder(cfg.model)
    _register(cfg)

    backoff = cfg.poll_min_s
    jobs_done = 0

    log.info(
        "Daemon started — backend=%s node_id=%s model=%s",
        cfg.backend_url, cfg.node_id, cfg.model,
    )

    while True:
        assignment = _poll(cfg)

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

        try:
            embeddings, gpu_seconds = encoder.encode(texts)
        except Exception as exc:
            error = f"encode_error:{exc}"
            log.error("Encode failed: %s", exc)

        duration_ms = int((time.perf_counter() - t_wall) * 1000)
        ok = _report(cfg, assignment, embeddings, gpu_seconds, duration_ms, error)

        jobs_done += 1
        status = "OK" if ok and not error else "FAIL"
        log.info(
            "Subjob %s [%s] — %dms %.3fs GPU (total completed: %d)",
            assignment["subjob_id"], status, duration_ms, gpu_seconds, jobs_done,
        )
