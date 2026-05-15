from __future__ import annotations

import argparse
import hashlib
import time
from dataclasses import dataclass
from typing import List

import numpy as np
import psutil
import requests

try:
    from sentence_transformers import SentenceTransformer
except Exception:  # pragma: no cover
    SentenceTransformer = None


@dataclass
class AgentConfig:
    backend_url: str
    node_id: str
    poll_seconds: int
    tier: str
    model: str
    agent_version: str
    api_key: str | None = None  # X-API-Key (NODE) — None only in legacy tests


class Embedder:
    def __init__(self, model_name: str) -> None:
        self.model_name = model_name
        self._model = None
        if SentenceTransformer is not None:
            try:
                self._model = SentenceTransformer(model_name)
            except Exception:
                self._model = None

    def encode(self, texts: List[str]) -> List[List[float]]:
        if self._model is not None:
            vectors = self._model.encode(texts, normalize_embeddings=True)
            return np.asarray(vectors, dtype=np.float32).tolist()
        return [self._hash_embed(t) for t in texts]

    @staticmethod
    def _hash_embed(text: str, size: int = 128) -> List[float]:
        digest = hashlib.sha256(text.encode("utf-8")).digest()
        seed = int.from_bytes(digest[:8], "big")
        rng = np.random.default_rng(seed)
        vec = rng.normal(0, 1, size)
        norm = np.linalg.norm(vec) or 1.0
        return (vec / norm).astype(np.float32).tolist()


def get_stats() -> tuple[int, int, str]:
    ram_free_mb = int(psutil.virtual_memory().available / (1024 * 1024))
    vram_free_mb = 0
    gpu_model = "none"
    return vram_free_mb, ram_free_mb, gpu_model


def post_json(base: str, path: str, payload: dict, api_key: str | None = None) -> dict:
    headers = {"X-API-Key": api_key} if api_key else {}
    resp = requests.post(
        f"{base.rstrip('/')}{path}",
        json=payload,
        headers=headers,
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


def run(config: AgentConfig) -> None:
    embedder = Embedder(config.model)

    while True:
        vram_free_mb, ram_free_mb, gpu_model = get_stats()
        node_payload = {
            "node_id": config.node_id,
            "status": "idle",
            "gpu_model": gpu_model,
            "vram_free_mb": vram_free_mb,
            "ram_free_mb": ram_free_mb,
            "max_chunks": 1,
            "tier": config.tier,
            "agent_version": config.agent_version,
        }

        try:
            post_json(config.backend_url, "/register_node", node_payload, api_key=config.api_key)
            poll = post_json(config.backend_url, "/get_job", node_payload, api_key=config.api_key)
        except Exception:
            time.sleep(config.poll_seconds)
            continue

        assignment = poll.get("assignment")
        if not assignment:
            time.sleep(config.poll_seconds)
            continue

        start = time.time()
        status = "completed"
        error = None
        embeddings = None

        try:
            embeddings = embedder.encode(assignment["texts"])
        except Exception as exc:  # pragma: no cover
            status = "failed"
            error = f"temporary_gpu_error:{exc}"

        duration_ms = int((time.time() - start) * 1000)
        result_payload = {
            "job_id": assignment["job_id"],
            "subjob_id": assignment["subjob_id"],
            "node_id": config.node_id,
            "status": status,
            "chunk_index": assignment["chunk_index"],
            "embeddings": embeddings,
            "text_count": len(assignment["texts"]),
            "duration_ms": duration_ms,
            "gpu_seconds": round(duration_ms / 1000.0, 3),
            "error": error,
            "callback_token": assignment["callback_token"],
        }

        try:
            post_json(config.backend_url, "/report_result", result_payload, api_key=config.api_key)
        except Exception:
            pass

        time.sleep(0.2)


def parse_args() -> AgentConfig:
    import os
    parser = argparse.ArgumentParser(description="MeshEmbed node agent")
    parser.add_argument("--backend-url", required=True)
    parser.add_argument("--node-id", required=True)
    parser.add_argument("--poll-seconds", type=int, default=3)
    parser.add_argument("--tier", default="B")
    parser.add_argument("--model", default="intfloat/multilingual-e5-small")
    parser.add_argument("--agent-version", default="0.1.0")
    args = parser.parse_args()
    # API key ALWAYS from env, never CLI: it would show up in `ps`, logs, etc.
    api_key = os.environ.get("MESHEMBED_NODE_API_KEY")
    if not api_key:
        # Explicit warning; start anyway so local dev against no-auth
        # backends still works. In prod, the systemd unit passes the env var.
        print(
            "[warn] MESHEMBED_NODE_API_KEY is not set; requests will go "
            "without X-API-Key and will be rejected by backends with auth.",
            flush=True,
        )
    return AgentConfig(
        backend_url=args.backend_url,
        node_id=args.node_id,
        poll_seconds=args.poll_seconds,
        tier=args.tier,
        model=args.model,
        agent_version=args.agent_version,
        api_key=api_key,
    )


if __name__ == "__main__":
    run(parse_args())
