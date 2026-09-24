"""The node release after the first real customer run (2026-09-21..24).

Each test is one failure seen on a real node, stated as the behaviour that
must now hold:

* 186 advertised generation models it could not run: the operator's pinned
  list reached the encoder unsplit.
* 187 sat on `warming` for an hour: its pins were embedding-only, and the
  warm pass skipped the LLMs without a word.
* a failed or refused download also read `warming`, for ever.
* readiness and the warm pass disagreed about how much disk is enough.
* the node could only fetch from our mirror; the operator decided upstream by
  default, with the mirror as an optional override.
* the only anti-repetition knob llama.cpp has was never forwarded.
* the node API key sat in the systemd unit, readable by any local user.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from meshembed_node import llm, worker  # noqa: E402

pytestmark = pytest.mark.unit

S3B = llm.ModelSpec(model_id="m/3b", file="3b.gguf", sha256="a" * 64, size_mb=1840,
                    min_ram_gb=4.0, context=4096, url="https://up/3b.gguf")
S7B = llm.ModelSpec(model_id="m/7b", file="7b.gguf", sha256="b" * 64, size_mb=4466,
                    min_ram_gb=8.0, context=4096, url="https://up/7b.gguf")


@pytest.fixture
def node(monkeypatch):
    """A node with the runtime, 28 GB free RAM, lots of disk, nothing on disk."""
    monkeypatch.setattr(llm, "load_catalog", lambda *a, **k: {S3B.model_id: S3B, S7B.model_id: S7B})
    monkeypatch.setattr(llm, "runtime_available", lambda: True)
    monkeypatch.setattr(llm, "gpu_info", lambda: {})
    monkeypatch.setattr(llm, "gpu_offload_available", lambda: False)
    monkeypatch.setattr(llm, "_usable_ram_gb", lambda: 28.0)
    monkeypatch.setattr(llm, "_loaded_gb", lambda: 0.0)
    monkeypatch.setattr(llm, "_loaded_id", lambda: None)
    monkeypatch.setattr(llm, "_verified_path", lambda s: None)
    monkeypatch.setattr(llm, "_free_disk_gb", lambda p: 300.0)
    monkeypatch.setattr(llm, "MIRROR", "")
    monkeypatch.setattr(llm, "_PINNED", None)
    monkeypatch.setattr(llm, "_LAST_FETCH_ERROR", None)
    return monkeypatch


# ── 186: the encoder must never see a generation id ──────────────────────────

def test_the_encoder_gets_only_embedding_ids_in_the_operators_order(node):
    pinned = ["BAAI/bge-m3", "m/3b", "intfloat/e5-small", "m/7b"]
    assert worker._embedding_only(pinned) == ["BAAI/bge-m3", "intfloat/e5-small"]


def test_an_unreadable_catalogue_keeps_todays_behaviour(monkeypatch):
    """Unpinning every embedding model would be worse than the old bug."""
    def boom(*a, **k):
        raise RuntimeError("catalogue gone")
    monkeypatch.setattr(llm, "load_catalog", boom)
    assert worker._embedding_only(["a", "m/3b"]) == ["a", "m/3b"]


# ── 187: not permitted is not warming ────────────────────────────────────────

def test_a_node_whose_pins_exclude_every_llm_says_not_pinned(node):
    node.setattr(llm, "_PINNED", {"BAAI/bge-m3"})
    assert llm.readiness()["blocked"] == "not_pinned"


def test_pinning_the_model_moves_it_on_to_warming(node):
    node.setattr(llm, "_PINNED", {"BAAI/bge-m3", "m/3b"})
    assert llm.readiness()["blocked"] == "warming"


def test_the_warm_pass_records_the_permission_it_was_given(node):
    node.setattr(llm, "ensure_model", lambda spec: None)
    llm.warm_models(["BAAI/bge-m3"])
    assert llm._PINNED == {"BAAI/bge-m3"}
    llm.warm_models(None)
    assert llm._PINNED is None, "no pins means no restriction"


# ── a failed fetch is not warming ────────────────────────────────────────────

def test_a_failed_fetch_is_reported_not_hidden(node):
    node.setattr(llm, "_LAST_FETCH_ERROR", {"model_id": "m/3b", "error": "download: 404", "at": 1})
    r = llm.readiness()
    assert r["blocked"] == "fetch_failed"
    assert r["last_fetch_error"]["error"] == "download: 404"


def test_a_download_is_retried_then_recorded(node, tmp_path):
    node.setattr(llm, "CACHE_DIR", tmp_path)
    node.setattr(llm, "_FETCH_BACKOFF_S", (0, 0, 0))
    calls = []

    class _Boom:
        def __init__(self, *a, **k):
            calls.append(1)
            raise ConnectionError("reset by peer")

    import types
    node.setitem(sys.modules, "requests", types.SimpleNamespace(get=_Boom))
    assert llm.ensure_model(S3B) is None
    assert len(calls) == 3, "three attempts, not one"
    assert llm._LAST_FETCH_ERROR["model_id"] == "m/3b"
    assert "reset by peer" in llm._LAST_FETCH_ERROR["error"]


# ── one disk rule ────────────────────────────────────────────────────────────

def test_room_for_the_headroom_but_not_the_file_is_insufficient_disk(node):
    """6 GB free: over the 5 GB headroom, but 6 - 1.8 = 4.2 is under it, so
    the warm pass will refuse -- and readiness must say so rather than
    `warming` for ever."""
    node.setattr(llm, "_PINNED", {"m/3b"})
    node.setattr(llm, "_free_disk_gb", lambda p: 6.0)
    assert llm.readiness()["blocked"] == "insufficient_disk"


# ── upstream by default, mirror as override ──────────────────────────────────

def test_without_a_mirror_the_node_fetches_upstream(node):
    assert llm._source_url(S3B) == "https://up/3b.gguf"
    r = llm.readiness()
    assert r["source"] is True and r["blocked"] == "warming"


def test_a_configured_mirror_overrides_upstream(node):
    node.setattr(llm, "MIRROR", "https://mirror/gguf")
    assert llm._source_url(S3B) == "https://mirror/gguf/3b.gguf"


def test_every_catalogue_model_carries_an_upstream_url_for_its_own_file():
    cat = llm.load_catalog()
    assert cat, "the shipped catalogue must load"
    for spec in cat.values():
        assert spec.url.startswith("https://") and spec.url.endswith("/" + spec.file), spec.model_id


# ── penalties reach llama.cpp only when asked for ────────────────────────────

def test_penalties_are_forwarded_when_asked_for():
    kw = llm._call_kwargs({"max_tokens": 64, "repeat_penalty": 1.15, "frequency_penalty": 0.2})
    assert kw["repeat_penalty"] == 1.15 and kw["frequency_penalty"] == 0.2


def test_an_existing_request_generates_exactly_as_before():
    kw = llm._call_kwargs({"max_tokens": 64, "temperature": 0.0})
    assert not {"repeat_penalty", "frequency_penalty", "presence_penalty"} & set(kw)


# ── the API key is not in the unit ───────────────────────────────────────────

def test_a_fresh_linux_unit_reads_credentials_from_the_0600_file():
    unit = (Path(__file__).resolve().parents[1] / "install.sh").read_text()
    block = unit[unit.index("cat > /tmp/meshembed-node.service"):]
    block = block[:block.index("\nEOF")]
    assert "EnvironmentFile=-$ENV_FILE" in block
    assert "Environment=MESHEMBED_NODE_API_KEY" not in block, (
        "a unit in /etc/systemd/system is readable by every local user")
