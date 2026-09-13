"""Batch LLM generation on a node: what must hold before any weights load.

docs/LLM_INFERENCE_DESIGN.md par.3. The properties that make this safe to run on
someone else's machine: a model is served only if its bytes are the pinned ones,
only if the machine can actually fit it, a node acquires what it can serve
instead of waiting to be given it, and a node that cannot generate correctly
fails loudly rather than returning something plausible.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from meshembed_node import llm  # noqa: E402


SPEC_KW = dict(
    model_id="test/tiny-q4",
    file="tiny.gguf",
    size_mb=1,
    min_ram_gb=0.001,
    context=512,
)


def _artifact(tmp_path: Path, body: bytes = b"GGUF-not-really") -> llm.ModelSpec:
    """Write a fake artifact and return a spec pinned to its real digest."""
    (tmp_path / "tiny.gguf").write_bytes(body)
    return llm.ModelSpec(sha256=hashlib.sha256(body).hexdigest(), **SPEC_KW)


# ── the catalog is data, and a broken one must not stop the node ───────────

def test_the_shipped_catalog_parses_and_pins_every_model():
    cat = llm.load_catalog()
    assert cat, "the shipped catalog must contain at least one model"
    for model_id, spec in cat.items():
        assert spec.model_id == model_id
        assert len(spec.sha256) == 64 and int(spec.sha256, 16) >= 0, (
            f"{model_id}: sha256 must be a real digest -- an unverified pin is worse "
            "than no pin, because it looks like verification"
        )
        assert spec.min_ram_gb > 0 and spec.context > 0


def test_an_unreadable_catalog_means_no_llm_work_not_a_crash(tmp_path):
    broken = tmp_path / "bad.json"
    broken.write_text("{ not json")
    assert llm.load_catalog(broken) == {}
    assert llm.load_catalog(tmp_path / "absent.json") == {}


# ── the pin is the whole point ─────────────────────────────────────────────

def test_a_matching_digest_verifies_and_is_cached(tmp_path, monkeypatch):
    monkeypatch.setattr(llm, "CACHE_DIR", tmp_path)
    spec = _artifact(tmp_path)

    assert llm._verified_path(spec) == tmp_path / "tiny.gguf"
    sidecar = tmp_path / "tiny.gguf.verified"
    assert sidecar.exists(), "the digest is cached so a 4 GB file is not rehashed per poll"


def test_a_wrong_digest_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(llm, "CACHE_DIR", tmp_path)
    _artifact(tmp_path)
    wrong = llm.ModelSpec(sha256="0" * 64, **SPEC_KW)

    assert llm._verified_path(wrong) is None


def test_a_replaced_file_is_re_verified_not_trusted_from_the_sidecar(tmp_path, monkeypatch):
    """The sidecar is a cache, not an authority. Someone swapping the weights
    under a verified name must not inherit the old verdict."""
    monkeypatch.setattr(llm, "CACHE_DIR", tmp_path)
    spec = _artifact(tmp_path)
    assert llm._verified_path(spec) is not None

    (tmp_path / "tiny.gguf").write_bytes(b"different weights entirely")
    assert llm._verified_path(spec) is None


# ── advertising capability honestly ────────────────────────────────────────

def test_a_model_is_advertised_only_when_present_and_verified(tmp_path, monkeypatch):
    monkeypatch.setattr(llm, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(llm, "runtime_available", lambda: True)
    spec = _artifact(tmp_path)
    cat = {spec.model_id: spec}

    assert [s.model_id for s in llm.servable_models(cat, ram_gb=8)] == [spec.model_id]

    (tmp_path / "tiny.gguf").unlink()
    (tmp_path / "tiny.gguf.verified").unlink()
    assert llm.servable_models(cat, ram_gb=8) == [], (
        "advertising a model we do not have would take a subjob and then make "
        "the customer's batch wait on a download"
    )


def test_a_machine_too_small_advertises_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(llm, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(llm, "runtime_available", lambda: True)
    body = b"weights"
    (tmp_path / "tiny.gguf").write_bytes(body)
    big = llm.ModelSpec(
        **{**SPEC_KW, "min_ram_gb": 32.0}, sha256=hashlib.sha256(body).hexdigest()
    )
    assert llm.servable_models({big.model_id: big}, ram_gb=4) == []


def test_without_the_runtime_nothing_is_advertised(tmp_path, monkeypatch):
    monkeypatch.setattr(llm, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(llm, "runtime_available", lambda: False)
    spec = _artifact(tmp_path)
    assert llm.servable_models({spec.model_id: spec}, ram_gb=64) == []


def test_the_advertised_entry_matches_the_encoders_shape(tmp_path, monkeypatch):
    """The backend routes on one SQL predicate over installed_models and must
    not need to know which runtime produced an entry."""
    monkeypatch.setattr(llm, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(llm, "runtime_available", lambda: True)
    spec = _artifact(tmp_path)
    monkeypatch.setattr(llm, "load_catalog", lambda *a, **k: {spec.model_id: spec})
    monkeypatch.setattr(llm, "_usable_ram_gb", lambda: 64.0)

    entries = llm.installed_llm_models()
    assert len(entries) == 1
    e = entries[0]

    # The three keys the backend actually reads must be exactly right: it
    # filters Job.model against model_id, cross-checks sha, and its jsonb
    # containment predicate is satisfied by a superset.
    assert e["model_id"] == spec.model_id
    assert e["sha"] == spec.sha256
    assert e["last_used_at"] == 0.0

    # Extra keys are deliberate and must ride along: exec_class records what
    # produced the output (docs/LLM_DETERMINISM.md), so a real divergence can
    # be told apart from a merely heterogeneous fleet. Asserting an exact dict
    # made this test fail the moment that was added -- which it did, and only
    # the backend suite was re-run at the time.
    assert "exec_class" in e


# ── fetching, and the digest that makes any source usable ──────────────────

def test_no_source_configured_means_no_fetch(tmp_path, monkeypatch):
    """Unset MESHEMBED_GGUF_MIRROR means the node downloads nothing at all,
    rather than falling back to some default host."""
    monkeypatch.setattr(llm, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(llm, "MIRROR", "")
    spec = llm.ModelSpec(sha256="a" * 64, **SPEC_KW)
    assert llm.ensure_model(spec) is None


def test_a_download_whose_digest_is_wrong_is_discarded(tmp_path, monkeypatch):
    monkeypatch.setattr(llm, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(llm, "MIRROR", "https://mirror.example.org/gguf")
    spec = llm.ModelSpec(sha256="b" * 64, **SPEC_KW)

    class FakeResp:
        def raise_for_status(self): pass
        def iter_content(self, n): yield b"the wrong weights"
        def __enter__(self): return self
        def __exit__(self, *a): return False

    import requests
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp())

    assert llm.ensure_model(spec) is None
    assert not (tmp_path / "tiny.gguf").exists(), "a bad download must not be left behind"
    assert not (tmp_path / "tiny.part").exists(), "nor its temporary file"


def test_a_good_download_lands_under_its_real_name(tmp_path, monkeypatch):
    monkeypatch.setattr(llm, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(llm, "MIRROR", "https://mirror.example.org/gguf")
    body = b"real weights here"
    spec = llm.ModelSpec(sha256=hashlib.sha256(body).hexdigest(), **SPEC_KW)

    class FakeResp:
        def raise_for_status(self): pass
        def iter_content(self, n): yield body
        def __enter__(self): return self
        def __exit__(self, *a): return False

    import requests
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp())

    got = llm.ensure_model(spec)
    assert got == tmp_path / "tiny.gguf"
    assert got.read_bytes() == body


# ── parameter translation ──────────────────────────────────────────────────

def test_generation_parameters_reach_the_runtime():
    call = llm._call_kwargs({
        "max_tokens": 128, "temperature": 0.0, "top_p": 0.9,
        "stop": ["\n\n"], "seed": 42,
        "response_format": {"type": "json_object"},
    })
    assert call["max_tokens"] == 128 and call["temperature"] == 0.0
    assert call["top_p"] == 0.9 and call["stop"] == ["\n\n"] and call["seed"] == 42
    assert call["response_format"] == {"type": "json_object"}, (
        "llama.cpp constrains generation with a JSON grammar, so malformed JSON "
        "becomes impossible rather than merely flagged afterwards"
    )


def test_absent_parameters_are_not_invented():
    call = llm._call_kwargs({"max_tokens": 16})
    assert set(call) == {"max_tokens", "temperature"}, (
        "sending a default top_p or seed we were not given would change what "
        "the model does"
    )


def test_the_cap_the_daemon_applied_bounds_the_runtime(monkeypatch):
    """llama.cpp spawns a thread per visible core unless told otherwise, which
    would drive straight through the lend envelope."""
    monkeypatch.setenv("OMP_NUM_THREADS", "3")
    assert llm._capped_threads() == 3


# ── warming: what makes a model actually spread ────────────────────────────

def test_a_node_with_nothing_on_disk_fetches_what_it_can_run(tmp_path, monkeypatch):
    """The deadlock this exists to break: a node advertises only what is on
    disk, is only routed work for what it advertises, and the download path
    ran only while serving that work. Nothing ever arrived."""
    monkeypatch.setattr(llm, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(llm, "MIRROR", "https://mirror.example.org/gguf")
    monkeypatch.setattr(llm, "runtime_available", lambda: True)
    monkeypatch.setattr(llm, "_usable_ram_gb", lambda: 64.0)
    body = b"real weights"
    spec = llm.ModelSpec(sha256=hashlib.sha256(body).hexdigest(), **SPEC_KW)
    monkeypatch.setattr(llm, "load_catalog", lambda *a, **k: {spec.model_id: spec})

    class FakeResp:
        def raise_for_status(self): pass
        def iter_content(self, n): yield body
        def __enter__(self): return self
        def __exit__(self, *a): return False
    import requests
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp())

    assert llm.servable_models() == [], "nothing on disk yet"
    assert llm.warm_models() == [spec.model_id]
    assert [s.model_id for s in llm.servable_models()] == [spec.model_id]


def test_warming_respects_the_operators_field_of_play(tmp_path, monkeypatch):
    """A pinned list is the whole permission: an unpinned model is not
    DOWNLOADED, not merely not served. Reuses the control the operator
    already has rather than inventing a second one."""
    monkeypatch.setattr(llm, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(llm, "MIRROR", "https://mirror.example.org/gguf")
    monkeypatch.setattr(llm, "runtime_available", lambda: True)
    monkeypatch.setattr(llm, "_usable_ram_gb", lambda: 64.0)
    spec = llm.ModelSpec(sha256="c" * 64, **SPEC_KW)
    monkeypatch.setattr(llm, "load_catalog", lambda *a, **k: {spec.model_id: spec})

    called = []
    monkeypatch.setattr(llm, "ensure_model", lambda s, **k: called.append(s) or None)
    assert llm.warm_models(pinned=["someone/else"]) == []
    assert called == [], "an unpinned model must not even be fetched"


def test_warming_will_not_fill_the_disk(tmp_path, monkeypatch):
    """Filling an operator's disk is a way to lose a node permanently."""
    monkeypatch.setattr(llm, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(llm, "MIRROR", "https://mirror.example.org/gguf")
    monkeypatch.setattr(llm, "runtime_available", lambda: True)
    monkeypatch.setattr(llm, "_usable_ram_gb", lambda: 64.0)
    monkeypatch.setattr(llm, "_free_disk_gb", lambda p: 1.0)     # 1 GB free
    big = llm.ModelSpec(**{**SPEC_KW, "size_mb": 5000}, sha256="d" * 64)
    monkeypatch.setattr(llm, "load_catalog", lambda *a, **k: {big.model_id: big})
    called = []
    monkeypatch.setattr(llm, "ensure_model", lambda s, **k: called.append(s) or None)

    assert llm.warm_models() == [] and called == []


def test_warming_skips_a_machine_that_cannot_run_the_model(tmp_path, monkeypatch):
    monkeypatch.setattr(llm, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(llm, "MIRROR", "https://mirror.example.org/gguf")
    monkeypatch.setattr(llm, "runtime_available", lambda: True)
    monkeypatch.setattr(llm, "_usable_ram_gb", lambda: 2.0)
    big = llm.ModelSpec(**{**SPEC_KW, "min_ram_gb": 32.0}, sha256="e" * 64)
    monkeypatch.setattr(llm, "load_catalog", lambda *a, **k: {big.model_id: big})
    called = []
    monkeypatch.setattr(llm, "ensure_model", lambda s, **k: called.append(s) or None)

    assert llm.warm_models() == [] and called == []


def test_warming_never_raises(monkeypatch):
    """A node that cannot warm must keep serving embeddings."""
    monkeypatch.setattr(llm, "runtime_available", lambda: True)
    def boom(*a, **k): raise RuntimeError("catalogue on fire")
    monkeypatch.setattr(llm, "load_catalog", boom)
    assert llm.warm_models() == []


def test_a_node_without_the_runtime_downloads_nothing(monkeypatch):
    """Most nodes. Absence is safe, not broken."""
    monkeypatch.setattr(llm, "runtime_available", lambda: False)
    called = []
    monkeypatch.setattr(llm, "ensure_model", lambda s, **k: called.append(s))
    assert llm.warm_models() == [] and called == []


# ── json_object must work for BOTH request shapes ──────────────────────────

class _FakeLlama:
    """Records what it was called with, and rejects response_format on the
    completion path exactly as llama_cpp does.

    Verified against llama-cpp-python 0.3.35: create_completion has 26 named
    parameters, no **kwargs, and response_format is not among them, so passing
    it raises TypeError.
    """
    def __init__(self): self.seen = {}

    def create_completion(self, prompt, **kw):
        if "response_format" in kw:
            raise TypeError(
                "Llama.create_completion() got an unexpected keyword argument "
                "'response_format'")
        self.seen = dict(kw)
        return {"choices": [{"text": '{"a":1}'}], "usage": {}}

    def create_chat_completion(self, messages, **kw):
        self.seen = dict(kw)
        return {"choices": [{"message": {"content": '{"a":1}'}}], "usage": {}}


def _run(monkeypatch, item, params):
    fake = _FakeLlama()
    spec = llm.ModelSpec(sha256="f" * 64, **SPEC_KW)
    r = llm.LlamaRunner()
    r._model, r._loaded_id = fake, spec.model_id
    monkeypatch.setattr(llm, "_json_grammar", lambda: "GRAMMAR")
    return r.generate(spec, item, params), fake


def test_a_prompt_item_asking_for_json_does_not_crash(monkeypatch):
    """It used to: create_completion rejects response_format, so every
    prompt-style JSON item failed permanently while the identical request in
    `messages` form succeeded."""
    gen, fake = _run(monkeypatch,
                     {"custom_id": "p", "prompt": "Return JSON."},
                     {"max_tokens": 32, "temperature": 0.0,
                      "response_format": {"type": "json_object"}})
    assert gen.text == '{"a":1}'
    assert "response_format" not in fake.seen
    assert fake.seen.get("grammar") == "GRAMMAR", (
        "the constraint must be APPLIED as a grammar, not silently dropped -- "
        "the customer asked for JSON and would otherwise get prose"
    )


def test_a_messages_item_still_uses_response_format(monkeypatch):
    """The chat path does accept it, and must keep using it."""
    _, fake = _run(monkeypatch,
                   {"custom_id": "c", "messages": [{"role": "user", "content": "x"}]},
                   {"max_tokens": 32, "temperature": 0.0,
                    "response_format": {"type": "json_object"}})
    assert fake.seen.get("response_format") == {"type": "json_object"}
    assert "grammar" not in fake.seen


def test_a_prompt_item_without_json_passes_no_grammar(monkeypatch):
    _, fake = _run(monkeypatch, {"custom_id": "p", "prompt": "Hello."},
                   {"max_tokens": 32, "temperature": 0.0})
    assert "grammar" not in fake.seen and "response_format" not in fake.seen


def test_json_is_refused_rather_than_silently_dropped(monkeypatch):
    """If the runtime has no grammar, failing the subjob is correct: returning
    unconstrained prose for a request that asked for JSON is the silent wrong
    answer this whole module refuses to give."""
    monkeypatch.setattr(llm, "_json_grammar", lambda: None)
    fake = _FakeLlama()
    spec = llm.ModelSpec(sha256="f" * 64, **SPEC_KW)
    r = llm.LlamaRunner(); r._model, r._loaded_id = fake, spec.model_id
    with pytest.raises(RuntimeError, match="json_object_unsupported"):
        r.generate(spec, {"custom_id": "p", "prompt": "x"},
                   {"max_tokens": 8, "temperature": 0.0,
                    "response_format": {"type": "json_object"}})
