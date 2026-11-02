"""LIC-M3 (2026-11-02): a model retired for its licence is never fetched, and the daemon deletes its own cached copy.
The 3B (Qwen research licence, non-commercial) was still in llm_catalog.json with a false "Apache-2.0" note, so
warm_models prefetched it on every LLM node with the mirror set."""
import ast
import json
from pathlib import Path

from meshembed_node import llm

ROOT = Path(__file__).resolve().parents[2]


def _backend_retired() -> set:
    tree = ast.parse((ROOT / "backend" / "app" / "model_aliases.py").read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(getattr(t, "id", None) == "RETIRED" for t in node.targets):
            return {ast.literal_eval(k) for k in node.value.keys}
    raise AssertionError("RETIRED not found in backend/app/model_aliases.py")


def test_the_node_retired_set_equals_the_backend_one():
    assert set(llm.RETIRED) == _backend_retired()


def test_no_retired_model_or_file_is_in_the_catalogue():
    cat = json.loads((Path(llm.__file__).parent / "llm_catalog.json").read_text())["models"]
    ids, files = {m["model_id"] for m in cat}, {m["file"] for m in cat}
    assert not ids & set(llm.RETIRED) and not files & set(llm.RETIRED.values())
    assert not set(llm.load_catalog(include_serve_only=True)) & set(llm.RETIRED)


def test_prune_deletes_the_weights_the_sidecar_and_a_partial_download(tmp_path):
    f = llm.RETIRED["meshembed/qwen2.5-3b-instruct-q4"]
    (tmp_path / f).write_bytes(b"x")
    (tmp_path / (f + ".verified")).write_text("{}")
    (tmp_path / Path(f).with_suffix(".part").name).write_bytes(b"y")
    (tmp_path / "qwen3-4b-q8_0.gguf").write_bytes(b"keep")                  # a live model stays
    removed = llm.prune_retired(tmp_path)
    assert sorted(removed) == sorted([f, f + ".verified", Path(f).with_suffix(".part").name])
    assert [p.name for p in tmp_path.iterdir()] == ["qwen3-4b-q8_0.gguf"]


def test_prune_removes_a_symlink_but_never_its_target(tmp_path):
    f = llm.RETIRED["meshembed/qwen2.5-3b-instruct-q4"]
    target = tmp_path / "elsewhere.bin"
    target.write_bytes(b"not ours")
    (tmp_path / "cache").mkdir()
    (tmp_path / "cache" / f).symlink_to(target)
    assert llm.prune_retired(tmp_path / "cache") == [f]
    assert target.read_bytes() == b"not ours"


def test_prune_on_a_clean_cache_does_nothing(tmp_path):
    assert llm.prune_retired(tmp_path) == []
    assert llm.prune_retired(tmp_path / "missing") == []


def test_the_warm_pass_prunes_first_even_without_the_runtime(monkeypatch):
    calls = []
    monkeypatch.setattr(llm, "prune_retired", lambda *a, **k: calls.append("prune") or [])
    monkeypatch.setattr(llm, "runtime_available", lambda: False)
    assert llm.warm_models() == [] and calls == ["prune"]
