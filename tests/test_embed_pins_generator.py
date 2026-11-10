"""The release-prep side of HF-SQUAT: scripts/catalogue/embed_pins.py (the table generator) and
scripts/catalogue/embed_pins_diff.py (the review view the auditor reads like code, 2026-11-08T17:31:14Z).
A fake hub that answers only what the real HfApi answers; no network, no model code."""
from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

pytestmark = pytest.mark.unit

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts" / "catalogue"


def _load(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


G = _load("embed_pins")
D = _load("embed_pins_diff")

MID = "intfloat/fake-e5"
OLD_REV, NEW_REV = "1" * 40, "2" * 40
WEIGHTS_OLD, WEIGHTS_NEW = "a" * 64, "b" * 64
SMALL = {
    "config.json": b'{"model_type": "bert"}',
    "modules.json": json.dumps([{"type": "sentence_transformers.models.Transformer"},
                                {"type": "sentence_transformers.models.Pooling"}]).encode(),
    "1_Pooling/config.json": b'{"word_embedding_dimension": 4}',
}


class FakeHub:
    """Two commits: OLD (weights a..a) then NEW (weights b..b, newest first in list_repo_commits). A real hub lists
    the commits reachable FROM `revision`, newest first; model_info(revision=...) answers for that commit only."""

    def __init__(self, small=None, extra_siblings=()):
        self.small = dict(SMALL if small is None else small)
        self.extra = list(extra_siblings)
        self.commits = [NS(commit_id=NEW_REV, created_at=dt.datetime(2025, 6, 2, tzinfo=dt.timezone.utc)),
                        NS(commit_id=OLD_REV, created_at=dt.datetime(2024, 1, 5, tzinfo=dt.timezone.utc))]

    def list_repo_commits(self, repo, revision=None):
        ids = [c.commit_id for c in self.commits]
        return self.commits[ids.index(revision):] if revision else list(self.commits)

    def model_info(self, repo, revision=None, files_metadata=False):
        w = WEIGHTS_NEW if revision == NEW_REV else WEIGHTS_OLD
        sib = [NS(rfilename="model.safetensors", lfs=NS(sha256=w)), NS(rfilename="README.md", lfs=None),
               NS(rfilename="pytorch_model.bin", lfs=NS(sha256="c" * 64))]
        sib += [NS(rfilename=p, lfs=None) for p in self.small] + list(self.extra)
        return NS(siblings=sib)

    def fetch(self, repo, path, revision, cache_dir):
        p = Path(cache_dir) / revision / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(self.small[path])
        return str(p)


def _row(rev="", sha=WEIGHTS_OLD):
    return {"model_id": MID, "hf_revision": rev, "sha256": sha, "added_at": "2026-01-01"}


def test_a_catalogue_revision_is_pinned_with_its_date_and_every_kept_file(tmp_path):
    hub = FakeHub()
    e, why = G.build_entry(hub, _row(OLD_REV), str(tmp_path), fetch=hub.fetch)
    assert why is None
    assert e["revision"] == OLD_REV and e["revision_source"] == "catalogue"
    assert e["revision_date"].startswith("2024-01-05")
    assert e["files"]["model.safetensors"] == WEIGHTS_OLD
    assert e["files"]["config.json"] == hashlib.sha256(SMALL["config.json"]).hexdigest()
    assert "README.md" not in e["files"] and "pytorch_model.bin" not in e["files"]   # never read, never pinned


def test_no_revision_is_resolved_to_the_commit_whose_weights_match_the_catalogue(tmp_path):
    hub = FakeHub()
    e, why = G.build_entry(hub, _row("", WEIGHTS_OLD), str(tmp_path), fetch=hub.fetch)
    assert why is None and e["revision"] == OLD_REV and e["revision_source"] == "resolved_by_weights_sha"
    assert e["revision_date"].startswith("2024-01-05")       # the auditor reads the resolved commit + its date


def test_no_commit_matching_the_catalogue_sha_is_refused_never_guessed(tmp_path):
    hub = FakeHub()
    e, why = G.build_entry(hub, _row("", "f" * 64), str(tmp_path), fetch=hub.fetch)
    assert e is None and "no commit" in why


def test_a_catalogue_revision_whose_weights_differ_from_the_catalogue_sha_is_refused(tmp_path):
    hub = FakeHub()
    e, why = G.build_entry(hub, _row(NEW_REV, WEIGHTS_OLD), str(tmp_path), fetch=hub.fetch)
    assert e is None and "weights sha" in why


@pytest.mark.parametrize("small,why", [
    ({**SMALL, "config.json": b'{"auto_map": {"AutoModel": "x.Y"}}'}, "custom code"),
    ({**SMALL, "modules.json": json.dumps([{"type": "evil.Module"}]).encode()}, "module type"),
])
def test_custom_code_and_foreign_modules_are_refused(tmp_path, small, why):
    hub = FakeHub(small=small)
    e, got = G.build_entry(hub, _row(OLD_REV), str(tmp_path), fetch=hub.fetch)
    assert e is None and why in got


def test_a_module_folder_with_only_pickle_weights_is_refused(tmp_path):
    hub = FakeHub(extra_siblings=[NS(rfilename="2_Dense/pytorch_model.bin", lfs=NS(sha256="d" * 64))])
    e, why = G.build_entry(hub, _row(OLD_REV), str(tmp_path), fetch=hub.fetch)
    assert e is None and "2_Dense" in why


def test_the_generated_entry_loads_in_the_node_table_loader(tmp_path):
    """What the generator writes is what the node accepts (extra keys like revision_date are ignored there)."""
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from meshembed_node import embed_pins as P
    hub = FakeHub()
    e, _ = G.build_entry(hub, _row(OLD_REV), str(tmp_path), fetch=hub.fetch)
    t = tmp_path / "t.json"
    t.write_text(json.dumps({"models": [e]}))
    assert MID in P.load_table(t)


# ---- the review view ----

def _table(*entries):
    return {e["model_id"]: e for e in entries}


def _e(mid, rev, files, src="catalogue", date="2024-01-05T00:00:00+00:00"):
    return {"model_id": mid, "revision": rev, "revision_source": src, "revision_date": date,
            "weights_sha": files.get("model.safetensors", ""), "files": files}


def test_the_diff_lists_every_file_sha_and_marks_what_changed():
    old = _table(_e("a/x", OLD_REV, {"model.safetensors": "1" * 64, "tokenizer.json": "2" * 64}),
                 _e("a/gone", OLD_REV, {"model.safetensors": "9" * 64}),
                 _e("a/same", OLD_REV, {"model.safetensors": "8" * 64}))
    new = _table(_e("a/x", NEW_REV, {"model.safetensors": "1" * 64, "tokenizer.json": "3" * 64,
                                     "vocab.txt": "4" * 64}),
                 _e("a/new", NEW_REV, {"model.safetensors": "5" * 64, "config.json": "6" * 64},
                    src="resolved_by_weights_sha", date="2025-06-02T00:00:00+00:00"),
                 _e("a/same", OLD_REV, {"model.safetensors": "8" * 64}))
    out = D.render(old, new)
    assert out.splitlines()[0] == "embed_pins diff: 1 added, 1 changed, 1 removed, 1 unchanged"
    assert "### ADDED a/new" in out and "resolved_by_weights_sha" in out and "2025-06-02" in out
    assert f"`config.json` `{'6' * 64}`" in out                       # every file of an added id
    assert f"`tokenizer.json` `{'3' * 64}` **CHANGED** (was `{'2' * 64}`)" in out
    assert f"`vocab.txt` `{'4' * 64}` **NEW FILE**" in out
    assert f"revision was `{OLD_REV}`" in out
    assert "### REMOVED a/gone" in out and "- a/same" in out


def test_the_diff_says_unknown_when_a_date_is_missing():
    e = _e("a/x", OLD_REV, {"model.safetensors": "1" * 64}, date="")
    assert "commit date UNKNOWN" in D.render({}, _table(e))


@pytest.mark.parametrize("mid", ["meshembed/qwen3-30b-a3b-q4", "Meshembed/qwen3-30b-a3b-q4"])
def test_our_generation_namespace_is_never_pinned_in_any_case(tmp_path, mid):
    hub = FakeHub()
    e, why = G.build_entry(hub, {**_row(OLD_REV), "model_id": mid}, str(tmp_path), fetch=hub.fetch)
    assert e is None and why == "generation namespace"
