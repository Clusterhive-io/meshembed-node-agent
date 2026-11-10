"""Model checkpoint SHA resolution — ROGUE_LAB FINDING 6, layer 1.

`_compute_model_sha` resolved the weights directory from
`auto_model.name_or_path`. For anything loaded from the HF hub — i.e. every
model in the catalog — that attribute is the model *id*
("intfloat/multilingual-e5-small"), not a path. So `os.path.isdir()` was always
False and the function returned "" **100% of the time**.

`worker._report` only sends the field when truthy, so no daemon has ever
reported a model_sha, and the backend's model_sha verification has therefore
been inert everywhere since it was written. Verified live: 1229/1229 results in
the sandbox carry no sha.

The fix resolves the real snapshot directory out of the HF cache with
`local_files_only=True`, so it never triggers a download and degrades to the
previous "" behaviour when the model isn't cached.
"""
from __future__ import annotations

import inspect

import pytest

from meshembed_node import encoder

pytestmark = pytest.mark.unit

_SRC = inspect.getsource(encoder._compute_model_sha)
_CODE = "\n".join(l for l in _SRC.splitlines() if not l.lstrip().startswith("#"))


def test_the_sha_comes_only_from_the_loaded_directory_never_the_hf_cache():
    """HF-SQUAT (auditor HIGH 2026-11-08; design P-7): every model is loaded from the VERIFIED pinned directory
    (embed_pins.prepare), which is exactly name_or_path, so the sha is that directory's. The old fallback into the
    HF cache by model id (snapshot_download local_files_only) is gone: one load path, nothing read unverified."""
    assert "snapshot_download" not in _CODE and "os.path.isdir(local_dir)" in _CODE


def test_a_sha_computation_never_downloads():
    """A sha computation must not fetch hundreds of MB mid-job: nothing in it talks to the hub at all."""
    assert "huggingface_hub" not in _CODE


def test_still_degrades_to_empty_rather_than_raising():
    """An unresolvable sha must never break encoding — the daemon stays
    functional with an empty sha, it just won't get strict-mode work."""
    assert 'return ""' in _CODE


def test_uncached_model_returns_empty_not_an_exception():
    """Simulates a model that isn't in the local cache."""
    class _Fake:
        def _first_module(self):
            raise RuntimeError("no module")
    sha = encoder._compute_model_sha(_Fake(), "definitely/not-a-real-model-xyz")
    assert sha == ""


def test_returns_the_weights_sha256_of_the_loaded_directory(tmp_path):
    """The pinned view is a directory holding model.safetensors: its sha256 is what the node reports (= the table's
    weights_sha = the catalogue pin). A model id that is not a directory gives "" (it was never loaded that way)."""
    import hashlib
    (tmp_path / "model.safetensors").write_bytes(b"WEIGHTS")

    class _Auto:
        name_or_path = str(tmp_path)

    class _First:
        auto_model = _Auto()

    class _Model:
        def _first_module(self):
            return _First()
    assert encoder._compute_model_sha(_Model(), "intfloat/multilingual-e5-small") == hashlib.sha256(b"WEIGHTS").hexdigest()
    _Auto.name_or_path = "intfloat/multilingual-e5-small"
    assert encoder._compute_model_sha(_Model(), "intfloat/multilingual-e5-small") == ""
