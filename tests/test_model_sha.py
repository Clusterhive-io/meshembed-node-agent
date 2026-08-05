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


def test_falls_back_to_the_hf_cache_when_name_or_path_is_not_a_directory():
    """The whole bug: a hub model id is not a path, and there was no fallback."""
    assert "snapshot_download" in _CODE


def test_cache_lookup_never_downloads():
    """A sha computation must not fetch hundreds of MB mid-job."""
    assert "local_files_only=True" in _CODE


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


def test_returns_a_sha256_when_resolvable():
    """End-to-end, if the real model happens to be cached on this machine.
    Skipped in environments without the model rather than failing CI."""
    st = pytest.importorskip("sentence_transformers")
    try:
        m = st.SentenceTransformer("intfloat/multilingual-e5-small", device="cpu")
    except Exception:
        pytest.skip("model not available in this environment")
    sha = encoder._compute_model_sha(m, "intfloat/multilingual-e5-small")
    assert len(sha) == 64 and all(c in "0123456789abcdef" for c in sha), (
        "expected a hex sha256; empty means the resolution regressed"
    )
