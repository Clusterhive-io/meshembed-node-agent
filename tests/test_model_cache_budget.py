"""M60 OOM fix — the resident model cache is VRAM-budgeted, and a large operator
allow-list stays fully ELIGIBLE (reported by installed_models, downloaded to
disk) without holding every model RESIDENT in VRAM.

Regression for: a node assigned the 16-model catalog on an 8 GB M60 eager-loaded
all 16 (`_cache_size = max(_cache_size, len(desired))` + eager preload) → CUDA
OOM on every real chunk. The fix decouples eligibility from residency.
"""
import meshembed_node.encoder as enc_mod
from meshembed_node.encoder import Encoder, _vram_budget_models


def test_vram_budget_scales_and_floors(monkeypatch):
    monkeypatch.setenv("MESHEMBED_MODEL_VRAM_MB", "2000")
    assert _vram_budget_models(0) == 1          # never zero
    assert _vram_budget_models(8000) == 3       # 8000*0.75/2000 = 3  (an 8 GB card)
    assert _vram_budget_models(24000) == 9      # scales up with VRAM
    # a giant per-model estimate still floors at 1, not 0
    monkeypatch.setenv("MESHEMBED_MODEL_VRAM_MB", "999999")
    assert _vram_budget_models(8000) == 1


def test_cache_size_capped_by_vram_on_cuda(monkeypatch):
    monkeypatch.setattr(enc_mod, "_DEVICE", "cuda")
    monkeypatch.setattr(enc_mod, "vram_free_mb", lambda: 8000)
    monkeypatch.setenv("MESHEMBED_MODEL_CACHE_SIZE", "16")
    monkeypatch.setenv("MESHEMBED_MODEL_VRAM_MB", "2000")
    enc = Encoder("intfloat/multilingual-e5-small", preload=False)
    # 16 configured, but only 3 fit in 8 GB -> capped to 3 (this is the OOM fix)
    assert enc._cache_size == 3


def test_cache_size_cpu_keeps_configured(monkeypatch):
    monkeypatch.setattr(enc_mod, "_DEVICE", "cpu")
    monkeypatch.setenv("MESHEMBED_MODEL_CACHE_SIZE", "5")
    enc = Encoder("m", preload=False)
    assert enc._cache_size == 5


def _wire_fakes(monkeypatch, enc):
    """Stub disk-download and VRAM-load so no real ST/torch/network is needed.
    _ensure_on_disk records a disk sha; _ensure_loaded honours the LRU bound."""
    monkeypatch.setattr(
        enc, "_ensure_on_disk",
        lambda name: enc._sha_by_model.__setitem__(name, "sha-" + name),
    )

    def fake_load(name, eager):
        with enc._lock:
            while len(enc._cache) >= enc._cache_size:
                enc._cache.popitem(last=False)
            enc._cache[name] = (object(), "sha-" + name, 1.0)
            enc._sha_by_model[name] = "sha-" + name
        return enc._cache[name][0], "sha-" + name

    monkeypatch.setattr(enc, "_ensure_loaded", fake_load)


def test_large_allowlist_stays_eligible_without_oom(monkeypatch):
    monkeypatch.setattr(enc_mod, "_DEVICE", "cpu")
    monkeypatch.setenv("MESHEMBED_MODEL_CACHE_SIZE", "2")
    enc = Encoder("org/model-0", preload=False)
    assert enc._cache_size == 2
    _wire_fakes(monkeypatch, enc)

    models = [f"org/model-{i}" for i in range(16)]
    enc.set_served_models(models)

    # residency is bounded (the OOM fix): cache_size NOT bumped to 16, and at
    # most cache_size models are held resident.
    assert enc._cache_size == 2
    assert len(enc._cache) <= 2

    # eligibility: installed_models reports ALL 16 so the backend still routes
    # every assigned model (an evicted one just lazy-loads on demand).
    ims = enc.installed_models()
    assert {m["model_id"] for m in ims} == set(models)
    assert len(ims) == 16
    assert all(m["sha"] for m in ims), "every eligible model reports a sha (disk or resident)"


def test_clearing_allowlist_lifts_restriction(monkeypatch):
    monkeypatch.setattr(enc_mod, "_DEVICE", "cpu")
    monkeypatch.setenv("MESHEMBED_MODEL_CACHE_SIZE", "2")
    enc = Encoder("m0", preload=False)
    _wire_fakes(monkeypatch, enc)

    enc.set_served_models(["a", "b"])
    assert enc._served == ["a", "b"] and enc._pinned == {"a", "b"}

    enc.set_served_models(None)
    assert enc._served is None and enc._pinned is None
    # unpinned -> installed_models reflects the resident cache (a, b stay loaded;
    # clearing the allow-list does not evict them, it just lifts the routing gate)
    assert {m["model_id"] for m in enc.installed_models()} == {"a", "b"}
