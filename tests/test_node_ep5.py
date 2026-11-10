"""NODE-EP5 (auditor EP-5 2026-11-09T08:09:43Z): an owner-ticked embedding id that the signed pin table cannot load is
not advertised, so the backend never routes it, nor hands a canary for it, to this node. The owner's allow-list is
untouched: an empty advertised set must never lift the restriction."""
from __future__ import annotations

import meshembed_node.encoder as enc_mod
from meshembed_node import embed_pins
from meshembed_node.encoder import Encoder


def _enc(monkeypatch, pins):
    monkeypatch.setattr(enc_mod, "_DEVICE", "cpu")
    e = Encoder("m0", preload=False)
    monkeypatch.setattr(e, "_ensure_on_disk", lambda name: e._sha_by_model.__setitem__(name, "sha-" + name))
    monkeypatch.setattr(e, "_pin_ids", lambda: frozenset(pins))
    return e


def test_a_ticked_id_outside_the_pin_table_is_not_advertised(monkeypatch):
    e = _enc(monkeypatch, {"intfloat/multilingual-e5-small"})
    e.set_served_models(["intfloat/multilingual-e5-small", "BAAI/bge-m3"])
    assert [m["model_id"] for m in e.installed_models()] == ["intfloat/multilingual-e5-small"]


def test_the_owners_restriction_holds_when_nothing_survives(monkeypatch):
    e = _enc(monkeypatch, set())
    e.set_served_models(["BAAI/bge-m3"])
    assert e._pinned == {"BAAI/bge-m3"} and e._served == ["BAAI/bge-m3"]     # still restricted, not "lazy-load any"
    assert e.installed_models() == []


def test_an_unreadable_table_advertises_no_embedding_model(monkeypatch, tmp_path):
    monkeypatch.setattr(enc_mod, "_DEVICE", "cpu")
    bad = tmp_path / "embed_pins.json"
    bad.write_text("not json")
    monkeypatch.setattr(embed_pins, "TABLE_PATH", bad)
    monkeypatch.setattr(embed_pins.load_table, "__defaults__", (bad,))
    e = Encoder("m0", preload=False)
    monkeypatch.setattr(e, "_ensure_on_disk", lambda name: None)
    e.set_served_models(["intfloat/multilingual-e5-small"])
    assert e.installed_models() == []


def test_the_shipped_table_carries_the_canary_model_and_not_bge_m3():
    ids = frozenset(embed_pins.load_table())
    assert "intfloat/multilingual-e5-small" in ids          # store.py _CANARY_MODEL_ID (EP-1)
    assert "BAAI/bge-m3" not in ids and len(ids) == 15


def test_the_real_lookup_reads_the_table_once(monkeypatch):
    calls = []
    real = embed_pins.load_table

    def counting(*a, **k):
        calls.append(1)
        return real(*a, **k)
    monkeypatch.setattr(embed_pins, "load_table", counting)
    monkeypatch.setattr(enc_mod, "_DEVICE", "cpu")
    e = Encoder("m0", preload=False)
    assert "intfloat/multilingual-e5-small" in e._pin_ids() and "intfloat/multilingual-e5-small" in e._pin_ids()
    assert len(calls) == 1


import pytest  # noqa: E402


@pytest.mark.parametrize("body", ['["a"]', '"x"', '{"models": "x"}', '{"models": [1, "b", null]}', '{}'])
def test_ne1_a_table_of_the_wrong_shape_loads_as_empty_and_never_raises(tmp_path, body):
    """NE-1 (auditor 2026-11-09T08:18:53Z)."""
    f = tmp_path / "embed_pins.json"
    f.write_text(body)
    assert embed_pins.load_table(f) == {}
