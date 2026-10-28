"""P3-3 (auditor 2026-10-27 19:50Z) + SK-3 (20:15Z): the release build carries EXACTLY the two PROD public keys,
generated on 188 on 2026-10-28 (docs/RECORD_E3_PROD_KEYS_2026-10-28.md), and nothing else. A sandbox key (or any
other key) in either compiled set fails this test, so it can never ship."""
import base64
import hashlib

from meshembed_node import run_ticket_verify as RT
from meshembed_node import split_plan_verify as SPV

PROD_SPLIT_PLAN = {"v1": "bKtntmlv5wMX3zrbcMugBf/OZ6nqRlQTfUmt6+CiBRA="}
PROD_RUN_TICKET = {"rt1": "0i1VvFKwqZeLtMH5hl7lMOfs4uyQMlr0AGbLwUo2doY="}
SHA256_RAW = {"v1": "df9a92c19cadc8016e9ebe885d965a8fd331a6c01d65a16b847666d4c6decc34",
              "rt1": "cefed6919d141e80870120b79aea45e2a727df32b65024954a7b119113f4c084"}


def test_the_compiled_sets_are_exactly_the_prod_keys():
    assert SPV._TRUSTED_SPLIT_PLAN_KEYS == PROD_SPLIT_PLAN
    assert RT._TRUSTED_RUN_TICKET_KEYS == PROD_RUN_TICKET


def test_the_keys_match_the_recorded_sha256_and_are_32_bytes():
    for kid, b64 in {**PROD_SPLIT_PLAN, **PROD_RUN_TICKET}.items():
        raw = base64.b64decode(b64, validate=True)
        assert len(raw) == 32 and hashlib.sha256(raw).hexdigest() == SHA256_RAW[kid]


def test_the_two_keys_are_distinct_and_the_ids_never_cross():
    assert set(PROD_SPLIT_PLAN.values()).isdisjoint(PROD_RUN_TICKET.values())
    assert all(not k.startswith("rt") for k in SPV._TRUSTED_SPLIT_PLAN_KEYS)          # a plan key is never rt*
    assert all(k.startswith("rt") for k in RT._TRUSTED_RUN_TICKET_KEYS)
