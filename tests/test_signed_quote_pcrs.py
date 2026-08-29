"""E.2b: the signed-quote POST must carry the real E.1 PCR snapshot (so the
backend can bind reported PCRs to the signed pcrDigest), not an empty dict.
"""
import inspect

from meshembed_node import worker


def test_quote_post_sends_collected_pcrs():
    src = inspect.getsource(worker._attempt_signed_quote)
    assert "collect_tpm_state" in src, "must collect the E.1 PCRs"
    assert '"pcr_values": _pcrs' in src, "must POST the real PCRs, not {}"
    assert '"pcr_values": {}' not in src, "the empty-PCR placeholder must be gone"
