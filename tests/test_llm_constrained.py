"""Constrained output and the confidence score (cascade support, v0.3.63)."""
from __future__ import annotations

import math
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from meshembed_node import llm  # noqa: E402

pytestmark = pytest.mark.unit


def test_labels_become_a_grammar_of_alternatives():
    # The runtime is opt-in on nodes and absent on CI's unit runner; the
    # grammar is llama.cpp's, so without it there is nothing to test here.
    pytest.importorskip("llama_cpp")
    g = llm.grammar_for_labels(["INVOICE", "CONTRACT", "LETTER"])
    assert g is not None
    with pytest.raises(RuntimeError):
        llm.grammar_for_labels([])


def test_a_schema_becomes_a_grammar():
    # The runtime is opt-in on nodes and absent on CI's unit runner; the
    # grammar is llama.cpp's, so without it there is nothing to test here.
    pytest.importorskip("llama_cpp")
    g = llm.grammar_for_schema({"type": "object", "properties": {"seller": {"type": "string"}}, "required": ["seller"]})
    assert g is not None


def test_call_kwargs_carry_the_schema_grammar_and_never_ask_for_logprobs():
    # The runtime is opt-in on nodes and absent on CI's unit runner; the
    # grammar is llama.cpp's, so without it there is nothing to test here.
    pytest.importorskip("llama_cpp")
    out = llm._call_kwargs({"max_tokens": 8, "response_format": {"type": "json_schema", "schema": {"type": "object"}}})
    assert "grammar" in out and "logprobs" not in out
    out = llm._call_kwargs({"max_tokens": 8, "response_format": {"type": "json_object"}})
    assert out["response_format"] == {"type": "json_object"} and "grammar" not in out
    # labels are applied by the logits processor in generate(), not here
    out = llm._call_kwargs({"max_tokens": 8, "response_format": {"type": "labels", "labels": ["A", "B"]}})
    assert "grammar" not in out and "logprobs" not in out


class _FakeModel:
    """Tokenizer stand-in: one token per character, EOS = 0, im_end = 1."""
    def tokenize(self, b, add_bos=False, special=False):
        t = b.decode()
        if special and t == "<|im_end|>":
            return [1]
        if special:
            return [7, 8]
        return [ord(c) for c in t]
    def token_eos(self):
        return 0


def test_label_trie_allows_only_label_continuations_then_eos():
    m = _FakeModel()
    trie = llm._LabelTrie(m, ["AB", "AC"], llm._eos_ids(m))
    first = trie.next_tokens(())
    assert first == {ord("A"), ord(" ")}                     # as written, or with a leading space
    assert trie.next_tokens((ord("A"),)) == {ord("B"), ord("C")}
    assert trie.next_tokens((ord("A"), ord("B"))) == {0, 1}    # complete: only end-of-answer
    assert trie.next_tokens((ord("Z"),)) == {0, 1}            # off the trie: end


def test_confidence_processor_scores_the_previous_choice_under_the_mask():
    np = pytest.importorskip("numpy")
    m = _FakeModel()
    trie = llm._LabelTrie(m, ["AB", "AC"], llm._eos_ids(m))
    proc = llm._ConfidenceProcessor(trie)
    vocab = 128
    prompt = np.array([10, 11, 12])
    # step 1: at the root; the model favours 'A' 9:1 over ' '
    s1 = np.full(vocab, -30.0, dtype=np.float32); s1[ord("A")] = 2.2; s1[ord(" ")] = 0.0
    out1 = proc(prompt, s1.copy())
    assert np.isinf(out1[ord("Z")]) and out1[ord("A")] == 2.2          # masked to the label starts
    # step 2: the sampler chose 'A'; among B / C the model is 50/50
    s2 = np.full(vocab, -30.0, dtype=np.float32); s2[ord("B")] = 1.0; s2[ord("C")] = 1.0
    proc(np.append(prompt, ord("A")), s2.copy())
    # step 3: it chose 'B'; only EOS-class tokens remain
    s3 = np.full(vocab, -30.0, dtype=np.float32); s3[0] = 0.0; s3[1] = 0.0
    out3 = proc(np.append(prompt, [ord("A"), ord("B")]), s3.copy())
    assert set(np.where(np.isfinite(out3))[0]) == {0, 1}
    import math
    pA = math.exp(2.2) / (math.exp(2.2) + 1.0)                  # 'A' vs ' ' after masking
    assert abs(proc.confidence() - math.sqrt(pA * 0.5)) < 1e-6


def test_confidence_processor_without_a_trie_records_raw_probabilities():
    np = pytest.importorskip("numpy")
    proc = llm._ConfidenceProcessor(None)
    s = np.zeros(4, dtype=np.float32); s[2] = 5.0
    proc(np.array([1]), s.copy())
    proc(np.array([1, 2]), s.copy())
    import math
    assert abs(proc.confidence() - math.exp(5.0) / (math.exp(5.0) + 3)) < 1e-6
    assert llm._ConfidenceProcessor(None).confidence() is None


def test_confidence_is_the_geometric_mean_probability():
    chat = {"choices": [{"logprobs": {"content": [{"logprob": math.log(0.9)}, {"logprob": math.log(0.4)}]}}]}
    assert abs(llm.confidence_from(chat) - math.sqrt(0.9 * 0.4)) < 1e-9
    comp = {"choices": [{"logprobs": {"token_logprobs": [math.log(0.5), None, math.log(0.5)]}}]}
    assert abs(llm.confidence_from(comp) - 0.5) < 1e-9


def test_no_logprobs_means_no_confidence_not_a_crash():
    assert llm.confidence_from({"choices": [{}]}) is None
    assert llm.confidence_from({}) is None
    assert llm.confidence_from({"choices": [{"logprobs": {"content": []}}]}) is None
