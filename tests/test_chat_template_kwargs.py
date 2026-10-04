"""Per-model chat-template arguments (design A3, orchestrator GO 18:48Z).

A thinking model (Qwen3.x) must be prompted with its own template and
enable_thinking=False; llama-cpp-python's default chat handler cannot pass that
(3/20 against 19/20 measured). The node renders the GGUF template itself, in a
sandboxed Jinja environment, ONLY for catalogue entries that carry kwargs; every
other model is prompted exactly as before.
"""
import json
from pathlib import Path

import pytest

jinja2 = pytest.importorskip("jinja2")          # comes with the opt-in llama-cpp-python runtime

from meshembed_node import llm  # noqa: E402

MINI_QWEN3 = (
    "{% for m in messages %}<|im_start|>{{ m.role }}\n{{ m.content }}<|im_end|>\n{% endfor %}"
    "{% if add_generation_prompt %}<|im_start|>assistant\n"
    "{% if enable_thinking is defined and enable_thinking is false %}<think>\n\n</think>\n\n{% endif %}"
    "{% endif %}")


class FakeModel:
    def __init__(self, template=MINI_QWEN3):
        self.metadata = {"tokenizer.chat_template": template}
        self.prompt = None
        self.kw = None
        self.chat_called = False

    def reset(self):
        pass

    def create_completion(self, prompt, **kw):
        if "response_format" in kw:
            raise TypeError("create_completion() got an unexpected keyword argument 'response_format'")
        self.prompt, self.kw = prompt, kw
        return {"choices": [{"text": "A"}], "usage": {"prompt_tokens": 10, "completion_tokens": 1}}

    def create_chat_completion(self, messages, **kw):
        self.chat_called, self.kw = True, kw
        return {"choices": [{"message": {"content": "A"}}], "usage": {}}


def _spec(kwargs, sha="a" * 64):
    return llm.ModelSpec(model_id="test/think-q4", file="t.gguf", sha256=sha, size_mb=1, min_ram_gb=0.001,
                         context=512, chat_template_kwargs=kwargs)


def _gen(fake, spec, params):
    r = llm.LlamaRunner()
    r._model, r._loaded_id = fake, spec.model_id
    return r.generate(spec, {"custom_id": "x", "messages": [{"role": "user", "content": "Pick one."}]}, params)


@pytest.fixture(autouse=True)
def _fresh_cache(monkeypatch):
    import sys
    import types
    try:
        import llama_cpp  # noqa: F401
    except ImportError:
        # generate() imports LogitsProcessorList on every call; the runtime is opt-in
        stub = types.ModuleType("llama_cpp")
        stub.LogitsProcessorList = list
        monkeypatch.setitem(sys.modules, "llama_cpp", stub)
    monkeypatch.setattr(llm, "_TEMPLATES", {})
    monkeypatch.setattr(llm, "_json_grammar", lambda: "GRAMMAR")


def test_kwargs_render_the_models_own_template_and_complete_it():
    fake = FakeModel()
    gen = _gen(fake, _spec({"enable_thinking": False}), {"max_tokens": 4, "temperature": 0.0})
    assert not fake.chat_called
    assert fake.prompt.endswith("<|im_start|>assistant\n<think>\n\n</think>\n\n")
    assert "<|im_start|>user\nPick one.<|im_end|>" in fake.prompt
    assert gen.text == "A"


def test_json_object_becomes_a_grammar_on_the_rendered_path():
    fake = FakeModel()
    _gen(fake, _spec({"enable_thinking": False}),
         {"max_tokens": 16, "temperature": 0.0, "response_format": {"type": "json_object"}})
    assert fake.kw.get("grammar") == "GRAMMAR" and "response_format" not in fake.kw


def test_labels_keep_their_logits_processor_on_the_rendered_path(monkeypatch):
    fake = FakeModel()
    monkeypatch.setattr(llm, "_LabelTrie", lambda model, labels, eos: None)
    _gen(fake, _spec({"enable_thinking": False}),
         {"max_tokens": 4, "temperature": 0.0, "response_format": {"type": "labels", "labels": ["A", "B"]}})
    assert fake.kw.get("logits_processor") is not None


def test_without_kwargs_the_prompt_path_is_unchanged():
    fake = FakeModel()
    _gen(fake, _spec(None), {"max_tokens": 4, "temperature": 0.0})
    assert fake.chat_called and fake.prompt is None


def test_the_template_is_compiled_once_per_model_file():
    fake = FakeModel()
    spec = _spec({"enable_thinking": False})
    _gen(fake, spec, {"max_tokens": 4})
    first = llm._TEMPLATES[spec.sha256]
    _gen(fake, spec, {"max_tokens": 4})
    assert llm._TEMPLATES[spec.sha256] is first and len(llm._TEMPLATES) == 1


def test_the_template_runs_in_a_sandbox():
    fake = FakeModel(template="{{ ''.__class__.__mro__[1].__subclasses__() }}")
    with pytest.raises(jinja2.exceptions.SecurityError):
        _gen(fake, _spec({"enable_thinking": False}), {"max_tokens": 4})


def test_kwargs_come_from_the_catalogue_only():
    """A job cannot set template arguments: they are not a batch parameter."""
    fake = FakeModel()
    _gen(fake, _spec(None), {"max_tokens": 4, "chat_template_kwargs": {"enable_thinking": False}})
    assert fake.chat_called and fake.prompt is None


QWEN25 = ("meshembed/qwen2.5-0.5b-instruct-q4", "meshembed/qwen2.5-3b-instruct-q4", "meshembed/qwen2.5-7b-instruct-q4")


def test_the_qwen25_models_are_untouched():
    """No thinking mode: they keep llama-cpp's default chat handler, exactly as before."""
    cat = {m["model_id"]: m for m in json.loads((Path(llm.__file__).parent / "llm_catalog.json").read_text())["models"]}
    assert all(mid in cat and "chat_template_kwargs" not in cat[mid] for mid in QWEN25)
    specs = llm.load_catalog()
    assert all(specs[mid].chat_template_kwargs is None for mid in QWEN25)


def test_qwen3_is_served_with_thinking_off():
    """Qwen3 thinks by default; through the default handler it scored 2/20 vs 17/20 (2026-10-02)."""
    spec = llm.load_catalog()["meshembed/qwen3-4b-q8"]
    assert spec.chat_template_kwargs == {"enable_thinking": False}
    assert spec.sha256 == "fb684cd1056921c526f12a9efbad10c4627e151ecc1e28314fae1c2cce0c2c15"


def test_only_the_thinking_models_carry_template_kwargs():
    """Template arguments are an exception, reviewed per model, never a default."""
    with_kwargs = {mid for mid, s in llm.load_catalog().items() if s.chat_template_kwargs is not None}
    assert with_kwargs == {"meshembed/qwen3-4b-q8"}


# ── Jinja2 >= 3.1.6 (security auditor, 098c7d9 review) ─────────────────────
def test_the_format_attr_sandbox_bypass_is_refused():
    """CVE-2025-27516: |attr("format") reached str.format and escaped the sandbox
    before Jinja2 3.1.6. On a safe Jinja2 the same payload raises SecurityError."""
    assert llm.jinja2_safe(), "this test environment must run Jinja2 >= 3.1.6"
    payload = '{{ ("{0.__class__.__mro__[1].__subclasses__}"|attr("format"))(1) }}'
    with pytest.raises(jinja2.exceptions.SecurityError):
        _gen(FakeModel(template=payload), _spec({"enable_thinking": False}), {"max_tokens": 4})


def test_an_old_jinja2_neither_renders_nor_advertises(monkeypatch):
    monkeypatch.setattr(llm, "jinja2_safe", lambda: False)
    with pytest.raises(RuntimeError, match="jinja2_below_3.1.6"):
        _gen(FakeModel(), _spec({"enable_thinking": False}), {"max_tokens": 4})
    monkeypatch.setattr(llm, "runtime_available", lambda: True)
    monkeypatch.setattr(llm, "_verified_path", lambda spec: True)
    monkeypatch.setattr(llm, "_loaded_id", lambda: None)
    cat = {"t/think": _spec({"enable_thinking": False}), "t/plain": _spec(None, sha="b" * 64)}
    cat["t/plain"] = llm.ModelSpec(model_id="t/plain", file="p.gguf", sha256="b" * 64, size_mb=1,
                                   min_ram_gb=0.001, context=512)
    served = [s.model_id for s in llm.servable_models(catalog=cat, ram_gb=64)]
    assert served == ["t/plain"]


def test_the_installers_pin_jinja2_next_to_the_runtime():
    root = Path(llm.__file__).resolve().parents[1]
    for name in ("install.sh", "install-mac.sh", "install.ps1"):
        text = (root / name).read_text()
        assert text.count('"llama-cpp-python==0.3.35" "jinja2>=3.1.6"') == text.count('"llama-cpp-python==0.3.35"') >= 1, name
    assert "jinja2>=3.1.6" in (root / "requirements.txt").read_text()
