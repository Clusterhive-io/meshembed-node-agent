"""Fleet half of patch 0004 (auditor 2026-10-21 18:38Z): a failed item's reported error and its log line never carry
customer text. Only our own closed codes pass; a library exception (e.g. llama-cpp-python's json_schema converter,
which can quote the schema) is reduced to its type; chat_template_error loses its template-text suffix."""
import inspect
import logging

from meshembed_node import worker

CANARY = "CANARYpatientZq7"


def test_our_closed_codes_pass_unchanged():
    for msg in ("json_object_unsupported_by_runtime", "chat_template_missing", "runtime_unavailable",
                "labels_empty", "model_unavailable:qwen3-4b", "chat_template_runtime_unsafe:jinja2_below_3.1.6"):
        assert worker._safe_error(RuntimeError(msg)) == msg


def test_chat_template_error_is_cut_to_its_code():
    assert worker._safe_error(RuntimeError("chat_template_error:Conversation roles must alternate")) == \
        "chat_template_error"
    assert worker._safe_error(RuntimeError(f"chat_template_error:{CANARY}")) == "chat_template_error"


def test_library_messages_are_reduced_to_their_type():
    class LlamaGrammarError(RuntimeError):      # a library RuntimeError subclass: never trusted as a code
        pass
    for exc, want in ((ValueError(f"Unrecognized schema: {{'description': '{CANARY}'}}"), "ValueError"),
                      (RuntimeError(f"failed to parse {CANARY}"), "RuntimeError"),
                      (LlamaGrammarError("bad_grammar"), "LlamaGrammarError"),
                      (KeyError(CANARY), "KeyError"),
                      (UnicodeDecodeError("utf-8", CANARY.encode(), 0, 1, "x"), "UnicodeDecodeError")):
        out = worker._safe_error(exc)
        assert out == want and CANARY not in out


def test_the_generate_and_encode_paths_use_it_and_never_the_raw_message():
    src = inspect.getsource(worker)
    assert 'error = f"generate_error:{_safe_error(exc)}"' in src
    assert 'error = f"encode_error:{_safe_error(exc)}"' in src
    assert 'f"generate_error:{exc}"' not in src and 'f"encode_error:{exc}"' not in src
    assert 'log.error("Generation failed: %s", exc)' not in src and 'log.error("Encode failed: %s", exc)' not in src


def test_the_log_line_carries_no_canary(caplog):
    caplog.set_level(logging.ERROR)
    exc = ValueError(f"Unrecognized schema: {CANARY}")
    worker.log.error("Generation failed: %s", worker._safe_error(exc))
    assert CANARY not in caplog.text and "ValueError" in caplog.text


def test_memory_exhaustion_keeps_its_closed_signal_for_the_backend():
    # store.py lowers the node's concurrency when the reported error contains "oom": keep that signal, as a code
    for exc in (RuntimeError(f"CUDA out of memory. Tried to allocate 2.00 GiB ({CANARY})"),
                RuntimeError("CUBLAS_STATUS_ALLOC_FAILED when calling cublasCreate"),
                ValueError(f"llama_decode: out of memory {CANARY}")):
        out = worker._safe_error(exc)
        assert out == "oom" and CANARY not in out
    assert "oom" in f"encode_error:{worker._safe_error(RuntimeError('CUDA out of memory'))}".lower()


def test_model_load_failed_keeps_its_code():
    # the backend pauses the (node, model) pair on model_load_failed (A3); the model name is a catalogue id
    assert worker._safe_error(RuntimeError("model_load_failed:intfloat/multilingual-e5-small")) == \
        "model_load_failed:intfloat/multilingual-e5-small"


def test_a_library_runtime_error_shaped_like_a_code_does_not_pass():
    # auditor 20:37Z nit: the heads are an explicit list of OURS
    assert worker._safe_error(RuntimeError(f"x:{CANARY}")) == "RuntimeError"
    assert worker._safe_error(RuntimeError("some_library_code")) == "RuntimeError"
    assert worker._safe_error(RuntimeError(f"model_unavailable:{CANARY} with spaces")) == "model_unavailable"


def test_decrypt_errors_are_reduced_too():
    import inspect
    assert 'error = f"decrypt_error:{_safe_error(exc)}"' in inspect.getsource(worker)

