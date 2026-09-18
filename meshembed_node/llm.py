"""Batch LLM generation on an operator node, via llama.cpp / GGUF.

docs/LLM_INFERENCE_DESIGN.md par.3. The runtime choice is not a preference, it
falls out of MODEL_ONBOARDING_POLICY.md:

- **No torch.** llama.cpp sidesteps the whole torch ABI surface, which is the
  thing that has broken this fleet before (a node that installs torchvision
  reports zero models). It also runs on CPU-only machines, which par.11 argues
  is the capacity that actually exists in an office.
- **No third-party code executes.** GGUF is a static weights format: nothing
  runs author code at load time, so the `trust_remote_code` gate that keeps
  jina and nomic out of the embedding catalog does not even arise here.

Two more rules this module keeps:

- **Every artifact is pinned by SHA-256**, verified after download AND before
  load. A node that cannot verify a file does not serve that model; it does not
  fall back. The pin is what makes the SOURCE safe rather than something the
  source has to be trusted for: if bytes change upstream, verification fails and
  the node refuses to serve. `MESHEMBED_GGUF_MIRROR` therefore takes any HTTPS
  prefix; our own mirror is worth having for availability and bandwidth at fleet
  scale, not for integrity.
- **A model is advertised only if this machine can actually run it.** The
  backend routes on `installed_models`, so advertising a 7B on a 4 GB box
  would take work the node then fails. Capability is measured, not declared.

There is deliberately no fallback path. `encoder.encode` degrades to a
hash-embed when a model will not load, because a wrong vector is detectable
downstream by its sha. A wrong completion is not detectable at all, so a node
that cannot generate correctly must fail the subjob and say so.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)

# Where verified GGUF artifacts live on the node.
CACHE_DIR = Path(
    os.environ.get("MESHEMBED_GGUF_DIR", str(Path.home() / ".meshembed" / "gguf"))
)
# Where artifacts are fetched from. Any HTTPS prefix; the SHA-256 pin is what
# makes the source safe, so this may point at our own mirror or at an upstream
# repository. Unset means the node never downloads weights at all.
MIRROR = os.environ.get("MESHEMBED_GGUF_MIRROR", "").rstrip("/")

# Shipped beside this module; a signed data file, so adding a model to the
# fleet is a catalog change and a release, not a code change.
CATALOG_PATH = Path(__file__).with_name("llm_catalog.json")

_DOWNLOAD_CHUNK = 1 << 20


@dataclass(frozen=True)
class ModelSpec:
    model_id: str          # what the backend routes on
    file: str              # artifact name on the mirror
    sha256: str            # pinned; verified on download and on load
    size_mb: int
    min_ram_gb: float      # to LOAD and generate at a usable rate
    context: int           # n_ctx to open
    note: str = ""


@dataclass
class Generation:
    text: str
    input_tokens: int
    output_tokens: int
    seconds: float
    model_sha: str
    # Geometric-mean token probability of the completion, 0..1, or None when
    # the runtime returned no logprobs. The cascade's escalation signal: a
    # constrained answer the model was unsure of is exactly the item worth
    # sending to a bigger model.
    confidence: Optional[float] = None


def load_catalog(path: Path = CATALOG_PATH) -> Dict[str, ModelSpec]:
    """Read the fleet catalog. A missing or broken catalog means no LLM work.

    Never raises: a node whose catalog is unreadable must keep serving
    embeddings rather than crash-looping. It simply advertises no LLM models,
    which the backend reads as "do not route generation here".
    """
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return {
            e["model_id"]: ModelSpec(**e)
            for e in raw.get("models", [])
        }
    except Exception as exc:                       # pragma: no cover - defensive
        log.warning("llm: catalog unreadable (%s); no LLM models advertised", exc)
        return {}


def _usable_ram_gb() -> float:
    """RAM we may actually count on, not RAM installed.

    Uses available rather than total: a workstation with 16 GB where the owner
    has 13 GB in use cannot run a 7B model, and finding that out by being
    assigned one is the failure mode this avoids.
    """
    try:
        import psutil
        return psutil.virtual_memory().available / (1024 ** 3)
    except Exception:
        return 0.0


def runtime_available() -> bool:
    try:
        import llama_cpp  # noqa: F401
        return True
    except Exception:
        return False


_EXEC_CLASS: Optional[Dict[str, Any]] = None


def execution_class() -> Dict[str, Any]:
    """What produced this node's output, beyond the model weights.

    docs/LLM_DETERMINISM.md. Identical weights and greedy decoding do not by
    themselves guarantee two nodes agree: llama.cpp dispatches different SIMD
    kernels per CPU, and a GPU is a different kernel set entirely. Thread count
    and runtime version were measured and did NOT diverge; CPU microarchitecture
    is untested and is the plausible one.

    So the node reports the class rather than the platform guessing at it. This
    is deliberately only VISIBILITY: nothing routes on it yet, because we do not
    have field measurements to route on. It is what makes those measurements
    interpretable -- without it a real divergence and a heterogeneous fleet look
    identical, and a canary reference cannot be scoped to the class that
    produced it.

    `simd` comes from llama.cpp's own report of the kernels it CHOSE, not from
    /proc/cpuinfo: what the CPU supports and what the build uses are different
    questions, and only the second affects the arithmetic.

    Cached: the answer cannot change without a restart.
    """
    global _EXEC_CLASS
    if _EXEC_CLASS is not None:
        return _EXEC_CLASS
    info: Dict[str, Any] = {"runtime": None, "gpu_offload": None, "simd": None}
    try:
        import llama_cpp
        info["runtime"] = f"llama-cpp-python/{llama_cpp.__version__}"
        try:
            info["gpu_offload"] = bool(llama_cpp.llama_supports_gpu_offload())
        except Exception:
            pass
        try:
            raw = llama_cpp.llama_print_system_info()
            text = raw.decode() if isinstance(raw, bytes) else str(raw)
            # "AVX2 = 1 | FMA = 0 | ..." -> the enabled names, sorted so the
            # class id is stable across builds that reorder the report.
            enabled = sorted(
                part.split("=")[0].strip()
                for part in text.replace("CPU :", "").split("|")
                if "=" in part and part.split("=")[1].strip() == "1"
            )
            info["simd"] = ",".join(enabled) or None
        except Exception:
            pass
    except Exception:
        return info                      # no runtime: every field stays None
    # A short stable handle for grouping. Routing, when it exists, groups on
    # this rather than comparing three fields.
    info["class_id"] = hashlib.sha256(
        f"{info['runtime']}|{info['gpu_offload']}|{info['simd']}".encode()
    ).hexdigest()[:12]
    _EXEC_CLASS = info
    return info


def servable_models(
    catalog: Optional[Dict[str, ModelSpec]] = None,
    ram_gb: Optional[float] = None,
) -> List[ModelSpec]:
    """Catalog entries this machine can run AND has verified on disk.

    Both halves matter. Advertising a model we have the RAM for but not the
    file would take a subjob and then spend minutes downloading it while the
    customer's batch waits; advertising a file we cannot fit would take one and
    fail. `warm_models` is what puts the file there, ahead of advertising it;
    without that step nothing would ever download a model, because a node is
    only routed work for models it already advertises.
    """
    if not runtime_available():
        return []
    cat = catalog if catalog is not None else load_catalog()
    ram = _usable_ram_gb() if ram_gb is None else ram_gb
    out = []
    for spec in cat.values():
        if ram < spec.min_ram_gb:
            continue
        if not _verified_path(spec):
            continue
        out.append(spec)
    return out


# Free disk to leave after a fetch. A catalogue could hold several 7B models,
# and filling an operator's disk is a way to lose a node permanently. We do not
# report their disk usage (that is deliberately not ours to watch) but we do
# refuse to be the process that exhausts it.
DISK_HEADROOM_GB = float(os.environ.get("MESHEMBED_GGUF_DISK_HEADROOM_GB", "5"))


def _free_disk_gb(path: Path) -> Optional[float]:
    try:
        import shutil
        target = path if path.exists() else path.parent
        return shutil.disk_usage(str(target)).free / (1024 ** 3)
    except Exception:
        return None


def warm_models(pinned: Optional[List[str]] = None) -> List[str]:
    """Fetch catalogue models this machine could serve but does not yet have.

    This is what makes a model SPREAD. Without it the node is deadlocked: it
    advertises only models already on disk, it is only routed work for models
    it advertises, and the only download path runs while serving that work. A
    fresh node would sit there forever with a catalogue it never acts on.

    What it will not do:

    - Fetch for a machine that cannot run the model anyway (available RAM, not
      installed -- same test `servable_models` applies).
    - Fetch outside the operator's "field of play". When the operator has
      pinned models in the dashboard, that list is the whole permission: an
      unpinned model is not downloaded, not just not served. Reusing the
      existing control rather than inventing a second one.
    - Fill the disk. Refuses when free space would drop under DISK_HEADROOM_GB.

    Returns the model_ids actually fetched. Never raises: warming is
    best-effort and a node that cannot warm must keep serving embeddings.
    """
    if not runtime_available():
        return []
    try:
        catalog = load_catalog()
        if not catalog:
            return []
        ram = _usable_ram_gb()
        allowed = set(pinned) if pinned else None
        fetched: List[str] = []
        for spec in catalog.values():
            if allowed is not None and spec.model_id not in allowed:
                continue
            if ram < spec.min_ram_gb:
                continue
            if _verified_path(spec) is not None:
                continue                       # already here
            free = _free_disk_gb(CACHE_DIR)
            if free is not None and free - (spec.size_mb / 1024.0) < DISK_HEADROOM_GB:
                log.warning(
                    "llm: not fetching %s -- would leave under %.1f GB free",
                    spec.model_id, DISK_HEADROOM_GB,
                )
                continue
            if ensure_model(spec) is not None:
                fetched.append(spec.model_id)
        return fetched
    except Exception as exc:                   # pragma: no cover - defensive
        log.warning("llm: warm pass failed (%s); node keeps serving embeddings", exc)
        return []


def readiness() -> Dict[str, Any]:
    """Why this machine is, or is not, serving generation.

    "Not ready" has five quite different causes and the operator cannot tell
    them apart from the dashboard: the runtime was never installed, the node
    has nowhere to fetch weights from, the machine is too small for anything
    in the catalogue, the disk is too full, or it simply has not warmed yet.
    Before this, all five looked identical -- a switch stuck on "installing".

    Cheap enough for every poll: no downloads, no model loads, one statvfs.
    Never raises; a node that cannot answer reports `unknown` rather than
    breaking its own poll.
    """
    out: Dict[str, Any] = {
        "runtime": False, "mirror": False, "models_ready": 0,
        "catalog": 0, "fits": 0, "ram_gb": None, "free_disk_gb": None,
        "blocked": "unknown",
    }
    try:
        out["runtime"] = runtime_available()
        out["gpu"] = {**gpu_info(), "offload": bool(out["runtime"] and gpu_offload_available())}
        out["mirror"] = bool(MIRROR)
        catalog = load_catalog()
        out["catalog"] = len(catalog)
        ram = _usable_ram_gb()
        out["ram_gb"] = round(ram, 1)
        fits = [s for s in catalog.values() if ram >= s.min_ram_gb]
        out["fits"] = len(fits)
        out["models_ready"] = sum(1 for s in fits if _verified_path(s) is not None)
        free = _free_disk_gb(CACHE_DIR)
        out["free_disk_gb"] = None if free is None else round(free, 1)

        if not out["runtime"]:
            out["blocked"] = "no_runtime"        # operator has not opted in
        elif out["models_ready"]:
            out["blocked"] = None                # serving
        elif not fits:
            out["blocked"] = "insufficient_ram"  # smallest model does not fit
        elif not out["mirror"]:
            out["blocked"] = "no_mirror"         # nowhere to fetch weights from
        elif free is not None and free < DISK_HEADROOM_GB:
            out["blocked"] = "insufficient_disk"
        else:
            out["blocked"] = "warming"           # fetching, or about to
    except Exception as exc:                     # pragma: no cover - defensive
        log.debug("llm: readiness unavailable (%s)", exc)
    return out


def installed_llm_models() -> List[dict]:
    """The daemon's /get_job + /register payload shape, matching the encoder's.

    Same three keys as `Encoder.installed_models` on purpose: the backend's
    model filter is one SQL predicate over `nodes.installed_models` and it must
    not need to know which runtime produced an entry.
    """
    klass = execution_class()
    return [
        {
            "model_id": s.model_id,
            "sha": s.sha256,
            "last_used_at": 0.0,
            # Extra keys ride along harmlessly: the backend reads model_id and
            # sha, and its jsonb containment filter is satisfied by a superset.
            "exec_class": klass.get("class_id"),
            "runtime": klass.get("runtime"),
            "simd": klass.get("simd"),
            "gpu_offload": klass.get("gpu_offload"),
        }
        for s in servable_models()
    ]


def _artifact_path(spec: ModelSpec) -> Path:
    return CACHE_DIR / spec.file


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(_DOWNLOAD_CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def _verified_path(spec: ModelSpec) -> Optional[Path]:
    """The artifact, if it is present and its bytes are the pinned ones.

    The digest is cached in a sidecar so a 4 GB file is not re-hashed on every
    poll; the sidecar is only trusted when the file's size and mtime match what
    was recorded, so a replaced file is re-verified.
    """
    path = _artifact_path(spec)
    if not path.exists():
        return None
    stat = path.stat()
    sidecar = path.with_suffix(path.suffix + ".verified")
    try:
        rec = json.loads(sidecar.read_text(encoding="utf-8"))
        if (
            rec.get("sha256") == spec.sha256
            and rec.get("size") == stat.st_size
            and rec.get("mtime") == int(stat.st_mtime)
        ):
            return path
    except Exception:
        pass

    actual = _sha256_file(path)
    if actual != spec.sha256:
        log.error(
            "llm: %s failed verification (want %s, got %s) -- refusing to serve it",
            spec.model_id, spec.sha256[:12], actual[:12],
        )
        return None
    try:
        sidecar.write_text(
            json.dumps({"sha256": actual, "size": stat.st_size, "mtime": int(stat.st_mtime)}),
            encoding="utf-8",
        )
    except Exception:                              # pragma: no cover - best effort
        pass
    return path


def ensure_model(spec: ModelSpec, timeout: int = 1800) -> Optional[Path]:
    """Return a verified artifact, downloading it from our mirror if needed.

    Downloads to a temporary name and renames only after the digest matches, so
    an interrupted download can never be picked up as a usable model by the
    next poll.
    """
    path = _verified_path(spec)
    if path is not None:
        return path
    if not MIRROR:
        log.warning(
            "llm: %s not on disk and no MESHEMBED_GGUF_MIRROR set -- not fetching "
            "from any third-party host by design", spec.model_id,
        )
        return None

    import requests
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = _artifact_path(spec).with_suffix(".part")
    url = f"{MIRROR}/{spec.file}"
    log.info("llm: fetching %s (%d MB) from the mirror", spec.model_id, spec.size_mb)
    try:
        with requests.get(url, stream=True, timeout=timeout) as resp:
            resp.raise_for_status()
            with tmp.open("wb") as fh:
                for chunk in resp.iter_content(_DOWNLOAD_CHUNK):
                    fh.write(chunk)
    except Exception as exc:
        log.error("llm: download of %s failed: %s", spec.model_id, exc)
        tmp.unlink(missing_ok=True)
        return None

    actual = _sha256_file(tmp)
    if actual != spec.sha256:
        log.error(
            "llm: %s downloaded but digest is wrong (want %s, got %s) -- discarded",
            spec.model_id, spec.sha256[:12], actual[:12],
        )
        tmp.unlink(missing_ok=True)
        return None
    tmp.rename(_artifact_path(spec))
    return _verified_path(spec)


class LlamaRunner:
    """One loaded GGUF at a time, guarded by a lock.

    One at a time because these are gigabytes: an LRU over two 7B models is a
    way to make a workstation swap. The lock is held across generation because
    llama.cpp's context is not safe to share, and because the node's whole
    point is to take one subjob at a time per worker anyway.
    """

    def __init__(self, threads: Optional[int] = None):
        self._lock = threading.RLock()
        self._model = None
        self._loaded_id: Optional[str] = None
        self._threads = threads

    def _load(self, spec: ModelSpec):
        from llama_cpp import Llama
        path = ensure_model(spec)
        if path is None:
            raise RuntimeError(f"model_unavailable:{spec.model_id}")
        if self._model is not None:
            self._model = None                     # free before allocating
        log.info("llm: loading %s", spec.model_id)
        kwargs: Dict[str, Any] = {
            "model_path": str(path),
            "n_ctx": spec.context,
            "verbose": False,
            "logits_all": False,
        }
        # Honour the lend envelope: resources.apply_cpu_cap has already pinned
        # affinity and thread counts, and llama.cpp would otherwise spawn one
        # thread per visible core regardless (docs/NODE_RESOURCE_CAP.md).
        threads = self._threads or _capped_threads()
        if threads:
            kwargs["n_threads"] = threads
        layers = gpu_layers_choice()
        try:
            self._model = Llama(**kwargs, n_gpu_layers=layers)
        except Exception as exc:
            if layers == 0:
                raise
            # A card that cannot hold the model (VRAM) or a driver that cannot
            # run this build must cost the node nothing but the offload: the
            # same weights load on the CPU, slower. Say so once.
            log.warning("llm: GPU offload failed for %s (%s) -- loading on CPU", spec.model_id, exc)
            self._model = Llama(**kwargs, n_gpu_layers=0)
        self._loaded_id = spec.model_id
        return self._model

    def generate(self, spec: ModelSpec, item: dict, params: dict) -> Generation:
        """Run one item. Raises on failure -- never returns a plausible guess."""
        with self._lock:
            model = (
                self._model
                if self._loaded_id == spec.model_id and self._model is not None
                else self._load(spec)
            )
            # Start every item from an EMPTY context. llama.cpp keeps the KV
            # cache of the previous call and re-uses any shared prefix, and
            # the tail of the prompt is then evaluated on a different batch
            # path than a cold prompt would be. Measured 2026-09-13 on a 7B
            # Q4 at T=0: the same prompt gave 107, 133 and 131 tokens on one
            # instance depending on what ran before it, and reset() restored
            # the cold output byte for byte (docs/LLM_DETERMINISM.md, "Instance reuse").
            # Without this, a node that has just served an item with the
            # same system prompt disagrees with a fresh node, and canaries
            # and twins would score honest hardware for it. The cost is
            # re-evaluating the prompt per item, which on the batch lane is
            # noise next to generation.
            model.reset()
            t0 = time.perf_counter()
            call = _call_kwargs(params)
            fmt = params.get("response_format") or {}
            trie = None
            if fmt.get("type") == "labels":
                trie = _LabelTrie(model, list(fmt.get("labels") or []), _eos_ids(model))
            proc = _ConfidenceProcessor(trie)
            from llama_cpp import LogitsProcessorList
            call["logits_processor"] = LogitsProcessorList([proc])
            if item.get("messages"):
                # The model's own chat template, out of the GGUF metadata. A
                # template rendered on the backend would be the wrong one for
                # every model but the one it was written for.
                resp = model.create_chat_completion(
                    messages=item["messages"], **call
                )
                text = (resp["choices"][0]["message"].get("content") or "")
            else:
                # create_completion does NOT accept response_format -- only
                # create_chat_completion does. Passing it raises TypeError, so
                # every prompt-style item asking for JSON failed permanently
                # while the identical request in `messages` form succeeded.
                #
                # The constraint is applied as a GRAMMAR instead, which this
                # call does support and which is what response_format compiles
                # to internally. Dropping the parameter silently was the other
                # option and it is worse: the customer asked for JSON and would
                # have got prose, with no error to explain it.
                raw = dict(call)
                if (raw.pop("response_format", None) or {}).get("type") == "json_object":
                    grammar = _json_grammar()
                    if grammar is not None:
                        raw["grammar"] = grammar
                    else:
                        raise RuntimeError("json_object_unsupported_by_runtime")
                resp = model.create_completion(prompt=item["prompt"], **raw)
                text = resp["choices"][0].get("text") or ""
            seconds = time.perf_counter() - t0

        usage = resp.get("usage") or {}
        return Generation(
            text=text,
            input_tokens=int(usage.get("prompt_tokens") or 0),
            # The runtime's own counter, not an estimate: this is what the
            # customer is billed on and what the platform pays the operator
            # for (docs/BILLING_BASIS.md).
            output_tokens=int(usage.get("completion_tokens") or 0),
            confidence=proc.confidence(),
            seconds=seconds,
            model_sha=spec.sha256,
        )


_JSON_GRAMMAR = None


def _json_grammar():
    """The JSON grammar llama.cpp ships, compiled once.

    Returns None if this runtime build has neither, so the caller can fail the
    subjob explicitly rather than quietly returning unconstrained prose for a
    request that asked for JSON.
    """
    global _JSON_GRAMMAR
    if _JSON_GRAMMAR is not None:
        return _JSON_GRAMMAR
    try:
        from llama_cpp.llama_grammar import JSON_GBNF, LlamaGrammar
        _JSON_GRAMMAR = LlamaGrammar.from_string(JSON_GBNF, verbose=False)
    except Exception as exc:              # pragma: no cover - build dependent
        log.warning("llm: no JSON grammar available in this runtime (%s)", exc)
        return None
    return _JSON_GRAMMAR


def _capped_threads() -> Optional[int]:
    """Threads llama.cpp may use, from the cap the daemon already applied."""
    for var in ("OMP_NUM_THREADS", "MKL_NUM_THREADS"):
        raw = os.environ.get(var)
        if raw:
            try:
                val = int(raw)
                if val > 0:
                    return val
            except ValueError:
                pass
    try:
        import psutil
        return len(psutil.Process().cpu_affinity()) or None
    except Exception:
        return None


def gpu_offload_available() -> bool:
    """True when this runtime build can put layers on a GPU (CUDA / Metal)."""
    try:
        from llama_cpp import llama_supports_gpu_offload
        return bool(llama_supports_gpu_offload())
    except Exception:
        return False


def gpu_layers_choice(env: Optional[Dict[str, str]] = None, offload: Optional[bool] = None) -> int:
    """How many layers to offload: MESHEMBED_LLM_GPU_LAYERS if set (0 = CPU),
    else all of them when the runtime supports offload, else none. Pure, so it
    is testable without a card."""
    e = os.environ if env is None else env
    raw = (e.get("MESHEMBED_LLM_GPU_LAYERS") or "").strip()
    if raw:
        try:
            return max(-1, int(raw))
        except ValueError:
            pass
    can = gpu_offload_available() if offload is None else offload
    return -1 if can else 0


_GPU_INFO: Optional[Dict[str, Any]] = None


def gpu_info() -> Dict[str, Any]:
    """What card this machine has, if any -- for the readiness report. One
    nvidia-smi call, cached; Apple Silicon by platform; never raises."""
    global _GPU_INFO
    if _GPU_INFO is not None:
        return _GPU_INFO
    info: Dict[str, Any] = {"name": None, "vram_mb": None, "driver": None, "kind": None}
    try:
        import platform, subprocess
        if platform.system() == "Darwin" and platform.machine() == "arm64":
            info.update(name="Apple Silicon", kind="metal")
        else:
            out = subprocess.run(
                ["nvidia-smi", "--query-gpu=name,memory.total,driver_version",
                 "--format=csv,noheader,nounits"],
                capture_output=True, text=True, timeout=5,
            ).stdout.strip().splitlines()
            if out:
                name, mem, drv = [x.strip() for x in out[0].split(",")[:3]]
                info.update(name=name, vram_mb=int(float(mem)), driver=drv, kind="cuda")
    except Exception:
        pass
    _GPU_INFO = info
    return info


def _call_kwargs(params: dict) -> Dict[str, Any]:
    """Translate our normalised parameters into llama.cpp's call signature."""
    out: Dict[str, Any] = {
        "max_tokens": int(params.get("max_tokens", 512)),
        "temperature": float(params.get("temperature", 0.0)),
    }
    if "top_p" in params:
        out["top_p"] = float(params["top_p"])
    if params.get("stop"):
        out["stop"] = list(params["stop"])
    if params.get("seed") is not None:
        out["seed"] = int(params["seed"])
    fmt = params.get("response_format") or {}
    kind = fmt.get("type")
    if kind == "json_object":
        # llama.cpp constrains generation with a JSON grammar, so a malformed
        # object becomes impossible rather than merely flagged afterwards.
        out["response_format"] = {"type": "json_object"}
    elif kind == "json_schema":
        # Constrained to THIS schema: the answer cannot lack a required key or
        # put a string where a number goes. Fewer output tokens, no repair.
        out["grammar"] = grammar_for_schema(fmt.get("schema") or {})
    # `labels` is applied in generate() by a logits processor (see
    # _ConfidenceProcessor), not a grammar: the processor both constrains the
    # answer to the label set and measures the model's confidence AMONG the
    # labels. `logprobs=` is deliberately not requested -- llama.cpp only
    # serves it with logits_all=True, ~2.4 GB of RAM on a 150k vocabulary.
    return out


def grammar_for_labels(labels: list):
    """A GBNF grammar that admits exactly one of `labels`."""
    from llama_cpp.llama_grammar import LlamaGrammar
    if not labels:
        raise RuntimeError("labels_empty")
    def q(l):
        esc = str(l).replace('\\', '\\\\').replace('"', '\\"')
        return '"' + esc + '"'
    return LlamaGrammar.from_string("root ::= " + " | ".join(q(l) for l in labels), verbose=False)


def grammar_for_schema(schema: dict):
    """A GBNF grammar derived from a JSON schema (llama.cpp's converter)."""
    import json as _json
    from llama_cpp.llama_grammar import LlamaGrammar
    return LlamaGrammar.from_json_schema(_json.dumps(schema), verbose=False)


class _LabelTrie:
    """Token sequences of the allowed labels, walked as the model generates.
    A label is tokenised as written and with a leading space, because a chat
    template may or may not leave the answer at the start of a line."""

    def __init__(self, model, labels: list, eos_ids: set):
        self.root: dict = {}
        self.eos_ids = set(eos_ids)
        for lab in labels:
            for text in (str(lab), " " + str(lab)):
                toks = model.tokenize(text.encode("utf-8"), add_bos=False, special=False)
                node = self.root
                for t in toks:
                    node = node.setdefault(int(t), {})
                node.setdefault("_end", True)

    def next_tokens(self, generated: tuple) -> set:
        node = self.root
        for t in generated:
            node = node.get(int(t))
            if node is None:
                return set(self.eos_ids)          # off the trie (cannot happen when masked)
        out = {k for k in node if k != "_end"}
        if node.get("_end"):
            out |= self.eos_ids
        return out


class _ConfidenceProcessor:
    """A llama.cpp logits processor that records log p(chosen token) per step.

    The processor at step t sees the token chosen at step t-1 (the last of
    input_ids), so it scores it against the distribution it stored at t-1.
    With a label trie it also masks the distribution to the allowed next
    tokens, so the recorded probability is renormalised over the labels --
    the model's confidence among the answers it was allowed to give. Without
    a trie (JSON, text) the probability is under the raw distribution, with
    a grammar applied afterwards by the sampler; structural tokens a grammar
    forces can then read as "unsure", which makes that number conservative.
    """

    def __init__(self, trie: Optional[_LabelTrie] = None):
        self.trie = trie
        self.n_prompt: Optional[int] = None
        self.prev = None
        self.logps: list = []

    def __call__(self, input_ids, scores):
        import numpy as np
        ids = np.asarray(input_ids)
        if self.n_prompt is None:
            self.n_prompt = len(ids)
        gen = tuple(int(t) for t in ids[self.n_prompt:])
        if self.prev is not None and gen:
            self.logps.append(self._logp(self.prev, gen[-1]))
        if self.trie is not None:
            allowed = self.trie.next_tokens(gen)
            masked = np.full(scores.shape, -np.inf, dtype=scores.dtype)
            idx = [i for i in allowed if 0 <= i < scores.shape[-1]]
            if idx:
                masked[idx] = scores[idx]
                scores = masked
        self.prev = np.array(scores, dtype=np.float32, copy=True)
        return scores

    @staticmethod
    def _logp(logits, tok: int) -> float:
        import numpy as np
        m = float(np.max(logits))
        if not np.isfinite(m):
            return -50.0
        lse = m + float(np.log(np.sum(np.exp(logits - m))))
        v = float(logits[tok]) - lse if 0 <= tok < logits.shape[-1] else -50.0
        return v if v == v and v > -1e9 else -50.0

    def confidence(self) -> Optional[float]:
        if not self.logps:
            return None
        import math
        return max(0.0, min(1.0, math.exp(sum(self.logps) / len(self.logps))))


def _eos_ids(model) -> set:
    """End-of-answer tokens: the model's EOS and, for chat models, the
    end-of-turn token if the tokenizer knows one."""
    ids = set()
    try:
        ids.add(int(model.token_eos()))
    except Exception:
        pass
    for marker in ("<|im_end|>", "<|eot_id|>", "<|end|>"):
        try:
            t = model.tokenize(marker.encode("utf-8"), add_bos=False, special=True)
            if len(t) == 1:
                ids.add(int(t[0]))
        except Exception:
            pass
    return ids


def confidence_from(resp: dict) -> Optional[float]:
    """Geometric-mean token probability from a llama.cpp response, or None.

    Chat responses carry `choices[0].logprobs.content[].logprob`; completion
    responses `choices[0].logprobs.token_logprobs`. Both are natural logs.
    """
    try:
        lp = (resp.get("choices") or [{}])[0].get("logprobs") or {}
        vals = None
        if isinstance(lp.get("content"), list):
            vals = [t.get("logprob") for t in lp["content"] if isinstance(t, dict)]
        elif isinstance(lp.get("token_logprobs"), list):
            vals = lp["token_logprobs"]
        vals = [float(v) for v in (vals or []) if v is not None]
        if not vals:
            return None
        import math
        return max(0.0, min(1.0, math.exp(sum(vals) / len(vals))))
    except Exception:
        return None


def spec_for(model_id: str, catalog: Optional[Dict[str, ModelSpec]] = None) -> Optional[ModelSpec]:
    cat = catalog if catalog is not None else load_catalog()
    return cat.get(model_id)
