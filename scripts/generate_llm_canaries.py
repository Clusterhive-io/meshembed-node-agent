#!/usr/bin/env python3
"""Generate canary ground truth on the pinned artifact.

docs/LLM_INFERENCE_DESIGN.md par.5.1. This runs where the RUNTIME and the
WEIGHTS are -- a node, or any box with llama-cpp-python and the verified GGUF.
It never runs on the backend, which has neither and should not acquire them.

Why it must be this way, and not a hand-written expected answer: the reference
is only meaningful if it is what an honest node on this fleet generation
actually produces. The embedding canaries learned this the expensive way --
references computed with a different library version put honest nodes in the
warn band, and warn carries a penalty. So the reference is generated, here, by
the same code path a real subjob takes.

    python generate_llm_canaries.py --model meshembed/qwen2.5-0.5b-instruct-q4 \\
        > canaries.json

Then, on the backend:

    python -m scripts.load_llm_canaries --file canaries.json

The prompts are deliberately boring, short and deterministic: a canary is not a
benchmark. It has to be cheap enough to run often, and it has to have one
obvious answer so that a disagreement means the node, not the question.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from meshembed_node import llm  # noqa: E402


# Shapes drawn from the workloads this line targets: classification, field
# extraction, short factual recall. Each has one defensible answer, so a
# disagreement is about the node rather than about the prompt.
PROMPTS = [
    "Classify this as INVOICE, CONTRACT or LETTER. Reply with one word only. "
    "Text: Amount due 4,300 EUR. Payment terms 30 days. VAT 21%.",

    "Classify this as INVOICE, CONTRACT or LETTER. Reply with one word only. "
    "Text: The parties agree to the terms set out in schedule 1 for a term of "
    "24 months.",

    "Reply with one short sentence. The lease between Acme SL and Brown Ltd "
    "runs until 31 March 2027. When does it end?",

    "Return JSON with keys seller and buyer, nothing else. "
    "Text: sale from Nordwind GmbH to Vega SA.",

    "Reply with one word. Is 'Lisbon' a city or a country?",

    "Extract the total. Reply with the number only. "
    "Text: subtotal 1,200.00 EUR, VAT 252.00 EUR, total 1,452.00 EUR.",
]

# Pinned with the reference and stored beside it. A canary evaluated at
# different settings than it was generated with would fail an honest node for
# our own bookkeeping, so these travel together and the backend never
# substitutes its own defaults.
PARAMS = {"max_tokens": 64, "temperature": 0.0, "seed": 20260908}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model", required=True, help="catalog model_id")
    ap.add_argument("--repeat", type=int, default=2,
                    help="generations per prompt; all must agree or the prompt "
                         "is dropped as non-reproducible on this build")
    args = ap.parse_args()

    spec = llm.spec_for(args.model)
    if spec is None:
        print(f"model not in the catalog: {args.model}", file=sys.stderr)
        return 1
    if llm.ensure_model(spec) is None:
        print(f"artifact unavailable or failed verification: {args.model}",
              file=sys.stderr)
        return 1

    runner = llm.LlamaRunner()
    out = []
    for prompt in PROMPTS:
        item = {"custom_id": "seed", "messages": [{"role": "user", "content": prompt}]}
        texts = []
        for _ in range(max(1, args.repeat)):
            texts.append(runner.generate(spec, item, PARAMS).text)

        # A prompt whose own output is not stable on THIS build can never be a
        # canary: it would fail honest nodes at random. Drop it here, loudly,
        # rather than let it into the pool and discover it as a phantom fraud
        # signal weeks later.
        if len(set(texts)) != 1:
            print(f"DROPPED (not reproducible on this build): {prompt[:60]}...",
                  file=sys.stderr)
            continue

        out.append({
            "model": args.model,
            "model_sha": spec.sha256,
            "prompt": prompt,
            "ground_truth_text": texts[0],
            "model_params": PARAMS,
        })

    if not out:
        print("no reproducible prompts -- refusing to emit an empty pool",
              file=sys.stderr)
        return 1

    json.dump({"canaries": out}, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
    print(f"generated {len(out)} of {len(PROMPTS)} prompts", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
