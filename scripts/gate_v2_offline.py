"""Offline estimate of the v2 gate from stored model-only runs (no LLM call).

v2 decision: rule tier -> flagged; model tier -> the stored model-only verdict; clean -> 0.
The model-only runs sent every artifact to the LLM with the same cleaned input, so this is
the v2 pipeline up to model non-determinism. The embedder is off here; with it on, the gate
can only route more artifacts to the model.

    python -m scripts.gate_v2_offline
"""

import asyncio
import json
import os

from scripts.union_gate import R, flagged, rates
from src.blue_team import BlueTeamGuardrail
from src.red_team import RedTeamPoisoner

RUNS = {
    "synthetic": "ablation_4096/runs/synthetic_{cond}_{i}/guardrail_simulation.json",
    "external": "external/runs/external_{cond}_{i}/guardrail_simulation.json",
}


def load(name):
    if name == "synthetic":
        return RedTeamPoisoner(seed=42).generate_dataset(1000, 0.2)
    return json.load(open(f"data/{name}.json", encoding="utf-8"))


def main():
    g = BlueTeamGuardrail(enable_semantic_search=False)
    for name in ("synthetic", "external", "hard"):
        data = load(name)
        labels = [int(d["is_malicious"]) for d in data]
        tiers = [g._route(d["artifact"])[0] for d in data]
        print(f"\n== {name} ({sum(labels)} poisoned / {len(labels)}) ==")
        for t in ("rule", "model", "clean"):
            pos = sum(1 for x, y in zip(tiers, labels) if x == t and y)
            neg = sum(1 for x, y in zip(tiers, labels) if x == t and not y)
            print(f"  tier {t:<5} poisoned {pos:>4}  benign {neg:>4}")
        floor = sum(1 for x, y in zip(tiers, labels) if x == "clean" and y)
        print(
            f"  miss floor (poisoned never seen by rule or model): {floor / sum(labels):.1%}"
        )
        if name not in RUNS:
            print("  no stored model-only runs: gate only")
            continue
        for i in (1, 2, 3):
            model = flagged(os.path.join(R, RUNS[name].format(cond="model_only", i=i)))
            assert [model[k][1] for k in range(len(data))] == labels, "dataset drift"
            v2 = [
                int(t == "rule" or (t == "model" and model[k][0]))
                for k, t in enumerate(tiers)
            ]
            fnr, fpr = rates(v2, labels)
            print(f"  v2 estimate, model-only run {i}: FNR {fnr:.1%}  FPR {fpr:.1%}")
            if name == "external":
                for src in ("gandalf", "llmail"):
                    idx = [k for k, d in enumerate(data) if d["source"] == src]
                    print(f"      {src:<8} FNR {rates(v2, labels, idx)[0]:.1%}")
    asyncio.run(g.close())


if __name__ == "__main__":
    main()
