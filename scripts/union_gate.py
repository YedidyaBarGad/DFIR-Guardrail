"""Offline "union" gate: flag an artifact if the pre-filter OR the model-only run flags it.

Uses stored runs only (no LLM call). It answers: if the model saw every artifact and the
pre-filter's flags were kept, how do FNR and FPR change vs. the shipped gate?

    python -m scripts.union_gate            # needs results/prefilter_only/*_embedder_on.json
"""

import json
import os
from collections import defaultdict

R = "results"
SETS = {
    "synthetic": (
        None,  # seed-42 generator, labels come from the run files
        "prefilter_only/synthetic_1000_embedder_on.json",
        "ablation_4096/runs/synthetic_{cond}_{i}/guardrail_simulation.json",
        ("prefilter_on", "model_only"),
    ),
    "external": (
        "data/external.json",
        "prefilter_only/external_embedder_on.json",
        "external/runs/external_{cond}_{i}/guardrail_simulation.json",
        ("prefilter_on", "model_only"),
    ),
}


def flagged(run_path):
    """Per-item flag from a stored run (errors count as flagged, as in compute_metrics)."""
    d = json.load(open(run_path, encoding="utf-8"))
    out = {}
    for f in d["findings"]:
        out[f["id"] - 1] = (
            int(not f["verdict"].startswith("Safe")),
            int(f["ground_truth"] == "Malicious"),
        )
    return out


def rates(flags, labels, idx=None):
    idx = range(len(labels)) if idx is None else idx
    pos = [i for i in idx if labels[i]]
    neg = [i for i in idx if not labels[i]]
    fnr = sum(1 for i in pos if not flags[i]) / len(pos) if pos else float("nan")
    fpr = sum(1 for i in neg if flags[i]) / len(neg) if neg else float("nan")
    return fnr, fpr


def main():
    rows = []
    for name, (ds, pf_path, run_tmpl, conds) in SETS.items():
        pf = json.load(open(os.path.join(R, pf_path), encoding="utf-8"))["flags"]
        sources = None
        if ds:
            data = json.load(open(ds, encoding="utf-8"))
            sources = [d.get("source", "") for d in data]
        per = defaultdict(list)
        for i in (1, 2, 3):
            pipe = flagged(os.path.join(R, run_tmpl.format(cond="prefilter_on", i=i)))
            model = flagged(os.path.join(R, run_tmpl.format(cond="model_only", i=i)))
            labels = [pipe[k][1] for k in range(len(pf))]
            pipe_f = [pipe[k][0] for k in range(len(pf))]
            model_f = [model[k][0] for k in range(len(pf))]
            union = [int(a or b) for a, b in zip(pf, model_f)]
            stray = sum(1 for p, g in zip(pipe_f, pf) if p and not g)
            for label, fl in (
                ("pre-filter only", pf),
                ("pre-filter + LLM (shipped)", pipe_f),
                ("LLM only", model_f),
                ("union (pre-filter OR LLM-only)", union),
            ):
                per[label].append(rates(fl, labels))
            per["_stray"].append(stray)
            if sources:
                for src in sorted({s for s, y in zip(sources, labels) if y}):
                    idx = [
                        k for k, s in enumerate(sources) if s == src or not labels[k]
                    ]
                    for label, fl in (
                        ("pre-filter only", pf),
                        ("shipped", pipe_f),
                        ("LLM only", model_f),
                        ("union", union),
                    ):
                        per[f"src:{src}:{label}"].append(
                            rates(fl, labels, [k for k in idx if labels[k]])
                        )
        print(f"\n== {name} ==")
        print(
            f"pipeline flags not in current pre-filter flags (per run): {per.pop('_stray')}"
        )
        for label, v in per.items():
            fnr = [x[0] for x in v]
            fpr = [x[1] for x in v]
            f = f"FNR {min(fnr):.1%}-{max(fnr):.1%}"
            if not label.startswith("src:"):
                f += f"  FPR {min(fpr):.1%}-{max(fpr):.1%}"
            print(f"{label:<45} {f}")


if __name__ == "__main__":
    main()
