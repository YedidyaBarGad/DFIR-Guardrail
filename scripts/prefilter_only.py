"""Score the pre-filter alone (no LLM) with the embedder on or off, and save per-item flags.

    python -m scripts.prefilter_only --dataset data/external.json --embedder off
    python -m scripts.prefilter_only --synthetic 1000 --embedder on

The full-pipeline runs in results/ used embedder=on, so the "pre-filter only" rows in the
README must be reproducible in both modes. Output: results/prefilter_only/<name>_embedder_<on|off>.json
"""

import argparse
import json
import os

from src.blue_team import BlueTeamGuardrail
from src.red_team import RedTeamPoisoner


def main() -> int:
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--dataset", help="JSON list of {id, artifact, is_malicious}")
    g.add_argument(
        "--synthetic", type=int, help="seed-42 generator, N samples, 0.2 poison"
    )
    ap.add_argument("--embedder", choices=["on", "off"], required=True)
    ap.add_argument("--out_dir", default="results/prefilter_only")
    a = ap.parse_args()

    if a.dataset:
        with open(a.dataset, encoding="utf-8") as f:
            data = json.load(f)
        name = os.path.splitext(os.path.basename(a.dataset))[0]
    else:
        data = RedTeamPoisoner().generate_dataset(a.synthetic, 0.2)
        name = f"synthetic_{a.synthetic}"

    guard = BlueTeamGuardrail(enable_semantic_search=a.embedder == "on")
    if (a.embedder == "on") != (guard.embedder is not None):
        print(
            "embedder requested on but could not be loaded; refusing to mislabel the run"
        )
        return 2

    flags = [int(guard._pre_filter_and_clean(d["artifact"])[0]) for d in data]
    labels = [int(bool(d["is_malicious"])) for d in data]
    tp = sum(f and y for f, y in zip(flags, labels))
    fp = sum(f and not y for f, y in zip(flags, labels))
    pos, neg = sum(labels), len(labels) - sum(labels)
    summary = {
        "dataset": name,
        "embedder": a.embedder,
        "n": len(data),
        "TP": tp,
        "FN": pos - tp,
        "FP": fp,
        "TN": neg - fp,
        "FNR": (pos - tp) / pos if pos else 0.0,
        "FPR": fp / neg if neg else 0.0,
        "flags": flags,  # index = dataset order
    }
    os.makedirs(a.out_dir, exist_ok=True)
    path = os.path.join(a.out_dir, f"{name}_embedder_{a.embedder}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(summary, f)
    print({k: v for k, v in summary.items() if k != "flags"}, "->", path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
