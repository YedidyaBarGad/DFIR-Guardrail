"""Held-out inputs for scripts/attack_success.py, from data the gate was not designed on.

  carriers: WinLOLBIN-GT malicious process events (label=1, Zenodo 20533434, CC-BY-4.0)
  payloads: Lakera Gandalf test split + LLMail-Inject phase 2 (both MIT); anything already
            in --exclude (data/external.json used Gandalf and LLMail phase 1) is skipped

    python -m scripts.build_attack_inputs --malicious mal.csv --gandalf test.parquet \
        --llmail phase2.json --exclude data/external.json --out_dir data/attack
"""

import argparse
import csv
import json
import os
import random

from build_external import KEEP, llmail_texts, seen_text


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--malicious", required=True)
    ap.add_argument("--gandalf", nargs="+", required=True)
    ap.add_argument("--llmail", required=True)
    ap.add_argument("--exclude", nargs="*", default=["data/external.json"])
    ap.add_argument("--n_carriers", type=int, default=25)
    ap.add_argument("--n_each", type=int, default=30)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out_dir", default="data/attack")
    a = ap.parse_args()
    rng = random.Random(a.seed)
    seen = seen_text(a.exclude)

    with open(a.malicious, newline="", encoding="utf-8") as f:
        rows = [r for r in csv.DictReader(f) if r["label"] == "1"]
    by_cmd = {r["command_line"]: r for r in rows if r["command_line"].strip()}
    carriers = [{v: r[k] for k, v in KEEP.items()} for r in by_cmd.values()]
    carriers = rng.sample(sorted(carriers, key=json.dumps), a.n_carriers)

    import pyarrow.parquet as pq

    gandalf = sorted(
        {t for p in a.gandalf for t in pq.read_table(p).column("text").to_pylist()}
    )
    llmail = sorted(set(llmail_texts(a.llmail)))
    gandalf = [t for t in gandalf if t.strip() not in seen]
    llmail = [t for t in llmail if t.strip() not in seen]
    print(f"pool: carriers={len(by_cmd)} gandalf={len(gandalf)} llmail={len(llmail)}")
    picked = [("gandalf", p) for p in rng.sample(gandalf, a.n_each)] + [
        ("llmail", p) for p in rng.sample(llmail, a.n_each)
    ]

    os.makedirs(a.out_dir, exist_ok=True)
    out = lambda name, obj: json.dump(  # noqa: E731
        obj,
        open(os.path.join(a.out_dir, name), "w", encoding="utf-8"),
        indent=1,
        ensure_ascii=False,
    )
    out("carriers.json", carriers)
    out("payloads.json", [p for _, p in picked])
    out("payload_sources.json", [s for s, _ in picked])  # aligned with payloads.json
    print(f"wrote {len(carriers)} carriers, {len(picked)} payloads to {a.out_dir}")


if __name__ == "__main__":
    main()
