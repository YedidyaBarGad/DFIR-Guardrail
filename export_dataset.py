"""Dump the seeded synthetic dataset as per-artifact JSON (ops-mode input) + labels.json."""

import argparse
import json
from pathlib import Path

from src.red_team import RedTeamPoisoner

ap = argparse.ArgumentParser()
ap.add_argument("--out", default="synthetic_dfir")
ap.add_argument("--num_samples", type=int, default=500)
ap.add_argument("--poison_ratio", type=float, default=0.2)
a = ap.parse_args()

out = Path(a.out)
out.mkdir(exist_ok=True)
data = RedTeamPoisoner().generate_dataset(a.num_samples, a.poison_ratio)
for d in data:
    (out / f"artifact_{d['id']}.json").write_text(json.dumps(d["artifact"], indent=2))
(out / "labels.json").write_text(json.dumps({d["id"]: d["is_malicious"] for d in data}))
print(f"wrote {len(data)} artifacts to {out}")
