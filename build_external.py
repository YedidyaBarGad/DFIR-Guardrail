"""Build data/external.json: third-party payloads (LLMail-Inject, Lakera Gandalf) in
third-party benign process events (WinLOLBIN-GT). Output is {id, artifact, is_malicious}.

Inputs (download separately, see README "External dataset"):
  --benign   winlolbin_gt_sample_unprocessed_benign_500_lines.csv (Zenodo 20533434, CC-BY-4.0)
  --gandalf  Lakera/gandalf_ignore_instructions parquet files (MIT)
  --llmail   llmail-inject labelled_unique_submissions_phase1.json, possibly truncated (MIT)
"""

import argparse
import csv
import json
import random
import re

ap = argparse.ArgumentParser()
ap.add_argument("--benign", required=True)
ap.add_argument("--gandalf", nargs="+", required=True)
ap.add_argument("--llmail", required=True)
ap.add_argument("--out", default="data/external.json")
ap.add_argument("--n_each", type=int, default=125)
a = ap.parse_args()
rng = random.Random(42)

# Sensor-like fields only: the CSV also has attack_rationale/attack_outcome prose and label.
KEEP = {
    "process_name": "FileName",
    "process_path": "ExecutablePath",
    "command_line": "CommandLine",
    "parent_command_line": "ParentCommandLine",
}
with open(a.benign, newline="", encoding="utf-8") as f:
    rows = [r for r in csv.DictReader(f) if r["label"] == "0"]
benign = [{v: r[k] for k, v in KEEP.items()} for r in rows]
rng.shuffle(benign)


def llmail_texts(path):
    """Stream complete entries from a possibly truncated {text: {attack_attempt, ...}} JSON."""
    s = open(path, encoding="utf-8").read()
    dec, i, out = json.JSONDecoder(), s.index("{") + 1, []
    while True:
        try:
            k, i = dec.raw_decode(s, re.compile(r"\s*,?\s*").match(s, i).end())
            i = re.compile(r"\s*:\s*").match(s, i).end()
            v, i = dec.raw_decode(s, i)
        except (ValueError, AttributeError):
            return out  # reached the truncation point
        if v.get("attack_attempt") == "True":
            out.append(k)


import pyarrow.parquet as pq  # noqa: E402

gandalf = sorted(
    {t for p in a.gandalf for t in pq.read_table(p).column("text").to_pylist()}
)
llmail = sorted(set(llmail_texts(a.llmail)))
print(f"pool: gandalf={len(gandalf)} llmail={len(llmail)} benign={len(benign)}")
payloads = [("gandalf", p) for p in rng.sample(gandalf, a.n_each)] + [
    ("llmail", p) for p in rng.sample(llmail, a.n_each)
]
assert len(payloads) <= len(benign) // 2, "need disjoint clean and carrier rows"
carriers, clean = benign[: len(payloads)], benign[len(payloads) :]

data = []
for (src, payload), art in zip(payloads, carriers):
    field = rng.choice(["CommandLine", "ParentCommandLine"])
    art = dict(art)
    art[field] = rng.choice([f"{art[field]} {payload}", f"{payload} {art[field]}"])
    data.append({"artifact": art, "is_malicious": True, "source": src})
data += [
    {"artifact": r, "is_malicious": False, "source": "winlolbin_gt"} for r in clean
]
rng.shuffle(data)
for i, d in enumerate(data):
    d["id"] = i
json.dump(data, open(a.out, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
print(f"wrote {len(data)} ({sum(d['is_malicious'] for d in data)} poisoned) to {a.out}")
