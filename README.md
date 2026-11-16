# 🛡️ DFIR-Guardrail
>
> Detecting indirect prompt injections in forensic artifacts before AI-assisted triage

![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)
![Ollama](https://img.shields.io/badge/Ollama-Local_LLM-black.svg)
![Environment](https://img.shields.io/badge/Environment-Google_Colab-F9AB00.svg)

If a SOC feeds alert or artifact data to an LLM, an attacker who controls one string in that data, like a command line or a file description, gets to talk to the model. **DFIR-Guardrail** is a purple team lab for that problem:
* A red-team generator hides prompt injections in forensic artifacts (Amcache, Prefetch, event-log fields).
* A blue-team guardrail flags suspicious artifacts before they reach the analysis model, and quarantines them for a human. It does not rewrite or sanitize.

> **Status:** research prototype, not a production control. Small datasets, one small local model (`phi3:mini`). No real or client data is in this repository.

## 📊 Headline results

Measured on data the guardrail was not designed on (frozen before the run, [protocol](docs/EVALUATION.md)):

| Test | Without guardrail | With guardrail (gate v2) |
|---|---|---|
| **Attack success:** a third-party payload flips the analyst LLM's verdict on a malicious event to "benign" | 18.2% | 2.6% |
| **Detection on `hard.json`** (132 evasive payloads, 368 benign traps) | model alone: 32% missed, 68% false alarms | 58% missed, 9% false alarms |

Methods, all other runs and caveats: **[docs/RESULTS.md](docs/RESULTS.md)**.

## 🔎 What I found

1. **Measurements lie unless you check where they come from.** My filter missed 1.6% of my own synthetic attacks, 53% of third-party ones, and 81% of a hand-built evasive set. When every model request failed, fail-closed scoring reported a perfect 0% miss rate. Ask whether a detection rate was measured on attacks the builders never saw, and watch the error rate as closely.
2. **Encoding tricks are easy; plain language is hard.** Base64, hex and invisible characters are decoded by code and never caused a persistent miss. Plain paraphrases, other languages, homoglyphs and instructions buried in filler did.
3. **Wiring matters as much as the parts.** The first pipeline needed the filter and the LLM to agree, so it did worse than either alone. Gate v2 lets precise rules decide alone and sends prose to the model. That cut misses from 62% to 22% on dev data. On the test set it still missed 58%, mostly payloads its router never forwards to the model.
4. **Small models catch a lot but cry wolf.** `phi3:mini` alone flags 41–68% of harmless events. It's useful for triage, not for final verdicts.
5. **What counts is whether the analyst can be steered.** Almost one in five third-party payloads flipped the analyst's verdict. The guardrail cut that to 1 in 40, mostly by quarantining poisoned events for a human. Treat it as one layer: have the model extract facts rather than interpret free text, and don't let a model's "benign" close an alert alone.

## 🏗️ How it works

```text
gate v2 (default)
artifact ──► high-precision rule hit ──────────────────────► flagged (1), no LLM veto
         ├─► prose field or weak signal ─► LLM classifier ─► 0 / 1
         │                                     └─ timeout/error ─► flagged (fail closed)
         └─► neither ──────────────────────────────────────► benign (0)
```

Rules for override phrasing and delimiter tags had no false positives on dev data, so they decide alone. Any field that reads like English prose goes to the LLM classifier, which runs locally through Ollama and fails closed. `--legacy_gate` restores the original filter-then-LLM pipeline. Components and CLI options: [docs/DESIGN.md](docs/DESIGN.md).

## 🚀 Running it

Needs a GPU with about 16 GB, such as a Colab T4. On CPU, requests time out and timeouts are scored as detections, which makes results invalid.

**Colab:** open `notebooks/colab_demo.ipynb` and choose Runtime > Run All.

**Locally:** install and start Ollama, then:

```bash
ollama pull phi3:mini
git clone https://github.com/YedidyaBarGad/DFIR-Guardrail.git
cd DFIR-Guardrail
pip install -r requirements.txt
```

```bash
python -m src.pipeline --mode sim --num_samples 1000 --poison_ratio 0.2
```

```bash
python -m src.pipeline --mode sim --dataset_file data/hard.json
```

**Reproducing results:**

| Notebook | Produces |
|---|---|
| `notebooks/colab_hard_eval.ipynb` | `hard.json` test run (`results/hard/`) |
| `notebooks/attack_success_eval.ipynb` | attack success (`results/attack_success/`) |
| `notebooks/ablation_eval.ipynb` | synthetic ablation (`results/ablation_4096/`) |
| `notebooks/external_eval.ipynb` | external dataset (`results/external/`) |
| `notebooks/padding_probe.ipynb` | padding probe (`results/padding_probe.csv`) |

The `hard.json` and attack-success notebooks clone the repo. They refuse to run if `src/` differs from the gate v2 freeze.

## ⚠️ Main limitations

* One small model and one analyst prompt; three repeats on the same data, so the ranges understate variance.
* Benign data is synthetic or lab-generated. Real SOC feeds have far fewer attacks, so false alarms cost more than these numbers show.
* The guard is itself an LLM and can be jailbroken. Adaptive attackers are not tested.
* `src/parsers/` and `--mode ops` are unit-tested only, never run on real forensic exports.

Full list: [docs/RESULTS.md](docs/RESULTS.md#limitations-of-the-evaluation).

## 📁 Layout

* `src/`: red team, blue team, pipeline, parsers. `tests/`: tests. `scripts/`: evaluation scripts.
* `data/`: `hard.json` (hand-built evasive set), `external.json` (built by `build_external.py`).
* `results/`: raw CSVs, run reports and logs behind every number.
* `docs/`: [RESULTS](docs/RESULTS.md), [DESIGN](docs/DESIGN.md), [EVALUATION](docs/EVALUATION.md) (frozen test protocol).
* Licence: code is MIT (`LICENSE`). WinLOLBIN-GT is CC-BY-4.0 (Zenodo 20533434); Gandalf and LLMail-Inject are MIT. `data/external.json` redistributes sampled rows from them; check each source's terms before reusing.
