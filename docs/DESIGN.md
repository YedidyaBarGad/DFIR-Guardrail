# Design

Component details. The overview and gate diagram are in the [README](../README.md).

## 🔴 Red team (`src/red_team.py`)

Generates a synthetic dataset of Amcache/Prefetch-style artifacts and injects payloads into string fields (`FileDescription`, `CommandLine`, `ExecutablePath`, ...). Techniques: plain, Base64, hex, zero-width spacing, cognitive-load padding, role-play override, delimiter smuggling and nested decoy objects. A fixed RNG seed (default 42) makes the dataset reproducible; LLM output is not (no Ollama seed is set).

## 🔵 Blue team (`src/blue_team.py`)

* **Heuristic pre-filter (gate):** Shannon-entropy checks, Base64/hex decoding of suspicious tokens, cognitive-load and role-play-override detectors, and, if `sentence-transformers` is installed and the model loads, cosine similarity against known injection phrasings. By default only artifacts the pre-filter marks suspicious go to the LLM; everything else is labelled benign without LLM review. `--no_prefilter` sends every artifact to the LLM to measure the model alone.
* **LLM classifier:** the system prompt tells the model it is a security classifier analyzing hostile text; untrusted artifact text goes in the user role. The model returns `{"analysis": "...", "result": 0|1}`. Deterministic decoding supplies decoded text; the model is not relied on to decode Base64.
* **Output format:** Ollama's `format: "json"` guarantees valid JSON but not the schema, and `phi3:mini` sometimes returns other keys (e.g. `"status": "SECURE"`). A response without `result` in {0, 1} is an error and fails closed. `LLM_STRUCTURED_OUTPUT=1` switches to a JSON-schema `format` that enforces the two keys; it did not change verdicts in the padding probe.
* **Fail-closed and bounded concurrency:** timeouts and inference errors count as flagged. An `asyncio.Semaphore` with HTTPX connection pooling sends several requests at once (set `OLLAMA_NUM_PARALLEL` on the daemon to match `--concurrency`); a circuit breaker fails fast on a hung endpoint.

## ⚙️ Pipeline (`src/pipeline.py`)

* **`sim`:** generates (or loads, with `--dataset_file`) poisoned and benign artifacts and reports FPR and FNR.
* **`compare`:** times the sequential scanner against the bounded-concurrency one.

Config comes from environment variables (`src/config.py`); logs are JSON lines (`src/logger.py`).

The project scores labelled datasets only. An earlier `ops` mode with parsers for forensic exports (EVTX, CSV, XML, JSON) and ECS normalization was removed because it was never run on real data; see git history before the removal commit.

## CLI options

| Option | Meaning |
|---|---|
| `--mode` | `sim` (default) or `compare` |
| `--concurrency` | simultaneous LLM requests (default from `src/config.py`); pair with `OLLAMA_NUM_PARALLEL` |
| `--output_dir` | where `guardrail_simulation.json` is written |
| `--num_samples`, `--poison_ratio` | synthetic dataset size (default 50) and poisoned share (default 0.2) |
| `--dataset_file` | JSON list of `{id, artifact, is_malicious}` to score instead of generating |
| `--no_prefilter` | send every artifact to the LLM |
| `--legacy_gate` | pre-v2 gate (pre-filter gates the LLM, LLM may veto); reproduces the published runs |
