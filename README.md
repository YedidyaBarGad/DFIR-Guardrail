# 🛡️ DFIR-Guardrail
>
> Defending AI-Assisted Triage from Indirect Prompt Injections

![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)
![Ollama](https://img.shields.io/badge/Ollama-Local_LLM-black.svg)
![Environment](https://img.shields.io/badge/Environment-Google_Colab-F9AB00.svg)

**DFIR-Guardrail** is a multi-agent, purple team security lab designed to simulate and defend against a critical emerging threat: indirect prompt injections hidden within standard digital forensics artifacts (such as Amcache, Prefetch, and Event Logs).

As Security Operations Centers (SOC) increasingly rely on Large Language Models to parse triage data from endpoint agents, threat actors can weaponize system artifacts to blind analysts, manipulate timelines, or force AI models to drop critical Indicators of Compromise (IOCs). This pipeline implements a zero-trust AI architecture to sanitize forensic data before it reaches the primary analysis model

---

## 🏗️ Architecture & Threat Model

This project operates a closed-loop validation pipeline evaluating both offensive generation and defensive interception.

### 🔴 Red Team (`src/red_team.py`)

Simulates an advanced persistent threat (APT) weaponizing the forensic collection pipeline.

* **Adversarial Payload Generation:** Injects manipulative AI instructions into naturally parsed string fields (e.g., `FileDescription`, `CommandLine`, `ExecutablePath`).
* **Dynamic Obfuscation Engine:** Bypasses basic keyword filtering by randomly encoding payloads using **Base64**, **Hexadecimal**, and **zero-width Unicode spacing (ZWOP)**.
* **Deterministic Evaluation:** Utilizes fixed RNG seeds to ensure dataset generation is perfectly reproducible across validation runs.

### 🔵 Blue Team (`src/blue_team.py`)

Acts as a high-speed Semantic Guardrail, intercepting data before it compromises the primary SOC analyst LLM.

* **Role-Play Jailbreaking:** Safely bypasses corporate alignment blocks to allow local models to natively analyze malicious text in an authorized defensive context.
* **Guided Chain-of-Thought (CoT):** Forces the model to mentally decode obfuscated strings and write a brief `<analysis>` block before rendering a decision.
* **XML-Style Output Tagging:** Parses the LLM's final classification using strict regex extraction on `<result>` tags, rendering the Python pipeline immune to runaway generation or formatting hallucinations.
* **Asynchronous Sequential Processing:** Utilizes `asyncio.Semaphore` combined with HTTPX connection pooling and explicitly tuned context windows (`num_ctx`) to securely launch highly concurrent evaluations against local LLMs.

### ⚙️ Pipeline (`src/pipeline.py`)

The orchestrator that manages local LLM inference. It supports three modes of execution:

* **Operational Mode:** Extracts high-risk fields from parsed Windows forensic logs (KAPE/Velociraptor JSON exports) and scans them for indirect prompt injections, outputting a structured JSON analyst report.
* **Simulation Mode:** Executes a synthetic Red/Blue team evaluation, generating poisoned artifacts and measuring False Positive Rate (FPR) and False Negative Rate (FNR) metrics.
* **Compare Mode:** Runs the pure Sequential Baseline against the Asynchronous Sequential framework and computes the performance speedup directly on your hardware.

---

## 🚀 Execution & Deployment

This architecture is specifically engineered to operate efficiently within highly constrained hardware environments, including headless servers and cloud notebooks limited to a single 16GB VRAM GPU (e.g., NVIDIA T4).

### Running in Google Colab (Recommended)

The provided notebook automates the entire local LLM infrastructure setup within the Colab VM.

1. Open `colab_demo.ipynb` in Google Colab.
2. Select **Runtime** > **Run All**.
3. The notebook will automatically:
   * Install native GPU dependencies (`pciutils`, `lshw`).
   * Download and launch the **Ollama** daemon with optimized VRAM splitting (`OLLAMA_NUM_PARALLEL`).
   * Pull the highly efficient model (e.g., Microsoft Phi-3).
   * Warm up the GPU to absorb cold-start penalties and execute the pipeline comparison matrix.

### Running Locally

Ensure Ollama is installed and running locally (`localhost:11434`), and that you have pulled your target model (e.g. `phi3`):

```bash
ollama pull phi3:mini
```

Clone the repository and install requirements:

```bash
# Clone the repository
git clone https://github.com/YedidyaBarGad/DFIR-Guardrail.git
cd DFIR-Guardrail
# Install requirements
pip install -r requirements.txt
```

You can execute the pipeline in various modes:

#### 1. Compare Benchmark (Speedup Testing)

Generates 1,000 synthetic artifacts and tests the pure Sequential Baseline against the optimized Async Sequential Pipeline.

```bash
python src/pipeline.py --num_samples 1000 --mode compare
```

#### 2. Simulation Mode (Red Team Testing)

Generates a synthetic dataset of forensic artifacts injected with obfuscated payloads, runs the scan, prints evaluation metrics, and saves the structured analyst report to `guardrail_simulation.json`.

```bash
python src/pipeline.py --num_samples 5000 --poison_ratio 0.01 --mode async
```

#### 3. Operational Mode (Scan Real Artifacts)

Scans real Windows forensic artifacts parsed from tools like **KAPE** or **Velociraptor** (in JSON format) and generates a structured threat report saved to `guardrail_analysis.json`.

```bash
python src/pipeline.py --input_dir /path/to/forensics/json --output_dir /path/to/output/reports
```

**CLI Options:**

* `--mode`: The execution mode for the pipeline. Choices are:
  * `sim` (Default): Synthetically generates and tests poisoned and benign artifacts.
  * `ops`: Scans a real directory of JSON forensic artifacts.
  * `compare`: Runs a pure sequential scan followed by an async sequential scan to benchmark speedup.
* `--concurrency`: The number of simultaneous connections to open against the LLM in `async` or `compare` mode (default: `3`). *Note: This must be paired with setting `OLLAMA_NUM_PARALLEL` on the Ollama daemon.*
* `--input_dir`: (Ops mode only) Path to the directory containing parsed JSON forensic artifacts for analysis.
* `--output_dir`: (Ops and Sim mode) Path where the structured scan report (`guardrail_analysis.json` or `guardrail_simulation.json`) will be saved.
* `--num_samples`: (Sim and Compare mode) Number of synthetic artifacts to generate (default: `50`).
* `--poison_ratio`: (Sim mode only) Proportion of artifacts to inject with prompt payloads, e.g., `0.2` for 20% (default: `0.2`).

---

## 📊 Performance Metrics

By combining a **Hybrid Filtering Approach** with **Asynchronous Sequential Processing**, the pipeline achieves incredibly high throughput and scale even when bottlenecked by a single GPU.

### ⚡ 1,000-Artifact Scale Benchmark (Async vs Sequential)

To test the pipeline's operational performance, we ran a direct comparison scan of **1,000 Windows forensic artifacts** containing heavily obfuscated payloads using Microsoft `phi3` on a local GPU:

```text
--- Comparison Results ---
Metric                    | Sequential Baseline  | Async Sequential    
-----------------------------------------------------------------------
Scan Time                 | 347.76             s | 149.42             s
Speedup                   | 1.00x                | 2.33               x
Total processed           | 1000                 | 1000                
True Positives            | 187                  | 189                 
True Negatives            | 806                  | 806                 
False Positives           | 0                    | 0                   
False Negatives           | 6                    | 5                   
Errors                    | 1                    | 0                   
False Positive Rate (FPR) | 0.00%                | 0.00%               
False Negative Rate (FNR) | 3.11%                | 2.58%               
```

* **Performance Optimization:** Shifting from standard sequential HTTP queries to connection-pooled Async IO with constrained context windows yielded a **2.33x Speedup** while dropping the False Negative Rate down to an incredibly low **2.58%**.

---

## 🛡️ Production Readiness Assessment & Disclaimer

This project is a **Proof of Concept (PoC)** designed for security research and simulation. It is **not** currently suitable for enterprise production deployment in a Security Operations Center (SOC).

### 🚀 Completed Hardening

* **Structured LLM Outputs & Roles:** Enforces strict JSON schemas (`{"analysis": "...", "result": X}`) and explicitly isolates system instructions from untrusted user payloads using native Chat API roles to mitigate recursive prompt injection.
* **Semantic Evasion & Entropy Detection:** Deployed `sentence-transformers` for dynamic Cosine Similarity scoring against adversarial intent, and `shannon_entropy` mathematical calculations to catch undocumented obfuscation techniques without relying on brittle regex keywords.
* **Architectural Resilience (DoS/OOM Protection):** Replaced legacy RAM-heavy JSON parsing with `ijson` streaming for infinite scale, integrated an active Circuit Breaker pattern to fast-fail hangs without timing out, and secured forensic logs via `RotatingFileHandler`.
* **Fail-Closed Model:** Network timeouts or inference failures (returning `-1`) fail closed, quarantining the event as a potential bypass rather than failing open.
* **Asynchronous Concurrency:** Eradicated the sequential HTTP bottleneck. Replaced it with asyncio Semaphores and explicitly constrained context memory targeting single-GPU saturation without OOM failures.

### 🔍 Remaining Production Gaps

* **Prompt Robustness:** Small Language Models (SLMs) remain vulnerable to advanced jailbreaking techniques (cognitive load, roleplay overrides) that mimic benign system data perfectly.
* **Schema & Format Ingestion:** Hardcoded heuristic field filtering; lacks standardized schema normalizations (e.g., Elastic Common Schema) or multi-format ingestion (CSV, EVTX, XML).
* **Operations & Observability:** Configuration is hardcoded; lacks structured JSON logging (for Splunk/SIEM ingestion) and Prometheus monitoring metrics.
