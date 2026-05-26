
# 🛡️ DFIR-Guardrail
**Defending AI-Assisted Triage from Indirect Prompt Injections**

![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)
![Ollama](https://img.shields.io/badge/Ollama-Local_LLM-black.svg)
![Environment](https://img.shields.io/badge/Environment-Google_Colab-F9AB00.svg)

**DFIR-Guardrail** is a multi-agent, purple team security lab designed to simulate and defend against a critical emerging threat: indirect prompt injections hidden within standard digital forensics artifacts (such as Amcache, Prefetch, and Event Logs). 

As Security Operations Centers (SOC) increasingly rely on Large Language Models to parse triage data from endpoint agents, threat actors can weaponize system artifacts to blind analysts, manipulate timelines, or force AI models to drop critical Indicators of Compromise (IOCs). This pipeline implements a zero-trust AI architecture to sanitize forensic data before it reaches the primary analysis model.

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
* **Guided Chain-of-Thought (CoT):** Forces the model to mentally decode obfuscated strings and write a brief `<analysis>` block before rendering a decision, virtually eliminating False Negatives.
* **XML-Style Output Tagging:** Parses the LLM's final classification using strict regex extraction on `<result>` tags, rendering the Python pipeline immune to runaway generation or formatting hallucinations.

### ⚙️ Pipeline (`src/pipeline.py`)
The orchestrator that manages local LLM inference. It supports two modes of execution:
*   **Operational Mode:** Extracts high-risk fields from parsed Windows forensic logs (KAPE/Velociraptor JSON exports) and scans them for indirect prompt injections, outputting a structured JSON analyst report.
*   **Simulation Mode:** Executes a synthetic Red/Blue team evaluation, generating poisoned artifacts and measuring False Positive Rate (FPR) and False Negative Rate (FNR) metrics.

---

## 🚀 Execution & Deployment

This architecture is specifically engineered to operate efficiently within highly constrained hardware environments, including headless servers and cloud notebooks limited to a single 16GB VRAM GPU (e.g., NVIDIA T4).

### Running in Google Colab (Recommended)
The provided notebook automates the entire local LLM infrastructure setup within the Colab VM.

1. Open `colab_demo.ipynb` in Google Colab.
2. Select **Runtime** > **Run All**.
3. The notebook will automatically:
   * Install native GPU dependencies (`pciutils`, `lshw`).
   * Download and launch the **Ollama** daemon as a background subprocess.
   * Pull the highly efficient model (e.g., Microsoft Phi-3).
   * Warm up the GPU to absorb cold-start penalties and execute the evaluation pipeline.

### Running Locally
Ensure Ollama is installed and running locally (`localhost:11434`), and that you have pulled your target model (e.g. `phi3`):
```bash
ollama pull phi3
```

Clone the repository and install requirements:
```bash
# Clone the repository
git clone https://github.com/YedidyaBarGad/DFIR-Guardrail.git
cd DFIR-Guardrail

# Install requirements
pip install -r requirements.txt
```

You can execute the pipeline in one of two modes:

#### 1. Simulation Mode (Red Team Testing)
Runs the end-to-end evaluation using a generated synthetic dataset to compute detection accuracy metrics.
```bash
python -m src.pipeline
```

#### 2. Operational Mode (Scan Real Artifacts)
Scans real Windows forensic artifacts parsed from tools like **KAPE** or **Velociraptor** (in JSON format) and generates a structured threat report.
```bash
python -m src.pipeline --input_dir /path/to/forensics/json --output_dir /path/to/output/reports
```

**CLI Options:**
*   `--input_dir`: Path to the directory containing parsed JSON forensic artifacts for analysis.
*   `--output_dir`: Path where the structured scan report (`guardrail_analysis.json`) will be saved.

---

## 📊 Performance Metrics

By combining a **Hybrid Filtering Approach** with LLM classification, the pipeline achieves high speed and zero-trust security even without local GPU acceleration. 

### ⚡ 5,000-Artifact Scale Benchmark
To test the pipeline's operational performance, we ran a scan of **5,000 Windows forensic artifacts** containing 4,950 benign items and 50 highly obfuscated prompt injections (Base64, Hex, zero-width spaces, and roleplay overrides):
*   **Detection Accuracy:** 100% of prompt injections detected.
*   **Filter Bypass Rate:** 100% of benign artifacts (4,950/4,950) successfully bypassed the LLM.
*   **Scan Duration:** **204.37 seconds** (averaging 4s per failed localhost network timeout on the 50 suspicious items).
*   **Performance Optimization:** Without hybrid filtering, a sequential LLM scan on the same dataset would take **5.5 hours**. The pre-filtering mechanism achieved a **98.9% reduction in execution time**.


---

## 🛡️ Production Readiness Assessment & Disclaimer
This project is a **Proof of Concept (PoC)** designed for security research and simulation. It is **not** currently suitable for enterprise production deployment in a Security Operations Center (SOC).

### 🚀 Completed Hardening
*   **Fail-Closed Model:** Network timeouts or inference failures (returning `-1`) fail closed, quarantining the event as a potential bypass rather than failing open.
*   **Hybrid Pre-Filtering:** Removal of zero-width spaces (`\u200B`) and programmatic decoding (Base64/Hex) before LLM routing, bypassing the LLM for 99% of benign logs (yielding a 98.9% throughput speedup in benchmarking).

### 🔍 Remaining Production Gaps
*   **Sequential Bottleneck:** Lacks async concurrency and batch processing (e.g., vLLM serving). Sequential HTTP calls build latency queues on high-volume endpoints.
*   **Prompt Robustness:** Small Language Models (SLMs) remain vulnerable to advanced jailbreaking techniques (cognitive load, roleplay overrides).
*   **Schema & Format Ingestion:** Hardcoded heuristic field filtering; lacks standardized schema normalizations (e.g., Elastic Common Schema) or multi-format ingestion (CSV, EVTX, XML).
*   **Operations & Observability:** Configuration is hardcoded; lacks structured JSON logging (for Splunk/SIEM ingestion) and Prometheus monitoring metrics.
