
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
The orchestrator that runs the localized multi-model inference, manages batch processing, and computes strict False Positive Rate (FPR) and False Negative Rate (FNR) metrics.

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
If you have Ollama installed and running locally (`localhost:11434`), you can execute the pipeline directly:

```bash
# Clone the repository
git clone [https://github.com/YedidyaBarGad/DFIR-Guardrail.git](https://github.com/YedidyaBarGad/DFIR-Guardrail.git)
cd DFIR-Guardrail

# Install requirements
pip install -r requirements.txt

# Execute the pipeline
PYTHONPATH=. python src/pipeline.py

```

---

## 📊 Performance Metrics

By leveraging Few-Shot prompting anchored with complex system baseline data, the current architecture successfully filters out standard OS noise while identifying obfuscated APT payloads.

> **Target Baseline Achievement:** > * **False Positive Rate (FPR):** 0.00%
> * **False Negative Rate (FNR):** 0.00%
> * **Parsing Errors:** 0
> 
> 

