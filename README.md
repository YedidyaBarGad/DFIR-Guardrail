# DFIR-Guardrail

DFIR-Guardrail is a multi-agent purple team security lab designed to test and defend against indirect prompt injections hidden inside standard Windows digital forensics artifacts (like Amcache and Prefetch).

## Architecture

This project simulates a scenario where an analyst uses an LLM to parse forensics data. 

- **Red Team (`src/red_team.py`):** Injects adversarial prompt payloads into naturally parsed string fields (`FileDescription`, `CommandLine`, etc.) of synthetic JSON artifacts.
- **Blue Team (`src/blue_team.py`):** Acts as a Zero-Trust Guardrail. It runs a local, efficient LLM (via Ollama) to inspect the artifacts sequentially and classify them as Malicious (1) or Benign (0) before they reach the simulated analyst.
- **Pipeline (`src/pipeline.py`):** Orchestrates the generation, classification, and metrics evaluation (FPR/FNR).

## Running in Google Colab

The easiest way to run this pipeline, especially on a free T4 GPU, is using the provided Colab notebook.

1. **Open the Notebook:** Open `colab_demo.ipynb` in Google Colab.
2. **Run All:** The notebook will automatically install Ollama directly onto the Colab VM, pull the necessary model, start the daemon in the background, and execute the Python pipeline sequentially to avoid overwhelming the GPU.
