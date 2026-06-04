import time
import argparse
import os
import json
import asyncio

from src.red_team import RedTeamPoisoner
from src.blue_team import BlueTeamGuardrail

def compute_metrics(results):
    TP = TN = FP = FN = ERR = 0
    for r in results:
        t = r.get("true_label", -1)
        p = r.get("predicted_label", -1)
        if p == -1: 
            ERR += 1
            continue
        if t == 1 and p == 1: TP += 1
        elif t == 0 and p == 0: TN += 1
        elif t == 0 and p == 1: FP += 1
        elif t == 1 and p == 0: FN += 1
            
    total_benign = TN + FP
    total_malicious = TP + FN
    fpr = (FP / total_benign) if total_benign > 0 else 0.0
    fnr = (FN / total_malicious) if total_malicious > 0 else 0.0
    return {
        "Total processed": len(results),
        "True Positives": TP, "True Negatives": TN,
        "False Positives": FP, "False Negatives": FN,
        "Errors": ERR,
        "False Positive Rate (FPR)": fpr,
        "False Negative Rate (FNR)": fnr
    }

def extract_high_risk_fields(item):
    high_risk_keys = ["CommandLine", "FileDescription", "ExecutablePath", "ImagePath", "Arguments", "ParentCommandLine", "PayloadData", "Message"]
    extracted_content = {}
    for key, value in item.items():
        if any(risk_key.lower() in key.lower() for risk_key in high_risk_keys) and value:
            extracted_content[key] = value
    return extracted_content

def load_real_data(input_dir):
    dataset = []
    if not os.path.exists(input_dir): return dataset
    for filename in os.listdir(input_dir):
        if filename.endswith(".json"):
            filepath = os.path.join(input_dir, filename)
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        for idx, item in enumerate(data):
                            if isinstance(item, dict):
                                relevant_text = extract_high_risk_fields(item)
                                if relevant_text:
                                    dataset.append({"id": f"{filename}_{idx}", "artifact_source": filename, "content": relevant_text})
                    elif isinstance(data, dict):
                        relevant_text = extract_high_risk_fields(data)
                        if relevant_text:
                            dataset.append({"id": filename, "artifact_source": filename, "content": relevant_text})
            except Exception:
                pass
    return dataset

async def analyze_single(idx, item, blue_team, is_simulation):
    if is_simulation:
        artifact = item["artifact"]
        artifact_id = f"sim_{idx}"
        predicted_class = await blue_team.classify_artifact(artifact_id, artifact)
        
        result = {
            "id": item["id"],
            "true_label": 1 if item["is_malicious"] else 0,
            "predicted_label": predicted_class
        }
        source_file = "simulation"
        content = artifact
    else:
        artifact_for_model = {"Source": item["artifact_source"], "Content": item["content"]}
        artifact_id = item["id"]
        predicted_class = await blue_team.classify_artifact(artifact_id, artifact_for_model)
        
        result = None
        source_file = item["artifact_source"]
        content = item["content"]

    if predicted_class == 1:
        verdict = "Malicious (Prompt Injection Detected)"
    elif predicted_class == -1:
        verdict = "Suspicious (Inference Error / Potential Bypass)"
    else:
        verdict = "Safe (Benign)"

    report_entry = {
        "id": idx + 1,
        "verdict": verdict
    }
    
    if not is_simulation:
        report_entry["source_file"] = source_file
    else:
        report_entry["ground_truth"] = "Malicious" if item["is_malicious"] else "Benign"

    is_threat = (predicted_class == 1 or predicted_class == -1)
    if is_threat:
        report_entry["suspicious_content"] = content
        if predicted_class == -1:
            report_entry["error_detail"] = "Failed to analyze. Flagged under fail-closed."

    return result, report_entry, is_threat

async def run_guardrail_scan_async(dataset, blue_team, is_simulation=False, mode="async"):
    import tqdm.asyncio
    analyst_report = {
        "metadata": {"scan_time_seconds": 0, "total_artifacts_scanned": len(dataset), "threats_detected": 0},
        "findings": []
    }
    if is_simulation:
        analyst_report["metadata"]["metrics"] = {}

    start_time = time.time()
    
    tasks = [analyze_single(idx, item, blue_team, is_simulation) for idx, item in enumerate(dataset)]
    
    if mode == "async":
        # Run concurrently and show progress bar
        output = await tqdm.asyncio.tqdm.gather(*tasks, desc="Scanning artifacts (Async Sequential)")
    else:
        # Run purely sequentially
        import tqdm
        output = []
        for t in tqdm.tqdm(tasks, desc="Scanning artifacts (Pure Sequential)"):
            output.append(await t)
    
    results = []
    for (res, rep, is_threat) in output:
        if res: results.append(res)
        analyst_report["findings"].append(rep)
        if is_threat:
            analyst_report["metadata"]["threats_detected"] += 1
            
    elapsed = time.time() - start_time
    analyst_report["metadata"]["scan_time_seconds"] = round(elapsed, 2)
    print(f"\nScan completed in {elapsed:.2f} seconds. Throughput: {len(dataset)/elapsed:.2f} items/sec.")
    
    if is_simulation:
        metrics = compute_metrics(results)
        analyst_report["metadata"]["metrics"] = metrics
        
    return results, analyst_report

async def async_main():
    parser = argparse.ArgumentParser(description="DFIR-Guardrail Pipeline")
    parser.add_argument("--input_dir", type=str, help="Path to parsed artifacts from KAPE or Velociraptor for analysis")
    parser.add_argument("--output_dir", type=str, help="Path to save the validation results")
    parser.add_argument("--num_samples", type=int, default=50, help="Number of samples to generate for Red Team simulation")
    parser.add_argument("--poison_ratio", type=float, default=0.2, help="Poison ratio for Red Team simulation")
    parser.add_argument("--mode", type=str, default="async", choices=["async", "sequential", "compare"], help="Execution mode")
    args = parser.parse_args()

    print("--- Starting DFIR-Guardrail Pipeline ---")
    model_name = os.getenv("LLM_MODEL", "phi3:mini")
    ollama_host = os.getenv("LLM_ENDPOINT", "http://localhost:11434")
    
    blue_team = BlueTeamGuardrail(ollama_host=ollama_host, model_name=model_name)

    if args.input_dir and args.output_dir:
        dataset = load_real_data(args.input_dir)
        is_sim = False
    else:
        red_team = RedTeamPoisoner()
        dataset = red_team.generate_dataset(num_samples=args.num_samples, poison_ratio=args.poison_ratio)
        is_sim = True

    if not dataset:
        print("No valid high-risk data found.")
        return
        
    print(f"-> {'Generated' if is_sim else 'Loaded'} {len(dataset)} items containing high-risk fields.")
    
    # Warm up the LLM to load the model into VRAM and avoid skewing the timer
    print("Warming up the LLM (Loading model into VRAM)...")
    await blue_team.classify_artifact("warmup", {"Message": "Hello model, please wake up."})
    
    if args.mode == "compare":
        print("\n--- Running Pure Sequential Baseline ---")
        _, report_seq = await run_guardrail_scan_async(dataset, blue_team, is_simulation=is_sim, mode="sequential")
        print("\n--- Running Asynchronous Sequential ---")
        _, analyst_report = await run_guardrail_scan_async(dataset, blue_team, is_simulation=is_sim, mode="async")
        
        print("\n--- Comparison Results ---")
        seq_t = report_seq["metadata"]["scan_time_seconds"]
        async_t = analyst_report["metadata"]["scan_time_seconds"]
        
        print(f"{'Metric':<25} | {'Sequential Baseline':<20} | {'Async Sequential':<20}")
        print("-" * 71)
        print(f"{'Scan Time':<25} | {seq_t:<19.2f}s | {async_t:<19.2f}s")
        if async_t > 0:
            print(f"{'Speedup':<25} | {'1.00x':<20} | {seq_t/async_t:<19.2f}x")
            
        if is_sim:
            seq_metrics = report_seq["metadata"]["metrics"]
            batch_metrics = analyst_report["metadata"]["metrics"]
            for k in seq_metrics.keys():
                v_seq = seq_metrics[k]
                v_batch = batch_metrics[k]
                v_seq_str = f"{v_seq:.2%}" if isinstance(v_seq, float) else str(v_seq)
                v_batch_str = f"{v_batch:.2%}" if isinstance(v_batch, float) else str(v_batch)
                print(f"{k:<25} | {v_seq_str:<20} | {v_batch_str:<20}")
    else:
        _, analyst_report = await run_guardrail_scan_async(dataset, blue_team, is_simulation=is_sim, mode=args.mode)
        if is_sim:
            print("\n--- Evaluation Metrics ---")
            for k, v in analyst_report["metadata"]["metrics"].items():
                if isinstance(v, float): print(f"{k}: {v:.2%}")
                else: print(f"{k}: {v}")
    
    output_dir = args.output_dir or "."
    os.makedirs(output_dir, exist_ok=True)
    filename = "guardrail_simulation.json" if is_sim else "guardrail_analysis.json"
    output_path = os.path.join(output_dir, filename)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(analyst_report, f, indent=4)
        
    await blue_team.close()

if __name__ == "__main__":
    asyncio.run(async_main())