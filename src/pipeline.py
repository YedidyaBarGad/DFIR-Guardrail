import time
from src.red_team import RedTeamPoisoner
from src.blue_team import BlueTeamGuardrail

def compute_metrics(results):
    """
    Computes False Positive Rate and False Negative Rate.
    """
    TP = 0  # True Positive (Malicious correctly identified as Malicious)
    TN = 0  # True Negative (Benign correctly identified as Benign)
    FP = 0  # False Positive (Benign incorrectly identified as Malicious)
    FN = 0  # False Negative (Malicious incorrectly identified as Benign)
    ERR = 0 # Parsing errors
    
    for r in results:
        t = r["true_label"]
        p = r["predicted_label"]
        
        if p == -1:
            ERR += 1
            continue
            
        if t == 1 and p == 1:
            TP += 1
        elif t == 0 and p == 0:
            TN += 1
        elif t == 0 and p == 1:
            FP += 1
        elif t == 1 and p == 0:
            FN += 1
            
    total_benign = TN + FP
    total_malicious = TP + FN
    
    fpr = (FP / total_benign) if total_benign > 0 else 0.0
    fnr = (FN / total_malicious) if total_malicious > 0 else 0.0
    
    return {
        "Total processed": len(results),
        "True Positives": TP,
        "True Negatives": TN,
        "False Positives": FP,
        "False Negatives": FN,
        "Errors": ERR,
        "False Positive Rate (FPR)": fpr,
        "False Negative Rate (FNR)": fnr
    }

def main():
    print("--- Starting DFIR-Guardrail Pipeline ---")
    
    # 1. Initialize components
    # Using 'phi3' as a placeholder for a small, fast model
    model_name = "phi3" 
    red_team = RedTeamPoisoner()
    blue_team = BlueTeamGuardrail(model_name=model_name)
    
    # 2. Generate Dataset
    print("\n[Red Team] Generating dataset of 50 samples with 20% poison ratio...")
    dataset = red_team.generate_dataset(num_samples=50, poison_ratio=0.2)
    malicious_count = sum(1 for item in dataset if item["is_malicious"])
    print(f"-> Generated {len(dataset)} artifacts ({malicious_count} malicious).")
    
    # 3. Process with Guardrail LLM
    print(f"\n[Blue Team] Processing sequentially via Ollama (Model: {model_name})...")
    start_time = time.time()
    results = blue_team.process_sequential(dataset)
    elapsed = time.time() - start_time
    print(f"-> Processing complete in {elapsed:.2f} seconds.")
    
    # 4. Metrics & Validation
    print("\n--- Evaluation Metrics ---")
    metrics = compute_metrics(results)
    for k, v in metrics.items():
        if isinstance(v, float):
            print(f"{k}: {v:.2%}")
        else:
            print(f"{k}: {v}")
            
if __name__ == "__main__":
    main()
