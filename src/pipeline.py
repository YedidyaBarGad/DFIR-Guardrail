import argparse
import asyncio
import json
import os
import time
import sys
from typing import Any, Dict, Iterable, List, Optional, Tuple

from src.blue_team import BlueTeamGuardrail
from src.config import get_settings
from src.logger import get_logger
from src.red_team import RedTeamPoisoner

logger = get_logger("dfir_guardrail.pipeline")


def compute_metrics(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculate DFIR detection performance metrics (FPR, FNR, TP, TN, FP, FN)."""
    TP = TN = FP = FN = ERR = 0
    for r in results:
        t = r.get("true_label", -1)
        p = r.get("predicted_label", -1)
        if p == -1:
            # Fail-closed: an error counts as flagged, so a missed attack is not hidden
            ERR += 1
            p = 1
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
        "False Negative Rate (FNR)": fnr,
    }


async def analyze_single(
    idx: int, item: dict, blue_team: BlueTeamGuardrail
) -> Tuple[Optional[dict], dict, bool]:
    """Analyze one artifact; any failure becomes a fail-closed error so one bad item cannot kill the scan."""
    try:
        return await _analyze(idx, item, blue_team)
    except Exception as e:
        logger.error(
            f"Item {idx} could not be analyzed: {e!r}",
            extra={"event_type": "item_error", "index": idx, "error": repr(e)},
        )
        entry = {
            "id": idx + 1,
            "verdict": "Suspicious (Inference Error / Potential Bypass)",
            "error_detail": f"Item could not be analyzed ({e!r}). Flagged under fail-closed.",
        }
        malicious = isinstance(item, dict) and item.get("is_malicious")
        entry["ground_truth"] = "Malicious" if malicious else "Benign"
        result = {
            "id": item.get("id", idx) if isinstance(item, dict) else idx,
            "true_label": 1 if malicious else 0,
            "predicted_label": -1,
        }
        return result, entry, True


async def _analyze(
    idx: int, item: dict, blue_team: BlueTeamGuardrail
) -> Tuple[Optional[dict], dict, bool]:
    """Analyze a single labelled artifact and build its report finding."""
    artifact = item["artifact"]
    artifact_id = f"sim_{idx}"
    predicted_class = await blue_team.classify_artifact(artifact_id, artifact)
    result = {
        "id": item["id"],
        "true_label": 1 if item["is_malicious"] else 0,
        "predicted_label": predicted_class,
    }
    source_file = "simulation"
    content = artifact

    is_threat = predicted_class == 1 or predicted_class == -1
    if predicted_class == 1:
        verdict = "Malicious (Prompt Injection Detected)"
        logger.warning(
            f"Threat detected: Prompt injection in artifact {artifact_id}",
            extra={
                "event_type": "threat_detected",
                "artifact_id": artifact_id,
                "source": source_file,
                "threat_type": "prompt_injection",
            },
        )
    elif predicted_class == -1:
        verdict = "Suspicious (Inference Error / Potential Bypass)"
        logger.warning(
            f"Threat flagged under fail-closed: Inference error in artifact {artifact_id}",
            extra={
                "event_type": "threat_detected",
                "artifact_id": artifact_id,
                "source": source_file,
                "threat_type": "fail_closed_error",
            },
        )
    else:
        verdict = "Safe (Benign)"

    report_entry = {
        "id": idx + 1,
        "verdict": verdict,
        "ground_truth": "Malicious" if item["is_malicious"] else "Benign",
    }

    if is_threat:
        report_entry["suspicious_content"] = content
        if predicted_class == -1:
            report_entry["error_detail"] = (
                "Failed to analyze. Flagged under fail-closed."
            )

    return result, report_entry, is_threat


async def run_guardrail_scan_async(
    dataset: Iterable[dict],
    blue_team: BlueTeamGuardrail,
    mode: str = "async",
) -> Tuple[List[dict], dict]:
    """Scan an iterable of labelled artifacts with a bounded window of in-flight tasks."""
    from tqdm import tqdm

    metadata = {
        "scan_time_seconds": 0,
        "total_artifacts_scanned": 0,
        "threats_detected": 0,
        "metrics": {},
    }
    analyst_report = {"metadata": metadata, "findings": []}
    results: List[dict] = []

    start_time = time.time()
    logger.info(
        f"========== STARTING SCAN: MODE={mode.upper()} ==========",
        extra={
            "event_type": "scan_start",
            "mode": mode,
        },
    )

    window = 1 if mode != "async" else max(1, blue_team.concurrency) * 4
    pending: set = set()
    pbar = tqdm(desc=f"Scanning artifacts ({mode})", unit="item")

    def handle(task: "asyncio.Future") -> None:
        res, rep, is_threat = task.result()
        metadata["total_artifacts_scanned"] += 1
        if res:
            results.append(res)
        if is_threat:
            metadata["threats_detected"] += 1
        analyst_report["findings"].append(rep)
        pbar.update(1)

    try:
        for idx, item in enumerate(dataset):
            pending.add(asyncio.ensure_future(analyze_single(idx, item, blue_team)))
            if len(pending) >= window:
                done, pending = await asyncio.wait(
                    pending, return_when=asyncio.FIRST_COMPLETED
                )
                for t in done:
                    handle(t)
        if pending:
            done, pending = await asyncio.wait(pending)
            for t in done:
                handle(t)
    finally:
        for t in pending:
            t.cancel()
        pbar.close()

    analyst_report["findings"].sort(key=lambda f: f["id"])
    total = metadata["total_artifacts_scanned"]
    elapsed = time.time() - start_time
    metadata["scan_time_seconds"] = round(elapsed, 2)
    throughput = total / elapsed if elapsed > 0 else 0

    logger.info(
        f"Scan completed in {elapsed:.2f} seconds. Throughput: {throughput:.2f} items/sec.",
        extra={
            "event_type": "scan_complete",
            "elapsed_seconds": round(elapsed, 4),
            "total_artifacts": total,
            "threats_detected": metadata["threats_detected"],
        },
    )
    print(
        f"\nScan completed in {elapsed:.2f} seconds. Throughput: {throughput:.2f} items/sec."
    )

    metadata["metrics"] = compute_metrics(results)

    return results, analyst_report


def warn_if_backend_failed(metrics: Dict[str, Any]) -> None:
    """Fail-closed counts errors as flagged, so a dead backend would otherwise look like detections."""
    total, errs = metrics.get("Total processed", 0), metrics.get("Errors", 0)
    if total and errs > 0.01 * total:
        print(
            f"WARNING: {errs}/{total} inference errors. These were scored as flagged, so the "
            "metrics above reflect the pre-filter/timeouts, not the model. Do not cite them."
        )


def print_run_config(blue_team: BlueTeamGuardrail, concurrency: int) -> None:
    """Print what a benchmark actually ran with, so results can be cited and reproduced."""
    import httpx

    host, model = blue_team.ollama_host, blue_team.model_name
    version = digest = "unknown"
    try:
        version = (
            httpx.get(f"{host}/api/version", timeout=5).json().get("version", version)
        )
        for m in httpx.get(f"{host}/api/tags", timeout=5).json().get("models", []):
            if m.get("name") == model:
                digest = f"{m.get('digest', '')[:12]} {m.get('details', {}).get('quantization_level', '')}"
    except Exception:
        pass  # best effort; the scan itself does not depend on it
    print("--- Run configuration ---")
    print(f"model={model} digest/quant={digest} ollama={version}")
    cfg = blue_team.config
    print(
        f"options: temperature=0.0 num_ctx={cfg.llm_num_ctx} num_predict=200 (no seed) "
        f"structured_output={'on' if cfg.llm_structured_output else 'off'}"
    )
    print(
        f"prefilter={'off' if blue_team.skip_prefilter else 'on'} "
        f"gate={'legacy' if blue_team.legacy_gate else 'v2'} "
        f"embedder={'on' if blue_team.embedder is not None else 'off'} "
        f"concurrency={concurrency} (set OLLAMA_NUM_PARALLEL on the daemon to match)"
    )


async def async_main() -> int:
    """CLI entrypoint for DFIR-Guardrail pipeline."""
    config = get_settings()

    parser = argparse.ArgumentParser(description="DFIR-Guardrail Pipeline")
    parser.add_argument(
        "--output_dir", type=str, help="Path to save the validation results"
    )
    parser.add_argument(
        "--num_samples",
        type=int,
        default=50,
        help="Number of samples to generate for Red Team simulation",
    )
    parser.add_argument(
        "--poison_ratio",
        type=float,
        default=0.2,
        help="Poison ratio for Red Team simulation",
    )
    parser.add_argument(
        "--mode",
        type=str,
        choices=["sim", "compare"],
        default="sim",
        help="Mode: 'sim' scores a labelled dataset; 'compare' times sequential vs bounded-concurrency scans.",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=config.concurrency_limit,
        help="Number of concurrent LLM requests to make in async mode.",
    )
    parser.add_argument(
        "--dataset_file",
        type=str,
        help="Sim mode: JSON list of {id, artifact, is_malicious} to score instead of generating one.",
    )
    parser.add_argument(
        "--no_prefilter",
        action="store_true",
        help="Send every artifact to the LLM (skip the heuristic pre-filter) to measure the model alone.",
    )
    parser.add_argument(
        "--legacy_gate",
        action="store_true",
        help="Use the pre-v2 gate (pre-filter decides what the LLM sees; the LLM may veto). Reproduces the published runs.",
    )
    args = parser.parse_args()

    print("--- Starting DFIR-Guardrail Pipeline ---")

    blue_team = BlueTeamGuardrail(
        ollama_host=config.llm_endpoint,
        model_name=config.llm_model,
        max_concurrent_requests=args.concurrency,
        config=config,
    )

    blue_team.skip_prefilter = args.no_prefilter
    blue_team.legacy_gate = args.legacy_gate
    if args.dataset_file:
        with open(args.dataset_file, encoding="utf-8") as f:
            dataset = json.load(f)
    else:
        dataset = RedTeamPoisoner().generate_dataset(
            num_samples=args.num_samples, poison_ratio=args.poison_ratio
        )
    print(f"-> Generated {len(dataset)} items.")

    # Warm up the LLM
    print("Warming up the LLM (Loading model into VRAM)...")
    await blue_team.warmup()
    print_run_config(blue_team, args.concurrency)

    if args.mode == "compare":
        print("\n--- Running Pure Sequential Baseline ---")
        _, report_seq = await run_guardrail_scan_async(
            dataset, blue_team, mode="sequential"
        )
        print("\n--- Running Async (bounded concurrency) ---")
        _, analyst_report = await run_guardrail_scan_async(
            dataset, blue_team, mode="async"
        )

        print("\n--- Comparison Results ---")
        seq_t = report_seq["metadata"]["scan_time_seconds"]
        async_t = analyst_report["metadata"]["scan_time_seconds"]

        print(f"{'Metric':<25} | {'Sequential Baseline':<20} | {'Async (bounded)':<20}")
        print("-" * 71)
        print(f"{'Scan Time':<25} | {seq_t:<19.2f}s | {async_t:<19.2f}s")
        if async_t > 0:
            print(f"{'Speedup':<25} | {'1.00x':<20} | {seq_t/async_t:<19.2f}x")

        seq_metrics = report_seq["metadata"]["metrics"]
        batch_metrics = analyst_report["metadata"]["metrics"]
        for k in seq_metrics.keys():
            v_seq = seq_metrics[k]
            v_batch = batch_metrics[k]
            v_seq_str = f"{v_seq:.2%}" if isinstance(v_seq, float) else str(v_seq)
            v_batch_str = (
                f"{v_batch:.2%}" if isinstance(v_batch, float) else str(v_batch)
            )
            print(f"{k:<25} | {v_seq_str:<20} | {v_batch_str:<20}")
        warn_if_backend_failed(seq_metrics)
        warn_if_backend_failed(batch_metrics)
    else:
        _, analyst_report = await run_guardrail_scan_async(
            dataset, blue_team, mode="async"
        )
        print("\n--- Evaluation Metrics ---")
        for k, v in analyst_report["metadata"]["metrics"].items():
            if isinstance(v, float):
                print(f"{k}: {v:.2%}")
            else:
                print(f"{k}: {v}")
        warn_if_backend_failed(analyst_report["metadata"]["metrics"])

    if analyst_report["metadata"]["total_artifacts_scanned"] == 0:
        print("No valid data found.")

    output_dir = args.output_dir or "."
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "guardrail_simulation.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(analyst_report, f, indent=4, default=str)

    await blue_team.close()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(async_main()))
