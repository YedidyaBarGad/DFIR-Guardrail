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
from src.parsers.ecs_normalizer import ECSNormalizer
from src.parsers.factory import load_forensic_data
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


def extract_high_risk_fields(item: Dict[str, Any]) -> Dict[str, Any]:
    """Extract known high-risk execution and metadata fields normalized to Elastic Common Schema (ECS)."""
    normalizer = ECSNormalizer()
    ecs_record = normalizer.normalize(item)
    return normalizer.extract_high_risk_ecs(ecs_record)


def load_real_data(
    input_path: str, skipped: Optional[List[Dict[str, str]]] = None
) -> List[Dict[str, Any]]:
    """Parse multi-format forensic artifacts from a file or directory into a list (small inputs, tests).

    Large inputs should iterate `load_forensic_data` directly so memory stays flat.
    """
    return list(load_forensic_data(input_path, skipped=skipped))


async def analyze_single(
    idx: int, item: dict, blue_team: BlueTeamGuardrail, is_simulation: bool
) -> Tuple[Optional[dict], dict, bool]:
    """Analyze one artifact; any failure becomes a fail-closed error so one bad item cannot kill the scan."""
    try:
        return await _analyze(idx, item, blue_team, is_simulation)
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
        result = None
        if is_simulation:
            malicious = isinstance(item, dict) and item.get("is_malicious")
            entry["ground_truth"] = "Malicious" if malicious else "Benign"
            result = {
                "id": item.get("id", idx) if isinstance(item, dict) else idx,
                "true_label": 1 if malicious else 0,
                "predicted_label": -1,
            }
        return result, entry, True


async def _analyze(
    idx: int, item: dict, blue_team: BlueTeamGuardrail, is_simulation: bool
) -> Tuple[Optional[dict], dict, bool]:
    """Analyze a single artifact, update Prometheus metrics, and generate report findings."""
    if is_simulation:
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
    else:
        # Send high-risk fields plus unmapped fields once; the full ECS record
        # repeats every value 2-3x and overflows the model's context window.
        artifact_for_model = {
            "Source": item["artifact_source"],
            "Content": item["content"],
        }
        custom = item.get("ecs", {}).get("custom")
        if custom:
            artifact_for_model["Custom"] = custom
        artifact_id = item["id"]
        predicted_class = await blue_team.classify_artifact(
            artifact_id, artifact_for_model
        )

        result = None
        source_file = item["artifact_source"]
        content = item["content"]

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

    report_entry = {"id": idx + 1, "verdict": verdict}

    if not is_simulation:
        report_entry["source_file"] = source_file
        if "ecs" in item:
            report_entry["ecs"] = item["ecs"]
    else:
        report_entry["ground_truth"] = "Malicious" if item["is_malicious"] else "Benign"

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
    is_simulation: bool = False,
    mode: str = "async",
) -> Tuple[List[dict], dict]:
    """Scan an iterable of artifacts with a bounded window of in-flight tasks.

    Memory stays flat for generators: only `window` items are alive at once. Simulation
    reports keep every finding; ops reports keep threats only (benign items are counted).
    """
    from tqdm import tqdm

    metadata = {
        "scan_time_seconds": 0,
        "total_artifacts_scanned": 0,
        "threats_detected": 0,
    }
    if is_simulation:
        metadata["metrics"] = {}
    analyst_report = {"metadata": metadata, "findings": []}
    results: List[dict] = []

    start_time = time.time()
    logger.info(
        f"========== STARTING SCAN: MODE={mode.upper()} ==========",
        extra={
            "event_type": "scan_start",
            "mode": mode,
            "is_simulation": is_simulation,
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
        if is_simulation or is_threat:
            analyst_report["findings"].append(rep)
        pbar.update(1)

    try:
        for idx, item in enumerate(dataset):
            pending.add(
                asyncio.ensure_future(
                    analyze_single(idx, item, blue_team, is_simulation)
                )
            )
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

    if is_simulation:
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
        "--input_dir",
        type=str,
        help="Path to parsed artifacts from KAPE, Velociraptor, or forensic logs (directory or single file: JSON, CSV, XML, EVTX) for analysis",
    )
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
        choices=["sim", "ops", "compare"],
        default="sim",
        help="Mode: 'sim' for synthetic dataset generation, 'ops' (EXPERIMENTAL, unvalidated) for real forensic exports,'compare' for benchmark.",
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
    skipped: List[Dict[str, str]] = []
    if args.input_dir or args.mode == "ops":
        if not args.input_dir:
            print("Error: --input_dir must be specified in 'ops' mode.")
            return 2
        print(
            "WARNING: ops mode is experimental. The parsers have not been run on real "
            "forensic exports, and detection rates were measured only in sim mode."
        )
        if not os.path.exists(args.input_dir):
            print(f"Error: input path does not exist: {args.input_dir}")
            return 2
        dataset = load_forensic_data(args.input_dir, skipped=skipped)
        if args.mode == "compare":
            dataset = list(dataset)  # compare scans the data twice
        is_sim = False
    elif args.dataset_file:
        with open(args.dataset_file, encoding="utf-8") as f:
            dataset = json.load(f)
        is_sim = True
    else:
        red_team = RedTeamPoisoner()
        dataset = red_team.generate_dataset(
            num_samples=args.num_samples, poison_ratio=args.poison_ratio
        )
        is_sim = True

    if is_sim:
        print(f"-> Generated {len(dataset)} items.")

    # Warm up the LLM
    print("Warming up the LLM (Loading model into VRAM)...")
    await blue_team.warmup()
    print_run_config(blue_team, args.concurrency)

    if args.mode == "compare":
        print("\n--- Running Pure Sequential Baseline ---")
        _, report_seq = await run_guardrail_scan_async(
            dataset, blue_team, is_simulation=is_sim, mode="sequential"
        )
        print("\n--- Running Async (bounded concurrency) ---")
        _, analyst_report = await run_guardrail_scan_async(
            dataset, blue_team, is_simulation=is_sim, mode="async"
        )

        print("\n--- Comparison Results ---")
        seq_t = report_seq["metadata"]["scan_time_seconds"]
        async_t = analyst_report["metadata"]["scan_time_seconds"]

        print(f"{'Metric':<25} | {'Sequential Baseline':<20} | {'Async (bounded)':<20}")
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
                v_batch_str = (
                    f"{v_batch:.2%}" if isinstance(v_batch, float) else str(v_batch)
                )
                print(f"{k:<25} | {v_seq_str:<20} | {v_batch_str:<20}")
            warn_if_backend_failed(seq_metrics)
            warn_if_backend_failed(batch_metrics)
    else:
        _, analyst_report = await run_guardrail_scan_async(
            dataset,
            blue_team,
            is_simulation=is_sim,
            mode="async" if args.mode in ["sim", "ops"] else args.mode,
        )
        if is_sim:
            print("\n--- Evaluation Metrics ---")
            for k, v in analyst_report["metadata"]["metrics"].items():
                if isinstance(v, float):
                    print(f"{k}: {v:.2%}")
                else:
                    print(f"{k}: {v}")
            warn_if_backend_failed(analyst_report["metadata"]["metrics"])

    total = analyst_report["metadata"]["total_artifacts_scanned"]
    if total == 0 and not skipped:
        print("No valid data found.")
    analyst_report["metadata"]["skipped_files"] = skipped
    if skipped:
        print(f"WARNING: {len(skipped)} file(s) were NOT fully scanned:")
        for sk in skipped:
            print(f"  [{sk['reason']}] {sk['filepath']}: {sk['detail']}")

    output_dir = args.output_dir or "."
    os.makedirs(output_dir, exist_ok=True)
    filename = "guardrail_simulation.json" if is_sim else "guardrail_analysis.json"
    output_path = os.path.join(output_dir, filename)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(analyst_report, f, indent=4, default=str)

    await blue_team.close()
    # Exit non-zero when a file was too big or unreadable: a clean report must not hide that
    incomplete = any(sk["reason"] in ("size_limit", "parse_error") for sk in skipped)
    return 1 if incomplete else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(async_main()))
