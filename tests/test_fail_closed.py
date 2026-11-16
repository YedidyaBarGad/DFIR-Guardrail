import asyncio

from src.pipeline import (
    compute_metrics,
    run_guardrail_scan_async,
    warn_if_backend_failed,
)


class _Stub:
    concurrency = 2

    def __init__(self, verdict):
        self.verdict = verdict

    async def classify_artifact(self, artifact_id, artifact):
        return self.verdict


def test_dead_backend_is_scored_flagged_but_warned(capsys):
    results = [{"true_label": i % 2, "predicted_label": -1} for i in range(100)]
    m = compute_metrics(results)
    assert m["Errors"] == 100 and m["False Negative Rate (FNR)"] == 0.0  # looks perfect
    warn_if_backend_failed(m)
    assert "Do not cite them" in capsys.readouterr().out


def test_few_errors_do_not_warn(capsys):
    warn_if_backend_failed({"Total processed": 500, "Errors": 5})
    assert capsys.readouterr().out == ""


def test_malformed_item_does_not_abort_scan():
    data = [
        {"id": 0, "artifact": {"a": "x"}, "is_malicious": False},
        {"id": 1, "is_malicious": True},  # no "artifact" key
        {"id": 2, "artifact": {"a": "y"}, "is_malicious": True},
    ]
    results, report = asyncio.run(
        run_guardrail_scan_async(data, _Stub(1), is_simulation=True)
    )
    assert report["metadata"]["total_artifacts_scanned"] == 3
    assert any(r["predicted_label"] == -1 for r in results)
    assert report["metadata"]["metrics"]["Errors"] == 1
