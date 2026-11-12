from typing import Union

from prometheus_client import Counter, Gauge, Histogram, start_http_server

artifacts_scanned_total = Counter(
    "dfir_artifacts_scanned_total",
    "Total count of DFIR artifacts scanned",
    ["source", "status"],
)
threats_detected_total = Counter(
    "dfir_threats_detected_total",
    "Total count of prompt injection threats detected",
    ["threat_type"],
)
scan_duration_seconds = Histogram(
    "dfir_scan_duration_seconds",
    "Histogram of total scan durations in seconds",
    buckets=[0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, float("inf")],
)
llm_request_duration_seconds = Histogram(
    "dfir_llm_request_duration_seconds",
    "Histogram of individual LLM inference latency in seconds",
    buckets=[0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 15.0, float("inf")],
)
circuit_breaker_status = Gauge(
    "dfir_circuit_breaker_status",
    "Circuit breaker status (0 = CLOSED/NORMAL, 1 = OPEN/TRIPPED)",
)


def record_artifact_scanned(source: str, status: str) -> None:
    """Record an artifact scan event with source and status labels."""
    artifacts_scanned_total.labels(source=source, status=status).inc()


def record_threat_detected(threat_type: str) -> None:
    """Record a detected threat by category (e.g., 'prompt_injection', 'fail_closed')."""
    threats_detected_total.labels(threat_type=threat_type).inc()


def record_scan_duration(duration_seconds: float) -> None:
    """Record total pipeline scan duration."""
    scan_duration_seconds.observe(duration_seconds)


def record_llm_request_duration(duration_seconds: float) -> None:
    """Record individual LLM roundtrip latency."""
    llm_request_duration_seconds.observe(duration_seconds)


def set_circuit_breaker_status(is_open: Union[bool, int]) -> None:
    """Update circuit breaker state gauge (0 = normal, 1 = open/tripped)."""
    circuit_breaker_status.set(1 if is_open else 0)


def start_metrics_server(port: int = 8000) -> bool:
    """Start Prometheus HTTP exposition server on the specified port.

    Returns True if started successfully, False otherwise.
    """
    try:
        start_http_server(port)
        return True
    except Exception:
        return False
