import io
import json
import logging
import os
import pytest

from src.blue_team import BlueTeamGuardrail
from src.config import Config, get_settings
from src.logger import JSONFormatter, get_logger


@pytest.fixture(autouse=True)
def clean_environment():
    """Ensure clean configuration state for every test."""
    yield
    get_settings(reload=True)


def test_config_defaults():
    """Verify that default Config provides robust out-of-the-box enterprise defaults."""
    config = Config()
    assert config.llm_endpoint == "http://localhost:11434"
    assert config.llm_model == "phi3:mini"
    assert config.llm_timeout == 15.0
    assert config.concurrency_limit == 3
    assert config.log_level == "INFO"
    assert config.log_format == "json"
    assert config.log_file == "guardrail_execution.log"
    assert config.shannon_entropy_threshold == 4.5
    assert config.semantic_similarity_threshold == 0.45


def test_config_environment_overrides(monkeypatch):
    """Verify that all configuration parameters can be overridden via environment variables."""
    monkeypatch.setenv("LLM_ENDPOINT", "http://production-vllm:8000")
    monkeypatch.setenv("LLM_MODEL", "meta-llama/Meta-Llama-3-70B")
    monkeypatch.setenv("LLM_TIMEOUT", "45.5")
    monkeypatch.setenv("CONCURRENCY_LIMIT", "8")
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("LOG_FORMAT", "text")
    monkeypatch.setenv("LOG_FILE", "custom_guardrail.log")
    monkeypatch.setenv("SHANNON_ENTROPY_THRESHOLD", "5.2")
    monkeypatch.setenv("SEMANTIC_SIMILARITY_THRESHOLD", "0.85")

    settings = get_settings(reload=True)
    assert settings.llm_endpoint == "http://production-vllm:8000"
    assert settings.llm_model == "meta-llama/Meta-Llama-3-70B"
    assert settings.llm_timeout == 45.5
    assert settings.concurrency_limit == 8
    assert settings.log_level == "DEBUG"
    assert settings.log_format == "text"
    assert settings.log_file == "custom_guardrail.log"
    assert settings.shannon_entropy_threshold == 5.2
    assert settings.semantic_similarity_threshold == 0.85


def test_json_log_formatting():
    """Verify structured JSON log lines carry the standard fields and extras."""
    formatter = JSONFormatter()
    logger = logging.getLogger("test_json_logger")
    record = logger.makeRecord(
        name="dfir_guardrail.test",
        level=logging.WARNING,
        fn="test_observability.py",
        lno=55,
        msg="Suspicious prompt injection payload detected",
        args=(),
        exc_info=None,
        extra={
            "event_type": "threat_detected",
            "artifact_id": "art_999",
            "threat_type": "prompt_injection",
            "entropy_score": 4.88,
        },
    )

    output = formatter.format(record)
    parsed = json.loads(output)

    assert "timestamp" in parsed
    assert parsed["level"] == "WARNING"
    assert parsed["logger"] == "dfir_guardrail.test"
    assert parsed["event_type"] == "threat_detected"
    assert parsed["message"] == "Suspicious prompt injection payload detected"
    assert parsed["artifact_id"] == "art_999"
    assert parsed["threat_type"] == "prompt_injection"
    assert parsed["entropy_score"] == 4.88


def test_get_logger_stream_and_file():
    """Verify get_logger returns a properly configured logger."""
    test_config = Config(
        log_level="INFO",
        log_format="json",
        log_file="test_exec.log",
    )
    custom_logger = get_logger("dfir_guardrail.custom_test", config=test_config)
    assert custom_logger.level == logging.INFO
    assert len(custom_logger.handlers) >= 1

    # Cleanup handler file reference
    for h in list(custom_logger.handlers):
        h.close()
        custom_logger.removeHandler(h)
    if os.path.exists("test_exec.log"):
        try:
            os.remove("test_exec.log")
        except OSError:
            pass


def test_blue_team_backward_compatibility():
    """Verify BlueTeamGuardrail maintains full backward compatibility with optional parameters."""
    # Use enable_semantic_search=False to avoid network I/O during unit tests
    bt_default = BlueTeamGuardrail(enable_semantic_search=False)
    assert bt_default.ollama_host == "http://localhost:11434"
    assert bt_default.model_name == "phi3:mini"

    bt_custom = BlueTeamGuardrail(
        ollama_host="http://custom-node:11434",
        model_name="phi3:custom",
        max_concurrent_requests=10,
        enable_semantic_search=False,
    )
    assert bt_custom.ollama_host == "http://custom-node:11434"
    assert bt_custom.model_name == "phi3:custom"
