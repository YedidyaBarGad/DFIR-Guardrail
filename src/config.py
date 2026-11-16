import os
from dataclasses import dataclass
from typing import Optional


def _get_bool(key: str, default: bool) -> bool:
    val = os.getenv(key)
    if val is None:
        return default
    return val.strip().lower() in ("true", "1", "yes", "t", "on")


def _get_int(key: str, default: int) -> int:
    val = os.getenv(key)
    if val is None:
        return default
    try:
        return int(val.strip())
    except (ValueError, TypeError):
        return default


def _get_float(key: str, default: float) -> float:
    val = os.getenv(key)
    if val is None:
        return default
    try:
        return float(val.strip())
    except (ValueError, TypeError):
        return default


@dataclass
class Config:
    """Enterprise configuration for DFIR-Guardrail."""

    llm_endpoint: str = "http://localhost:11434"
    llm_model: str = "phi3:mini"
    llm_timeout: float = 15.0
    llm_num_ctx: int = 4096  # 2048 truncated or corrupted padded prompts (see README)
    llm_structured_output: bool = (
        False  # Ollama JSON-schema constrained decoding instead of free-form JSON
    )
    llm_backend: str = "ollama"  # "ollama" | "anthropic"
    anthropic_api_key: str = ""  # env only; never logged
    concurrency_limit: int = 3
    log_level: str = "INFO"
    log_format: str = "json"
    log_file: str = "guardrail_execution.log"
    max_file_size_mb: int = 50
    shannon_entropy_threshold: float = 4.5
    semantic_similarity_threshold: float = 0.45

    @classmethod
    def from_env(cls) -> "Config":
        """Instantiate Config dynamically parsed from environment variables."""
        return cls(
            llm_endpoint=os.getenv("LLM_ENDPOINT", "http://localhost:11434"),
            llm_model=os.getenv("LLM_MODEL", "phi3:mini"),
            llm_timeout=_get_float("LLM_TIMEOUT", 15.0),
            llm_num_ctx=_get_int("LLM_NUM_CTX", 4096),
            llm_structured_output=_get_bool("LLM_STRUCTURED_OUTPUT", False),
            llm_backend=os.getenv("LLM_BACKEND", "ollama").strip().lower(),
            anthropic_api_key=os.getenv("ANTHROPIC_API_KEY", ""),
            concurrency_limit=max(1, _get_int("CONCURRENCY_LIMIT", 3)),
            log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
            log_format=os.getenv("LOG_FORMAT", "json").lower(),
            log_file=os.getenv("LOG_FILE", "guardrail_execution.log"),
            max_file_size_mb=_get_int("MAX_FILE_SIZE_MB", 50),
            shannon_entropy_threshold=_get_float("SHANNON_ENTROPY_THRESHOLD", 4.5),
            semantic_similarity_threshold=_get_float(
                "SEMANTIC_SIMILARITY_THRESHOLD", 0.45
            ),
        )


_settings: Optional[Config] = None


def get_settings(reload: bool = False) -> Config:
    """Return singleton configuration, re-parsing environment if reload=True."""
    global _settings
    if _settings is None or reload:
        _settings = Config.from_env()
    return _settings
