import json
import logging
import logging.handlers
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from src.config import Config, get_settings

STANDARD_LOG_ATTRS = {
    "name",
    "msg",
    "args",
    "levelname",
    "levelno",
    "pathname",
    "filename",
    "module",
    "exc_info",
    "exc_text",
    "stack_info",
    "lineno",
    "funcName",
    "created",
    "msecs",
    "relativeCreated",
    "thread",
    "threadName",
    "processName",
    "process",
    "message",
}


class SIEMJSONFormatter(logging.Formatter):
    """Structured JSON log formatter optimized for SIEM ingestion (e.g. Splunk).

    Ensures top-level fields: timestamp (ISO8601 UTC), level, logger,
    event_type, message, and dynamically serializes any contextual extra
    fields.
    """

    def format(self, record: logging.LogRecord) -> str:
        # Format ISO8601 UTC timestamp
        timestamp = datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat()

        payload: Dict[str, Any] = {
            "timestamp": timestamp,
            "level": record.levelname,
            "logger": record.name,
            "event_type": getattr(record, "event_type", "general"),
            "message": record.getMessage(),
        }

        # Dynamically append extra attributes passed via logging methods
        for key, value in record.__dict__.items():
            if key not in STANDARD_LOG_ATTRS and key != "event_type":
                try:
                    json.dumps(value)
                    payload[key] = value
                except (TypeError, OverflowError):
                    payload[key] = str(value)

        # Handle exception traces
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, ensure_ascii=False)


def get_logger(
    name: str = "dfir_guardrail", config: Optional[Config] = None
) -> logging.Logger:
    """Configure and return a structured logger adhering to SIEM guidelines.

    Supports both SIEM JSON and standard text formatting, with dual stream
    and rotating file handlers.
    """
    settings = config or get_settings()
    logger = logging.getLogger(name)

    # Avoid duplicate handlers if already configured
    if logger.handlers:
        return logger

    # Resolve log level
    level = getattr(logging, settings.log_level.upper(), logging.INFO)
    logger.setLevel(level)

    # Resolve formatter
    if settings.log_format == "text":
        formatter: logging.Formatter = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | [%(name)s] | %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%SZ",
        )
    else:
        formatter = SIEMJSONFormatter()

    # Stream Handler (stdout)
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setLevel(level)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    # Rotating File Handler (for persistent log forwarders like Splunk Universal Forwarder)
    if settings.log_file:
        try:
            file_handler = logging.handlers.RotatingFileHandler(
                settings.log_file,
                maxBytes=10 * 1024 * 1024,
                backupCount=5,
                encoding="utf-8",
            )
            file_handler.setLevel(level)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except Exception:
            # Silently degrade if file cannot be opened (e.g., read-only filesystem)
            pass

    # Prevent propagation to root logger to avoid double logging
    logger.propagate = False
    return logger
