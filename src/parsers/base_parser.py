"""Abstract Base Class for modular forensic artifact streaming parsers."""

import os
from abc import ABC, abstractmethod
from typing import Any, Dict, Iterator, Optional

from src.config import Config, get_settings
from src.logger import get_logger

logger = get_logger("dfir_guardrail.parsers")


class BaseForensicParser(ABC):
    """Abstract Base Class for memory-efficient forensic artifact parsers."""

    def __init__(self, config: Optional[Config] = None):
        self.config = config or get_settings()
        self.max_file_size_bytes = self.config.max_file_size_mb * 1024 * 1024
        # Parse failures for the current file; the loader reports them so a broken
        # file is never mistaken for a clean one.
        self.errors: list = []

    def validate_file_size(self, filepath: str) -> bool:
        """Validate that file size does not exceed max_file_size_mb.

        Logs a structured SIEM warning and returns False if file is oversized.
        """
        if not os.path.exists(filepath):
            logger.error(
                f"File not found: {filepath}",
                extra={"event_type": "file_not_found", "filepath": filepath},
            )
            return False

        try:
            file_size = os.path.getsize(filepath)
        except OSError as e:
            logger.error(
                f"Failed to access file {filepath}: {e}",
                extra={
                    "event_type": "file_access_error",
                    "filepath": filepath,
                    "error": str(e),
                },
            )
            return False

        filename = os.path.basename(filepath)
        if file_size > self.max_file_size_bytes:
            logger.warning(
                f"File {filename} exceeds {self.config.max_file_size_mb}MB limit. Skipping to prevent memory exhaustion.",
                extra={
                    "event_type": "file_skipped_size_limit",
                    "artifact_filename": filename,
                    "filepath": filepath,
                    "file_size": file_size,
                    "limit_bytes": self.max_file_size_bytes,
                },
            )
            return False

        return True

    @abstractmethod
    def parse(self, filepath: str) -> Iterator[Dict[str, Any]]:
        """Stream forensic artifact records one-by-one from the file.

        Must be implemented as a generator yielding individual event dictionaries
        to guarantee O(1) constant memory consumption regardless of file size.

        Args:
            filepath: Path to the forensic artifact file.

        Yields:
            Dict[str, Any]: Unnormalized or raw parsed record dictionary.
        """
        pass
