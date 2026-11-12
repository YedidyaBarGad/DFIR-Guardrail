"""Memory-efficient streaming JSON and JSONL parser using ijson."""

import json
from typing import Any, Dict, Iterator, Optional

import ijson

from src.config import Config
from src.logger import get_logger
from src.parsers.base_parser import BaseForensicParser

logger = get_logger("dfir_guardrail.parsers.json")


class JSONStreamingParser(BaseForensicParser):
    """Memory-efficient streaming parser for JSON arrays, objects, and JSONL forensic files."""

    def __init__(self, config: Optional[Config] = None):
        super().__init__(config)

    def _is_jsonl(self, filepath: str) -> bool:
        """Heuristically determine if file is JSON Lines (JSONL/NDJSON)."""
        lower = filepath.lower()
        if lower.endswith((".jsonl", ".ndjson")):
            return True

        # Peek first two non-empty lines
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                first_line = ""
                for line in f:
                    s = line.strip()
                    if s:
                        first_line = s
                        break
                if not first_line:
                    return False

                # If first line doesn't start with { or [, not json
                if not first_line.startswith(("{", "[")):
                    return False

                # If it starts with [, it's a JSON array
                if first_line.startswith("["):
                    return False

                # Check if first line parses as standalone JSON
                try:
                    parsed_first = json.loads(first_line)
                    if not isinstance(parsed_first, dict):
                        return False
                except Exception:
                    return False

                # Check if second non-empty line exists and also starts with { and parses
                for line in f:
                    s = line.strip()
                    if s:
                        if s.startswith("{"):
                            try:
                                json.loads(s)
                                return True
                            except Exception:
                                return False
                        return False
        except Exception:
            return False

        return False

    def _parse_jsonl(self, filepath: str) -> Iterator[Dict[str, Any]]:
        """Stream JSON Lines line by line with O(1) memory usage."""
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line_no, line in enumerate(f, start=1):
                clean_line = line.strip()
                if not clean_line:
                    continue
                try:
                    record = json.loads(clean_line)
                    if isinstance(record, dict):
                        yield record
                    elif isinstance(record, list):
                        for sub_item in record:
                            if isinstance(sub_item, dict):
                                yield sub_item
                except json.JSONDecodeError as e:
                    logger.warning(
                        f"Skipping malformed JSON line {line_no} in {filepath}: {e}",
                        extra={
                            "event_type": "jsonl_line_error",
                            "filepath": filepath,
                            "line_number": line_no,
                            "error": str(e),
                        },
                    )

    def parse(self, filepath: str) -> Iterator[Dict[str, Any]]:
        """Stream forensic records from JSON or JSONL file.

        Supports:
        1. Line-delimited JSON (.jsonl, .ndjson or multi-line JSON objects).
        2. Top-level JSON arrays ([{...}, {...}]) using streaming ijson.items.
        3. Top-level JSON key-value maps ({"rec1": {...}}) using streaming ijson.kvitems.
        4. Single flat JSON objects ({"CommandLine": "..."}).
        """
        if not self.validate_file_size(filepath):
            return

        if self._is_jsonl(filepath):
            yield from self._parse_jsonl(filepath)
            return

        # Use ijson for streaming large JSON documents
        try:
            with open(filepath, "rb") as f:
                parser = ijson.parse(f)
                try:
                    _, first_event, _ = next(parser)
                except StopIteration:
                    return

                f.seek(0)

                if first_event == "start_array":
                    # Top-level array of forensic records
                    for item in ijson.items(f, "item", use_float=True):
                        if isinstance(item, dict):
                            yield item
                elif first_event == "start_map":
                    # Key-value container or single flat record
                    flat_record: Dict[str, Any] = {}
                    nested: Dict[str, Any] = {}

                    for key, value in ijson.kvitems(f, "", use_float=True):
                        if isinstance(value, dict):
                            nested[key] = value
                        else:
                            flat_record[key] = value

                    if flat_record:
                        # Root is itself a record (nested dicts are part of it)
                        flat_record.update(nested)
                        yield flat_record
                    else:
                        # Root is a container of records
                        for key, value in nested.items():
                            if "id" not in value and "_id" not in value:
                                value["_record_key"] = key
                            yield value
                else:
                    logger.warning(
                        f"Unexpected root JSON structure in {filepath}: {first_event}",
                        extra={
                            "event_type": "json_unexpected_root",
                            "filepath": filepath,
                        },
                    )
        except Exception as e:
            # Fallback to line-by-line reading if ijson encountered an unexpected stream boundary
            logger.warning(
                f"ijson stream failed for {filepath}, attempting JSONL fallback: {e}",
                extra={
                    "event_type": "json_ijson_fallback",
                    "filepath": filepath,
                    "error": str(e),
                },
            )
            yield from self._parse_jsonl(filepath)
