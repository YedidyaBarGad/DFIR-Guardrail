"""Parser factory and unified forensic ingestion dispatcher."""

import os
from typing import Any, Dict, Iterator, List, Optional

from src.config import Config, get_settings
from src.logger import get_logger
from src.parsers.base_parser import BaseForensicParser
from src.parsers.csv_parser import CSVStreamingParser
from src.parsers.ecs_normalizer import ECSNormalizer
from src.parsers.evtx_parser import EVTXStreamingParser
from src.parsers.json_parser import JSONStreamingParser
from src.parsers.xml_parser import XMLStreamingParser

logger = get_logger("dfir_guardrail.parsers.factory")


class ParserFactory:
    """Dispatches appropriate forensic parser based on file extension and magic bytes."""

    @staticmethod
    def detect_format_from_magic(filepath: str) -> Optional[str]:
        """Detect file format using initial magic bytes."""
        try:
            with open(filepath, "rb") as f:
                header = f.read(512)
                if not header:
                    return None

                # EVTX file magic
                if header.startswith((b"ElfFile\x00", b"ElfChnk\x00")):
                    return "evtx"

                # XML magic
                clean_header = header.lstrip()
                if clean_header.startswith((b"<?xml", b"<Events", b"<Event", b"<\x00?\x00x\x00m\x00l")):
                    return "xml"

                # JSON magic
                if clean_header.startswith((b"{", b"[")):
                    return "json"

                # CSV check (printable ascii/utf-8 with commas/tabs and newlines)
                if b"\n" in header and (b"," in header or b"\t" in header):
                    return "csv"
        except Exception:
            return None
        return None

    @classmethod
    def get_parser(
        cls, filepath: str, config: Optional[Config] = None
    ) -> BaseForensicParser:
        """Return the appropriate BaseForensicParser instance for the given file.

        First checks file extension, then falls back to magic byte inspection.
        """
        cfg = config or get_settings()
        ext = os.path.splitext(filepath)[1].lower()

        if ext in (".json", ".jsonl", ".ndjson"):
            return JSONStreamingParser(cfg)
        elif ext in (".csv", ".tsv"):
            return CSVStreamingParser(cfg)
        elif ext in (".xml",):
            return XMLStreamingParser(cfg)
        elif ext in (".evtx",):
            return EVTXStreamingParser(cfg)

        # Fallback to magic byte detection
        detected = cls.detect_format_from_magic(filepath)
        if detected == "evtx":
            return EVTXStreamingParser(cfg)
        elif detected == "xml":
            return XMLStreamingParser(cfg)
        elif detected == "json":
            return JSONStreamingParser(cfg)
        elif detected == "csv":
            return CSVStreamingParser(cfg)

        raise ValueError(
            f"Unsupported forensic artifact format for file: {filepath} (extension: '{ext}')"
        )


def load_forensic_data(
    input_path: str,
    config: Optional[Config] = None,
    only_high_risk: bool = True,
    skipped: Optional[List[Dict[str, str]]] = None,
) -> Iterator[Dict[str, Any]]:
    """Recursively load and stream ECS-normalized forensic records from a file or directory.

    Files that cannot be fully scanned (too big, unsupported, parse error) are appended to
    `skipped` as {filepath, reason, detail}; nothing is skipped by name or extension.

    Yields:
        Dict[str, Any] containing:
            - id: Unique artifact ID (e.g. filename_idx)
            - artifact_source: Base filename
            - filepath: Full path to source artifact
            - content: High-risk ECS fields for guardrail inspection
            - ecs: Full normalized ECS record
    """
    if not os.path.exists(input_path):
        logger.warning(
            f"Input path does not exist: {input_path}",
            extra={"event_type": "input_path_not_found", "input_path": input_path},
        )
        return

    cfg = config or get_settings()
    normalizer = ECSNormalizer()
    if skipped is None:
        skipped = []

    # Collect files to process
    target_files = []
    if os.path.isfile(input_path):
        target_files.append(input_path)
    else:
        for root, dirs, files in os.walk(input_path):
            # Sort for deterministic processing
            dirs.sort()
            files.sort()
            for f in files:
                target_files.append(os.path.join(root, f))

    for filepath in target_files:
        try:
            parser = ParserFactory.get_parser(filepath, cfg)
        except ValueError as err:
            logger.warning(
                f"Skipping unsupported file {filepath}: {err}",
                extra={"event_type": "unsupported_file_skipped", "filepath": filepath},
            )
            skipped.append({"filepath": filepath, "reason": "unsupported_format", "detail": str(err)})
            continue

        try:
            too_big = os.path.getsize(filepath) > parser.max_file_size_bytes
        except OSError:
            too_big = False
        if too_big:
            skipped.append({"filepath": filepath, "reason": "size_limit", "detail": f"over {cfg.max_file_size_mb}MB"})
            continue

        filename = os.path.basename(filepath)
        record_idx = 0

        for raw_record in parser.parse(filepath):
            if not isinstance(raw_record, dict) or not raw_record:
                continue

            # Normalize to ECS schema
            ecs_record = normalizer.normalize(raw_record)

            # Extract high-risk string fields for the LLM / semantic guardrail
            high_risk_ecs = normalizer.extract_high_risk_ecs(ecs_record)

            # Never drop a record unseen: injections hide in any field, so records
            # without a known high-risk field are scanned via their full original text.
            content = high_risk_ecs if high_risk_ecs else {"event.original": str(ecs_record.get("event.original", ""))}

            record_id = raw_record.get("_record_id") or raw_record.get("_record_key") or record_idx
            item = {
                "id": f"{filename}_{record_id}",
                "artifact_source": filename,
                "filepath": filepath,
                "content": content,
                "ecs": ecs_record,
            }
            record_idx += 1
            yield item

        for err in parser.errors:
            skipped.append({"filepath": filepath, "reason": "parse_error", "detail": err})
