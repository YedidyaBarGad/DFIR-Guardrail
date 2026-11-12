"""Modular EVTX parser for Windows Event Log formats with streaming fallback."""

import os
import re
import struct
from defusedxml import ElementTree as ET
from typing import Any, Dict, Iterator, Optional

from src.config import Config
from src.logger import get_logger
from src.parsers.base_parser import BaseForensicParser
from src.parsers.xml_parser import XMLStreamingParser, _element_to_dict

logger = get_logger("dfir_guardrail.parsers.evtx")

# Check for python-evtx library
EVTX_MODULE = None
try:
    import Evtx.Evtx as EvtxModule

    EVTX_MODULE = EvtxModule
except ImportError:
    try:
        import evtx as EvtxModule

        EVTX_MODULE = EvtxModule
    except ImportError:
        EVTX_MODULE = None


class EVTXStreamingParser(BaseForensicParser):
    """Memory-efficient parser for Windows Event Log (.evtx) files and event streams."""

    EVTX_MAGIC = b"ElfFile\x00"
    CHUNK_MAGIC = b"ElfChnk\x00"
    RECORD_MAGIC = b"\x2a\x2a\x00\x00"

    def __init__(self, config: Optional[Config] = None):
        super().__init__(config)

    def _parse_with_library(self, filepath: str) -> Iterator[Dict[str, Any]]:
        """Stream events using python-evtx library if installed."""
        try:
            with EVTX_MODULE.Evtx(filepath) as evtx_file:
                for record in evtx_file.records():
                    try:
                        xml_str = record.xml()
                        root = ET.fromstring(xml_str)
                        record_dict = _element_to_dict(root)
                        record_dict["_record_id"] = record.record_num()
                        yield record_dict
                    except Exception as rec_err:
                        logger.warning(
                            f"Skipping malformed EVTX record in {filepath}: {rec_err}",
                            extra={
                                "event_type": "evtx_record_error",
                                "filepath": filepath,
                            },
                        )
        except Exception as e:
            self.errors.append(str(e))
            logger.error(
                f"Error in python-evtx library parser for {filepath}: {e}",
                extra={
                    "event_type": "evtx_library_error",
                    "filepath": filepath,
                    "error": str(e),
                },
            )

    def _extract_xml_from_bytes(self, data: bytes) -> Iterator[Dict[str, Any]]:
        """Extract and parse XML fragments (<Event>...</Event>) embedded in raw binary data."""
        # Check UTF-8 XML patterns
        xml_pattern_utf8 = re.compile(rb"<Event[\s\S]*?<\/Event>", re.IGNORECASE)
        for match in xml_pattern_utf8.finditer(data):
            try:
                xml_text = match.group(0).decode("utf-8", errors="replace")
                root = ET.fromstring(xml_text)
                yield _element_to_dict(root)
            except Exception:
                pass

        # Check UTF-16LE XML patterns (common in Windows Event Log BinXml memory buffers)
        xml_pattern_utf16 = re.compile(
            rb"<\x00E\x00v\x00e\x00n\x00t[\s\S]*?<\x00/\x00E\x00v\x00e\x00n\x00t\x00>",
            re.IGNORECASE,
        )
        for match in xml_pattern_utf16.finditer(data):
            try:
                xml_text = match.group(0).decode("utf-16le", errors="replace")
                root = ET.fromstring(xml_text)
                yield _element_to_dict(root)
            except Exception:
                pass

    def _parse_fallback_binary(self, filepath: str) -> Iterator[Dict[str, Any]]:
        """Fallback streaming parser scanning EVTX chunks and extracting structured records."""
        yielded_any = False
        try:
            with open(filepath, "rb") as f:
                # Read file header (4096 bytes)
                header = f.read(4096)
                if not header.startswith(self.EVTX_MAGIC):
                    logger.warning(
                        f"EVTX header magic missing in {filepath}, proceeding with payload scanning",
                        extra={
                            "event_type": "evtx_magic_missing",
                            "filepath": filepath,
                        },
                    )

                chunk_idx = 0
                record_counter = 0

                while True:
                    # Chunks are 65536 bytes (64 KB)
                    chunk_data = f.read(65536)
                    if not chunk_data:
                        break
                    chunk_idx += 1

                    # 1. Try extracting any embedded XML events from the chunk
                    chunk_events = list(self._extract_xml_from_bytes(chunk_data))
                    if chunk_events:
                        for evt in chunk_events:
                            yielded_any = True
                            record_counter += 1
                            evt["_record_id"] = record_counter
                            yield evt
                        continue

                    # 2. Parse binary EVTX record headers (0x00002a2a)
                    offset = 0
                    while offset < len(chunk_data) - 24:
                        pos = chunk_data.find(self.RECORD_MAGIC, offset)
                        if pos == -1:
                            break

                        try:
                            # Record structure:
                            # 0..4: Magic (0x00002a2a)
                            # 4..8: Record length (uint32)
                            # 8..16: Record ID (uint64)
                            # 16..24: Timestamp (FILETIME uint64)
                            if pos + 24 <= len(chunk_data):
                                rec_len = struct.unpack_from("<I", chunk_data, pos + 4)[
                                    0
                                ]
                                rec_id = struct.unpack_from("<Q", chunk_data, pos + 8)[
                                    0
                                ]

                                if 24 <= rec_len <= len(chunk_data) - pos:
                                    rec_body = chunk_data[pos + 24 : pos + rec_len]
                                    # Extract ASCII and UTF-16 strings from the record
                                    strings_ascii = [
                                        s.decode("ascii")
                                        for s in re.findall(
                                            rb"[\x20-\x7e]{4,}", rec_body
                                        )
                                    ]
                                    strings_utf16 = [
                                        s.decode("utf-16le")
                                        for s in re.findall(
                                            rb"(?:[\x20-\x7e]\x00){4,}", rec_body
                                        )
                                    ]
                                    all_strings = strings_ascii + strings_utf16

                                    record_dict: Dict[str, Any] = {
                                        "_record_id": rec_id,
                                        "event.original": " ".join(all_strings),
                                    }

                                    # Heuristically populate common fields if identified in strings
                                    for s in all_strings:
                                        s_low = s.lower()
                                        if s.endswith(".exe") or ".exe " in s_low:
                                            if (
                                                "process.command_line"
                                                not in record_dict
                                            ):
                                                record_dict["process.command_line"] = s
                                            elif (
                                                "process.executable" not in record_dict
                                            ):
                                                record_dict["process.executable"] = s
                                        elif "\\" in s and (
                                            ":" in s or s.startswith("\\")
                                        ):
                                            if "file.path" not in record_dict:
                                                record_dict["file.path"] = s

                                    yielded_any = True
                                    yield record_dict
                                    offset = pos + rec_len
                                    continue
                        except Exception:
                            pass

                        offset = pos + 4

            # If no binary records were identified, scan the entire file for any XML records
            if not yielded_any:
                logger.info(
                    f"No binary chunks matched in {filepath}, delegating to XML parser",
                    extra={"event_type": "evtx_xml_fallback", "filepath": filepath},
                )
                xml_parser = XMLStreamingParser(self.config)
                yield from xml_parser.parse(filepath)

        except Exception as e:
            self.errors.append(str(e))
            logger.error(
                f"Error in fallback EVTX parsing for {filepath}: {e}",
                extra={
                    "event_type": "evtx_fallback_error",
                    "filepath": filepath,
                    "error": str(e),
                },
            )

    def parse(self, filepath: str) -> Iterator[Dict[str, Any]]:
        """Stream event log records from EVTX or event log export.

        Prefers python-evtx if installed, otherwise uses robust binary/XML chunk scanner.
        If the file content is XML, routes seamlessly to XML streaming.
        """
        if not self.validate_file_size(filepath):
            return

        # Check if the file is actually an XML-formatted export
        try:
            with open(filepath, "rb") as f:
                prefix = f.read(512).strip()
                if prefix.startswith(
                    (b"<?xml", b"<Events", b"<Event", b"<\x00?\x00x\x00m\x00l")
                ):
                    xml_parser = XMLStreamingParser(self.config)
                    yield from xml_parser.parse(filepath)
                    return
        except Exception:
            pass

        if EVTX_MODULE is not None:
            yield from self._parse_with_library(filepath)
        else:
            yield from self._parse_fallback_binary(filepath)
