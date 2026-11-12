"""Memory-efficient streaming CSV parser for forensic artifacts."""

import csv
import sys
from typing import Any, Dict, Iterator, Optional

from src.config import Config
from src.logger import get_logger
from src.parsers.base_parser import BaseForensicParser

logger = get_logger("dfir_guardrail.parsers.csv")

# Safely expand CSV field size limit for large DFIR script blocks and memory dumps
_max_limit = sys.maxsize
while True:
    try:
        csv.field_size_limit(_max_limit)
        break
    except OverflowError:
        _max_limit = int(_max_limit / 10)


class CSVStreamingParser(BaseForensicParser):
    """Memory-efficient streaming parser for KAPE, Velociraptor, and generic forensic CSVs."""

    def __init__(self, config: Optional[Config] = None):
        super().__init__(config)

    def _open_file(self, filepath: str):
        """Open file trying common DFIR encodings (utf-8-sig, utf-8, latin-1)."""
        encodings = ["utf-8-sig", "utf-8", "latin-1"]
        for enc in encodings:
            try:
                f = open(filepath, "r", encoding=enc, errors="replace", newline="")
                # Test read header line to verify
                pos = f.tell()
                f.readline()
                f.seek(pos)
                return f
            except Exception:
                continue
        return open(filepath, "r", encoding="utf-8", errors="replace", newline="")

    def parse(self, filepath: str) -> Iterator[Dict[str, Any]]:
        """Stream forensic records from CSV file line-by-line using csv.DictReader.

        Guarantees O(1) memory consumption regardless of row count.
        """
        if not self.validate_file_size(filepath):
            return

        f = None
        try:
            f = self._open_file(filepath)
            # Detect delimiter (comma or tab or semicolon)
            sample = f.read(4096)
            f.seek(0)
            delimiter = ","
            if sample:
                try:
                    dialect = csv.Sniffer().sniff(sample, delimiters=",\t;")
                    delimiter = dialect.delimiter
                except Exception:
                    if "\t" in sample and sample.count("\t") > sample.count(","):
                        delimiter = "\t"

            reader = csv.DictReader(f, delimiter=delimiter)
            for row_idx, row in enumerate(reader, start=1):
                if not row:
                    continue
                # Clean up None keys or whitespace in values
                clean_row = {
                    (k.strip() if isinstance(k, str) else str(k)): (
                        v.strip() if isinstance(v, str) else v
                    )
                    for k, v in row.items()
                    if k is not None
                }
                # Skip completely blank lines
                if any(clean_row.values()):
                    yield clean_row
        except Exception as e:
            self.errors.append(str(e))
            logger.error(
                f"Error parsing CSV file {filepath}: {e}",
                extra={"event_type": "csv_parse_error", "filepath": filepath, "error": str(e)},
            )
        finally:
            if f and not f.closed:
                f.close()
