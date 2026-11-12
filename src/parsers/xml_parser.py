"""Memory-efficient streaming XML parser for Windows Event Log and forensic XML exports."""

import xml.etree.ElementTree as ET  # types only; parsing uses defusedxml

from defusedxml import ElementTree as SafeET
from typing import Any, Dict, Iterator, Optional

from src.config import Config
from src.logger import get_logger
from src.parsers.base_parser import BaseForensicParser

logger = get_logger("dfir_guardrail.parsers.xml")


def _strip_ns(tag: str) -> str:
    """Strip XML namespace prefix from tag name."""
    if tag.startswith("{"):
        return tag.split("}", 1)[1]
    return tag


def _element_to_dict(elem: ET.Element) -> Dict[str, Any]:
    """Recursively convert an XML element tree into a clean Python dictionary.

    Specially handles Windows Event Log XML structures such as:
    <EventData><Data Name="CommandLine">cmd.exe</Data></EventData>
    """
    res: Dict[str, Any] = {}

    # Include element attributes if present
    for attr_k, attr_v in elem.attrib.items():
        clean_attr = _strip_ns(attr_k)
        res[clean_attr] = attr_v

    # Process child elements
    data_items: Dict[str, Any] = {}
    has_children = False

    for child in elem:
        has_children = True
        child_tag = _strip_ns(child.tag)

        # Handle Windows EventData <Data Name="...">value</Data> pattern
        if child_tag.lower() == "data" and "Name" in child.attrib:
            data_name = child.attrib["Name"]
            data_val = child.text.strip() if child.text else ""
            data_items[data_name] = data_val
            continue

        child_dict = _element_to_dict(child)

        # If child has no attributes/children and only text, collapse to string
        if not child.attrib and len(child) == 0:
            val = child.text.strip() if child.text else ""
        else:
            val = child_dict
            # If child has both text and child elements/attributes
            if child.text and child.text.strip():
                if isinstance(val, dict):
                    val["#text"] = child.text.strip()

        if child_tag in res:
            # If multiple children share the same tag, collect into list
            existing = res[child_tag]
            if isinstance(existing, list):
                existing.append(val)
            else:
                res[child_tag] = [existing, val]
        else:
            res[child_tag] = val

    if data_items:
        # Merge <Data Name="..."> fields directly for easier access
        res.update(data_items)

    # Promote EventData sub-keys to top level for convenient direct access
    for container_key in ("EventData", "eventdata"):
        if container_key in res and isinstance(res[container_key], dict):
            for sub_k, sub_v in res[container_key].items():
                if sub_k not in res:
                    res[sub_k] = sub_v

    # If element has text and no children, store text
    if not has_children and elem.text and elem.text.strip():
        res["#text"] = elem.text.strip()

    return res


class XMLStreamingParser(BaseForensicParser):
    """Memory-efficient streaming parser for XML forensic exports using iterparse."""

    def __init__(self, config: Optional[Config] = None):
        super().__init__(config)

    def parse(self, filepath: str) -> Iterator[Dict[str, Any]]:
        """Stream forensic records from XML file with O(1) memory overhead.

        Uses xml.etree.ElementTree.iterparse and clears processed elements and root
        to eliminate memory bloat on large multi-gigabyte event log dumps.
        """
        if not self.validate_file_size(filepath):
            return

        try:
            context = SafeET.iterparse(filepath, events=("start", "end"))
            root: Optional[ET.Element] = None
            depth = 0
            records_yielded = 0

            # Target tags common in forensic exports
            known_record_tags = {
                "event",
                "record",
                "item",
                "row",
                "entry",
                "artifact",
                "logentry",
            }

            for event, elem in context:
                if event == "start":
                    if root is None:
                        root = elem
                    depth += 1
                elif event == "end":
                    depth -= 1
                    clean_tag = _strip_ns(elem.tag).lower()

                    # Yield if element is a known forensic record or a direct child of the root container
                    is_record = clean_tag in known_record_tags or (
                        depth == 1 and root is not None and elem is not root
                    )

                    if is_record:
                        record_dict = _element_to_dict(elem)
                        # Add tag name metadata if helpful
                        if "_tag" not in record_dict:
                            record_dict["_tag"] = _strip_ns(elem.tag)

                        records_yielded += 1
                        yield record_dict

                        # Critical: clear the element and purge from root to maintain constant memory
                        elem.clear()
                        if root is not None:
                            root.clear()

            # Handle case where the file is a single standalone record at root
            if records_yielded == 0 and root is not None:
                record_dict = _element_to_dict(root)
                if record_dict:
                    record_dict["_tag"] = _strip_ns(root.tag)
                    yield record_dict

        except Exception as e:
            self.errors.append(str(e))
            logger.error(
                f"Error parsing XML file {filepath}: {e}",
                extra={
                    "event_type": "xml_parse_error",
                    "filepath": filepath,
                    "error": str(e),
                },
            )
