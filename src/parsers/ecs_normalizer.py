"""Elastic Common Schema (ECS) Normalizer for DFIR forensic artifacts.

Standardizes disparate forensic event logs (Windows Event Log, Sysmon, KAPE,
Velociraptor, Amcache, Prefetch) into standard Elastic Common Schema fields,
guaranteeing backward compatibility and high-risk field extraction.
"""

import json
from typing import Any, Dict, List, Optional, Set


class ECSNormalizer:
    """Normalizes forensic artifact dictionaries to Elastic Common Schema (ECS)."""

    # Field mapping rules: normalized ECS field -> list of source synonyms (normalized lowercase without separators)
    FIELD_SYNONYMS: Dict[str, List[str]] = {
        "process.command_line": [
            "process.command_line",
            "commandline",
            "command_line",
            "processcommandline",
            "commandlinearguments",
            "scriptblocktext",
            "arguments",
            "args",
            "cmdline",
            "process_cmdline",
        ],
        "process.executable": [
            "process.executable",
            "image",
            "imagepath",
            "executablepath",
            "newprocessname",
            "processpath",
            "binarypath",
            "exepath",
            "executable",
            "exe",
        ],
        "process.name": [
            "process.name",
            "processname",
            "process_name",
            "originalfilename",
            "imagename",
            "appname",
            "applicationname",
            "programname",
        ],
        "process.parent.command_line": [
            "process.parent.command_line",
            "parentcommandline",
            "parent_command_line",
            "parentprocesscommandline",
            "parentcmdline",
            "parent_cmdline",
        ],
        "process.parent.executable": [
            "process.parent.executable",
            "parentimage",
            "parentprocessname",
            "parentexecutable",
            "parent_executable",
            "parentprocesspath",
        ],
        "file.path": [
            "file.path",
            "targetfilename",
            "targetfilepath",
            "filepath",
            "file_path",
            "filefullpath",
            "destinationpath",
            "fullpath",
            "path",
        ],
        "file.name": [
            "file.name",
            "filename",
            "file_name",
            "basefilename",
            "name",
        ],
        "file.description": [
            "file.description",
            "filedescription",
            "file_description",
            "description",
        ],
        "message": [
            "message",
            "msg",
            "details",
            "payloaddata",
            "payload",
            "formattedmessage",
            "eventdata_message",
        ],
        "event.original": [
            "event.original",
            "raw",
            "rawxml",
            "originalevent",
            "rawevent",
        ],
        "user.name": [
            "user.name",
            "subjectusername",
            "targetusername",
            "username",
            "user_name",
            "accountname",
            "user",
            "usersid",
        ],
        "host.name": [
            "host.name",
            "computername",
            "computer",
            "hostname",
            "host_name",
            "machinename",
            "sourcehost",
        ],
    }

    # High-risk ECS fields prioritized for prompt injection and malicious payload guardrail inspection
    HIGH_RISK_ECS_FIELDS: List[str] = [
        "process.command_line",
        "process.executable",
        "process.name",
        "process.parent.command_line",
        "process.parent.executable",
        "file.path",
        "file.name",
        "file.description",
        "message",
    ]

    def __init__(self):
        # Precompile inverted lookup table for fast O(1) matching: normalized_clean_key -> ecs_key
        self._lookup: Dict[str, str] = {}
        for ecs_key, synonyms in self.FIELD_SYNONYMS.items():
            for syn in synonyms:
                clean_syn = self._clean_key(syn)
                self._lookup[clean_syn] = ecs_key

    @staticmethod
    def _clean_key(key: str) -> str:
        """Strip non-alphanumeric chars and lowercase for canonical matching."""
        return "".join(c for c in key.lower() if c.isalnum() or c == ".")

    @classmethod
    def normalize_record(cls, raw_record: Dict[str, Any]) -> Dict[str, Any]:
        """Class method convenience wrapper for normalize."""
        return cls().normalize(raw_record)

    def normalize(self, raw_record: Dict[str, Any]) -> Dict[str, Any]:
        """Map arbitrary forensic artifact dictionary to standard ECS fields.

        Preserves unmapped fields under 'custom' or 'labels' to ensure zero data loss.
        Populates both standard flat dotted keys (e.g. 'process.command_line') and
        hierarchical dictionary structures (e.g. record['process']['command_line']).
        """
        if not isinstance(raw_record, dict):
            return {}

        ecs_record: Dict[str, Any] = {}
        custom_fields: Dict[str, Any] = {}
        labels_fields: Dict[str, Any] = (
            dict(raw_record.get("labels", {})) if isinstance(raw_record.get("labels"), dict) else {}
        )

        # Retain pre-existing custom fields if already structured
        if isinstance(raw_record.get("custom"), dict):
            custom_fields.update(raw_record["custom"])

        # Flatten nested EventData or System if present (common in Windows Event XML)
        flattened_items: List[tuple] = []
        for k, v in raw_record.items():
            if k in ("custom", "labels"):
                continue
            if isinstance(v, dict) and k.lower() in ("eventdata", "system", "event"):
                for sub_k, sub_v in v.items():
                    flattened_items.append((f"{k}.{sub_k}", sub_v))
            else:
                flattened_items.append((k, v))

        mapped_ecs_fields: Dict[str, Any] = {}

        for orig_key, value in flattened_items:
            clean_k = self._clean_key(orig_key)
            ecs_key = self._lookup.get(clean_k)

            # Check if orig_key without prefix matches (e.g. EventData.CommandLine -> commandline)
            if not ecs_key and "." in orig_key:
                clean_suffix = self._clean_key(orig_key.split(".")[-1])
                ecs_key = self._lookup.get(clean_suffix)

            if ecs_key:
                # Do not overwrite if already set by a more direct key
                if value not in (None, ""):
                    if ecs_key not in mapped_ecs_fields:
                        mapped_ecs_fields[ecs_key] = value
                    elif mapped_ecs_fields[ecs_key] != value:
                        # Keep the second synonym so it is still scanned
                        custom_fields[orig_key] = value
            else:
                if value not in (None, ""):
                    custom_fields[orig_key] = value

        # Set flat ECS keys
        for ecs_key, val in mapped_ecs_fields.items():
            ecs_record[ecs_key] = val

        # Ensure event.original is populated
        if "event.original" not in ecs_record:
            if "event.original" in raw_record:
                ecs_record["event.original"] = raw_record["event.original"]
            else:
                try:
                    ecs_record["event.original"] = json.dumps(raw_record, default=str)
                except Exception:
                    ecs_record["event.original"] = str(raw_record)

        # Ensure hierarchical / nested dictionary structure without breaking flat keys
        self._inject_nested_structures(ecs_record)

        # Attach custom and labels
        if custom_fields:
            ecs_record["custom"] = custom_fields
        if labels_fields:
            ecs_record["labels"] = labels_fields

        return ecs_record

    def _inject_nested_structures(self, record: Dict[str, Any]) -> None:
        """Create nested dictionary representations corresponding to flat dotted keys."""
        for flat_key, val in list(record.items()):
            if "." in flat_key:
                parts = flat_key.split(".")
                curr = record
                for part in parts[:-1]:
                    if part not in curr or not isinstance(curr[part], dict):
                        curr[part] = {}
                    curr = curr[part]
                curr[parts[-1]] = val

    def extract_high_risk_ecs(self, ecs_record: Dict[str, Any]) -> Dict[str, Any]:
        """Extract only normalized fields containing strings to be inspected by the guardrail.

        Inspects standard high-risk fields (process, file, message) and any
        suspicious string fields in custom payloads.
        """
        if not isinstance(ecs_record, dict):
            return {}

        extracted: Dict[str, Any] = {}

        # 1. Check direct flat high-risk keys
        for key in self.HIGH_RISK_ECS_FIELDS:
            val = ecs_record.get(key)
            if val is not None and isinstance(val, str) and val.strip():
                extracted[key] = val.strip()

        # 2. Check nested structures if flat keys were absent
        if "process" in ecs_record and isinstance(ecs_record["process"], dict):
            proc = ecs_record["process"]
            if "command_line" in proc and "process.command_line" not in extracted:
                if isinstance(proc["command_line"], str) and proc["command_line"].strip():
                    extracted["process.command_line"] = proc["command_line"].strip()
            if "executable" in proc and "process.executable" not in extracted:
                if isinstance(proc["executable"], str) and proc["executable"].strip():
                    extracted["process.executable"] = proc["executable"].strip()
            if "name" in proc and "process.name" not in extracted:
                if isinstance(proc["name"], str) and proc["name"].strip():
                    extracted["process.name"] = proc["name"].strip()
            if "parent" in proc and isinstance(proc["parent"], dict):
                parent = proc["parent"]
                if "command_line" in parent and "process.parent.command_line" not in extracted:
                    if isinstance(parent["command_line"], str) and parent["command_line"].strip():
                        extracted["process.parent.command_line"] = parent["command_line"].strip()
                if "executable" in parent and "process.parent.executable" not in extracted:
                    if isinstance(parent["executable"], str) and parent["executable"].strip():
                        extracted["process.parent.executable"] = parent["executable"].strip()

        if "file" in ecs_record and isinstance(ecs_record["file"], dict):
            f_dict = ecs_record["file"]
            for field in ("path", "name", "description"):
                ecs_f = f"file.{field}"
                if field in f_dict and ecs_f not in extracted:
                    if isinstance(f_dict[field], str) and f_dict[field].strip():
                        extracted[ecs_f] = f_dict[field].strip()

        if "message" in ecs_record and "message" not in extracted:
            val = ecs_record["message"]
            if isinstance(val, str) and val.strip():
                extracted["message"] = val.strip()

        # 3. Check custom payload fields for high-risk keys (e.g. script_block, payload)
        custom = ecs_record.get("custom")
        if isinstance(custom, dict):
            high_risk_custom_keywords = ("command", "payload", "script", "arguments", "powershell", "macro")
            for k, v in custom.items():
                if isinstance(v, str) and v.strip():
                    lower_k = k.lower()
                    if any(kw in lower_k for kw in high_risk_custom_keywords):
                        extracted[f"custom.{k}"] = v.strip()

        return extracted
