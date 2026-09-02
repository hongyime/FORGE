"""Unit tests for forge.report.persistence_audit (E1.2)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from forge.report.persistence_audit import (
    DEFAULT_RECURRING_THRESHOLD,
    PersistenceFinding,
    PersistenceFindings,
    Severity,
    render_markdown,
    scan_for_persistence_patterns,
)


REF = datetime(2026, 6, 1, 9, 0, 0, tzinfo=timezone.utc)


def _entry(
    ts: datetime,
    *,
    tool: str,
    event_type: str = "tool_invocation",
    input_params: dict | None = None,
    correlation_id: str = "corr-1",
    agent_role: str = "operator",
    wrap: bool = False,
) -> dict:
    """Build one JSONL record. When wrap=True, use the hash-chain shape."""
    entry = {
        "timestamp_utc": ts.timestamp(),
        "sequence_number": 0,
        "correlation_id": correlation_id,
        "event_type": event_type,
        "agent_role": agent_role,
        "tool_name": tool,
        "input_params": input_params or {},
        "output_summary": None,
        "duration_ms": None,
        "success": True,
        "error_detail": None,
    }
    if wrap:
        return {"entry": entry, "prev_hash": "0" * 64, "entry_hash": "1" * 64}
    return entry


def _write_log(path: Path, records: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec) + "\n")


# ---------------------------------------------------------------------------
# Pattern detection
# ---------------------------------------------------------------------------


def test_detects_scheduled_task_pattern(tmp_path: Path) -> None:
    """Same tool at the same minute across multiple days is flagged."""
    log = tmp_path / "audit.jsonl"
    records = [
        _entry(
            REF + timedelta(days=d, seconds=s),
            tool="probe_beacon",
            input_params={"target": "10.0.0.5"},
        )
        for d in range(3)
        for s in range(0, DEFAULT_RECURRING_THRESHOLD)
    ]
    _write_log(log, records)

    result = scan_for_persistence_patterns(log, engagement_id=42)

    recurring = [f for f in result.findings if f.pattern_type == "recurring_action"]
    assert recurring, "expected at least one recurring_action finding"
    assert any(f.action == "probe_beacon" for f in recurring)
    assert result.total_events_scanned == len(records)


def test_detects_service_create_event(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    _write_log(
        log,
        [
            _entry(
                REF,
                tool="cmd_exec",
                input_params={"command": "sc create EvilSvc binPath= C:\\evil.exe"},
            )
        ],
    )
    result = scan_for_persistence_patterns(log, engagement_id=1)
    kinds = {f.pattern_type for f in result.findings}
    assert "service_event" in kinds
    svc = next(f for f in result.findings if f.pattern_type == "service_event")
    assert svc.severity is Severity.HIGH
    assert "sc create" in svc.evidence.lower()


def test_detects_registry_autorun_modification(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    _write_log(
        log,
        [
            _entry(
                REF,
                tool="registry_write",
                input_params={
                    "path": (
                        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
                        r"\Updater"
                    ),
                    "value": r"C:\Users\x\payload.exe",
                },
                wrap=True,  # exercise hash-chain wrapper path
            )
        ],
    )
    result = scan_for_persistence_patterns(log, engagement_id=7)
    reg = [f for f in result.findings if f.pattern_type == "registry_autorun"]
    assert reg, "expected registry_autorun finding"
    assert reg[0].severity is Severity.HIGH


def test_detects_startup_folder_write(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    _write_log(
        log,
        [
            _entry(
                REF,
                tool="file_write",
                input_params={
                    "path": (
                        r"C:\Users\bob\AppData\Roaming\Microsoft\Windows"
                        r"\Start Menu\Programs\Startup\hook.lnk"
                    )
                },
            )
        ],
    )
    result = scan_for_persistence_patterns(log, engagement_id=1)
    hits = [f for f in result.findings if f.pattern_type == "startup_folder"]
    assert hits
    assert hits[0].severity is Severity.HIGH


# ---------------------------------------------------------------------------
# Whitelist and severity filtering
# ---------------------------------------------------------------------------


def test_whitelist_suppresses_legitimate_admin_tool(tmp_path: Path) -> None:
    """A registry write from Windows Update must not be flagged."""
    log = tmp_path / "audit.jsonl"
    _write_log(
        log,
        [
            _entry(
                REF,
                tool="windows_update",
                input_params={
                    "path": r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\wu"
                },
            )
        ],
    )
    result = scan_for_persistence_patterns(log, engagement_id=1)
    assert result.findings == ()


def test_custom_whitelist_replaces_default(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    _write_log(
        log,
        [
            _entry(
                REF,
                tool="deploy_agent",
                input_params={
                    "path": r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\svc"
                },
            )
        ],
    )
    result = scan_for_persistence_patterns(
        log, engagement_id=1, whitelist=("deploy_agent",)
    )
    assert result.findings == ()


def test_min_severity_filter(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    # Recurring only (MEDIUM) + one HIGH service event.
    recs = [
        _entry(REF + timedelta(days=d), tool="probe", correlation_id="c")
        for d in range(DEFAULT_RECURRING_THRESHOLD)
    ]
    recs.append(
        _entry(
            REF + timedelta(hours=1),
            tool="cmd",
            input_params={"command": "sc create X binPath= x"},
        )
    )
    _write_log(log, recs)

    high_only = scan_for_persistence_patterns(
        log, engagement_id=1, min_severity=Severity.HIGH
    )
    assert high_only.findings
    assert all(f.severity is Severity.HIGH for f in high_only.findings)


# ---------------------------------------------------------------------------
# Time filtering
# ---------------------------------------------------------------------------


def test_time_range_filter_excludes_out_of_window(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    inside = _entry(
        REF,
        tool="cmd",
        input_params={"command": "sc create A binPath= a"},
    )
    outside = _entry(
        REF + timedelta(days=30),
        tool="cmd",
        input_params={"command": "sc create B binPath= b"},
    )
    _write_log(log, [inside, outside])

    result = scan_for_persistence_patterns(
        log,
        engagement_id=1,
        time_start=REF - timedelta(hours=1),
        time_end=REF + timedelta(hours=1),
    )
    assert len(result.findings) == 1
    assert "sc create a" in result.findings[0].evidence


# ---------------------------------------------------------------------------
# Severity scoring
# ---------------------------------------------------------------------------


def test_severity_scoring_ranks_correctly() -> None:
    assert Severity.HIGH.rank > Severity.MEDIUM.rank > Severity.LOW.rank


def test_registry_and_startup_are_high(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    _write_log(
        log,
        [
            _entry(
                REF,
                tool="reg_write",
                input_params={
                    "path": r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\A"
                },
            ),
            _entry(
                REF + timedelta(seconds=1),
                tool="file_write",
                input_params={
                    "path": r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\x.lnk"
                },
            ),
        ],
    )
    result = scan_for_persistence_patterns(log, engagement_id=1)
    assert len(result.findings) == 2
    assert {f.severity for f in result.findings} == {Severity.HIGH}


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------


def test_markdown_contains_required_section_and_columns(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    _write_log(
        log,
        [
            _entry(
                REF,
                tool="cmd",
                input_params={"command": "sc create Bad binPath= c:\\bad.exe"},
            )
        ],
    )
    result = scan_for_persistence_patterns(log, engagement_id=1)
    md = render_markdown(result)

    assert md.startswith("## Potential Persistence Indicators")
    assert "| Severity |" in md
    assert "| Pattern |" in md
    assert "| Recommendation |" in md
    assert "HIGH" in md
    assert "Service create/modify" in md
    assert "engagement" in md.lower()


def test_markdown_empty_findings_renders_placeholder(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    _write_log(log, [_entry(REF, tool="benign_probe")])
    result = scan_for_persistence_patterns(log, engagement_id=1)
    md = render_markdown(result)
    assert "No persistence indicators detected" in md


# ---------------------------------------------------------------------------
# Read-only contract
# ---------------------------------------------------------------------------


def test_scan_does_not_modify_audit_log(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    _write_log(
        log,
        [
            _entry(
                REF,
                tool="cmd",
                input_params={"command": "sc create X binPath= x"},
            )
        ],
    )
    before = log.read_bytes()
    before_mtime = log.stat().st_mtime_ns
    scan_for_persistence_patterns(log, engagement_id=1)
    assert log.read_bytes() == before
    assert log.stat().st_mtime_ns == before_mtime


def test_missing_log_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        scan_for_persistence_patterns(tmp_path / "nope.jsonl", engagement_id=1)


def test_malformed_lines_are_skipped(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    log.write_text(
        "\n".join(
            [
                "not json at all",
                json.dumps(
                    _entry(
                        REF,
                        tool="cmd",
                        input_params={"command": "sc create A binPath= a"},
                    )
                ),
                "{broken",
                "",
            ]
        ),
        encoding="utf-8",
    )
    result = scan_for_persistence_patterns(log, engagement_id=1)
    assert len(result.findings) == 1


def test_returns_frozen_findings_container(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    _write_log(log, [_entry(REF, tool="benign_probe")])
    result = scan_for_persistence_patterns(log, engagement_id=99)
    assert isinstance(result, PersistenceFindings)
    with pytest.raises((AttributeError, Exception)):
        result.findings = ()  # type: ignore[misc]
