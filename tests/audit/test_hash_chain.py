"""
tests/audit/test_hash_chain.py - Audit JSONL hash-chain integrity tests.

Covers:
    * Empty file -> ok=True, lines=0
    * Genuine logged chain -> ok=True, every line verified
    * Tampered entry payload -> failure detected at the tampered line
    * Tampered prev_hash -> failure detected
    * Reordered lines -> failure detected
    * Truncated chain -> ok up to truncation point
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from forge.audit.logger import AuditLogger
from forge.audit.models import AuditEntry, AuditEventType
from forge.audit.verifier import verify_audit_log


def _make_entry(i: int) -> AuditEntry:
    return AuditEntry(
        correlation_id=f"cid-{i}",
        event_type=AuditEventType.TOOL_INVOCATION,
        agent_role="recon",
        tool_name=f"tool-{i}",
        success=True,
        output_summary=f"summary-{i}",
    )


@pytest.mark.asyncio
async def test_empty_file_verifies_ok(tmp_path: Path) -> None:
    p = tmp_path / "empty.jsonl"
    p.write_text("")
    result = verify_audit_log(p)
    assert result.ok is True
    assert result.lines_checked == 0


@pytest.mark.asyncio
async def test_real_chain_verifies(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path=p)
    for i in range(20):
        await logger.log(_make_entry(i))
    await logger.close()

    result = verify_audit_log(p)
    assert result.ok is True, f"verification failed: {result}"
    assert result.lines_checked == 20


@pytest.mark.asyncio
async def test_tampered_payload_detected(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path=p)
    for i in range(5):
        await logger.log(_make_entry(i))
    await logger.close()

    # Tamper with line 3: change the entry's output_summary.
    lines = p.read_text(encoding="utf-8").splitlines()
    wrapper = json.loads(lines[2])
    wrapper["entry"]["output_summary"] = "TAMPERED"
    lines[2] = json.dumps(wrapper, separators=(",", ":"))
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = verify_audit_log(p)
    assert result.ok is False
    assert result.failure_line == 3
    assert result.failure_reason and "entry_hash mismatch" in result.failure_reason


@pytest.mark.asyncio
async def test_tampered_prev_hash_detected(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path=p)
    for i in range(5):
        await logger.log(_make_entry(i))
    await logger.close()

    # Forge prev_hash on line 3.
    lines = p.read_text(encoding="utf-8").splitlines()
    wrapper = json.loads(lines[2])
    wrapper["prev_hash"] = "f" * 64
    lines[2] = json.dumps(wrapper, separators=(",", ":"))
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = verify_audit_log(p)
    assert result.ok is False
    assert result.failure_line == 3
    # Either prev_hash mismatch or recompute mismatch is acceptable proof.
    assert result.failure_reason and (
        "prev_hash mismatch" in result.failure_reason
        or "entry_hash mismatch" in result.failure_reason
    )


@pytest.mark.asyncio
async def test_swapped_lines_detected(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path=p)
    for i in range(5):
        await logger.log(_make_entry(i))
    await logger.close()

    lines = p.read_text(encoding="utf-8").splitlines()
    lines[1], lines[2] = lines[2], lines[1]
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = verify_audit_log(p)
    assert result.ok is False
    # Swap will be detected at line 2 (first one with wrong prev_hash).
    assert result.failure_line == 2


@pytest.mark.asyncio
async def test_truncated_chain_verifies_to_cut(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path=p)
    for i in range(10):
        await logger.log(_make_entry(i))
    await logger.close()

    # Truncate to first 5 lines - the chain should still verify cleanly.
    lines = p.read_text(encoding="utf-8").splitlines()
    p.write_text("\n".join(lines[:5]) + "\n", encoding="utf-8")

    result = verify_audit_log(p)
    assert result.ok is True
    assert result.lines_checked == 5


@pytest.mark.asyncio
async def test_disabled_chain_does_not_break_existing_callers(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path=p, hash_chain=False)
    for i in range(3):
        await logger.log(_make_entry(i))
    await logger.close()

    # When chain is disabled, lines are raw entry JSON (no wrapper). The
    # verifier should reject this cleanly, not crash.
    result = verify_audit_log(p)
    assert result.ok is False
    assert result.failure_line == 1
    assert result.failure_reason and "wrapper keys" in result.failure_reason
