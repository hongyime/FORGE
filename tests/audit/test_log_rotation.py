"""
tests/audit/test_log_rotation.py - AuditLogger size-cap rotation tests.

Verifies:
    * Default behaviour (max_bytes=None) -> no rotation, single growing file.
    * max_bytes triggers rotation when total written exceeds cap.
    * backup_count caps the number of rolled files; oldest deleted.
    * Rotated files are self-contained hash chains (verifier passes per file).
    * Rotation under load doesn't lose entries.
    * Rotation when log file already exists picks up at the right size.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from forge.audit.logger import AuditLogger
from forge.audit.models import AuditEntry, AuditEventType
from forge.audit.verifier import verify_audit_log


def _entry(i: int) -> AuditEntry:
    return AuditEntry(
        correlation_id=f"cid-{i}",
        event_type=AuditEventType.MESSAGE_RECEIVED,
        agent_role="recon",
        tool_name=f"tool-{i}",
        success=True,
        # Pad with predictable bulk to make rotation deterministic.
        output_summary="x" * 200,
    )


@pytest.mark.asyncio
async def test_no_rotation_when_max_bytes_unset(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path=p)
    for i in range(50):
        await logger.log(_entry(i))
    await logger.close()
    # No .1 file produced.
    assert not (tmp_path / "audit.jsonl.1").exists()
    assert p.exists() and p.stat().st_size > 0


@pytest.mark.asyncio
async def test_rotation_triggers_when_cap_exceeded(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path=p, max_bytes=2_000, backup_count=3)
    for i in range(50):
        await logger.log(_entry(i))
    await logger.close()
    # At least one rotation should have happened.
    assert (tmp_path / "audit.jsonl.1").exists()


@pytest.mark.asyncio
async def test_backup_count_caps_rolled_files(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path=p, max_bytes=500, backup_count=2)
    for i in range(100):
        await logger.log(_entry(i))
    await logger.close()
    # backup_count=2 means at most audit.jsonl.1 and audit.jsonl.2
    assert (tmp_path / "audit.jsonl.1").exists()
    assert (tmp_path / "audit.jsonl.2").exists()
    # No .3 file should exist.
    assert not (tmp_path / "audit.jsonl.3").exists()


@pytest.mark.asyncio
async def test_rotated_files_each_have_valid_hash_chain(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path=p, max_bytes=1_500, backup_count=3)
    for i in range(60):
        await logger.log(_entry(i))
    await logger.close()
    # Each existing log file must independently verify.
    files = [p] + [
        tmp_path / f"audit.jsonl.{i}" for i in (1, 2, 3)
        if (tmp_path / f"audit.jsonl.{i}").exists()
    ]
    assert len(files) >= 2  # at least one rotation happened
    for f in files:
        result = verify_audit_log(f)
        assert result.ok, f"{f.name} chain broken: {result.failure_reason}"
        assert result.lines_checked > 0


@pytest.mark.asyncio
async def test_no_entries_lost_across_rotation(tmp_path: Path) -> None:
    """When backup_count is large enough to hold all rolled files, no entries are lost."""
    p = tmp_path / "audit.jsonl"
    # Each entry is ~500-600 bytes. Use small max_bytes to force rotation,
    # but generous backup_count so nothing is purged.
    logger = AuditLogger(log_path=p, max_bytes=1_500, backup_count=20)
    n = 30
    for i in range(n):
        await logger.log(_entry(i))
    await logger.close()
    files = [p]
    for i in range(1, 21):
        rotated = tmp_path / f"audit.jsonl.{i}"
        if rotated.exists():
            files.append(rotated)
    total_lines = 0
    for f in files:
        total_lines += sum(1 for _ in f.read_text(encoding="utf-8").splitlines() if _)
    assert total_lines == n, f"got {total_lines} lines across {len(files)} files, want {n}"


@pytest.mark.asyncio
async def test_max_bytes_zero_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        AuditLogger(log_path=tmp_path / "x.jsonl", max_bytes=0)


@pytest.mark.asyncio
async def test_existing_file_size_is_picked_up(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    # Pre-populate file beyond the cap so the very NEXT write rotates.
    p.write_text("x" * 5_000, encoding="utf-8")
    logger = AuditLogger(log_path=p, max_bytes=1_000, backup_count=2)
    await logger.log(_entry(0))
    await logger.close()
    # The pre-existing junk gets rolled into .1.
    assert (tmp_path / "audit.jsonl.1").exists()
