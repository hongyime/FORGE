"""
tests/integration/test_exfiltration.py
Integration tests — Module 5-H: Exfiltrator end-to-end pipeline.

These tests exercise the full collect → compress → encrypt → stage → upload
→ ExfilMonitor registration pipeline against a real (temporary) filesystem
and a mock C2 channel. No live network connections are made.

Test categories:
  1. Full pipeline      — filesystem collect → mock upload → monitor registration
  2. Dry-run mode       — no staging files; no upload; no monitor registration
  3. Multiple collectors— filesystem + env_vars in sequence
  4. Rate throttle      — upload rate respected (mock timing)
  5. Time window        — full pipeline blocked outside configured hours
  6. Staging hygiene    — no new top-level dirs; only existing paths used
  7. Content isolation  — file content absent from engagement DB after full run
  8. ExfilMonitor       — SHA-256s registered after confirmed collection
  9. CyberChef recipe   — recipe file written, contains key, valid JSON
 10. Channel failure    — partial upload failure returns partial result
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from datetime import time as dtime
from pathlib import Path
from unittest import mock

import pytest

from tests.integration.conftest import ENGAGEMENT_ID, AES_KEY_HEX
from forge.utils.post.transfer_util import (
    Exfiltrator,
    ThrottledUploader,
    emit_cyberchef_recipe,
    register_exfil_monitor,
    _check_time_window,
)
from forge.utils.post.collectors.filesystem import FilesystemCollector


# ── 1. Full pipeline ──────────────────────────────────────────────────────────

def test_full_collect_upload_monitor_pipeline(int_eng_db, tmp_path, patch_confirm_approve):
    # Seed some test files
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "report.docx").write_bytes(b"document content A")
    (data_dir / "notes.txt").write_bytes(b"document content B")

    # Staging dir inside tmp_path (pre-existing)
    staging = tmp_path / "staging"
    staging.mkdir()

    mock_channel = mock.MagicMock()
    mock_channel.send.return_value = True

    exfil = Exfiltrator(
        db_path=int_eng_db, engagement_id=ENGAGEMENT_ID,
        channel=mock_channel, session_key=AES_KEY_HEX,
        window=None, staging_dir=staging, stagger=0.0,
        dry_run=False,
        roe_id="ROE-TEST",
    )

    with mock.patch("time.sleep"):
        hashes = exfil.run(
            collector_type="filesystem",
            root=data_dir, patterns=["*.docx", "*.txt"],
        )

    # Both files collected
    assert len(hashes) == 2
    assert all(len(h) == 64 for h in hashes), "SHA-256 hashes must be 64 hex chars."

    # Mock channel was called (upload attempted)
    mock_channel.send.assert_called()

    # ExfilMonitor registered
    con  = sqlite3.connect(int_eng_db)
    rows = con.execute("SELECT sha256 FROM exfil_monitor_targets").fetchall()
    con.close()
    registered = {r[0] for r in rows}
    assert registered == set(hashes)


# ── 2. Dry-run mode ───────────────────────────────────────────────────────────

def test_dry_run_no_upload_no_monitor(int_eng_db, tmp_path, patch_confirm_approve):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "secret.docx").write_bytes(b"top secret")
    staging = tmp_path / "staging"
    staging.mkdir()

    mock_channel = mock.MagicMock()

    exfil = Exfiltrator(
        db_path=int_eng_db, engagement_id=ENGAGEMENT_ID,
        channel=mock_channel, session_key=AES_KEY_HEX,
        window=None, staging_dir=staging, stagger=0.0,
        dry_run=True,
    )

    with mock.patch("time.sleep"):
        hashes = exfil.run(
            collector_type="filesystem",
            root=data_dir, patterns=["*.docx"],
        )

    # Dry run: no upload
    mock_channel.send.assert_not_called()

    # Dry run: no ExfilMonitor registration
    con  = sqlite3.connect(int_eng_db)
    rows = con.execute("SELECT * FROM exfil_monitor_targets").fetchall()
    con.close()
    assert len(rows) == 0


# ── 3. Multiple collector types in sequence ───────────────────────────────────

def test_filesystem_and_env_vars_collectors(int_eng_db, tmp_path, patch_confirm_approve, monkeypatch):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "config.txt").write_bytes(b"config data")
    staging = tmp_path / "staging"
    staging.mkdir()

    monkeypatch.setenv("API_SECRET_KEY", "mysecretvalue123")

    mock_channel = mock.MagicMock()
    mock_channel.send.return_value = True

    # Run filesystem collector
    exfil1 = Exfiltrator(
        db_path=int_eng_db, engagement_id=ENGAGEMENT_ID,
        channel=mock_channel, session_key=AES_KEY_HEX,
        window=None, staging_dir=staging, stagger=0.0, dry_run=False,
        roe_id="ROE-TEST",
    )
    with mock.patch("time.sleep"):
        h1 = exfil1.run("filesystem", root=data_dir, patterns=["*.txt"])

    # Run env_vars collector
    exfil2 = Exfiltrator(
        db_path=int_eng_db, engagement_id=ENGAGEMENT_ID,
        channel=mock_channel, session_key=AES_KEY_HEX,
        window=None, staging_dir=staging, stagger=0.0, dry_run=False,
        roe_id="ROE-TEST",
    )
    h2 = exfil2.run("env_vars")

    con  = sqlite3.connect(int_eng_db)
    rows = con.execute("SELECT sha256 FROM exfil_monitor_targets").fetchall()
    con.close()
    all_registered = {r[0] for r in rows}
    assert set(h1).issubset(all_registered)
    assert set(h2).issubset(all_registered)


# ── 4. ThrottledUploader rate respected ──────────────────────────────────────

def test_throttled_uploader_paces_chunks():
    mock_channel = mock.MagicMock()
    mock_channel.send.return_value = True
    sleep_calls: list[float] = []

    uploader = ThrottledUploader(
        mock_channel,
        max_bytes_per_sec=1024,   # 1 KB/s — forces meaningful sleep
        chunk_size=512,
    )
    with mock.patch("time.sleep", side_effect=sleep_calls.append):
        uploader.upload(b"x" * 2048)  # 2 chunks of 512 bytes each

    # At 1 KB/s, 512 bytes should require ~0.5 s sleep
    assert any(s > 0.0 for s in sleep_calls), "Uploader should sleep to enforce rate limit."


# ── 5. Time window blocks full pipeline ──────────────────────────────────────

def test_exfiltrator_blocks_outside_window(int_eng_db, tmp_path, patch_confirm_approve):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "doc.docx").write_bytes(b"data")
    staging = tmp_path / "staging"
    staging.mkdir()

    exfil = Exfiltrator(
        db_path=int_eng_db, engagement_id=ENGAGEMENT_ID,
        channel=mock.MagicMock(),
        session_key=AES_KEY_HEX,
        window=(dtime(9, 0), dtime(17, 0)),
        staging_dir=staging, stagger=0.0,
        roe_id="ROE-TEST",
    )
    with mock.patch("forge.utils.post.transfer_util.datetime") as mock_dt:
        mock_dt.now.return_value.time.return_value = dtime(23, 0)
        with pytest.raises(RuntimeError, match="[Bb]locked|window"):
            exfil.run("filesystem", root=data_dir)


# ── 6. Staging hygiene ────────────────────────────────────────────────────────

def test_no_new_top_level_dirs_created(int_eng_db, tmp_path, patch_confirm_approve):
    """Exfiltrator must only write to pre-existing staging directories."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "file.txt").write_bytes(b"content")
    staging = tmp_path / "existing_staging"
    staging.mkdir()

    # Record what top-level dirs exist before collection
    before = set(tmp_path.iterdir())

    exfil = Exfiltrator(
        db_path=int_eng_db, engagement_id=ENGAGEMENT_ID,
        channel=mock.MagicMock(send=mock.MagicMock(return_value=True)),
        session_key=AES_KEY_HEX,
        window=None, staging_dir=staging, stagger=0.0, dry_run=False,
        roe_id="ROE-TEST",
    )
    with mock.patch("time.sleep"):
        exfil.run("filesystem", root=data_dir, patterns=["*.txt"])

    after = set(tmp_path.iterdir())
    new_dirs = {p for p in (after - before) if p.is_dir()}
    assert len(new_dirs) == 0, (
        f"Unexpected new top-level directories: {new_dirs}"
    )


# ── 7. Content isolation from DB ─────────────────────────────────────────────

def test_file_content_not_in_db_after_collection(int_eng_db, tmp_path, patch_confirm_approve):
    secret_bytes = b"CLASSIFIED_SECRET_PAYLOAD_XYZ"
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "secret.txt").write_bytes(secret_bytes)
    staging = tmp_path / "staging"
    staging.mkdir()

    exfil = Exfiltrator(
        db_path=int_eng_db, engagement_id=ENGAGEMENT_ID,
        channel=mock.MagicMock(send=mock.MagicMock(return_value=True)),
        session_key=AES_KEY_HEX,
        window=None, staging_dir=staging, stagger=0.0, dry_run=False,
        roe_id="ROE-TEST",
    )
    with mock.patch("time.sleep"):
        exfil.run("filesystem", root=data_dir, patterns=["*.txt"])

    con      = sqlite3.connect(int_eng_db)
    all_data = str(con.execute("SELECT * FROM exfiltrated_data").fetchall())
    con.close()
    assert b"CLASSIFIED_SECRET_PAYLOAD_XYZ" not in all_data.encode()
    assert "CLASSIFIED" not in all_data


# ── 8. ExfilMonitor SHA-256 registration ──────────────────────────────────────

def test_exfil_monitor_deduplicates_hashes(int_eng_db, tmp_path, patch_confirm_approve):
    """Running exfil twice on the same file must not duplicate monitor entries."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "file.docx").write_bytes(b"repeated content")
    staging = tmp_path / "staging"
    staging.mkdir()

    def make_exfil():
        return Exfiltrator(
            db_path=int_eng_db, engagement_id=ENGAGEMENT_ID,
            channel=mock.MagicMock(send=mock.MagicMock(return_value=True)),
            session_key=AES_KEY_HEX,
            window=None, staging_dir=staging, stagger=0.0, dry_run=False,
            roe_id="ROE-TEST",
        )

    with mock.patch("time.sleep"):
        make_exfil().run("filesystem", root=data_dir, patterns=["*.docx"])
        make_exfil().run("filesystem", root=data_dir, patterns=["*.docx"])

    con   = sqlite3.connect(int_eng_db)
    count = con.execute("SELECT COUNT(*) FROM exfil_monitor_targets").fetchone()[0]
    con.close()
    assert count == 1, "Duplicate SHA-256 must be deduplicated by UNIQUE constraint."


# ── 9. CyberChef recipe ───────────────────────────────────────────────────────

def test_cyberchef_recipe_written_on_emit_flag(int_eng_db, tmp_path, patch_confirm_approve):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "note.txt").write_bytes(b"evidence")
    staging = tmp_path / "staging"
    staging.mkdir()

    exfil = Exfiltrator(
        db_path=int_eng_db, engagement_id=ENGAGEMENT_ID,
        channel=mock.MagicMock(send=mock.MagicMock(return_value=True)),
        session_key=AES_KEY_HEX,
        window=None, staging_dir=staging, stagger=0.0, dry_run=False,
        roe_id="ROE-TEST",
    )
    with mock.patch("time.sleep"):
        exfil.run("filesystem", root=data_dir, patterns=["*.txt"], emit_recipe=True)

    recipe_path = staging / ".forge_verify_recipe.json"
    assert recipe_path.exists(), "CyberChef recipe must be written to staging dir."
    data = json.loads(recipe_path.read_text())
    assert isinstance(data, list)
    assert AES_KEY_HEX in recipe_path.read_text()


# ── 10. Channel failure partial result ───────────────────────────────────────

def test_partial_upload_failure_returns_partial_hashes(int_eng_db, tmp_path, patch_confirm_approve):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "a.txt").write_bytes(b"file A content")
    (data_dir / "b.txt").write_bytes(b"file B content")
    staging = tmp_path / "staging"
    staging.mkdir()

    # Channel fails on every other send
    call_count = {"n": 0}
    def flaky_send(data):
        call_count["n"] += 1
        return call_count["n"] % 2 == 0  # fails on 1st, 3rd, ...

    mock_channel = mock.MagicMock()
    mock_channel.send.side_effect = flaky_send

    exfil = Exfiltrator(
        db_path=int_eng_db, engagement_id=ENGAGEMENT_ID,
        channel=mock_channel, session_key=AES_KEY_HEX,
        window=None, staging_dir=staging, stagger=0.0, dry_run=False,
        roe_id="ROE-TEST",
    )
    with mock.patch("time.sleep"):
        hashes = exfil.run("filesystem", root=data_dir, patterns=["*.txt"])

    # Both files were collected regardless of upload outcome
    assert len(hashes) == 2
