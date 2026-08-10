"""
tests/integration/conftest.py

Shared fixtures for Phase 5 integration tests.

Environment variables consumed:
  MOCK_SSH_HOST  — SSH service host (default: localhost)
  MOCK_SSH_PORT  — SSH service port (default: 2223)

CI service definitions (GitHub Actions):
  mock-ssh:
    image: linuxserver/openssh-server:latest
    ports: ["2223:2222"]
    env: {PASSWORD_ACCESS: "true", USER_NAME: testuser, USER_PASSWORD: testpass}

If MOCK_SSH_HOST / MOCK_SSH_PORT are not set, integration tests are skipped
automatically — they must not fail in environments without Docker services.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from unittest import mock

import pytest

ENGAGEMENT_ID = 1
AES_KEY_HEX = "bb" * 32
MOCK_SSH_HOST = os.getenv("MOCK_SSH_HOST", "")
MOCK_SSH_PORT = int(os.getenv("MOCK_SSH_PORT", "2223"))
SSH_AVAILABLE = bool(MOCK_SSH_HOST)


@pytest.fixture()
def int_eng_db(tmp_path: Path) -> Path:
    """Full-schema engagement DB for integration tests."""
    db = tmp_path / "int_engagement.db"
    con = sqlite3.connect(db)
    con.executescript(f"""
        CREATE TABLE IF NOT EXISTS engagements (
            id INTEGER PRIMARY KEY, name TEXT, status TEXT DEFAULT 'ACTIVE'
        );
        INSERT INTO engagements VALUES ({ENGAGEMENT_ID}, 'int-test-eng', 'ACTIVE');

        CREATE TABLE IF NOT EXISTS engagement_scope (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL,
            scope_entry TEXT NOT NULL
        );
        INSERT INTO engagement_scope (engagement_id, scope_entry)
            VALUES ({ENGAGEMENT_ID}, '10.0.0.0/24');
        INSERT INTO engagement_scope (engagement_id, scope_entry)
            VALUES ({ENGAGEMENT_ID}, '127.0.0.1');
        INSERT INTO engagement_scope (engagement_id, scope_entry)
            VALUES ({ENGAGEMENT_ID}, 'localhost');

        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER, phase TEXT, module TEXT, action TEXT,
            target TEXT, result TEXT, operator TEXT,
            logged_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS lateral_movement (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER, target TEXT, technique TEXT,
            command TEXT, success INTEGER, output TEXT,
            executed_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS exfiltrated_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER, file_path TEXT,
            sha256 TEXT, size_bytes INTEGER,
            collected_at TEXT DEFAULT (datetime('now')),
            artifact_family   TEXT,
            artifact_subtype  TEXT,
            source_platform   TEXT,
            collection_method TEXT,
            confidence        REAL,
            report_safe_summary TEXT
        );
        CREATE TABLE IF NOT EXISTS exfil_monitor_targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER, sha256 TEXT UNIQUE,
            registered_at TEXT DEFAULT (datetime('now'))
        );
    """)
    con.commit()
    con.close()
    return db


@pytest.fixture()
def patch_confirm_approve(monkeypatch):
    m = mock.MagicMock()
    m.ask.return_value = True
    monkeypatch.setattr("questionary.confirm", lambda *a, **kw: m)
    return m


@pytest.fixture()
def patch_confirm_deny(monkeypatch):
    m = mock.MagicMock()
    m.ask.return_value = False
    monkeypatch.setattr("questionary.confirm", lambda *a, **kw: m)
    return m
