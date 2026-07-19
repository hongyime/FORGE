"""
tests/phase5/conftest.py

Shared fixtures for all Phase 5 unit and integration tests.

Fixtures:
  tmp_kb_db          — Phase 0 KB SQLite (schtasks_legit_names, lolbas_pipe_names)
  tmp_eng_db         — Engagement SQLite (scope, audit_log, all Phase 5 tables)
  engagement_id      — canonical test engagement ID (1)
  in_scope_host      — "10.0.0.50" (within 10.0.0.0/24 scope)
  out_of_scope_host  — "192.168.99.99" (not in scope)
  mock_cred_password — LateralMovementCredential (auth_type='password')
  mock_cred_kerberos — LateralMovementCredential (auth_type='kerberos')
  patch_confirm      — auto-approve questionary.confirm()
  patch_confirm_deny — auto-deny questionary.confirm()
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from unittest import mock

import pytest

ENGAGEMENT_ID  = 1
IN_SCOPE_HOST  = "10.0.0.50"
OUT_SCOPE_HOST = "192.168.99.99"
AES_KEY_HEX    = "aa" * 32      # 32 bytes test key


@pytest.fixture()
def tmp_kb_db(tmp_path: Path) -> Path:
    db = tmp_path / "kb.db"
    con = sqlite3.connect(db)
    con.executescript("""
        CREATE TABLE IF NOT EXISTS schtasks_legit_names (
            id   INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE
        );
        INSERT INTO schtasks_legit_names (name) VALUES
            ('MicrosoftEdgeUpdateTaskMachineCore'),
            ('GoogleUpdateTaskMachineCore'),
            ('WindowsDefenderScheduledScan');

        CREATE TABLE IF NOT EXISTS cron_legit_names (
            id   INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE
        );
        INSERT INTO cron_legit_names (name) VALUES
            ('cron-helper'), ('sys-update'), ('logrotate-daily');

        CREATE TABLE IF NOT EXISTS lolbas_pipe_names (
            id   INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE
        );
        INSERT INTO lolbas_pipe_names (name) VALUES
            ('atsvc'), ('winreg'), ('lsarpc');
    """)
    con.commit()
    con.close()
    return db


@pytest.fixture()
def tmp_eng_db(tmp_path: Path) -> Path:
    db = tmp_path / "engagement.db"
    con = sqlite3.connect(db)
    con.executescript(f"""
        CREATE TABLE IF NOT EXISTS engagements (
            id INTEGER PRIMARY KEY, name TEXT, status TEXT DEFAULT 'ACTIVE'
        );
        INSERT INTO engagements VALUES ({ENGAGEMENT_ID}, 'test-eng', 'ACTIVE');

        CREATE TABLE IF NOT EXISTS engagement_scope (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL,
            scope_entry   TEXT NOT NULL
        );
        INSERT INTO engagement_scope (engagement_id, scope_entry)
            VALUES ({ENGAGEMENT_ID}, '10.0.0.0/24');
        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL,
            ip TEXT NOT NULL,
            hostname TEXT
        );
        INSERT INTO hosts (engagement_id, ip, hostname)
            VALUES ({ENGAGEMENT_ID}, '{IN_SCOPE_HOST}', 'host-1');

        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER,
            phase TEXT, module TEXT, action TEXT, target TEXT,
            result TEXT, operator TEXT,
            logged_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS lateral_movement (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER, source_host_id INTEGER, target_host_id INTEGER,
            technique TEXT, credential_id INTEGER,
            command TEXT, success INTEGER, output TEXT,
            scope_verified INTEGER DEFAULT 0, operator_confirmed INTEGER DEFAULT 0,
            executed_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS persistence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER, host_id INTEGER,
            technique TEXT, target_os TEXT, install_cmd TEXT,
            cleanup_cmd TEXT, lolbins_used TEXT,
            obfuscation_applied INTEGER DEFAULT 0, installed INTEGER DEFAULT 0, verified INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now'))
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
        CREATE TABLE IF NOT EXISTS payloads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER,
            payload_type TEXT,
            target_os TEXT,
            technique TEXT,
            obfuscation_chain TEXT,
            delivery_url TEXT,
            content_hash TEXT,
            generated_at TEXT DEFAULT (datetime('now')),
            lots_host TEXT,
            metadata_stripped INTEGER DEFAULT 1
        );
    """)
    con.commit()
    con.close()
    return db


@pytest.fixture()
def mock_cred_password():
    from forge.contracts.models import LateralMovementCredential
    return LateralMovementCredential(
        credential_id=1, username="testuser", domain="CORP",
        password="P@ssw0rd!", auth_type="password",
    )


@pytest.fixture()
def mock_cred_kerberos(tmp_path: Path):
    from forge.contracts.models import LateralMovementCredential
    ccache = tmp_path / "test.ccache"
    ccache.write_bytes(b"\x05\x04" + b"\x00" * 32)
    return LateralMovementCredential(
        credential_id=2, username="svc_account", domain="CORP",
        ccache_path=ccache, auth_type="kerberos",
    )


@pytest.fixture()
def patch_confirm(monkeypatch):
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
