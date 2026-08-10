from __future__ import annotations

import sqlite3
from pathlib import Path

from forge.db.session import get_engagement_db
from forge.phase1.email_harvester import extract_emails, run_email_harvest


def _setup_engagement(db_path: Path) -> None:
    conn = get_engagement_db(db_path)
    try:
        conn.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (1, 'engagement-1', '["example.com"]', 'ACTIVE', 'tester')
            ON CONFLICT(id) DO NOTHING
            """
        )
        conn.execute(
            """
            INSERT INTO hosts (engagement_id, ip, hostname, os_family, in_scope)
            VALUES (1, '198.18.1.1', 'portal.example.com', 'unknown', 1)
            ON CONFLICT(engagement_id, ip) DO NOTHING
            """
        )
        conn.commit()
    finally:
        conn.close()


def test_extract_emails_returns_unique_lowercase() -> None:
    text = "Admin@Example.com security@example.com admin@example.com"
    parsed = extract_emails(text)
    assert parsed == ["admin@example.com", "security@example.com"]


def test_run_email_harvest_writes_emails_and_audit(tmp_path: Path) -> None:
    db_path = tmp_path / "eng.db"
    _setup_engagement(db_path)
    discovered = run_email_harvest(
        engagement_id=1,
        domain="example.com",
        db_path=db_path,
        operator="tester",
    )
    assert "admin@example.com" in discovered
    conn = sqlite3.connect(db_path)
    try:
        email_count = conn.execute("SELECT COUNT(*) FROM emails WHERE engagement_id=1").fetchone()[
            0
        ]
        audit_count = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE engagement_id=1 AND module='email_harvester'"
        ).fetchone()[0]
    finally:
        conn.close()
    assert email_count >= 1
    assert audit_count == 1
