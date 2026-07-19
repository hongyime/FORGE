from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from forge.db.session import get_engagement_db
from forge.phase1 import subdomain_enum
from forge.utils.intel import http_pacing
from forge.phase1.subdomain_enum import enumerate_subdomains


def _setup_db(db_path: Path) -> None:
    conn = get_engagement_db(db_path)
    try:
        conn.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (1, 'engagement-1', '["example.com"]', 'ACTIVE', 'tester')
            ON CONFLICT(id) DO NOTHING
            """
        )
        conn.commit()
    finally:
        conn.close()


def test_enumerate_subdomains_writes_hosts_and_audit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "eng.db"
    _setup_db(db_path)
    monkeypatch.setattr("forge.phase1.subdomain_enum._collect_crtsh_subdomains", lambda _domain: [])
    discovered = enumerate_subdomains(
        engagement_id=1,
        domain="example.com",
        resume=True,
        db_path=db_path,
        operator="tester",
    )
    assert discovered
    conn = sqlite3.connect(db_path)
    try:
        host_count = conn.execute("SELECT COUNT(*) FROM hosts WHERE engagement_id=1").fetchone()[0]
        audit_count = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE engagement_id=1 AND module='subdomain_enum'"
        ).fetchone()[0]
        task_status = conn.execute(
            "SELECT status FROM task_progress WHERE engagement_id=1 AND task_key='subdomain_enum:example.com'"
        ).fetchone()[0]
    finally:
        conn.close()
    assert host_count >= 1
    assert audit_count >= 1
    assert task_status == "complete"


def test_enumerate_subdomains_resume_keeps_idempotent_task(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "eng.db"
    _setup_db(db_path)
    monkeypatch.setattr("forge.phase1.subdomain_enum._collect_crtsh_subdomains", lambda _domain: [])
    enumerate_subdomains(
        engagement_id=1,
        domain="example.com",
        resume=True,
        db_path=db_path,
        operator="tester",
    )
    enumerate_subdomains(
        engagement_id=1,
        domain="example.com",
        resume=True,
        db_path=db_path,
        operator="tester",
    )
    conn = sqlite3.connect(db_path)
    try:
        task_rows = conn.execute(
            "SELECT COUNT(*) FROM task_progress WHERE engagement_id=1 AND task_key='subdomain_enum:example.com'"
        ).fetchone()[0]
    finally:
        conn.close()
    assert task_rows == 1


def test_enumerate_subdomains_includes_passive_sources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "eng.db"
    _setup_db(db_path)
    monkeypatch.setattr(
        "forge.phase1.subdomain_enum._collect_crtsh_subdomains",
        lambda _domain: ["passive1.example.com"],
    )
    conn = get_engagement_db(db_path)
    try:
        conn.execute(
            """
            INSERT INTO emails (engagement_id, email, domain, source)
            VALUES (1, 'user@edge.example.com', 'edge.example.com', 'seed')
            """
        )
        conn.commit()
    finally:
        conn.close()
    enumerate_subdomains(
        engagement_id=1,
        domain="example.com",
        resume=True,
        db_path=db_path,
        operator="tester",
        passive=True,
    )
    conn = sqlite3.connect(db_path)
    try:
        hostnames = {
            row[0]
            for row in conn.execute(
                "SELECT hostname FROM hosts WHERE engagement_id=1 AND hostname IS NOT NULL"
            ).fetchall()
        }
    finally:
        conn.close()
    assert "edge.example.com" in hostnames
    assert "passive1.example.com" in hostnames


def test_enumerate_subdomains_marks_synthetic_placeholder_ips(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "eng.db"
    _setup_db(db_path)

    def _fake_gethostbyname(hostname: str) -> str:
        if hostname == "offline.example.com":
            raise OSError("unresolved")
        return "203.0.113.10"

    monkeypatch.setattr("forge.phase1.subdomain_enum.socket.gethostbyname", _fake_gethostbyname)

    enumerate_subdomains(
        engagement_id=1,
        domain="example.com",
        resume=True,
        db_path=db_path,
        operator="tester",
        passive=False,
        extra_labels=["offline"],
    )

    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            """
            SELECT ip, host_context
            FROM hosts
            WHERE engagement_id=1 AND hostname='offline.example.com'
            """
        ).fetchone()
    finally:
        conn.close()

    assert row is not None
    assert str(row[0]).startswith("198.18.")
    context = json.loads(str(row[1] or "{}"))
    assert context["synthetic_ip"] is True


def test_collect_crtsh_subdomains_paces_and_retries_429(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    http_pacing._clear_rate_limit_cooldowns_for_tests()
    monkeypatch.setenv("FORGE_CRTSH_REQUEST_DELAY_SECONDS", "0.25")
    monkeypatch.setenv("FORGE_CRTSH_RATE_LIMIT_RETRIES", "1")
    monkeypatch.setenv("FORGE_CRTSH_MAX_RETRY_AFTER_SECONDS", "1")
    sleeps: list[float] = []
    calls: list[str] = []
    monkeypatch.setattr(subdomain_enum.time, "sleep", lambda seconds: sleeps.append(float(seconds)))

    class _Response:
        def __enter__(self) -> "_Response":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self) -> bytes:
            return (
                b'['
                b'{"name_value":"www.example.com\\n*.api.example.com"},'
                b'{"name_value":"not a hostname"}'
                b']'
            )

    responses: list[object] = [
        subdomain_enum.urllib.error.HTTPError(
            "https://crt.sh/",
            429,
            "Too Many Requests",
            {"Retry-After": "5"},
            None,
        ),
        _Response(),
    ]

    def _urlopen(req: object, *, timeout: float) -> object:
        del timeout
        calls.append(str(getattr(req, "full_url", "")))
        item = responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    monkeypatch.setattr(subdomain_enum.urllib.request, "urlopen", _urlopen)

    result = subdomain_enum._collect_crtsh_subdomains("example.com", timeout=3.0)

    assert result == ["api.example.com", "www.example.com"]
    assert len(calls) == 2
    assert sleeps == [0.25, 1.0, 0.25]
