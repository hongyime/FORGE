from __future__ import annotations

import socket
import sqlite3
from pathlib import Path

from forge.db.session import get_engagement_db
from forge.phase1 import port_scanner
from forge.phase1.port_scanner import scan_engagement, scan_host
from forge.utils.intel import shodan_lookup


def _setup_host(db_path: Path) -> None:
    conn = get_engagement_db(db_path)
    try:
        conn.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (1, 'engagement-1', '["local"]', 'ACTIVE', 'tester')
            ON CONFLICT(id) DO NOTHING
            """
        )
        conn.execute(
            """
            INSERT INTO hosts (engagement_id, ip, hostname, os_family, in_scope)
            VALUES (1, '127.0.0.1', 'localhost', 'unknown', 1)
            ON CONFLICT(engagement_id, ip) DO NOTHING
            """
        )
        conn.commit()
    finally:
        conn.close()


def test_scan_host_detects_open_local_port() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    try:
        result = scan_host("127.0.0.1", [port], timeout=0.2)
    finally:
        server.close()
    assert result == [port]


def test_scan_engagement_persists_service_row(tmp_path: Path) -> None:
    db_path = tmp_path / "eng.db"
    _setup_host(db_path)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    try:
        findings = scan_engagement(
            engagement_id=1,
            db_path=db_path,
            ports=[port],
            timeout=0.2,
            operator="tester",
        )
    finally:
        server.close()
    assert len(findings) == 1
    conn = sqlite3.connect(db_path)
    try:
        service_count = conn.execute("SELECT COUNT(*) FROM services").fetchone()[0]
    finally:
        conn.close()
    assert service_count == 1


def test_scan_host_applies_env_port_delay_and_concurrency(monkeypatch) -> None:
    monkeypatch.setenv("FORGE_PORT_SCAN_PORT_DELAY_SECONDS", "0.2")
    monkeypatch.setenv("FORGE_PORT_SCAN_PORT_CONCURRENCY", "1")
    sleeps: list[float] = []

    async def _sleep(seconds: float) -> None:
        sleeps.append(float(seconds))

    async def _fake_is_open(_ip: str, port: int, _timeout: float) -> bool:
        return port == 443

    monkeypatch.setattr(port_scanner.asyncio, "sleep", _sleep)
    monkeypatch.setattr(port_scanner, "_is_open_async", _fake_is_open)

    result = scan_host("203.0.113.10", [80, 443], timeout=0.2)

    assert result == [443]
    assert sleeps == [0.2, 0.2]


def test_scan_engagement_skips_synthetic_placeholder_hosts(tmp_path: Path, monkeypatch) -> None:
    db_path = tmp_path / "eng.db"
    conn = get_engagement_db(db_path)
    try:
        conn.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (1, 'engagement-1', '["acme.example"]', 'ACTIVE', 'tester')
            ON CONFLICT(id) DO NOTHING
            """
        )
        conn.execute(
            """
            INSERT INTO hosts (engagement_id, ip, hostname, os_family, host_context, in_scope)
            VALUES (1, '198.18.1.20', 'cdn.acme.example', 'unknown', ?, 1)
            """,
            ('{"synthetic_ip": true, "discovery": "wayback"}',),
        )
        conn.commit()
    finally:
        conn.close()

    async def _fail_scan(*_args: object, **_kwargs: object) -> list[int]:
        raise AssertionError("synthetic placeholder hosts must not be actively scanned")

    monkeypatch.setattr(port_scanner, "_scan_host_async", _fail_scan)

    findings = scan_engagement(
        engagement_id=1,
        db_path=db_path,
        ports=[80],
        timeout=0.2,
        operator="tester",
    )

    assert findings == []
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            """
            SELECT action, result
            FROM audit_log
            WHERE engagement_id=1 AND module='port_scanner'
            """
        ).fetchone()
    finally:
        conn.close()
    assert row[0] == "scan_skipped"
    assert "synthetic_or_placeholder_ip" in row[1]


def test_enhanced_shodan_service_lookup_uses_shared_pacing(monkeypatch) -> None:
    monkeypatch.setenv("FORGE_SHODAN_REQUEST_DELAY_SECONDS", "0.25")
    monkeypatch.setenv("FORGE_SHODAN_RATE_LIMIT_RETRIES", "1")
    monkeypatch.setenv("FORGE_SHODAN_MAX_RETRY_AFTER_SECONDS", "1")
    sleeps: list[float] = []
    calls: list[tuple[str, dict[str, object]]] = []
    monkeypatch.setattr(shodan_lookup.time, "sleep", lambda seconds: sleeps.append(float(seconds)))

    class _Response:
        def __init__(
            self,
            status_code: int,
            payload: dict[str, object],
            headers: dict[str, str] | None = None,
        ) -> None:
            self.status_code = status_code
            self._payload = payload
            self.headers = headers or {}

        def json(self) -> dict[str, object]:
            return self._payload

    responses = [
        _Response(429, {}, {"Retry-After": "5"}),
        _Response(200, {"data": [{"port": 443, "product": "nginx"}]}),
    ]

    class _Client:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def __enter__(self) -> "_Client":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def get(self, url: str, *, params: dict[str, object]) -> _Response:
            calls.append((url, dict(params)))
            return responses.pop(0)

    monkeypatch.setattr(port_scanner.httpx, "Client", _Client)

    services = port_scanner._fetch_shodan_services("203.0.113.10", "test-key")

    assert services == {443: "nginx"}
    assert [call[0] for call in calls] == [
        "https://api.shodan.io/shodan/host/203.0.113.10",
        "https://api.shodan.io/shodan/host/203.0.113.10",
    ]
    assert calls[0][1] == {"key": "test-key"}
    assert sleeps == [0.25, 1.0, 0.25]
