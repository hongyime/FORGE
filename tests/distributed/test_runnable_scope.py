from __future__ import annotations

import json
import sqlite3
import types
from pathlib import Path

import pytest

from forge.db.session import get_engagement_db
from forge.distributed import runnable
from forge.phase1 import crawler
from forge.phase1 import port_scanner


def _bootstrap_engagement(db_path: Path, *, scope: list[str] | None = None) -> None:
    con = get_engagement_db(db_path)
    try:
        con.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (1001, 'scheduled-scope', ?, 'ACTIVE', 'tester')
            ON CONFLICT(id) DO UPDATE SET scope_json=excluded.scope_json
            """,
            (json.dumps(scope if scope is not None else ["allowed.example"]),),
        )
        con.commit()
    finally:
        con.close()


def test_scheduled_crawl_denies_out_of_scope_before_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(db_path, scope=["allowed.example"])

    def _fail_crawl(*_args: object, **_kwargs: object) -> list[object]:
        raise AssertionError("out-of-scope scheduled crawl must not reach crawler")

    monkeypatch.setattr(runnable, "crawl_target_sync", _fail_crawl)

    with pytest.raises(RuntimeError, match="engagement_scope_denied"):
        runnable.run_scheduled_task(
            1001,
            "crawl:https://evil.example",
            {"task_type": "crawl", "target": "https://evil.example"},
            db_path,
        )

    con = sqlite3.connect(db_path)
    try:
        row = con.execute(
            """
            SELECT action, target, result
            FROM audit_log
            WHERE engagement_id=1001 AND module='scheduled_task'
            """
        ).fetchone()
    finally:
        con.close()
    assert row[0] == "scheduled_task_scope_denied"
    assert row[1] == "https://evil.example"
    assert "engagement_scope_denied" in row[2]


def test_scheduled_crawl_allows_in_scope_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(db_path, scope=["allowed.example"])
    calls: list[dict[str, object]] = []

    def _fake_crawl(*args: object, **kwargs: object) -> list[object]:
        calls.append({"args": args, "kwargs": kwargs})
        return []

    monkeypatch.setattr(runnable, "crawl_target_sync", _fake_crawl)

    runnable.run_scheduled_task(
        1001,
        "crawl:https://allowed.example/app",
        {"task_type": "crawl", "target": "https://allowed.example/app"},
        db_path,
    )

    assert len(calls) == 1
    assert calls[0]["kwargs"]["target_url"] == "https://allowed.example/app"


def test_scheduled_crawl_scope_manifest_url_prefix_denies_same_host_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(db_path, scope=["allowed.example"])

    def _fail_crawl(*_args: object, **_kwargs: object) -> list[object]:
        raise AssertionError("manifest-denied scheduled crawl must not reach crawler")

    monkeypatch.setattr(runnable, "crawl_target_sync", _fail_crawl)

    with pytest.raises(RuntimeError, match="scope_manifest_denied"):
        runnable.run_scheduled_task(
            1001,
            "crawl:https://allowed.example/admin",
            {
                "task_type": "crawl",
                "target": "https://allowed.example/admin",
                "scope_manifest": json.dumps(
                    {
                        "roe_id": "ROE-ACME-2026-07",
                        "domains": ["allowed.example"],
                        "urls": ["https://allowed.example/app/"],
                    }
                ),
                "roe_id": "ROE-ACME-2026-07",
            },
            db_path,
        )


def test_scheduled_crawl_scope_manifest_prefix_blocks_discovered_link_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(db_path, scope=["allowed.example"])
    calls: list[str] = []

    class _Client:
        def __init__(self, **_kwargs: object) -> None:
            pass

        async def __aenter__(self) -> "_Client":
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        async def get(self, url: str) -> object:
            calls.append(url)
            if url == "https://allowed.example/admin":
                raise AssertionError("manifest-denied discovered URL must not be fetched")
            return types.SimpleNamespace(
                status_code=200,
                headers={},
                text='<html><a href="/admin">Admin</a></html>',
                url=url,
            )

    monkeypatch.setattr(crawler, "httpx", types.SimpleNamespace(AsyncClient=_Client, Headers=dict))

    runnable.run_scheduled_task(
        1001,
        "crawl:https://allowed.example/app/",
        {
            "task_type": "crawl",
            "target": "https://allowed.example/app/",
            "scope_manifest": json.dumps(
                {
                    "roe_id": "ROE-ACME-2026-07",
                    "domains": ["allowed.example"],
                    "urls": ["https://allowed.example/app/"],
                }
            ),
            "roe_id": "ROE-ACME-2026-07",
        },
        db_path,
    )

    assert calls == ["https://allowed.example/app/"]


def test_scheduled_crawl_engagement_url_scope_denies_same_host_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(db_path, scope=["https://allowed.example/app/"])

    def _fail_crawl(*_args: object, **_kwargs: object) -> list[object]:
        raise AssertionError("DB URL-scope-denied scheduled crawl must not reach crawler")

    monkeypatch.setattr(runnable, "crawl_target_sync", _fail_crawl)

    with pytest.raises(RuntimeError, match="engagement_scope_denied"):
        runnable.run_scheduled_task(
            1001,
            "crawl:https://allowed.example/admin",
            {"task_type": "crawl", "target": "https://allowed.example/admin"},
            db_path,
        )


def test_scheduled_sensitive_auth_bypass_requires_roe_before_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(db_path, scope=["allowed.example"])
    calls: list[str] = []

    def _fake_bypass(*_args: object, **kwargs: object) -> object:
        calls.append(str(kwargs.get("target_url") or ""))
        return object()

    monkeypatch.setattr(runnable, "run_bypass_assessment", _fake_bypass)

    with pytest.raises(RuntimeError, match="roe_id_required"):
        runnable.run_scheduled_task(
            1001,
            "auth-bypass:https://allowed.example/login",
            {"task_type": "auth-bypass", "target": "https://allowed.example/login"},
            db_path,
        )
    assert calls == []

    runnable.run_scheduled_task(
        1001,
        "auth-bypass:https://allowed.example/login",
        {
            "task_type": "auth-bypass",
            "target": "https://allowed.example/login",
            "roe_id": "ROE-ACME-2026-07",
        },
        db_path,
    )
    assert calls == ["https://allowed.example/login"]


def test_scheduled_ports_requires_scope_and_passes_scope_override(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(db_path, scope=["10.10.0.0/16"])
    calls: list[dict[str, object]] = []

    def _fake_scan(**kwargs: object) -> list[object]:
        calls.append(kwargs)
        return []

    monkeypatch.setattr(runnable, "scan_engagement_enhanced", _fake_scan)

    runnable.run_scheduled_task(
        1001,
        "ports:default",
        {"task_type": "ports"},
        db_path,
    )
    assert calls[0]["scope_override"] == ["10.10.0.0/16"]

    empty_db_path = tmp_path / "empty-scope.db"
    _bootstrap_engagement(empty_db_path, scope=[])
    with pytest.raises(RuntimeError, match="engagement_scope_required"):
        runnable.run_scheduled_task(
            1001,
            "ports:default",
            {"task_type": "ports"},
            empty_db_path,
        )


def test_scheduled_validate_requires_roe_before_provider_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(db_path, scope=["allowed.example"])

    def _fail_validate(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("scheduled validation without ROE must not reach provider validation")

    monkeypatch.setattr(runnable, "run_cloud_validate", _fail_validate)

    with pytest.raises(RuntimeError, match="roe_id_required"):
        runnable.run_scheduled_task(
            1001,
            "validate:81",
            {"task_type": "validate", "key_id": 81},
            db_path,
        )


def test_scheduled_validate_requires_scope_manifest_before_provider_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(db_path, scope=["allowed.example"])

    def _fail_validate(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("scheduled validation without manifest must not reach provider validation")

    monkeypatch.setattr(runnable, "run_cloud_validate", _fail_validate)

    with pytest.raises(RuntimeError, match="scope_manifest_required"):
        runnable.run_scheduled_task(
            1001,
            "validate:81",
            {"task_type": "validate", "key_id": 81, "roe_id": "ROE-ACME-2026-07"},
            db_path,
        )


def test_scheduled_validate_rejects_mismatched_scope_manifest_before_provider_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(db_path, scope=["allowed.example"])

    def _fail_validate(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("mismatched scheduled validation must not reach provider validation")

    monkeypatch.setattr(runnable, "run_cloud_validate", _fail_validate)

    with pytest.raises(RuntimeError, match="roe_id_scope_manifest_mismatch"):
        runnable.run_scheduled_task(
            1001,
            "validate:81",
            {
                "task_type": "validate",
                "key_id": 81,
                "roe_id": "ROE-ACME-2026-07",
                "scope_manifest": json.dumps(
                    {"roe_id": "ROE-OTHER-2026-07", "domains": ["allowed.example"]}
                ),
            },
            db_path,
        )


def test_enhanced_port_scan_scope_override_skips_drifted_host(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_engagement(db_path, scope=["10.10.0.0/16"])
    con = get_engagement_db(db_path)
    try:
        con.executemany(
            """
            INSERT INTO hosts (engagement_id, ip, hostname, os_family, in_scope)
            VALUES (1001, ?, ?, 'unknown', 1)
            """,
            [
                ("10.10.1.5", "app.allowed.example"),
                ("192.0.2.10", "drifted.example"),
            ],
        )
        con.commit()
    finally:
        con.close()

    scanned: list[str] = []

    async def _fake_scan_host(ip: str, *_args: object, **_kwargs: object) -> list[int]:
        scanned.append(ip)
        return []

    monkeypatch.setattr(port_scanner, "_scan_host_async", _fake_scan_host)

    result = port_scanner.scan_engagement_enhanced(
        engagement_id=1001,
        db_path=db_path,
        ports=[80],
        detect_cdn=False,
        detect_waf=False,
        scope_override=["10.10.0.0/16"],
    )

    assert result == []
    assert scanned == ["10.10.1.5"]
    con = sqlite3.connect(db_path)
    try:
        row = con.execute(
            """
            SELECT action, target, result
            FROM audit_log
            WHERE engagement_id=1001 AND module='port_scanner' AND target='192.0.2.10'
            """
        ).fetchone()
    finally:
        con.close()
    assert row[0] == "enhanced_scan_skipped"
    assert "scheduled_scope_denied" in row[2]
