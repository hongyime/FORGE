from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import httpx

from forge.db.session import get_engagement_db
from forge.phase2.xray_runner import (
    ingest_passive_file,
    ingest_xray_jsonl,
    run_passive_http_collection,
    run_passive_http_collection_for_engagement,
    summarize_passive_vulns,
)


def _bootstrap_db(db_path: Path) -> None:
    con = get_engagement_db(db_path)
    try:
        con.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (1001, 'Acme Example', ?, 'ACTIVE', 'tester')
            """,
            (json.dumps(["acme.example", "app.acme.example"]),),
        )
        con.commit()
    finally:
        con.close()


def test_ingest_xray_jsonl_counts_only_actual_inserted_rows(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    jsonl_path = tmp_path / "xray.jsonl"
    row = {
        "plugin": "xray-reflection",
        "target": "https://app.acme.example/search?q=test",
        "id": "xray-reflection:https://app.acme.example/search?q=test",
        "severity": "LOW",
    }
    jsonl_path.write_text(
        "\n".join(json.dumps(row) for _ in range(2)),
        encoding="utf-8",
    )

    inserted = ingest_xray_jsonl(1001, db_path, jsonl_path)

    assert inserted == 1
    con = get_engagement_db(db_path)
    try:
        count = con.execute(
            "SELECT COUNT(*) FROM passive_vulns WHERE engagement_id=1001"
        ).fetchone()[0]
    finally:
        con.close()
    assert count == 1


def test_ingest_har_counts_unique_passive_findings_only(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    har_path = tmp_path / "capture.har"
    entry = {
        "request": {"url": "https://app.acme.example/search?q=test"},
        "response": {
            "status": 500,
            "content": {"text": "SQL syntax error\nexception stack trace"},
        },
    }
    har_path.write_text(
        json.dumps({"log": {"entries": [entry, entry]}}),
        encoding="utf-8",
    )

    inserted = ingest_passive_file(1001, db_path, har_path)

    assert inserted == 2
    summary = summarize_passive_vulns(1001, db_path)
    assert summary["MEDIUM"] == 1
    assert summary["LOW"] == 1


def test_run_passive_http_collection_counts_duplicate_findings_as_zero_on_replay(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    class _Resp:
        text = "mysql exception"

    monkeypatch.setattr(httpx, "get", lambda *args, **kwargs: _Resp())

    first = run_passive_http_collection(
        1001,
        db_path,
        "https://app.acme.example/repeat?id=1",
    )
    second = run_passive_http_collection(
        1001,
        db_path,
        "https://app.acme.example/repeat?id=1",
    )

    assert first == 2
    assert second == 0
    summary = summarize_passive_vulns(1001, db_path)
    assert summary["MEDIUM"] == 1
    assert summary["LOW"] == 1


def test_run_passive_http_collection_for_engagement_uses_crawl_results_and_dedupes_targets(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = get_engagement_db(db_path)
    try:
        con.execute(
            """
            INSERT INTO crawl_results (engagement_id, url, final_url, title, screenshot_path, tech_stack_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                1001,
                "https://app.acme.example?id=1",
                "https://app.acme.example?id=1",
                "App",
                None,
                "{}",
            ),
        )
        con.execute(
            """
            INSERT INTO crawl_results (engagement_id, url, final_url, title, screenshot_path, tech_stack_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                1001,
                "https://app.acme.example?id=1#frag",
                "https://app.acme.example?id=1",
                "App",
                None,
                "{}",
            ),
        )
        con.commit()
    finally:
        con.close()

    requested_urls: list[str] = []

    class _Resp:
        text = "SQL syntax error\nStack trace"

    def _fake_get(url: str, timeout: float, proxy: str | None = None):  # noqa: ANN001
        requested_urls.append(url)
        assert timeout == 12.0
        assert proxy is None
        return _Resp()

    monkeypatch.setattr(httpx, "get", _fake_get)

    inserted = run_passive_http_collection_for_engagement(1001, db_path)

    assert inserted == 2
    assert requested_urls == ["https://app.acme.example?id=1"]
    summary = summarize_passive_vulns(1001, db_path)
    assert summary["MEDIUM"] == 1
    assert summary["LOW"] == 1


def test_run_passive_http_collection_for_engagement_falls_back_to_seed_targets(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = get_engagement_db(db_path)
    try:
        con.execute(
            """
            INSERT INTO engagement_seeds
                (engagement_id, seed_value, seed_type, source, status, depth, confidence, metadata_json)
            VALUES (?, ?, 'domain', 'operator', 'pending', 0, 1.0, '{}')
            """,
            (1001, "acme.example"),
        )
        con.commit()
    finally:
        con.close()

    requested_urls: list[str] = []

    class _Resp:
        text = "mysql driver banner"

    def _fake_get(url: str, timeout: float, proxy: str | None = None):  # noqa: ANN001
        requested_urls.append(url)
        assert timeout == 12.0
        assert proxy == "http://127.0.0.1:8080"
        return _Resp()

    monkeypatch.setattr(httpx, "get", _fake_get)

    inserted = run_passive_http_collection_for_engagement(
        1001,
        db_path,
        proxy="http://127.0.0.1:8080",
    )

    assert inserted == 1
    assert requested_urls == ["https://acme.example"]
    summary = summarize_passive_vulns(1001, db_path)
    assert summary["MEDIUM"] == 1


def test_run_passive_http_collection_for_engagement_falls_back_to_discovered_hostnames(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = get_engagement_db(db_path)
    try:
        con.execute(
            """
            INSERT INTO hosts (engagement_id, ip, hostname, os_family, host_context)
            VALUES (?, ?, ?, 'unknown', ?)
            """,
            (1001, "198.18.0.25", "portal.acme.example", '{"synthetic_ip": true}'),
        )
        con.commit()
    finally:
        con.close()

    requested_urls: list[str] = []

    class _Resp:
        text = "exception while rendering"

    def _fake_get(url: str, timeout: float, proxy: str | None = None):  # noqa: ANN001
        requested_urls.append(url)
        assert timeout == 12.0
        assert proxy is None
        return _Resp()

    monkeypatch.setattr(httpx, "get", _fake_get)

    inserted = run_passive_http_collection_for_engagement(1001, db_path)

    assert inserted == 1
    assert requested_urls == ["https://portal.acme.example"]
    summary = summarize_passive_vulns(1001, db_path)
    assert summary["LOW"] == 1


def test_run_passive_http_collection_for_engagement_falls_back_to_scope_entries(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    requested_urls: list[str] = []

    class _Resp:
        text = "mysql stack trace"

    def _fake_get(url: str, timeout: float, proxy: str | None = None):  # noqa: ANN001
        requested_urls.append(url)
        assert timeout == 12.0
        assert proxy is None
        return _Resp()

    monkeypatch.setattr(httpx, "get", _fake_get)

    inserted = run_passive_http_collection_for_engagement(1001, db_path)

    assert inserted == 4
    assert requested_urls == ["https://acme.example", "https://app.acme.example"]
    summary = summarize_passive_vulns(1001, db_path)
    assert summary["MEDIUM"] == 2
    assert summary["LOW"] == 2


def test_run_passive_http_collection_for_engagement_parallelizes_in_scope_targets(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = get_engagement_db(db_path)
    try:
        for index in range(1, 4):
            con.execute(
                """
                INSERT INTO crawl_results (engagement_id, url, final_url, title, screenshot_path, tech_stack_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    1001,
                    f"https://app.acme.example/page-{index}",
                    f"https://app.acme.example/page-{index}",
                    f"Page {index}",
                    None,
                    "{}",
                ),
            )
        con.commit()
    finally:
        con.close()

    active = 0
    peak = 0
    lock = threading.Lock()
    requested_urls: list[str] = []

    class _Resp:
        text = "mysql exception"

    def _fake_get(url: str, timeout: float, proxy: str | None = None):  # noqa: ANN001
        nonlocal active, peak
        requested_urls.append(url)
        assert timeout == 12.0
        assert proxy is None
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            if url.endswith("page-1"):
                time.sleep(0.04)
            elif url.endswith("page-2"):
                time.sleep(0.01)
            else:
                time.sleep(0.02)
            return _Resp()
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(httpx, "get", _fake_get)

    inserted = run_passive_http_collection_for_engagement(
        1001,
        db_path,
        max_workers=2,
    )

    assert inserted == 6
    assert set(requested_urls) == {
        "https://app.acme.example/page-1",
        "https://app.acme.example/page-2",
        "https://app.acme.example/page-3",
    }
    assert peak == 2
    summary = summarize_passive_vulns(1001, db_path)
    assert summary["MEDIUM"] == 3
    assert summary["LOW"] == 3


def test_run_passive_http_collection_for_engagement_defaults_to_sequential_targets(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = get_engagement_db(db_path)
    try:
        for index in range(1, 4):
            con.execute(
                """
                INSERT INTO crawl_results (engagement_id, url, final_url, title, screenshot_path, tech_stack_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    1001,
                    f"https://app.acme.example/slow-{index}",
                    f"https://app.acme.example/slow-{index}",
                    f"Slow {index}",
                    None,
                    "{}",
                ),
            )
        con.commit()
    finally:
        con.close()

    active = 0
    peak = 0
    lock = threading.Lock()
    requested_urls: list[str] = []

    class _Resp:
        text = "mysql exception"

    def _fake_get(url: str, timeout: float, proxy: str | None = None):  # noqa: ANN001
        nonlocal active, peak
        requested_urls.append(url)
        assert timeout == 12.0
        assert proxy is None
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(0.02)
            return _Resp()
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(httpx, "get", _fake_get)

    inserted = run_passive_http_collection_for_engagement(1001, db_path)

    assert inserted == 6
    assert requested_urls == [
        "https://app.acme.example/slow-3",
        "https://app.acme.example/slow-2",
        "https://app.acme.example/slow-1",
    ]
    assert peak == 1


def test_run_passive_http_collection_for_engagement_default_workers_can_be_raised_by_env(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)
    monkeypatch.setenv("FORGE_PASSIVE_HTTP_MAX_WORKERS", "2")

    con = get_engagement_db(db_path)
    try:
        for index in range(1, 4):
            con.execute(
                """
                INSERT INTO crawl_results (engagement_id, url, final_url, title, screenshot_path, tech_stack_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    1001,
                    f"https://app.acme.example/env-{index}",
                    f"https://app.acme.example/env-{index}",
                    f"Env {index}",
                    None,
                    "{}",
                ),
            )
        con.commit()
    finally:
        con.close()

    active = 0
    peak = 0
    lock = threading.Lock()

    class _Resp:
        text = "mysql exception"

    def _fake_get(url: str, timeout: float, proxy: str | None = None):  # noqa: ANN001
        nonlocal active, peak
        del url
        assert timeout == 12.0
        assert proxy is None
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(0.02)
            return _Resp()
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(httpx, "get", _fake_get)

    inserted = run_passive_http_collection_for_engagement(1001, db_path)

    assert inserted == 6
    assert peak == 2


def test_run_passive_http_collection_for_engagement_skips_out_of_scope_drifted_targets(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = get_engagement_db(db_path)
    try:
        con.execute(
            """
            INSERT INTO crawl_results (engagement_id, url, final_url, title, screenshot_path, tech_stack_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                1001,
                "https://app.acme.example/dashboard",
                "https://app.acme.example/dashboard",
                "App",
                None,
                "{}",
            ),
        )
        con.execute(
            """
            INSERT INTO crawl_results (engagement_id, url, final_url, title, screenshot_path, tech_stack_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                1001,
                "https://cdn.external-example.net/widget.js",
                "https://cdn.external-example.net/widget.js",
                "Widget",
                None,
                "{}",
            ),
        )
        con.commit()
    finally:
        con.close()

    requested_urls: list[str] = []

    class _Resp:
        text = "mysql stack trace"

    def _fake_get(url: str, timeout: float, proxy: str | None = None):  # noqa: ANN001
        requested_urls.append(url)
        assert timeout == 12.0
        assert proxy is None
        return _Resp()

    monkeypatch.setattr(httpx, "get", _fake_get)

    inserted = run_passive_http_collection_for_engagement(1001, db_path, max_workers=2)

    assert inserted == 2
    assert requested_urls == ["https://app.acme.example/dashboard"]
    summary = summarize_passive_vulns(1001, db_path)
    assert summary["MEDIUM"] == 1
    assert summary["LOW"] == 1


def test_vuln_passive_without_target_uses_engagement_backed_collection(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")

    called: dict[str, object] = {}

    def _fake_collect_for_engagement(
        engagement_id: int,
        db_path: Path,
        *,
        proxy: str | None = None,
        timeout: float = 12.0,
        limit: int = 12,
        max_workers: int | None = None,
    ) -> int:
        called["engagement_id"] = engagement_id
        called["db_path"] = db_path
        called["proxy"] = proxy
        called["timeout"] = timeout
        called["limit"] = limit
        called["max_workers"] = max_workers
        return 3

    monkeypatch.setattr(
        "forge.phase2.xray_runner.run_passive_http_collection_for_engagement",
        _fake_collect_for_engagement,
    )

    from forge.cli import vuln_passive

    vuln_passive(
        engagement="1001",
        target=None,
        input_file=None,
        proxy="http://127.0.0.1:8080",
    )

    assert called["engagement_id"] == 1001
    assert str(called["db_path"]).endswith("1001.db")
    assert called["max_workers"] is None
    assert called["proxy"] == "http://127.0.0.1:8080"
    assert called["timeout"] == 12.0
    assert called["limit"] == 12
