from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import typer
import pytest
from typer.testing import CliRunner

from forge.automation_cli import register_automation_commands
from forge.automation_target_feed import build_target_feed


app = typer.Typer()
register_automation_commands(app)
runner = CliRunner()


def _make_engagement_db(
    data_dir: Path, engagement_id: int, seeds: list[tuple[str, str]]
) -> None:
    db_path = data_dir / "engagements" / f"{engagement_id}.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "CREATE TABLE engagement_seeds ("
            " id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " engagement_id INTEGER NOT NULL,"
            " seed_value TEXT NOT NULL,"
            " seed_type TEXT NOT NULL,"
            " source TEXT DEFAULT 'discovered',"
            " status TEXT DEFAULT 'pending')"
        )
        for value, seed_type in seeds:
            conn.execute(
                "INSERT INTO engagement_seeds (engagement_id, seed_value, seed_type)"
                " VALUES (?, ?, ?)",
                (engagement_id, value, seed_type),
            )
        conn.commit()
    finally:
        conn.close()


def _make_dashboard_report(reports_dir: Path, family_id: str, payload: dict) -> None:
    data_dir = reports_dir / "dashboard" / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / f"{family_id}.json").write_text(json.dumps(payload), encoding="utf-8")


def test_feed_build_dry_run_merges_sources_with_provenance_and_writes_nothing(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    reports_dir = tmp_path / "reports"
    imports_dir = tmp_path / "imports"
    _make_engagement_db(data_dir, 1, [("portal.example", "domain")])
    _make_dashboard_report(
        reports_dir,
        "abc123",
        {
            "summary": {
                "hosts": ["web.example"],
                "urls": ["https://api.example/v1"],
                "emails": ["ops@example.com"],
            }
        },
    )
    imports_dir.mkdir(parents=True)
    (imports_dir / "threatfox.json").write_text(
        json.dumps({"data": [{"ioc": "badguy.example"}]}), encoding="utf-8"
    )
    out = tmp_path / "out" / "target-feed.json"

    result = runner.invoke(
        app,
        [
            "feed-build",
            "--output",
            str(out),
            "--json",
            "--data-dir",
            str(data_dir),
            "--reports-dir",
            str(reports_dir),
            "--imports-dir",
            str(imports_dir),
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["schema_version"] == "target-feed.v1"
    assert payload["dry_run"] is True
    assert payload["apply_requested"] is False
    assert not out.exists()

    typed_items = {
        (item["target_type"], item["canonical_value"]) for item in payload["items"]
    }
    assert ("domain", "portal.example") in typed_items
    provenances = " ".join(item["provenance"] for item in payload["items"])
    assert "report_family:abc123" in provenances
    assert "cti_file:threatfox.json" in provenances

    counts = payload["counts"]
    assert counts["total"] == len(payload["items"])
    assert counts["total"] >= 4
    assert counts["by_source"]["db"] >= 1
    assert counts["by_source"]["reports"] == 3
    assert counts["by_source"]["cti"] == 1
    assert counts["by_source_group"]["report_family:abc123"] == 3
    # deterministic ordering by target_key
    ordered_keys = [item["target_key"] for item in payload["items"]]
    assert ordered_keys == sorted(ordered_keys)
    assert any(item["source_group"] == "report_family:abc123" for item in payload["items"])


def test_feed_build_apply_writes_then_rerun_reports_no_new(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    _make_engagement_db(data_dir, 7, [("resume.example", "domain")])
    out = tmp_path / "imports" / "target-feed.json"

    first = runner.invoke(
        app,
        [
            "feed-build",
            "--apply",
            "--json",
            "--output",
            str(out),
            "--data-dir",
            str(data_dir),
            "--reports-dir",
            str(tmp_path / "missing-reports"),
            "--imports-dir",
            str(tmp_path / "missing-imports"),
        ],
    )
    assert first.exit_code == 0, first.output
    first_payload = json.loads(first.output)
    assert first_payload["dry_run"] is False
    assert first_payload["apply_requested"] is True
    assert out.exists()
    on_disk = json.loads(out.read_text(encoding="utf-8"))
    assert on_disk["schema_version"] == "target-feed.v1"
    assert len(on_disk["items"]) == first_payload["counts"]["total"]
    assert on_disk["items"][0]["source_group"] == "db"

    second = runner.invoke(
        app,
        [
            "feed-build",
            "--apply",
            "--json",
            "--output",
            str(out),
            "--data-dir",
            str(data_dir),
            "--reports-dir",
            str(tmp_path / "missing-reports"),
            "--imports-dir",
            str(tmp_path / "missing-imports"),
        ],
    )
    assert second.exit_code == 0, second.output
    second_payload = json.loads(second.output)
    assert second_payload["counts"]["new_vs_existing"] == 0
    assert second_payload["counts"]["omitted_duplicate"] >= 1
    assert second_payload["items"][0]["source_group"] == "db"


def test_feed_build_missing_and_malformed_sources_fail_soft(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True)
    (data_dir / "engagements").mkdir()
    broken_db = data_dir / "engagements" / "99.db"
    broken_db.write_bytes(b"this is not sqlite")
    reports_dir = tmp_path / "reports"
    _make_dashboard_report(reports_dir, "goodfam", {"hosts": ["fine.example"]})
    (reports_dir / "dashboard" / "data" / "corrupt.json").write_text(
        "{not json", encoding="utf-8"
    )

    payload = build_target_feed(
        sources=["db", "reports"],
        data_dir=data_dir,
        reports_dir=reports_dir,
        imports_dir=tmp_path / "nope",
        limit=None,
        existing_feed_path=None,
    )

    assert payload["counts"]["by_source"]["db"] == 0
    assert payload["counts"]["by_source"]["reports"] >= 1
    error_sources = {err["source"] for err in payload["source_errors"]}
    assert "db" in error_sources
    assert "reports" in error_sources


def test_feed_build_db_source_skips_master_sequence_db(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    _make_engagement_db(data_dir, 42, [("numeric.example", "domain")])
    master = data_dir / "engagements" / "master.db"
    conn = sqlite3.connect(master)
    try:
        conn.execute("CREATE TABLE engagement_id_sequence (id INTEGER PRIMARY KEY)")
        conn.commit()
    finally:
        conn.close()

    payload = build_target_feed(
        sources=["db"],
        data_dir=data_dir,
        reports_dir=tmp_path / "reports",
        imports_dir=tmp_path / "imports",
        limit=None,
        existing_feed_path=None,
    )

    assert payload["source_errors"] == []
    assert payload["counts"]["by_source"]["db"] == 1
    assert payload["items"][0]["canonical_value"] == "numeric.example"


def test_feed_build_supabase_selects_configured_columns_with_env_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed: dict[str, object] = {}

    class _Response:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> list[dict[str, str]]:
            return [
                {
                    "domain": "Portal.Example",
                    "url": "https://app.example/path?secret=drop",
                    "ignored": "skip.example",
                },
                {"email": "Ops@Example.com"},
            ]

    def _fake_get(url: str, *, headers: dict[str, str], timeout: float) -> _Response:
        observed["url"] = url
        observed["headers"] = headers
        observed["timeout"] = timeout
        return _Response()

    config = tmp_path / "imports" / "supabase-projects.local.json"
    config.parent.mkdir(parents=True)
    config.write_text(
        json.dumps(
            {
                "projects": [
                    {
                        "project_ref": "abc123",
                        "url": "https://abc123.supabase.co",
                        "key_env": "FORGE_SUPABASE_ABC123_READ_KEY",
                        "tables": ["targets"],
                        "target_columns": ["domain", "url", "email"],
                        "limit": 2,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("FORGE_SUPABASE_ABC123_READ_KEY", "test-read-key")
    monkeypatch.setattr("forge.automation_target_feed.httpx.get", _fake_get)

    payload = build_target_feed(
        sources=["supabase"],
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        imports_dir=tmp_path / "imports",
        limit=None,
        existing_feed_path=None,
        supabase_config_path=config,
    )

    assert observed["url"] == (
        "https://abc123.supabase.co/rest/v1/targets"
        "?select=domain,url,email&limit=2"
    )
    assert observed["headers"] == {
        "apikey": "test-read-key",
        "Authorization": "Bearer test-read-key",
        "Accept": "application/json",
    }
    typed_items = {
        (item["target_type"], item["canonical_value"]) for item in payload["items"]
    }
    assert ("domain", "portal.example") in typed_items
    assert ("url", "https://app.example/path") in typed_items
    assert ("email", "ops@example.com") in typed_items
    assert all("skip.example" not in item["canonical_value"] for item in payload["items"])
    assert payload["counts"]["by_source"]["supabase"] == 3
    assert payload["counts"]["by_source_group"]["supabase:abc123:targets"] == 2
    assert all(
        item["source_group"] == "supabase:abc123:targets"
        for item in payload["items"]
    )


def test_feed_build_supabase_missing_config_fails_soft(tmp_path: Path) -> None:
    payload = build_target_feed(
        sources=["supabase"],
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        imports_dir=tmp_path / "imports",
        limit=None,
        existing_feed_path=None,
        supabase_config_path=tmp_path / "missing.json",
    )

    assert payload["counts"]["by_source"]["supabase"] == 0
    assert payload["source_errors"] == [
        {
            "source": "supabase",
            "error": "not_configured:local_config_file_missing",
        }
    ]


def test_feed_build_supabase_unset_key_env_does_not_call_http(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "supabase-projects.local.json"
    config.write_text(
        json.dumps(
            {
                "projects": [
                    {
                        "project_ref": "abc123",
                        "url": "https://abc123.supabase.co",
                        "key_env": "FORGE_SUPABASE_ABC123_READ_KEY",
                        "tables": ["targets"],
                        "target_columns": ["domain"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    def _fail_get(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("unset Supabase key must not make HTTP requests")

    monkeypatch.delenv("FORGE_SUPABASE_ABC123_READ_KEY", raising=False)
    monkeypatch.setattr("forge.automation_target_feed.httpx.get", _fail_get)

    payload = build_target_feed(
        sources=["supabase"],
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        imports_dir=tmp_path / "imports",
        limit=None,
        existing_feed_path=None,
        supabase_config_path=config,
    )

    assert payload["items"] == []
    assert payload["source_errors"] == [
        {
            "source": "supabase",
            "error": "abc123:key_env_unset:FORGE_SUPABASE_ABC123_READ_KEY",
        }
    ]


def test_feed_build_supabase_caps_table_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed: dict[str, object] = {}

    class _Response:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> list[dict[str, str]]:
            return [{"domain": "one.example"}]

    def _fake_get(url: str, *, headers: dict[str, str], timeout: float) -> _Response:
        observed["url"] = url
        return _Response()

    config = tmp_path / "supabase-projects.local.json"
    config.write_text(
        json.dumps(
            {
                "projects": [
                    {
                        "project_ref": "abc123",
                        "url": "https://abc123.supabase.co",
                        "key_env": "FORGE_SUPABASE_ABC123_READ_KEY",
                        "tables": ["targets"],
                        "target_columns": ["domain"],
                        "limit": 50000,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("FORGE_SUPABASE_ABC123_READ_KEY", "test-read-key")
    monkeypatch.setattr("forge.automation_target_feed.httpx.get", _fake_get)

    build_target_feed(
        sources=["supabase"],
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        imports_dir=tmp_path / "imports",
        limit=None,
        existing_feed_path=None,
        supabase_config_path=config,
    )

    assert str(observed["url"]).endswith("&limit=1000")
