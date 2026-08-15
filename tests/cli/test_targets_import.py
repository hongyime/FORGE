from __future__ import annotations

import json
import sqlite3
import subprocess
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from forge.db.session import get_engagement_db
from forge.targets_import_cli import register_target_import_commands
from forge.targets_import import import_targets, load_target_feed


class _FakeConfig:
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.operator = "tester"

    def engagement_db_path(self, engagement_id: str) -> Path:
        return self.data_dir / "engagements" / f"{engagement_id}.db"


def _write_feed(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": "target-feed.v1",
                "generated_at": "2026-08-08T00:00:00Z",
                "items": [
                    {
                        "target_type": "domain",
                        "target_value": "Example.COM",
                        "source_kind": "telemetry",
                        "confidence": 0.9,
                        "first_seen_at": "2026-08-07T00:00:00Z",
                        "provenance": "network_domain",
                        "token": "must-not-persist",
                    },
                    {
                        "target_type": "domain",
                        "target_value": "example.com",
                        "source_kind": "duplicate",
                        "confidence": 0.1,
                        "first_seen_at": "2026-08-07T00:00:00Z",
                        "provenance": "duplicate",
                    },
                    {
                        "target_type": "url",
                        "target_value": "HTTPS://App.Example.COM/Login?secret=drop",
                        "source_kind": "webhook",
                        "confidence": 0.8,
                        "first_seen_at": "2026-08-07T00:00:00Z",
                        "provenance": "webhook_url",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )


def _write_multi_seed_feed(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": "target-feed.v1",
                "generated_at": "2026-08-08T00:00:00Z",
                "items": [
                    {"target_type": "email", "target_value": "Security@Example.COM"},
                    {"target_type": "telephone", "target_value": "00 1 555 123 4567"},
                    {"target_type": "handle", "target_value": "Forge_Handle"},
                    {"target_type": "organization", "target_value": "Example Holdings Inc"},
                    {"target_type": "person", "target_value": "Jane Doe"},
                    {"target_type": "ip", "target_value": "203.0.113.7"},
                    {"target_type": "ipv6", "target_value": "2001:db8::1"},
                    {"target_type": "cloud_ref", "target_value": "s3://Acme-Artifacts/mobile"},
                    {"target_type": "cloud_ref", "target_value": "aws_s3:acme-artifacts"},
                    {
                        "target_type": "auto",
                        "target_value": "https://files.example.com/releases/app.apk?token=drop",
                    },
                    {
                        "target_type": "url",
                        "target_value": "https://demo.supabase.co:443/rest/v1?apikey=drop",
                    },
                    {"target_type": "password", "target_value": "must-not-import"},
                ],
            }
        ),
        encoding="utf-8",
    )


def _write_unpack_error_feed(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": "target-feed.v1",
                "generated_at": "2026-08-08T00:00:00Z",
                "items": [
                    {"target_type": "auto", "target_value": "malformed delegated target"},
                    {"target_type": "domain", "target_value": "Example.COM"},
                ],
            }
        ),
        encoding="utf-8",
    )


def test_import_feed_file_creates_deduped_engagements_and_manifests(tmp_path: Path) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg = _FakeConfig(tmp_path / "data")

    results = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-ACME-2026-08",
        start=False,
        dry_run=False,
        limit=None,
        max_iter=3,
        config=cfg,  # type: ignore[arg-type]
    )

    assert len(results) == 2
    assert [result.created for result in results] == [True, True]
    domain_result = results[0]
    assert domain_result.engagement_id == 1
    assert domain_result.target_value == "example.com"
    assert domain_result.scope_manifest is not None
    manifest = json.loads(domain_result.scope_manifest.read_text(encoding="utf-8"))
    assert manifest["roe_id"] == "ROE-ACME-2026-08"
    assert manifest["domains"] == ["example.com"]
    assert manifest["urls"] == []

    db_path = cfg.engagement_db_path("1")
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute("SELECT scope_json, metadata_json FROM engagements").fetchone()
    finally:
        conn.close()
    metadata = json.loads(row[1])
    assert metadata["external_feed"] == "target-feed.v1"
    assert metadata["external_target_key"] == domain_result.target_key
    assert metadata["source_kind"] == "telemetry"
    assert metadata["provenance_summary"] == "network_domain"
    persisted = json.dumps(metadata)
    assert "must-not-persist" not in persisted
    assert json.loads(row[0]) == {"domains": ["example.com"], "urls": []}
    monitoring_row = sqlite3.connect(db_path)
    try:
        policy = monitoring_row.execute(
            """
            SELECT name, enabled, schedule_interval_minutes, mode,
                   last_snapshot_id, metadata_json
            FROM monitoring_policies
            """
        ).fetchone()
        snapshot_count = monitoring_row.execute(
            "SELECT COUNT(*) FROM monitoring_snapshots"
        ).fetchone()[0]
        trend_count = monitoring_row.execute(
            "SELECT COUNT(*) FROM monitoring_trend_points"
        ).fetchone()[0]
    finally:
        monitoring_row.close()
    assert policy[0] == "Target import seed exposure"
    assert policy[1] == 1
    assert policy[2] == 60
    assert policy[3] == "passive"
    assert policy[4] == 1
    policy_metadata = json.loads(policy[5])
    assert policy_metadata["refresh"] == {"type": "seed_exposure"}
    assert policy_metadata["source"] == "target_import"
    assert snapshot_count == 1
    assert trend_count == 1

    control_db = cfg.data_dir / "control.db"
    assert control_db.is_file()
    control_con = sqlite3.connect(control_db)
    try:
        index_rows = control_con.execute(
            """
            SELECT engagement_id, workspace_id, slug, summary_json
            FROM engagement_index
            ORDER BY engagement_id
            """
        ).fetchall()
    finally:
        control_con.close()
    assert [row[0] for row in index_rows] == [1, 2]
    assert index_rows[0][1] == "default"
    assert index_rows[0][2].startswith("engagement-1-external-target-")
    summary = json.loads(index_rows[0][3])
    assert summary["id"] == 1
    assert summary["workspace_id"] == "default"
    assert summary["seeds"] == ["example.com"]
    assert "must-not-persist" not in json.dumps(summary)


def test_import_feed_skips_allocator_id_with_existing_engagement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg = _FakeConfig(tmp_path / "data")

    existing_db = cfg.engagement_db_path("1")
    existing_db.parent.mkdir(parents=True, exist_ok=True)
    conn = get_engagement_db(existing_db)
    try:
        conn.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator, metadata_json)
            VALUES (1, 'existing', '{}', 'ACTIVE', 'tester', '{}')
            """
        )
        conn.commit()
    finally:
        conn.close()

    allocated = iter([1, 2, 3])
    monkeypatch.setattr(
        "forge.targets_import.allocate_engagement_id",
        lambda _data_dir: next(allocated),
    )

    results = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-ACME-2026-08",
        start=False,
        dry_run=False,
        limit=1,
        max_iter=3,
        config=cfg,  # type: ignore[arg-type]
    )

    assert len(results) == 1
    assert results[0].engagement_id == 2
    assert cfg.engagement_db_path("2").exists()


def test_import_feed_accepts_canonical_multi_seed_targets(tmp_path: Path) -> None:
    feed_path = tmp_path / "multi-seed-feed.json"
    _write_multi_seed_feed(feed_path)
    cfg = _FakeConfig(tmp_path / "data")

    results = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-ACME-2026-08",
        start=False,
        dry_run=False,
        limit=None,
        max_iter=3,
        config=cfg,  # type: ignore[arg-type]
    )

    assert [(result.target_type, result.target_value) for result in results] == [
        ("email", "security@example.com"),
        ("phone", "+15551234567"),
        ("username", "@forge_handle"),
        ("company", "Example Holdings Inc"),
        ("name", "Jane Doe"),
        ("ipv4", "203.0.113.7"),
        ("ipv6", "2001:db8::1"),
        ("cloud_ref", "aws_s3:acme-artifacts"),
        ("apk_url", "https://files.example.com/releases/app.apk"),
        ("cloud_ref", "https://demo.supabase.co:443/rest/v1"),
    ]
    assert len(results) == 10
    assert all(result.scope_manifest is not None for result in results)

    email_manifest = json.loads(results[0].scope_manifest.read_text(encoding="utf-8"))
    assert email_manifest["authorized_seeds"] == ["security@example.com"]
    assert email_manifest["domains"] == []
    assert email_manifest["ip_ranges"] == []
    assert email_manifest["urls"] == []

    ipv4_manifest = json.loads(results[5].scope_manifest.read_text(encoding="utf-8"))
    assert ipv4_manifest["authorized_seeds"] == ["203.0.113.7"]
    assert ipv4_manifest["ip_ranges"] == ["203.0.113.7/32"]

    apk_manifest = json.loads(results[8].scope_manifest.read_text(encoding="utf-8"))
    assert apk_manifest["domains"] == ["files.example.com"]
    assert apk_manifest["urls"] == ["https://files.example.com/releases/app.apk"]
    assert apk_manifest["authorized_seeds"] == ["https://files.example.com/releases/app.apk"]

    cloud_url_manifest = json.loads(results[9].scope_manifest.read_text(encoding="utf-8"))
    assert cloud_url_manifest["domains"] == ["demo.supabase.co"]
    assert cloud_url_manifest["urls"] == ["https://demo.supabase.co:443/rest/v1"]
    assert cloud_url_manifest["metadata"]["target_type"] == "cloud_ref"

    db_path = cfg.engagement_db_path("1")
    conn = sqlite3.connect(db_path)
    try:
        seed_row = conn.execute(
            "SELECT seed_value, seed_type FROM engagement_seeds"
        ).fetchone()
        scope_row = conn.execute("SELECT scope_json FROM engagements").fetchone()
    finally:
        conn.close()
    assert seed_row == ("security@example.com", "email")
    assert json.loads(scope_row[0]) == {
        "authorized_seeds": ["security@example.com"],
        "domains": [],
        "urls": [],
    }
    assert "must-not-import" not in json.dumps([result.target_value for result in results])


def test_reimport_reuses_existing_engagement_ids(tmp_path: Path) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg = _FakeConfig(tmp_path / "data")

    first = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id=None,
        start=False,
        dry_run=False,
        limit=1,
        max_iter=3,
        config=cfg,  # type: ignore[arg-type]
    )
    db_path = cfg.engagement_db_path("1")
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            UPDATE monitoring_policies
            SET next_run_at='2026-08-08T00:00:00Z'
            """
        )
        conn.commit()
    finally:
        conn.close()
    second = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id=None,
        start=False,
        dry_run=False,
        limit=1,
        max_iter=3,
        config=cfg,  # type: ignore[arg-type]
    )

    assert first[0].engagement_id == second[0].engagement_id == 1
    assert first[0].created is True
    assert second[0].created is False
    conn = sqlite3.connect(db_path)
    try:
        policy_rows = conn.execute(
            "SELECT next_run_at FROM monitoring_policies"
        ).fetchall()
        snapshot_count = conn.execute("SELECT COUNT(*) FROM monitoring_snapshots").fetchone()[0]
    finally:
        conn.close()
    assert policy_rows == [("2026-08-08T00:00:00Z",)]
    assert snapshot_count == 1


def test_start_launches_passive_kill_chain_with_scope_and_roe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg = _FakeConfig(tmp_path / "data")
    calls: list[list[str]] = []

    def _fake_run(
        command: list[str],
        *,
        check: bool,
        capture_output: bool,
        text: bool,
    ) -> object:
        calls.append(command)
        assert check is False
        assert capture_output is True
        assert text is True
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr("forge.targets_import.subprocess.run", _fake_run)

    results = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-ACME-2026-08",
        start=True,
        dry_run=False,
        limit=1,
        max_iter=3,
        config=cfg,  # type: ignore[arg-type]
    )

    assert results[0].started is True
    command = calls[0]
    assert command[2:4] == ["forge.cli", "kill-chain"]
    assert "--roe-id" in command
    assert "--scope-manifest" in command
    assert "--max-iter" in command
    assert "--no-attack-mode" in command
    assert "--no-auto-run-detected" in command
    assert "--attack-mode" not in command
    assert "--auto-run-detected" not in command


def test_start_treats_completed_kill_chain_exit_two_as_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg = _FakeConfig(tmp_path / "data")

    def _fake_run(command: list[str], **_: object) -> object:
        return subprocess.CompletedProcess(
            command,
            2,
            stdout="Kill-chain complete in 10.0s\nReport: reports/demo.md\n",
            stderr="Non-TTY invocation - not prompting.\n",
        )

    monkeypatch.setattr("forge.targets_import.subprocess.run", _fake_run)

    results = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-ACME-2026-08",
        start=True,
        dry_run=False,
        limit=1,
        max_iter=3,
        config=cfg,  # type: ignore[arg-type]
    )

    assert results[0].started is True


def test_start_treats_exit_two_with_completed_db_run_as_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg = _FakeConfig(tmp_path / "data")

    def _fake_run(command: list[str], **_: object) -> object:
        db_path = cfg.engagement_db_path("1")
        conn = sqlite3.connect(db_path)
        try:
            conn.execute(
                """
                INSERT INTO engagement_runs
                    (engagement_id, run_kind, status, seed_value, seed_type)
                VALUES (1, 'kill_chain', 'completed', 'example.com', 'domain')
                """
            )
            conn.commit()
        finally:
            conn.close()
        return subprocess.CompletedProcess(
            command,
            2,
            stdout="",
            stderr=(
                "Usage: python -m forge.cli targets import [OPTIONS]\n"
                "Invalid value: not enough values to unpack (expected 2, got 1)\n"
            ),
        )

    monkeypatch.setattr("forge.targets_import.subprocess.run", _fake_run)

    results = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-ACME-2026-08",
        start=True,
        dry_run=False,
        limit=1,
        max_iter=3,
        config=cfg,  # type: ignore[arg-type]
    )

    assert results[0].started is True


def test_start_keeps_real_kill_chain_cli_exit_two_as_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg = _FakeConfig(tmp_path / "data")

    def _fake_run(command: list[str], **_: object) -> object:
        return subprocess.CompletedProcess(
            command,
            2,
            stdout="",
            stderr="Usage: python -m forge.cli kill-chain [OPTIONS]\nInvalid value\n",
        )

    monkeypatch.setattr("forge.targets_import.subprocess.run", _fake_run)

    with pytest.raises(subprocess.CalledProcessError):
        import_targets(
            feed_url=None,
            feed_file=feed_path,
            auth_header_env=None,
            roe_id="ROE-ACME-2026-08",
            start=True,
            dry_run=False,
            limit=1,
            max_iter=3,
            config=cfg,  # type: ignore[arg-type]
        )


def test_start_limit_caps_passive_kill_chain_launches(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg = _FakeConfig(tmp_path / "data")
    calls: list[list[str]] = []

    def _fake_run(
        command: list[str],
        *,
        check: bool,
        capture_output: bool,
        text: bool,
    ) -> object:
        calls.append(command)
        assert check is False
        assert capture_output is True
        assert text is True
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr("forge.targets_import.subprocess.run", _fake_run)

    results = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-ACME-2026-08",
        start=True,
        dry_run=False,
        limit=2,
        max_iter=3,
        start_limit=1,
        config=cfg,  # type: ignore[arg-type]
    )

    assert [result.started for result in results] == [True, False]
    assert len(calls) == 1


def test_start_skips_engagement_with_existing_kill_chain_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg = _FakeConfig(tmp_path / "data")
    first = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-ACME-2026-08",
        start=False,
        dry_run=False,
        limit=1,
        max_iter=3,
        config=cfg,  # type: ignore[arg-type]
    )
    db_path = cfg.engagement_db_path("1")
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            INSERT INTO engagement_runs
                (engagement_id, run_kind, status, seed_value, seed_type)
            VALUES (?, 'kill_chain', 'completed', ?, ?)
            """,
            (1, first[0].target_value, first[0].target_type),
        )
        conn.commit()
    finally:
        conn.close()

    calls: list[list[str]] = []
    monkeypatch.setattr(
        "forge.targets_import.subprocess.run",
        lambda command, **_kwargs: calls.append(command),
    )

    second = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-ACME-2026-08",
        start=True,
        dry_run=False,
        limit=1,
        max_iter=3,
        config=cfg,  # type: ignore[arg-type]
    )

    assert second[0].created is False
    assert second[0].started is False
    assert calls == []


def test_start_requires_roe_before_engagement_write(tmp_path: Path) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg = _FakeConfig(tmp_path / "data")

    with pytest.raises(ValueError, match="--start requires --roe-id"):
        import_targets(
            feed_url=None,
            feed_file=feed_path,
            auth_header_env=None,
            roe_id=None,
            start=True,
            dry_run=False,
            limit=1,
            max_iter=3,
            config=cfg,  # type: ignore[arg-type]
        )

    assert not (cfg.data_dir / "engagements").exists()


def test_feed_url_uses_monitor_key_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    class _Response:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return {
                "schema_version": "target-feed.v1",
                "generated_at": "2026-08-08T00:00:00Z",
                "items": [
                    {
                        "target_type": "domain",
                        "target_value": "example.com",
                        "source_kind": "telemetry",
                        "confidence": 1,
                        "first_seen_at": "2026-08-08T00:00:00Z",
                        "provenance": "network_domain",
                    }
                ],
            }

    def _fake_get(url: str, *, headers: dict[str, str], timeout: float) -> _Response:
        observed.update({"url": url, "headers": headers, "timeout": timeout})
        return _Response()

    monkeypatch.setenv("TPH_MONITOR_KEY", "secret-value")
    monkeypatch.setattr("forge.targets_import.httpx.get", _fake_get)

    items = load_target_feed(
        feed_url="http://127.0.0.1:8011/monitor/targets/export",
        feed_file=None,
        auth_header_env="TPH_MONITOR_KEY",
        limit=None,
    )

    assert len(items) == 1
    assert observed["headers"] == {"X-Monitor-Key": "secret-value"}


def test_load_target_feed_skips_item_level_unpack_value_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_unpack_error_feed(feed_path)

    def _raise_unpack_error(value: str) -> str:
        raise ValueError("not enough values to unpack (expected 2, got 1)")

    monkeypatch.setattr("forge.targets_import._classify_target_value", _raise_unpack_error)

    items = load_target_feed(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        limit=None,
    )

    assert [(item.target_type, item.canonical_value) for item in items] == [
        ("domain", "example.com")
    ]


def test_targets_import_cli_registration_supports_dry_run(tmp_path: Path) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)

    app = typer.Typer()
    targets_app = typer.Typer()
    register_target_import_commands(targets_app)
    app.add_typer(targets_app, name="targets")

    result = CliRunner().invoke(
        app,
        [
            "targets",
            "import",
            "--feed-file",
            str(feed_path),
            "--dry-run",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "DRY RUN" in result.output
    assert "2 target(s) parsed and deduped" in result.output


def test_targets_import_cli_dry_run_skips_item_level_unpack_value_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_unpack_error_feed(feed_path)

    def _raise_unpack_error(value: str) -> str:
        raise ValueError("not enough values to unpack (expected 2, got 1)")

    monkeypatch.setattr("forge.targets_import._classify_target_value", _raise_unpack_error)

    app = typer.Typer()
    targets_app = typer.Typer()
    register_target_import_commands(targets_app)
    app.add_typer(targets_app, name="targets")

    result = CliRunner().invoke(
        app,
        [
            "targets",
            "import",
            "--feed-file",
            str(feed_path),
            "--dry-run",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "DRY RUN" in result.output
    assert "1 target(s) parsed and deduped" in result.output
    assert "not enough values to unpack" not in result.output
