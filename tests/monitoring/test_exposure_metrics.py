from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import typer
from typer.testing import CliRunner

from forge.db.schema import apply_schema
from forge.monitoring.cli import register_monitoring_commands
from forge.monitoring.exposure_metrics import exposure_metrics_for_data_dir, exposure_metrics_for_db
from forge.reporting.dashboard import generate_dashboard


def _build_db(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    apply_schema(con)
    con.execute(
        """
        INSERT INTO engagements (id, name, scope_json, status, operator)
        VALUES (1001, 'Acme Example', '["acme.example"]', 'ACTIVE', 'delta-one')
        """
    )
    con.commit()
    return con


def _metric(payload: dict[str, object], key_prefix: str) -> dict[str, object]:
    metrics = payload["engagements"][0]["metrics"]  # type: ignore[index]
    for item in metrics:
        if str(item["key"]).startswith(key_prefix):
            return item
    raise AssertionError(f"missing metric with prefix {key_prefix!r}: {json.dumps(payload)}")


def test_exposure_metrics_reports_open_finding_duration_without_writes(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    con = _build_db(db_path)
    try:
        con.execute(
            """
            INSERT INTO vulnerability_findings
                (id, engagement_id, vuln_type, target_url, parameter, severity, title, found_at)
            VALUES
                (42, 1001, 'xss', 'https://app.acme.example/search', 'q',
                 'HIGH', 'Reflected XSS', '2026-07-01T00:00:00Z')
            """
        )
        con.commit()
    finally:
        con.close()

    before = sqlite3.connect(db_path).execute("PRAGMA data_version").fetchone()[0]
    payload = exposure_metrics_for_db(db_path, now="2026-07-11T12:00:00Z")
    after = sqlite3.connect(db_path).execute("PRAGMA data_version").fetchone()[0]

    item = _metric(payload, "finding:vulnerability:xss:")
    assert payload["schema_ready"] is True
    assert payload["metric_count"] == 1
    assert payload["open_count"] == 1
    assert item["first_seen"] == "2026-07-01T00:00:00Z"
    assert item["last_seen"] == "2026-07-01T00:00:00Z"
    assert item["open_days"] == 10.5
    assert item["recurrence"] == 1
    assert item["mttr_hours"] is None
    assert before == after


def test_exposure_metrics_counts_reopened_monitoring_changes(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    con = _build_db(db_path)
    try:
        for snapshot_id, created_at in (
            (1, "2026-07-01T00:00:00Z"),
            (2, "2026-07-03T00:00:00Z"),
            (3, "2026-07-08T00:00:00Z"),
        ):
            con.execute(
                """
                INSERT INTO monitoring_snapshots
                    (id, engagement_id, snapshot_kind, state_hash, state_json, summary_json, created_at)
                VALUES (?, 1001, 'scheduled', ?, '{}', '{}', ?)
                """,
                (snapshot_id, f"hash-{snapshot_id}", created_at),
            )
        for row_id, snapshot_id, change_type in ((1, 1, "added"), (2, 2, "removed"), (3, 3, "added")):
            con.execute(
                """
                INSERT INTO monitoring_changes
                    (id, engagement_id, snapshot_id, entity_type, entity_key, change_type, severity)
                VALUES (?, 1001, ?, 'asset', 'host:api.acme.example', ?, 'MEDIUM')
                """,
                (row_id, snapshot_id, change_type),
            )
        con.commit()
    finally:
        con.close()

    payload = exposure_metrics_for_db(db_path, now="2026-07-10T00:00:00Z")

    item = _metric(payload, "monitoring:asset:host:api.acme.example")
    assert item["first_seen"] == "2026-07-01T00:00:00Z"
    assert item["last_seen"] == "2026-07-08T00:00:00Z"
    assert item["is_open"] is True
    assert item["open_days"] == 9.0
    assert item["recurrence"] == 3
    assert payload["recurrent_count"] == 1


def test_exposure_metrics_computes_remediation_mttr(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    con = _build_db(db_path)
    try:
        con.execute(
            """
            INSERT INTO remediation_items
                (id, engagement_id, finding_table, finding_ref, title, severity, status,
                 created_at, updated_at, retested_at)
            VALUES
                (7, 1001, 'manual', 'manual:stale-admin', 'Stale admin endpoint',
                 'HIGH', 'resolved', '2026-07-01T00:00:00Z',
                 '2026-07-04T00:00:00Z', '2026-07-03T12:00:00Z')
            """
        )
        con.commit()
    finally:
        con.close()

    payload = exposure_metrics_for_db(db_path, now="2026-07-10T00:00:00Z")

    item = _metric(payload, "remediation:manual:manual:stale-admin")
    assert item["is_open"] is False
    assert item["closed_at"] == "2026-07-03T12:00:00Z"
    assert item["open_days"] == 2.5
    assert item["mttr_hours"] == 60.0
    assert payload["mttr_sample_count"] == 1
    assert payload["mean_mttr_hours"] == 60.0


def test_exposure_metrics_tolerates_legacy_db_and_bad_timestamps(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    legacy = data_dir / "engagements" / "1001.db"
    legacy.parent.mkdir(parents=True)
    con = sqlite3.connect(legacy)
    try:
        con.execute("CREATE TABLE engagements (id INTEGER PRIMARY KEY, name TEXT)")
        con.execute("INSERT INTO engagements (id, name) VALUES (1001, 'Legacy')")
        con.commit()
    finally:
        con.close()

    ready = data_dir / "engagements" / "1002.db"
    con = _build_db(ready)
    try:
        con.execute("UPDATE engagements SET id=1002, name='Ready' WHERE id=1001")
        con.execute(
            """
            INSERT INTO remediation_items
                (engagement_id, finding_table, finding_ref, title, status, created_at, updated_at)
            VALUES
                (1002, 'manual', 'manual:bad-time', 'Bad time', 'open',
                 'not-a-time', 'also-not-a-time')
            """
        )
        con.commit()
    finally:
        con.close()

    payload = exposure_metrics_for_data_dir(data_dir, now="2026-07-10T00:00:00Z")

    assert payload["db_count"] == 2
    assert payload["schema_ready_db_count"] == 2
    assert payload["total_count"] == 1
    item = payload["db_results"][1]["engagements"][0]["metrics"][0]
    assert item["first_seen"] == ""
    assert item["open_days"] is None


def test_monitoring_cli_exposure_metrics_outputs_json(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    db_path = data_dir / "engagements" / "1001.db"
    con = _build_db(db_path)
    try:
        con.execute(
            """
            INSERT INTO active_validation_jobs
                (id, engagement_id, target_ref, target_kind, method, mode, status,
                 approved, requested_by, approved_by)
            VALUES
                (501, 1001, 'https://app.acme.example/admin', 'service',
                 'http_reachability', 'read_only_live', 'completed',
                 1, 'delta-one', 'lead')
            """
        )
        con.execute(
            """
            INSERT INTO active_validation_runs
                (id, engagement_id, job_id, status, result, started_at, completed_at, created_at)
            VALUES
                (701, 1001, 501, 'completed', 'reachable',
                 '2026-07-09T09:00:00Z', '2026-07-09T09:00:10Z',
                 '2026-07-09T09:00:10Z')
            """
        )
        con.commit()
    finally:
        con.close()

    app = typer.Typer()
    monitoring_app = typer.Typer()
    register_monitoring_commands(monitoring_app)
    app.add_typer(monitoring_app, name="monitoring")
    result = CliRunner().invoke(
        app,
        [
            "monitoring",
            "exposure-metrics",
            "--data-dir",
            str(data_dir),
            "--now",
            "2026-07-10T09:00:10Z",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["schema_version"] == "forge.monitoring.exposure_metrics.v1"
    assert payload["execution_policy"] == "read_only_exposure_metrics_no_commands_executed"
    assert payload["total_count"] == 1
    assert payload["open_count"] == 1
    assert payload["db_results"][0]["engagements"][0]["metrics"][0]["proof_types"] == [
        "http_reachability"
    ]


def test_dashboard_detail_payload_includes_exposure_duration_metrics(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    db_path = data_dir / "engagements" / "1001.db"
    con = _build_db(db_path)
    try:
        con.execute(
            """
            INSERT INTO vulnerability_findings
                (engagement_id, vuln_type, target_url, parameter, severity, title, found_at)
            VALUES
                (1001, 'idor', 'https://app.acme.example/account/1', '',
                 'HIGH', 'IDOR exposure', '2026-07-01T00:00:00Z')
            """
        )
        con.commit()
    finally:
        con.close()

    output = generate_dashboard(
        data_dir,
        tmp_path / "reports",
        tmp_path / "dashboard.html",
    )
    payload_paths = list((output.parent / output.stem / "data" / "engagements").glob("*.json"))
    assert len(payload_paths) == 1
    payload_path = payload_paths[0]
    payload = json.loads(payload_path.read_text(encoding="utf-8"))

    rows = payload["sections"]["exposure_duration_metrics"]
    assert rows[0]["Title"] == "IDOR exposure"
    assert rows[0]["Severity"] == "HIGH"
    assert rows[0]["State"] == "open"
    detail_paths = list((output.parent / output.stem / "engagements").glob("*/index.html"))
    assert len(detail_paths) == 1
    assert "Exposure Duration Metrics" in detail_paths[0].read_text(encoding="utf-8")
