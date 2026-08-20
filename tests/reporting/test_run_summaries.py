import json
import sqlite3
from pathlib import Path
from typing import Any

from forge.reporting.run_summaries import (
    RunSummaryCallbacks,
    annotate_audit_manifest_bundle,
    engagement_run_section_row,
    effective_run_status,
    latest_engagement_run,
    run_policy_summary,
)


def _connect() -> sqlite3.Connection:
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    return con


def _table_exists(con: sqlite3.Connection, table: str) -> bool:
    row = con.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone()
    return row is not None


def _fetch_rows(
    con: sqlite3.Connection,
    sql: str,
    params: tuple[Any, ...],
) -> list[sqlite3.Row]:
    return list(con.execute(sql, params).fetchall())


def _callbacks(
    *,
    manifest_calls: list[dict[str, Any]] | None = None,
) -> RunSummaryCallbacks:
    def summarize_manifest(
        _con: sqlite3.Connection,
        **kwargs: Any,
    ) -> dict[str, Any]:
        if manifest_calls is not None:
            manifest_calls.append(kwargs)
        return {
            "present": True,
            "verified": bool(kwargs.get("verify")),
            "verification_status": "verified" if kwargs.get("verify") else "not_checked",
            "short_hash": "abc123def456",
        }

    return RunSummaryCallbacks(
        table_exists=_table_exists,
        fetch_rows=_fetch_rows,
        format_dt=lambda value: f"fmt:{value}" if value else "",
        safe_json_loads=json.loads,
        truncate=lambda value, limit: str(value or "")[:limit],
        redact_error=lambda value, limit: str(value or "")[:limit],
        summarize_run_audit_manifest=summarize_manifest,
    )


def test_latest_engagement_run_returns_none_without_table() -> None:
    con = _connect()

    assert latest_engagement_run(con, 1001, callbacks=_callbacks()) is None


def test_latest_engagement_run_builds_policy_manifest_and_status_payload(
    tmp_path: Path,
) -> None:
    con = _connect()
    con.executescript(
        """
        CREATE TABLE engagement_runs (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            run_kind TEXT,
            status TEXT,
            seed_value TEXT,
            seed_type TEXT,
            seed_count INTEGER,
            max_iterations INTEGER,
            current_iteration INTEGER,
            resume_enabled INTEGER,
            dry_run INTEGER,
            attack_mode INTEGER,
            error TEXT,
            metadata_json TEXT,
            started_at TEXT,
            completed_at TEXT,
            updated_at TEXT
        );
        """
    )
    con.execute(
        """
        INSERT INTO engagement_runs VALUES
            (1, 1001, 'kill_chain', 'completed', 'old.example', 'domain',
             1, 1, 1, 0, 1, 0, '', '{}',
             '2026-08-12T01:00:00', '2026-08-12T01:05:00',
             '2026-08-12T01:05:00')
        """
    )
    metadata = {
        "pause_requested": True,
        "phase": "validation",
        "live_execution_policy": {
            "roe_id": "ROE-ACME-2026",
            "roe_present": True,
            "live_probing_allowed": True,
            "tool_execution_allowed": False,
            "active_recon_allowed": True,
            "credential_validation_allowed": False,
            "destructive_actions_allowed": False,
            "post_exploitation_allowed": False,
            "scope_gate": "custom_scope_gate",
        },
    }
    con.execute(
        """
        INSERT INTO engagement_runs VALUES
            (2, 1001, 'continuous_monitor', 'running', 'app.example', 'url',
             4, 3, 2, 1, 0, 1, ?, ?,
             '2026-08-12T02:00:00', '', '2026-08-12T02:10:00')
        """,
        ("x" * 220, json.dumps(metadata, sort_keys=True)),
    )
    manifest_calls: list[dict[str, Any]] = []
    db_path = tmp_path / "1001.db"

    summary = latest_engagement_run(
        con,
        1001,
        db_path=db_path,
        callbacks=_callbacks(manifest_calls=manifest_calls),
    )

    assert summary is not None
    assert summary["id"] == 2
    assert summary["run_kind"] == "continuous_monitor"
    assert summary["status"] == "pausing"
    assert summary["seed_value"] == "app.example"
    assert summary["seed_type"] == "url"
    assert summary["seed_count"] == 4
    assert summary["max_iterations"] == 3
    assert summary["current_iteration"] == 2
    assert summary["resume_enabled"] is True
    assert summary["dry_run"] is False
    assert summary["attack_mode"] is True
    assert summary["roe_id"] == "ROE-ACME-2026"
    assert summary["roe_present"] is True
    assert summary["roe_missing"] is False
    assert summary["live_probing_allowed"] is True
    assert summary["tool_execution_allowed"] is False
    assert summary["active_recon_allowed"] is True
    assert summary["credential_validation_allowed"] is False
    assert summary["destructive_actions_allowed"] is False
    assert summary["post_exploitation_allowed"] is False
    assert summary["scope_gate"] == "custom_scope_gate"
    assert len(summary["error"]) == 160
    assert summary["metadata"]["phase"] == "validation"
    assert summary["audit_manifest"]["verified"] is True
    assert summary["started_at"] == "fmt:2026-08-12T02:00:00"
    assert summary["completed_at"] == ""
    assert summary["updated_at"] == "fmt:2026-08-12T02:10:00"
    assert manifest_calls == [
        {
            "db_path": db_path,
            "engagement_id": 1001,
            "run_id": 2,
            "verify": True,
        }
    ]


def test_latest_engagement_run_uses_error_redactor() -> None:
    con = _connect()
    con.executescript(
        """
        CREATE TABLE engagement_runs (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            run_kind TEXT,
            status TEXT,
            seed_value TEXT,
            seed_type TEXT,
            seed_count INTEGER,
            max_iterations INTEGER,
            current_iteration INTEGER,
            resume_enabled INTEGER,
            dry_run INTEGER,
            attack_mode INTEGER,
            error TEXT,
            metadata_json TEXT,
            started_at TEXT,
            completed_at TEXT,
            updated_at TEXT
        );
        """
    )
    con.execute(
        """
        INSERT INTO engagement_runs VALUES (
            1, 1001, 'kill_chain', 'failed', 'app.example', 'url',
            1, 1, 1, 1, 0, 1,
            'abandoned before explicit completion', '{}', '', '', ''
        )
        """
    )
    callbacks = _callbacks()
    callbacks = RunSummaryCallbacks(
        table_exists=callbacks.table_exists,
        fetch_rows=callbacks.fetch_rows,
        format_dt=callbacks.format_dt,
        safe_json_loads=callbacks.safe_json_loads,
        truncate=callbacks.truncate,
        redact_error=lambda value, _limit: str(value).replace(
            "abandoned before explicit completion",
            "interrupted before finalization",
        ),
        summarize_run_audit_manifest=callbacks.summarize_run_audit_manifest,
    )

    summary = latest_engagement_run(con, 1001, callbacks=callbacks)

    assert summary is not None
    assert summary["error"] == "interrupted before finalization"


def test_run_policy_summary_defaults_and_effective_statuses() -> None:
    policy = run_policy_summary({}, dry_run=True, attack_mode=True)

    assert policy["roe_id"] == ""
    assert policy["roe_present"] is False
    assert policy["roe_missing"] is True
    assert policy["live_probing_allowed"] is False
    assert policy["tool_execution_allowed"] is False
    assert policy["active_recon_allowed"] is False
    assert policy["credential_validation_allowed"] is False
    assert policy["requires_explicit_roe"] is True
    assert policy["scope_gate"] == "engagement_scope_json_root_domains"
    assert effective_run_status("running", {"stop_requested": True}) == "stopping"
    assert effective_run_status("cancelled", {"lifecycle_state": "paused"}) == "paused"


def test_annotate_audit_manifest_bundle_selects_matching_audit_artifact() -> None:
    summary = {"status": "completed", "audit_manifest": {"short_hash": "abc123"}}
    artifacts = [
        {"kind": "report", "name": "engagement_1001.md", "href": "report.html"},
        {"kind": "audit", "name": "audit_1001_run_8_nomatch.json", "href": "old.json"},
        {"kind": "audit", "name": "audit_1001_run_9_abc123.json", "href": "new.json"},
    ]

    annotated = annotate_audit_manifest_bundle(summary, artifacts)

    assert annotated == {
        "status": "completed",
        "audit_manifest": {
            "short_hash": "abc123",
            "artifact_count": 2,
            "artifact_available": True,
            "artifact_name": "audit_1001_run_9_abc123.json",
            "artifact_href": "new.json",
        },
    }


def test_annotate_audit_manifest_bundle_leaves_missing_manifest_unchanged() -> None:
    summary = {"status": "completed"}

    assert annotate_audit_manifest_bundle(summary, []) is summary


def test_engagement_run_section_row_formats_policy_status_and_manifest() -> None:
    con = _connect()
    con.executescript(
        """
        CREATE TABLE engagement_runs (
            id INTEGER PRIMARY KEY,
            run_kind TEXT,
            status TEXT,
            seed_value TEXT,
            seed_type TEXT,
            seed_count INTEGER,
            max_iterations INTEGER,
            current_iteration INTEGER,
            resume_enabled INTEGER,
            dry_run INTEGER,
            attack_mode INTEGER,
            error TEXT,
            metadata_json TEXT,
            started_at TEXT,
            completed_at TEXT
        );
        """
    )
    metadata = {
        "stop_requested": True,
        "live_execution_policy": {
            "roe_id": "ROE-ACME-2026",
            "roe_missing": False,
            "live_probing_allowed": True,
            "tool_execution_allowed": False,
            "active_recon_allowed": True,
            "credential_validation_allowed": False,
            "destructive_actions_allowed": False,
            "post_exploitation_allowed": False,
        },
    }
    con.execute(
        """
        INSERT INTO engagement_runs VALUES (
            9,
            'kill_chain',
            'running',
            'app.example',
            'url',
            3,
            4,
            2,
            1,
            0,
            1,
            ?,
            ?,
            '2026-08-12T01:00:00',
            ''
        )
        """,
        ("e" * 140, json.dumps(metadata, sort_keys=True)),
    )
    row = con.execute("SELECT * FROM engagement_runs").fetchone()

    formatted = engagement_run_section_row(
        row,
        {"short_hash": "abc123", "verified": False, "verification_status": "mismatch"},
        format_dt=lambda value: f"fmt:{value}" if value else "",
        truncate=lambda value, limit: str(value or "")[:limit],
    )

    assert formatted == {
        "Kind": "kill_chain",
        "Status": "stopping",
        "Seed": "app.example",
        "Type": "url",
        "Seeds": "3",
        "Iteration": "2/4",
        "Resume": "yes",
        "Dry": "no",
        "Attack": "yes",
        "Live": "probe=yes tools=no active=yes creds=no",
        "ROE": "ROE-ACME-2026",
        "ROE Missing": "no",
        "Destructive": "no",
        "Post-Ex": "no",
        "Started": "fmt:2026-08-12T01:00:00",
        "Completed": "",
        "Error": "e" * 96,
        "Manifest": "abc123",
        "Manifest OK": "mismatch",
    }


def test_engagement_run_section_row_accepts_error_redactor() -> None:
    con = _connect()
    con.executescript(
        """
        CREATE TABLE engagement_runs (
            id INTEGER PRIMARY KEY,
            run_kind TEXT,
            status TEXT,
            seed_value TEXT,
            seed_type TEXT,
            seed_count INTEGER,
            max_iterations INTEGER,
            current_iteration INTEGER,
            resume_enabled INTEGER,
            dry_run INTEGER,
            attack_mode INTEGER,
            error TEXT,
            metadata_json TEXT,
            started_at TEXT,
            completed_at TEXT
        );
        """
    )
    con.execute(
        """
        INSERT INTO engagement_runs VALUES (
            9, 'kill_chain', 'failed', 'app.example', 'url', 1, 1, 1,
            1, 0, 1, 'abandoned before explicit completion', '{}', '', ''
        )
        """
    )
    row = con.execute("SELECT * FROM engagement_runs").fetchone()

    formatted = engagement_run_section_row(
        row,
        redact_error=lambda value, _limit: str(value).replace(
            "abandoned before explicit completion",
            "interrupted before finalization",
        ),
    )

    assert formatted["Error"] == "interrupted before finalization"
