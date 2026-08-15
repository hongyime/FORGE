from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from forge.webui.run_status import (
    annotate_run_audit_review,
    engagement_run_rows,
    iter_live_run_progress_snapshots,
    latest_running_engagement_run,
    live_run_progress_fingerprint,
    live_run_progress_payload,
    live_run_progress_snapshot,
)


def _connect() -> sqlite3.Connection:
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    return con


def _connect_file(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(path)


def _create_runs_table(con: sqlite3.Connection, *, include_engagement_id: bool = True) -> None:
    engagement_id_column = "engagement_id INTEGER," if include_engagement_id else ""
    con.executescript(
        f"""
        CREATE TABLE engagement_runs (
            id INTEGER PRIMARY KEY,
            {engagement_id_column}
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


def _insert_run(con: sqlite3.Connection, values: tuple[Any, ...], *, include_engagement_id: bool = True) -> None:
    columns = (
        "id, engagement_id, run_kind, status, seed_value, seed_type, seed_count, max_iterations, "
        "current_iteration, resume_enabled, dry_run, attack_mode, error, metadata_json, "
        "started_at, completed_at, updated_at"
        if include_engagement_id
        else "id, run_kind, status, seed_value, seed_type, seed_count, max_iterations, "
        "current_iteration, resume_enabled, dry_run, attack_mode, error, metadata_json, "
        "started_at, completed_at, updated_at"
    )
    placeholders = ", ".join("?" for _ in values)
    con.execute(f"INSERT INTO engagement_runs ({columns}) VALUES ({placeholders})", values)


def test_engagement_run_rows_preserves_web_api_payload_contract(tmp_path: Path) -> None:
    con = _connect()
    _create_runs_table(con)
    metadata = {
        "stop_requested": True,
        "phase": "iteration_2",
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
    _insert_run(
        con,
        (
            9,
            1001,
            "kill_chain",
            "running",
            "acme.example",
            "domain",
            3,
            5,
            2,
            1,
            0,
            1,
            "operator stopped",
            json.dumps(metadata, sort_keys=True),
            "2026-07-09T10:00:00",
            "",
            "2026-07-09T10:02:00",
        ),
    )
    manifest_calls: list[dict[str, Any]] = []
    review_calls: list[dict[str, Any]] = []

    def summarize_manifest(_con: sqlite3.Connection, **kwargs: Any) -> dict[str, Any]:
        manifest_calls.append(kwargs)
        return {"manifest_hash": "hash-9", "short_hash": "hash-9", "verified": True}

    def summarize_review(_con: sqlite3.Connection, **kwargs: Any) -> dict[str, Any]:
        review_calls.append(kwargs)
        return {"review_status": "attested"}

    rows = engagement_run_rows(
        con,
        1001,
        db_path=tmp_path / "1001.db",
        verify_manifests=True,
        format_dt=lambda value: f"fmt:{value}" if value else "",
        summarize_run_audit_manifest=summarize_manifest,
        audit_review_summary=summarize_review,
    )

    assert rows == [
        {
            "id": 9,
            "run_kind": "kill_chain",
            "status": "stopping",
            "raw_status": "running",
            "seed_value": "acme.example",
            "seed_type": "domain",
            "seed_count": 3,
            "max_iterations": 5,
            "current_iteration": 2,
            "resume_enabled": True,
            "dry_run": False,
            "attack_mode": True,
            "roe_id": "ROE-ACME-2026",
            "roe_present": True,
            "roe_missing": False,
            "live_probing_allowed": True,
            "tool_execution_allowed": False,
            "active_recon_allowed": True,
            "credential_validation_allowed": False,
            "destructive_actions_allowed": False,
            "post_exploitation_allowed": False,
            "requires_explicit_roe": True,
            "scope_gate": "custom_scope_gate",
            "error": "operator stopped",
            "metadata": metadata,
            "audit_manifest": {
                "manifest_hash": "hash-9",
                "short_hash": "hash-9",
                "verified": True,
                "review": {"review_status": "attested"},
            },
            "audit_review": {"review_status": "attested"},
            "started_at": "fmt:2026-07-09T10:00:00",
            "completed_at": "",
            "updated_at": "fmt:2026-07-09T10:02:00",
        }
    ]
    assert manifest_calls == [
        {
            "db_path": tmp_path / "1001.db",
            "engagement_id": 1001,
            "run_id": 9,
            "verify": True,
        }
    ]
    assert review_calls == [
        {"engagement_id": 1001, "run_id": 9, "manifest_hash": "hash-9"}
    ]


def test_latest_running_engagement_run_orders_newest_first() -> None:
    con = _connect()
    _create_runs_table(con)
    _insert_run(
        con,
        (1, 1001, "kill_chain", "running", "old", "domain", 1, 1, 1, 1, 1, 0, "", "{}", "1", "", "1"),
    )
    _insert_run(
        con,
        (2, 1001, "kill_chain", "running", "new", "domain", 1, 1, 1, 1, 1, 0, "", "{}", "2", "", "2"),
    )
    _insert_run(
        con,
        (3, 1001, "kill_chain", "completed", "done", "domain", 1, 1, 1, 1, 1, 0, "", "{}", "3", "", "3"),
    )

    row = latest_running_engagement_run(con, 1001)

    assert row is not None
    assert int(row["id"]) == 2
    assert json.loads(row["metadata_json"]) == {}


def test_annotate_run_audit_review_preserves_manifest_payload() -> None:
    con = _connect()
    review_calls: list[dict[str, Any]] = []

    def summarize_review(_con: sqlite3.Connection, **kwargs: Any) -> dict[str, Any]:
        review_calls.append(kwargs)
        return {"review_status": "approved"}

    run_summary = {
        "id": 17,
        "status": "completed",
        "audit_manifest": {"manifest_hash": "hash-17", "verified": True},
    }

    annotated = annotate_run_audit_review(
        con,
        run_summary,
        engagement_id=1001,
        audit_review_summary=summarize_review,
    )

    assert annotated == {
        "id": 17,
        "status": "completed",
        "audit_manifest": {
            "manifest_hash": "hash-17",
            "verified": True,
            "review": {"review_status": "approved"},
        },
        "audit_review": {"review_status": "approved"},
    }
    assert run_summary == {
        "id": 17,
        "status": "completed",
        "audit_manifest": {"manifest_hash": "hash-17", "verified": True},
    }
    assert review_calls == [
        {"engagement_id": 1001, "run_id": 17, "manifest_hash": "hash-17"}
    ]


def test_annotate_run_audit_review_ignores_non_dict_summary() -> None:
    con = _connect()

    assert annotate_run_audit_review(con, None, engagement_id=1001) is None


def test_live_run_progress_payload_and_fingerprint_preserve_bridge_contract() -> None:
    con = _connect()
    _create_runs_table(con)
    metadata = {
        "phase": "iteration_2",
        "last_step": "2.D html mining",
        "last_message": "hosts=3 refs=1",
        "last_step_elapsed_seconds": 1.25,
        "last_step_at": "2026-07-10T10:00:02Z",
        "counts": {"engagement_seeds": 8},
        "queue_metrics": {"artifact_queue": {"parsed": 2}},
        "last_iteration_delta": {"social_profiles": 2},
        "last_iteration_stable": False,
        "active_batch_label": "2.E email fan-out",
        "active_batch_eta_seconds": 3.5,
        "active_artifact_stage_label": "2.K3 artifact processing / parse",
        "active_artifact_eta_seconds": 0.0,
        "active_validation_stage_label": "2.J cloud validation",
        "active_validation_eta_seconds": 0.0,
        "active_finalization_stage_label": "report generate",
        "active_finalization_eta_seconds": 0.0,
    }
    _insert_run(
        con,
        (
            11,
            1001,
            "kill_chain",
            "running",
            "acme.example",
            "domain",
            3,
            5,
            2,
            1,
            0,
            0,
            "",
            json.dumps(metadata, sort_keys=True),
            "2026-07-10T10:00:00",
            "",
            "2026-07-10T10:00:02",
        ),
    )
    row = con.execute("SELECT * FROM engagement_runs").fetchone()

    payload = live_run_progress_payload(row)
    snapshot = live_run_progress_snapshot(row)

    assert payload == {
        "run_id": 11,
        "status": "running",
        "phase": "iteration_2",
        "last_step": "2.D html mining",
        "last_message": "hosts=3 refs=1",
        "last_step_elapsed_seconds": 1.25,
        "last_step_at": "2026-07-10T10:00:02Z",
        "current_iteration": 2,
        "max_iterations": 5,
        "run_kind": "kill_chain",
        "counts": {"engagement_seeds": 8},
        "queue_metrics": {"artifact_queue": {"parsed": 2}},
        "last_iteration_delta": {"social_profiles": 2},
        "last_iteration_stable": False,
        "active_batch_label": "2.E email fan-out",
        "active_batch_eta_seconds": 3.5,
        "active_artifact_stage_label": "2.K3 artifact processing / parse",
        "active_artifact_eta_seconds": 0.0,
        "active_validation_stage_label": "2.J cloud validation",
        "active_validation_eta_seconds": 0.0,
        "active_finalization_stage_label": "report generate",
        "active_finalization_eta_seconds": 0.0,
    }
    assert snapshot == (1001, live_run_progress_fingerprint(payload), payload)


def test_live_run_progress_payload_ignores_terminal_or_step_less_rows() -> None:
    con = _connect()
    _create_runs_table(con)
    _insert_run(
        con,
        (1, 1001, "kill_chain", "completed", "done", "domain", 1, 1, 1, 1, 1, 0, "", "{}", "1", "", "1"),
    )
    _insert_run(
        con,
        (2, 1002, "kill_chain", "running", "idle", "domain", 1, 1, 1, 1, 1, 0, "", "{}", "2", "", "2"),
    )
    rows = con.execute("SELECT * FROM engagement_runs ORDER BY id").fetchall()

    assert live_run_progress_payload(rows[0]) is None
    assert live_run_progress_payload(rows[1]) is None


def test_iter_live_run_progress_snapshots_scans_numeric_engagement_dbs(tmp_path: Path) -> None:
    engagements_dir = tmp_path / "engagements"
    engagements_dir.mkdir()
    first_db = engagements_dir / "1001.db"
    second_db = engagements_dir / "1002.db"
    missing_table_db = engagements_dir / "1003.db"
    for db_path in (first_db, second_db):
        con = sqlite3.connect(db_path)
        _create_runs_table(con)
        con.close()
    sqlite3.connect(missing_table_db).close()

    first_con = sqlite3.connect(first_db)
    first_metadata = {
        "last_step": "2.D html mining",
        "last_step_at": "2026-07-10T10:00:02Z",
    }
    _insert_run(
        first_con,
        (
            1,
            1001,
            "kill_chain",
            "running",
            "old.example",
            "domain",
            1,
            3,
            1,
            1,
            0,
            0,
            "",
            json.dumps(first_metadata),
            "2026-07-10T10:00:00",
            "",
            "2026-07-10T10:00:02",
        ),
    )
    _insert_run(
        first_con,
        (
            2,
            1001,
            "kill_chain",
            "completed",
            "new.example",
            "domain",
            1,
            3,
            2,
            1,
            0,
            0,
            "",
            json.dumps(first_metadata),
            "2026-07-10T10:01:00",
            "",
            "2026-07-10T10:01:02",
        ),
    )
    first_con.commit()
    first_con.close()

    second_con = sqlite3.connect(second_db)
    second_metadata = {
        "last_step": "2.E email fan-out",
        "last_step_at": "2026-07-10T10:02:02Z",
    }
    _insert_run(
        second_con,
        (
            3,
            1002,
            "kill_chain",
            "running",
            "active.example",
            "domain",
            1,
            3,
            2,
            1,
            0,
            0,
            "",
            json.dumps(second_metadata),
            "2026-07-10T10:02:00",
            "",
            "2026-07-10T10:02:02",
        ),
    )
    second_con.commit()
    second_con.close()

    def table_exists(con: sqlite3.Connection, table: str) -> bool:
        row = con.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            (table,),
        ).fetchone()
        return row is not None

    snapshots = iter_live_run_progress_snapshots(
        tmp_path,
        numeric_db_files=lambda _data_dir: [first_db, second_db, missing_table_db],
        table_exists=table_exists,
        connect=_connect_file,
    )

    assert len(snapshots) == 1
    engagement_id, _fingerprint, payload = snapshots[0]
    assert engagement_id == 1002
    assert payload["run_id"] == 3
    assert payload["last_step"] == "2.E email fan-out"


def test_iter_live_run_progress_snapshots_returns_empty_without_engagements_dir(tmp_path: Path) -> None:
    assert (
        iter_live_run_progress_snapshots(
            tmp_path,
            numeric_db_files=lambda _data_dir: [tmp_path / "1.db"],
            table_exists=lambda _con, _table: True,
            connect=_connect_file,
        )
        == []
    )
