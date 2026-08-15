from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from forge.webui.logs import logs_dir
from forge.webui.run_log_routes import (
    RunLogRouteNotFound,
    build_run_control_requester,
    engagement_log_route_file,
    engagement_log_tail_route_payload,
    engagement_logs_route_payload,
    engagement_runs_route_payload,
    run_control_route_payload,
)
from forge.webui.run_control import pause_marker_path


def _connect() -> sqlite3.Connection:
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    return con


def _create_runs_table(con: sqlite3.Connection) -> None:
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


def _write(path: Path, body: str, *, mtime: int = 1_786_529_400) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


def test_engagement_runs_route_payload_preserves_run_audit_envelope(tmp_path: Path) -> None:
    con = _connect()
    _create_runs_table(con)
    con.execute(
        """
        INSERT INTO engagement_runs (
            id, engagement_id, run_kind, status, seed_value, seed_type, seed_count,
            max_iterations, current_iteration, resume_enabled, dry_run, attack_mode,
            error, metadata_json, started_at, completed_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            7,
            1001,
            "kill_chain",
            "completed",
            "acme.example",
            "domain",
            1,
            2,
            2,
            1,
            0,
            1,
            "",
            "{}",
            "2026-08-14T01:00:00",
            "2026-08-14T01:02:00",
            "2026-08-14T01:02:00",
        ),
    )
    manifest_calls: list[dict[str, Any]] = []
    review_calls: list[dict[str, Any]] = []

    payload = engagement_runs_route_payload(
        con,
        engagement_id=1001,
        db_path=tmp_path / "1001.db",
        verify_manifests=True,
        format_dt=lambda value: f"fmt:{value}" if value else "",
        summarize_run_audit_manifest=lambda _con, **kwargs: manifest_calls.append(kwargs)
        or {"manifest_hash": "hash-7", "short_hash": "hash-7", "verified": True},
        audit_review_summary=lambda _con, **kwargs: review_calls.append(kwargs)
        or {"review_status": "pending"},
    )

    assert payload["items"][0]["id"] == 7
    assert payload["items"][0]["audit_manifest"]["manifest_hash"] == "hash-7"
    assert payload["items"][0]["audit_review"] == {"review_status": "pending"}
    assert manifest_calls == [
        {
            "db_path": tmp_path / "1001.db",
            "engagement_id": 1001,
            "run_id": 7,
            "verify": True,
        }
    ]
    assert review_calls == [
        {"engagement_id": 1001, "run_id": 7, "manifest_hash": "hash-7"}
    ]


def test_run_control_route_payload_updates_run_and_publishes(tmp_path: Path) -> None:
    con = _connect()
    _create_runs_table(con)
    con.execute(
        """
        INSERT INTO engagement_runs (
            id, engagement_id, run_kind, status, seed_value, seed_type, seed_count,
            max_iterations, current_iteration, resume_enabled, dry_run, attack_mode,
            error, metadata_json, started_at, completed_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            9,
            1001,
            "kill_chain",
            "running",
            "acme.example",
            "domain",
            1,
            3,
            2,
            1,
            0,
            1,
            "",
            "{}",
            "2026-08-14T01:00:00",
            "",
            "2026-08-14T01:02:00",
        ),
    )
    published: list[tuple[int, str, dict[str, Any]]] = []

    payload = run_control_route_payload(
        con,
        data_dir=tmp_path / ".forge_data",
        engagement_id=1001,
        control_kind="pause",
        requested_by="operator-web",
        body={"reason": " checkpoint "},
        publish_sync=lambda engagement_id, message, body: published.append(
            (engagement_id, message, body)
        ),
        format_dt=lambda value: "formatted-time",
    )

    marker_path = pause_marker_path(tmp_path / ".forge_data", 1001)
    assert payload["status"] == "pause_requested"
    assert payload["active_run_id"] == 9
    assert payload["reason"] == "checkpoint"
    assert json.loads(marker_path.read_text(encoding="utf-8")) == {
        "requested_at": "formatted-time",
        "requested_by": "operator-web",
        "reason": "checkpoint",
    }
    assert published[0][0:2] == (1001, "engagement_run_pause_requested")


def test_run_control_requester_binds_route_dependencies(tmp_path: Path) -> None:
    con = _connect()
    _create_runs_table(con)
    con.execute(
        """
        INSERT INTO engagement_runs (
            id, engagement_id, run_kind, status, seed_value, seed_type, seed_count,
            max_iterations, current_iteration, resume_enabled, dry_run, attack_mode,
            error, metadata_json, started_at, completed_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            10,
            1001,
            "kill_chain",
            "running",
            "acme.example",
            "domain",
            1,
            3,
            2,
            1,
            0,
            1,
            "",
            "{}",
            "2026-08-14T01:00:00",
            "",
            "2026-08-14T01:02:00",
        ),
    )
    published: list[tuple[int, str, dict[str, Any]]] = []
    data_dir = tmp_path / ".forge_data"

    request_control = build_run_control_requester(
        data_dir=data_dir,
        publish_sync=lambda engagement_id, message, body: published.append(
            (engagement_id, message, body)
        ),
        format_dt=lambda value: f"formatted:{bool(value)}",
    )

    payload = request_control(
        con,
        engagement_id=1001,
        control_kind="stop",
        requested_by="operator-web",
        body=None,
    )

    marker_path = data_dir / "run_control" / "engagement_1001_stop.json"
    assert payload["status"] == "stop_requested"
    assert payload["active_run_id"] == 10
    assert json.loads(marker_path.read_text(encoding="utf-8")) == {
        "requested_at": "formatted:True",
        "requested_by": "operator-web",
        "reason": "operator requested stop",
    }
    assert published[0][0:2] == (1001, "engagement_run_stop_requested")


def test_engagement_log_route_payloads_preserve_listing_download_and_tail(
    tmp_path: Path,
) -> None:
    root = logs_dir(tmp_path / ".forge_data")
    log_path = _write(root / "engagement_1001_kill_chain_1.log", "a\nb\nc\n")

    listing = engagement_logs_route_payload(
        logs_root=root,
        engagement_ref="engagement 1001/acme",
        engagement_id=1001,
        format_size=lambda size: f"{size} bytes",
        format_dt=lambda value: f"fmt:{bool(value)}",
    )

    assert listing["items"][0]["name"] == log_path.name
    assert listing["items"][0]["size_label"] == f"{log_path.stat().st_size} bytes"
    assert engagement_log_route_file(
        logs_root=root,
        engagement_id=1001,
        log_name=f"../{log_path.name}",
    ) == log_path.resolve()
    assert engagement_log_tail_route_payload(
        logs_root=root,
        engagement_id=1001,
        log_name=log_path.name,
        lines=2,
    ) == {"name": log_path.name, "tail": "b\nc", "requested_lines": 2}
    with pytest.raises(RunLogRouteNotFound, match="Log not found"):
        engagement_log_route_file(logs_root=root, engagement_id=1001, log_name="missing.log")
