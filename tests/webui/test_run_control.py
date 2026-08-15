import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from forge.webui.run_control import (
    RUN_CONTROL_KINDS,
    clear_run_control_markers,
    default_run_control_reason,
    launch_log_path,
    open_launch_log,
    pause_marker_path,
    request_run_control,
    run_control_dir,
    run_control_marker_payload,
    run_control_marker_path,
    run_control_progress_message,
    run_control_progress_payload,
    run_control_reason,
    stop_marker_path,
    write_run_control_marker,
)


def test_marker_paths_use_dedicated_run_control_directory(tmp_path: Path) -> None:
    data_dir = tmp_path / ".forge_data"

    assert RUN_CONTROL_KINDS == frozenset({"stop", "pause"})
    assert run_control_dir(data_dir) == data_dir / "run_control"
    assert stop_marker_path(data_dir, 1001) == data_dir / "run_control" / "engagement_1001_stop.json"
    assert pause_marker_path(data_dir, 1001) == data_dir / "run_control" / "engagement_1001_pause.json"
    assert run_control_marker_path(data_dir, 1001, "pause") == pause_marker_path(data_dir, 1001)
    assert run_control_marker_path(data_dir, 1001, "stop") == stop_marker_path(data_dir, 1001)
    assert (data_dir / "run_control").is_dir()
    with pytest.raises(ValueError, match="Unsupported control action"):
        run_control_marker_path(data_dir, 1001, "resume")


def test_clear_run_control_markers_removes_stale_stop_and_pause_files(tmp_path: Path) -> None:
    data_dir = tmp_path / ".forge_data"
    stop_path = stop_marker_path(data_dir, 1001)
    pause_path = pause_marker_path(data_dir, 1001)
    unrelated_path = run_control_dir(data_dir) / "engagement_1002_stop.json"
    stop_path.write_text("stale", encoding="utf-8")
    pause_path.write_text("stale", encoding="utf-8")
    unrelated_path.write_text("keep", encoding="utf-8")

    clear_run_control_markers(data_dir, 1001)

    assert not stop_path.exists()
    assert not pause_path.exists()
    assert unrelated_path.exists()


def test_run_control_reason_preserves_request_body_and_defaults() -> None:
    assert run_control_reason({"reason": "  pause at checkpoint  "}, "pause") == "pause at checkpoint"
    assert run_control_reason({}, "pause") == "operator requested pause"
    assert run_control_reason(None, "stop") == "operator requested stop"
    with pytest.raises(ValueError, match="Unsupported control action"):
        run_control_reason({"reason": "resume please"}, "resume")
    with pytest.raises(ValueError, match="Unsupported control action"):
        default_run_control_reason("resume")


def test_write_run_control_marker_preserves_payload_contract(tmp_path: Path) -> None:
    data_dir = tmp_path / ".forge_data"

    marker_path, payload = write_run_control_marker(
        data_dir,
        engagement_id=1001,
        control_kind="pause",
        requested_by="operator-web",
        reason="operator requested checkpoint",
        requested_at="2026-08-13 10:00:00",
    )

    assert marker_path == pause_marker_path(data_dir, 1001)
    assert payload == {
        "requested_at": "2026-08-13 10:00:00",
        "requested_by": "operator-web",
        "reason": "operator requested checkpoint",
    }
    assert json.loads(marker_path.read_text(encoding="utf-8")) == payload


def test_marker_payload_accepts_route_timestamp_formatter() -> None:
    assert run_control_marker_payload(
        requested_by="operator-web",
        reason="operator requested stop",
        epoch_seconds=1_786_530_000,
        format_dt=lambda value: f"formatted:{bool(value)}",
    ) == {
        "requested_at": "formatted:True",
        "requested_by": "operator-web",
        "reason": "operator requested stop",
    }


def test_launch_log_path_and_open_handle_are_deterministic(tmp_path: Path) -> None:
    logs_root = tmp_path / ".forge_data" / "logs"
    logs_root.mkdir(parents=True)

    expected = logs_root / "engagement_1001_kill_chain_123.log"
    assert launch_log_path(logs_root, 1001, epoch_seconds=123.9) == expected

    log_path, handle = open_launch_log(logs_root, 1001, epoch_seconds=123.9)
    try:
        handle.write("started\n")
    finally:
        handle.close()

    assert log_path == expected
    assert expected.read_text(encoding="utf-8") == "started\n"


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
            status TEXT,
            metadata_json TEXT,
            started_at TEXT,
            updated_at TEXT
        );
        """
    )


def test_request_run_control_updates_latest_running_row_and_publishes(
    tmp_path: Path,
) -> None:
    con = _connect()
    _create_runs_table(con)
    con.execute(
        """
        INSERT INTO engagement_runs
            (id, engagement_id, status, metadata_json, started_at, updated_at)
        VALUES
            (1, 1001, 'running', '{"phase":"old"}', '2026-08-13T09:00:00', ''),
            (2, 1001, 'running', '{"phase":"iteration_2"}', '2026-08-13T10:00:00', ''),
            (3, 1001, 'completed', '{"phase":"done"}', '2026-08-13T11:00:00', '')
        """
    )
    published: list[tuple[int, str, dict[str, Any]]] = []

    payload = request_run_control(
        con,
        tmp_path / ".forge_data",
        engagement_id=1001,
        control_kind="pause",
        requested_by="operator-web",
        body={"reason": " checkpoint "},
        requested_at="2026-08-13 10:20:00",
        publish_sync=lambda engagement_id, message, event_payload: published.append(
            (engagement_id, message, event_payload)
        ),
    )

    marker_path = pause_marker_path(tmp_path / ".forge_data", 1001)
    assert payload == {
        "status": "pause_requested",
        "engagement_id": 1001,
        "active_run_id": 2,
        "requested_by": "operator-web",
        "reason": "checkpoint",
        "marker_path": marker_path.as_posix(),
    }
    assert json.loads(marker_path.read_text(encoding="utf-8")) == {
        "requested_at": "2026-08-13 10:20:00",
        "requested_by": "operator-web",
        "reason": "checkpoint",
    }
    metadata = json.loads(
        con.execute("SELECT metadata_json FROM engagement_runs WHERE id=2").fetchone()[0]
    )
    assert metadata == {
        "phase": "iteration_2",
        "pause_reason": "checkpoint",
        "pause_requested": True,
        "pause_requested_at": "2026-08-13 10:20:00",
        "pause_requested_by": "operator-web",
    }
    assert json.loads(
        con.execute("SELECT metadata_json FROM engagement_runs WHERE id=1").fetchone()[0]
    ) == {"phase": "old"}
    assert published == [
        (
            1001,
            "engagement_run_pause_requested",
            {
                "active_run_id": 2,
                "requested_by": "operator-web",
                "reason": "checkpoint",
                "marker_path": marker_path.as_posix(),
            },
        )
    ]


def test_request_run_control_writes_marker_before_db_metadata_failure(tmp_path: Path) -> None:
    con = _connect()
    published: list[object] = []

    with pytest.raises(sqlite3.OperationalError):
        request_run_control(
            con,
            tmp_path / ".forge_data",
            engagement_id=1001,
            control_kind="stop",
            requested_by="operator-web",
            body=None,
            requested_at="2026-08-13 10:20:00",
            publish_sync=lambda *_args: published.append(_args),
        )

    marker_path = stop_marker_path(tmp_path / ".forge_data", 1001)
    assert marker_path.exists()
    assert json.loads(marker_path.read_text(encoding="utf-8")) == {
        "requested_at": "2026-08-13 10:20:00",
        "requested_by": "operator-web",
        "reason": "operator requested stop",
    }
    assert published == []


def test_run_control_progress_helpers_preserve_event_contract(tmp_path: Path) -> None:
    marker_path = tmp_path / ".forge_data" / "run_control" / "engagement_1001_stop.json"

    assert run_control_progress_message("stop") == "engagement_run_stop_requested"
    assert run_control_progress_payload(
        active_run_id=None,
        requested_by="operator-web",
        reason="operator requested stop",
        marker_path=marker_path,
    ) == {
        "active_run_id": None,
        "requested_by": "operator-web",
        "reason": "operator requested stop",
        "marker_path": marker_path.as_posix(),
    }
