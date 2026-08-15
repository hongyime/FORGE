from __future__ import annotations

import json
import sqlite3
from types import SimpleNamespace
from pathlib import Path

from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.orchestration.run_tracking import (
    EngagementRunCompletionAction,
    EngagementRunCompletionGuard,
    EngagementRunHandle,
    EngagementRunTracker,
    EngagementRunManifestWriteResult,
    SeedRunHandle,
    SeedRunTracker,
    RunControlInterruptTransition,
    abandoned_seed_run_recovery_log_message,
    apply_seed_run_finalization_entry,
    complete_engagement_run_once,
    current_run_progress_payload,
    engagement_progress_counts,
    engagement_progress_queue_metrics,
    engagement_run_completion_callback,
    engagement_run_completion_action,
    engagement_run_terminal_entry,
    finalize_seed_run_batch,
    infer_kill_chain_run_phase,
    kill_chain_engagement_run_metadata,
    record_run_progress_queue_group,
    clear_run_control_marker_paths,
    read_run_control_marker_request,
    restore_prior_artifact_queue_metrics,
    persisted_fanout_resume_reuse_log_message,
    resume_completed_skip_log_entry,
    run_control_interrupt_transition,
    run_control_request_from_run_metadata,
    seed_run_finalization_entry,
    strip_console_markup,
    terminal_artifact_queue_summary,
    update_artifact_processor_cumulative_metrics,
    update_kill_chain_run_progress_state,
    write_engagement_run_audit_manifest,
)


def _bootstrap(db_path: Path) -> None:
    con = sqlite3.connect(db_path)
    try:
        apply_schema(con)
        run_migrations(con)
        con.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (1001, 'Acme Example', '["acme.example"]', 'ACTIVE', 'delta-one')
            """
        )
        con.commit()
    finally:
        con.close()


def test_run_trackers_remain_legacy_import_compatible() -> None:
    from forge.engagement_orchestrator import (  # noqa: PLC0415
        EngagementRunHandle as LegacyEngagementRunHandle,
        EngagementRunTracker as LegacyEngagementRunTracker,
        SeedRunHandle as LegacySeedRunHandle,
        SeedRunTracker as LegacySeedRunTracker,
    )
    from forge.orchestration.run_tracking import (  # noqa: PLC0415
        EngagementRunHandle,
        SeedRunHandle,
    )

    assert LegacySeedRunHandle is SeedRunHandle
    assert LegacyEngagementRunHandle is EngagementRunHandle
    assert LegacySeedRunTracker is SeedRunTracker
    assert LegacyEngagementRunTracker is EngagementRunTracker


def test_seed_run_tracker_normalizes_runtime_source_labels(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap(db_path)

    tracker = SeedRunTracker(db_path, 1001)
    handle = tracker.start_run(
        "alice",
        "username",
        "fanout_e5_sherlock",
        source="social_profile",
        metadata={"iteration": 1},
    )

    con = sqlite3.connect(db_path)
    try:
        seed_row = con.execute(
            """
            SELECT source, metadata_json
            FROM engagement_seeds
            WHERE id=?
            """,
            (handle.seed_id,),
        ).fetchone()
        run_row = con.execute(
            """
            SELECT metadata_json
            FROM seed_runs
            WHERE id=?
            """,
            (handle.run_id,),
        ).fetchone()
    finally:
        con.close()

    assert seed_row is not None
    assert seed_row[0] == "discovered"
    assert json.loads(seed_row[1]) == {"iteration": 1, "raw_source": "social_profile"}
    assert run_row is not None
    assert json.loads(run_row[0]) == {"iteration": 1, "raw_source": "social_profile"}


def test_abandoned_seed_run_recovery_log_message_only_reports_positive_counts() -> None:
    assert abandoned_seed_run_recovery_log_message(0) is None
    assert abandoned_seed_run_recovery_log_message(-1) is None
    assert abandoned_seed_run_recovery_log_message(3) == (
        "marked 3 abandoned seed run(s) failed before retry"
    )


def test_persisted_fanout_resume_reuse_log_message_only_reports_positive_counts() -> None:
    assert persisted_fanout_resume_reuse_log_message(0) is None
    assert persisted_fanout_resume_reuse_log_message(-1) is None
    assert persisted_fanout_resume_reuse_log_message(5) == (
        "reusing persisted fan-out state for 5 seed/loop target(s)"
    )


def test_resume_completed_skip_log_entry_shapes_label_and_message() -> None:
    assert resume_completed_skip_log_entry("1.B harvest", " acme.example ") == (
        "1.B harvest (acme.example)",
        "[dim]resume skip \u2014 already completed for this engagement[/dim]",
    )


def test_seed_run_finalization_entry_merges_metadata_with_precedence() -> None:
    handle = SeedRunHandle(run_id=7, seed_id=11)
    entry = seed_run_finalization_entry(
        (
            handle,
            {
                "metadata": {
                    "iteration": 1,
                    "source": "seed",
                    "seed_only": "yes",
                }
            },
        ),
        base_metadata_value={"source": "base", "base_only": "yes"},
        status="completed",
        output_count=3,
        extra_metadata={"source": "extra", "extra_only": "yes"},
    )

    assert entry == {
        "handle": handle,
        "status": "completed",
        "output_count": 3,
        "error": None,
        "metadata": {
            "source": "extra",
            "base_only": "yes",
            "iteration": 1,
            "seed_only": "yes",
            "extra_only": "yes",
        },
    }
    assert (
        seed_run_finalization_entry(
            (None, {"metadata": {"ignored": True}}),
            base_metadata_value={},
            status="completed",
            output_count=1,
        )
        is None
    )


def test_apply_seed_run_finalization_entry_calls_finish_callback() -> None:
    handle = SeedRunHandle(run_id=7, seed_id=11)
    calls: list[dict[str, object]] = []

    def _finish_seed_run(seed_handle: object, **kwargs: object) -> None:
        calls.append({"handle": seed_handle, **kwargs})

    assert (
        apply_seed_run_finalization_entry(
            {
                "handle": handle,
                "status": "failed",
                "output_count": 2,
                "error": "timeout",
                "metadata": {"iteration": 1},
            },
            finish_seed_run=_finish_seed_run,
        )
        == "failed"
    )
    assert calls == [
        {
            "handle": handle,
            "status": "failed",
            "output_count": 2,
            "error": "timeout",
            "metadata": {"iteration": 1},
        }
    ]
    assert apply_seed_run_finalization_entry(None, finish_seed_run=_finish_seed_run) is None
    assert apply_seed_run_finalization_entry({"handle": handle}, finish_seed_run=_finish_seed_run) is None


def test_finalize_seed_run_batch_noops_without_tracker_or_handles() -> None:
    calls: list[str] = []

    kwargs = {
        "base_metadata_value": {},
        "status": "completed",
        "output_count": 0,
        "finish_seed_run": lambda **_kwargs: calls.append("finish"),
        "run_inprocess_batch": lambda *_args, **_kwargs: calls.append("prep") or [],
        "run_ordered_inprocess_apply_batch": lambda *_args, **_kwargs: calls.append("apply") or [],
        "progress_callback": lambda *_args, **_kwargs: None,
        "log": lambda *_args, **_kwargs: calls.append("log"),
        "parallel_workers": 2,
        "progress_label_prefix": "1.A module",
    }

    assert finalize_seed_run_batch([], seed_run_tracker=object(), **kwargs) == []
    assert (
        finalize_seed_run_batch(
            [(SeedRunHandle(run_id=1, seed_id=2), {"metadata": {}})],
            seed_run_tracker=None,
            **kwargs,
        )
        == []
    )
    assert calls == []


def test_finalize_seed_run_batch_prepares_applies_and_logs_parallel() -> None:
    handles = [
        (SeedRunHandle(run_id=1, seed_id=10), {"metadata": {"seed": "one"}}),
        (SeedRunHandle(run_id=2, seed_id=20), {"metadata": {"seed": "two"}}),
    ]
    events: list[object] = []
    finish_calls: list[dict[str, object]] = []

    def _run_batch(items: list[object], func: object, **kwargs: object) -> list[object]:
        events.append(("prep", list(items), kwargs))
        return [func(item) for item in items]  # type: ignore[misc]

    def _run_apply(items: list[object], func: object, **kwargs: object) -> list[object]:
        events.append(("apply", list(items), kwargs))
        return [func(item) for item in items]  # type: ignore[misc]

    def _finish_seed_run(seed_handle: object, **kwargs: object) -> None:
        finish_calls.append({"handle": seed_handle, **kwargs})

    result = finalize_seed_run_batch(
        handles,
        seed_run_tracker=object(),
        base_metadata_value={"base": "yes"},
        status="failed",
        output_count=3,
        error="timeout",
        extra_metadata={"extra": "yes"},
        finish_seed_run=_finish_seed_run,
        run_inprocess_batch=_run_batch,
        run_ordered_inprocess_apply_batch=_run_apply,
        progress_callback=lambda *_args, **_kwargs: None,
        log=lambda label, message: events.append(("log", label, message)),
        parallel_workers=4,
        progress_label_prefix="2.B module",
    )

    assert result == ["failed", "failed"]
    assert events[0] == (
        "log",
        "2.B module seed-run finalize prep",
        "[dim]parallel parse x2[/dim]",
    )
    assert events[1][0] == "prep"
    assert events[1][2]["max_workers"] == 4
    assert events[1][2]["progress_label"] == "2.B module seed-run finalize prep"
    assert events[2][0] == "apply"
    assert events[2][2]["progress_label"] == "2.B module seed-run finalize"
    assert events[2][2]["order_note"] == "seed-run finalization order preserved"
    assert finish_calls == [
        {
            "handle": handles[0][0],
            "status": "failed",
            "output_count": 3,
            "error": "timeout",
            "metadata": {"base": "yes", "seed": "one", "extra": "yes"},
        },
        {
            "handle": handles[1][0],
            "status": "failed",
            "output_count": 3,
            "error": "timeout",
            "metadata": {"base": "yes", "seed": "two", "extra": "yes"},
        },
    ]


def test_engagement_run_terminal_entry_marks_completed_when_report_ready_and_no_pending() -> None:
    entry = engagement_run_terminal_entry(
        base_metadata={"phase": "running", "base": "yes"},
        elapsed_seconds=12.3456,
        planned_report_path="reports/planned.md",
        report_path="reports/final.md",
        report_ready=True,
        report_provider=None,
        report_max_loops=2,
        finalization_failed=0,
        pending_counts={"artifact_queue": 0, "engagement_seeds": 0},
        report_finalization_metadata={
            "report_artifact_verified": True,
            "report_finalization_status": "completed",
        },
    )

    assert entry["status"] == "completed"
    assert entry["phase"] == "completed"
    assert entry["error"] is None
    assert entry["pending_total"] == 0
    assert entry["report_ready"] is True
    assert entry["metadata"] == {
        "phase": "completed",
        "base": "yes",
        "elapsed_seconds": 12.346,
        "planned_report_path": "reports/planned.md",
        "report_path": "reports/final.md",
        "report_provider": "default",
        "report_max_loops": 2,
        "finalization_failed": 0,
        "report_artifact_verified": True,
        "report_finalization_status": "completed",
    }


def test_engagement_run_terminal_entry_defaults_missing_report_loop_count() -> None:
    entry = engagement_run_terminal_entry(
        base_metadata={"phase": "running"},
        elapsed_seconds=1,
        planned_report_path="reports/planned.md",
        report_path="reports/final.md",
        report_ready=True,
        report_provider=None,
        report_max_loops=None,
        finalization_failed=0,
        pending_counts={},
        report_finalization_metadata={},
    )

    assert entry["status"] == "completed"
    assert entry["metadata"]["report_max_loops"] == 0


def test_engagement_run_terminal_entry_fails_with_pending_work() -> None:
    entry = engagement_run_terminal_entry(
        base_metadata={"phase": "running"},
        elapsed_seconds=1,
        planned_report_path="reports/planned.md",
        report_path="reports/final.md",
        report_ready=True,
        report_provider="template",
        report_max_loops=0,
        finalization_failed=1,
        pending_counts={"artifact_queue": 2, "engagement_seeds": 3},
        report_finalization_metadata={"report_artifact_verified": True},
        prereq_metadata={"phase": "prereq_review", "detected_prereqs": 4},
    )

    assert entry["status"] == "failed"
    assert entry["phase"] == "failed"
    assert entry["pending_total"] == 5
    assert entry["error"] == "max iterations exhausted with pending recursive work: 5"
    metadata = dict(entry["metadata"])
    assert metadata["phase"] == "prereq_review"
    assert metadata["report_provider"] == "template"
    assert metadata["finalization_failed"] == 1
    assert metadata["detected_prereqs"] == 4


def test_engagement_run_terminal_entry_fails_without_report_artifact() -> None:
    entry = engagement_run_terminal_entry(
        base_metadata={"phase": "running"},
        elapsed_seconds=1,
        planned_report_path="reports/planned.md",
        report_path="reports/planned.md",
        report_ready=False,
        report_provider="template",
        report_max_loops=0,
        finalization_failed=1,
        pending_counts={"artifact_queue": 2},
        report_finalization_metadata={"report_artifact_verified": False},
    )

    assert entry["status"] == "failed"
    assert entry["phase"] == "failed"
    assert entry["report_ready"] is False
    assert entry["error"] == "final report generation failed and no fallback artifact exists"


def test_engagement_run_completion_action_shapes_finish_and_audit_payload() -> None:
    action = engagement_run_completion_action(
        base_metadata={
            "phase": "running",
            "queue_metrics": {
                "artifact_queue": {
                    "queued": 1,
                    "downloaded": 2,
                    "parsed": 3,
                    "failed": 4,
                    "skipped": 5,
                }
            },
            "pending_work_total": 6,
        },
        elapsed_seconds=2.5,
        planned_report_path="reports/planned.md",
        report_path="reports/final.md",
        report_ready=True,
        report_provider="template",
        report_max_loops=0,
        finalization_failed=0,
        pending_counts={"artifact_queue": 0},
        report_finalization_metadata={
            "report_artifact_verified": True,
            "report_finalization_status": "completed",
        },
    )

    assert isinstance(action, EngagementRunCompletionAction)
    assert action.status == "completed"
    assert action.error is None
    assert action.pending_total == 0
    assert action.report_ready is True
    assert action.metadata["phase"] == "completed"
    assert action.terminal_audit_action == "artifact_queue_terminal_metrics"
    assert action.terminal_audit_result == (
        "queued=1 downloaded=2 parsed=3 failed=4 skipped=5 "
        "pending_work_total=6"
    )


def test_engagement_run_completion_action_remains_package_exported() -> None:
    from forge import orchestration as orchestration_package  # noqa: PLC0415

    assert orchestration_package.EngagementRunCompletionAction is EngagementRunCompletionAction
    assert orchestration_package.EngagementRunCompletionGuard is EngagementRunCompletionGuard
    assert (
        orchestration_package.abandoned_seed_run_recovery_log_message
        is abandoned_seed_run_recovery_log_message
    )
    assert (
        orchestration_package.persisted_fanout_resume_reuse_log_message
        is persisted_fanout_resume_reuse_log_message
    )
    assert (
        orchestration_package.resume_completed_skip_log_entry
        is resume_completed_skip_log_entry
    )
    assert orchestration_package.complete_engagement_run_once is complete_engagement_run_once
    assert (
        orchestration_package.engagement_run_completion_callback
        is engagement_run_completion_callback
    )
    assert orchestration_package.engagement_run_completion_action is engagement_run_completion_action
    assert (
        orchestration_package.EngagementRunManifestWriteResult
        is EngagementRunManifestWriteResult
    )
    assert (
        orchestration_package.write_engagement_run_audit_manifest
        is write_engagement_run_audit_manifest
    )


def test_complete_engagement_run_once_applies_side_effects_once(tmp_path: Path) -> None:
    guard = EngagementRunCompletionGuard()
    handle = EngagementRunHandle(run_id=99)
    order: list[str] = []
    audits: list[dict[str, object]] = []
    finishes: list[dict[str, object]] = []
    refreshed_statuses: list[str] = []

    class _Tracker:
        def finish_run(self, run_handle: object, **kwargs: object) -> None:
            order.append("finish")
            finishes.append({"handle": run_handle, **kwargs})

    def _audit(*args: object, **kwargs: object) -> None:
        order.append("audit")
        audits.append({"args": args, "kwargs": kwargs})

    action = complete_engagement_run_once(
        guard=guard,
        refresh_pending_work_state=lambda: order.append("pending") or {"artifact_queue": 0},
        set_progress_counts=lambda: order.append("progress"),
        build_base_metadata=lambda: {
            "phase": "running",
            "queue_metrics": {
                "artifact_queue": {
                    "queued": 1,
                    "downloaded": 0,
                    "parsed": 2,
                    "failed": 0,
                    "skipped": 0,
                }
            },
            "pending_work_total": 0,
        },
        audit=_audit,
        db_path=tmp_path / "engagement.db",
        engagement_id=1001,
        target="acme.example",
        tracker=_Tracker(),
        handle=handle,
        last_iteration=3,
        clear_run_control_markers=lambda: order.append("clear"),
        refresh_dashboard_review_surface=lambda status: (
            order.append("review"),
            refreshed_statuses.append(status),
        ),
        elapsed_seconds=1.25,
        planned_report_path="reports/planned.md",
        report_path="reports/final.md",
        report_ready=True,
        report_provider="template",
        report_max_loops=0,
        finalization_failed=0,
        report_finalization_metadata={"report_artifact_verified": True},
    )

    assert action is not None
    assert action.status == "completed"
    assert guard.completed is True
    assert order == ["pending", "progress", "audit", "finish", "clear", "review"]
    assert audits == [
        {
            "args": (
                tmp_path / "engagement.db",
                1001,
                "orchestrator",
                "kill_chain",
                "artifact_queue_terminal_metrics",
            ),
            "kwargs": {
                "target": "acme.example",
                "result": (
                    "queued=1 downloaded=0 parsed=2 failed=0 skipped=0 "
                    "pending_work_total=0"
                ),
            },
        }
    ]
    assert finishes == [
        {
            "handle": handle,
            "status": "completed",
            "current_iteration": 3,
            "error": None,
            "metadata": action.metadata,
        }
    ]
    assert refreshed_statuses == ["completed"]

    assert (
        complete_engagement_run_once(
            guard=guard,
            refresh_pending_work_state=lambda: {"artifact_queue": 99},
            set_progress_counts=lambda: order.append("unexpected"),
            build_base_metadata=lambda: {},
            audit=_audit,
            db_path=tmp_path / "engagement.db",
            engagement_id=1001,
            target="acme.example",
            tracker=_Tracker(),
            handle=handle,
            last_iteration=4,
            clear_run_control_markers=lambda: order.append("unexpected"),
            refresh_dashboard_review_surface=lambda status: refreshed_statuses.append(status),
            elapsed_seconds=2,
            planned_report_path="reports/planned.md",
            report_path="reports/final.md",
            report_ready=True,
            report_provider="template",
            report_max_loops=0,
            finalization_failed=0,
            report_finalization_metadata={},
        )
        is None
    )
    assert order == ["pending", "progress", "audit", "finish", "clear", "review"]


def test_engagement_run_completion_callback_applies_side_effects_once(
    tmp_path: Path,
) -> None:
    guard = EngagementRunCompletionGuard()
    handle = EngagementRunHandle(run_id=100)
    order: list[str] = []
    finishes: list[dict[str, object]] = []

    class _Tracker:
        def finish_run(self, run_handle: object, **kwargs: object) -> None:
            order.append("finish")
            finishes.append({"handle": run_handle, **kwargs})

    callback = engagement_run_completion_callback(
        guard=guard,
        refresh_pending_work_state=lambda: order.append("pending") or {"artifact_queue": 0},
        set_progress_counts=lambda: order.append("progress"),
        build_base_metadata=lambda: {"phase": "running", "pending_work_total": 0},
        audit=lambda *_args, **_kwargs: order.append("audit"),
        db_path=tmp_path / "engagement.db",
        engagement_id=1001,
        target="acme.example",
        tracker=_Tracker(),
        handle=handle,
        last_iteration=4,
        clear_run_control_markers=lambda: order.append("clear"),
        refresh_dashboard_review_surface=lambda _status: order.append("review"),
        elapsed_seconds=2.5,
        planned_report_path="reports/planned.md",
        report_path="reports/final.md",
        report_ready=True,
        report_provider="template",
        report_max_loops=0,
        finalization_failed=0,
        report_finalization_metadata={"report_artifact_verified": True},
    )

    action = callback({"prereq_detected_count": 1})

    assert action is not None
    assert action.status == "completed"
    assert action.metadata["prereq_detected_count"] == 1
    assert guard.completed is True
    assert order == ["pending", "progress", "audit", "finish", "clear", "review"]
    assert finishes == [
        {
            "handle": handle,
            "status": "completed",
            "current_iteration": 4,
            "error": None,
            "metadata": action.metadata,
        }
    ]
    assert callback({"prereq_detected_count": 2}) is None
    assert order == ["pending", "progress", "audit", "finish", "clear", "review"]


def test_terminal_artifact_queue_summary_formats_stable_status_order() -> None:
    assert terminal_artifact_queue_summary(
        {
            "queue_metrics": {
                "artifact_queue": {
                    "parsed": 4,
                    "failed": 2,
                    "queued": 1,
                    "skipped": 3,
                    "downloaded": 5,
                    "ignored": 99,
                }
            },
            "pending_work_total": 7,
        }
    ) == (
        "queued=1 downloaded=5 parsed=4 failed=2 skipped=3 "
        "pending_work_total=7"
    )


def test_terminal_artifact_queue_summary_defaults_missing_metrics() -> None:
    assert terminal_artifact_queue_summary({}) == (
        "queued=0 downloaded=0 parsed=0 failed=0 skipped=0 pending_work_total=0"
    )
    assert terminal_artifact_queue_summary(
        {"queue_metrics": {"artifact_queue": "bad"}, "pending_work_total": "3"}
    ) == (
        "queued=0 downloaded=0 parsed=0 failed=0 skipped=0 pending_work_total=3"
    )


def test_write_engagement_run_audit_manifest_commits_writer_result(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    con = sqlite3.connect(db_path)
    try:
        con.execute(
            "CREATE TABLE manifest_writes (engagement_id INTEGER, run_id INTEGER, db_name TEXT)"
        )

        def _writer(
            inner_con: sqlite3.Connection,
            *,
            db_path: Path,
            engagement_id: int,
            run_id: int,
        ) -> None:
            inner_con.execute(
                "INSERT INTO manifest_writes (engagement_id, run_id, db_name) VALUES (?, ?, ?)",
                (engagement_id, run_id, db_path.name),
            )

        result = write_engagement_run_audit_manifest(
            con,
            db_path=db_path,
            engagement_id=1001,
            run_id=7,
            write_run_audit_manifest=_writer,
        )
    finally:
        con.close()

    verify_con = sqlite3.connect(db_path)
    try:
        row = verify_con.execute(
            "SELECT engagement_id, run_id, db_name FROM manifest_writes"
        ).fetchone()
    finally:
        verify_con.close()

    assert result == EngagementRunManifestWriteResult(written=True)
    assert row == (1001, 7, "engagement.db")


def test_write_engagement_run_audit_manifest_rolls_back_writer_failure(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    con = sqlite3.connect(db_path)
    try:
        con.execute("CREATE TABLE manifest_writes (run_id INTEGER)")
        con.commit()

        def _writer(
            inner_con: sqlite3.Connection,
            *,
            db_path: Path,
            engagement_id: int,
            run_id: int,
        ) -> None:
            del db_path, engagement_id
            inner_con.execute("INSERT INTO manifest_writes (run_id) VALUES (?)", (run_id,))
            raise RuntimeError("manifest write failed")

        result = write_engagement_run_audit_manifest(
            con,
            db_path=db_path,
            engagement_id=1001,
            run_id=7,
            write_run_audit_manifest=_writer,
        )
        rows = con.execute("SELECT run_id FROM manifest_writes").fetchall()
    finally:
        con.close()

    assert result.written is False
    assert "manifest write failed" in str(result.error)
    assert rows == []


def test_engagement_progress_counts_merges_snapshot_and_db_counts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap(db_path)
    con = sqlite3.connect(db_path)
    try:
        con.executemany(
            """
            INSERT INTO cloud_assets (engagement_id, asset_type, identifier, source)
            VALUES (1001, ?, ?, 'artifact_queue_ingest')
            """,
            [("aws_s3", "ops-bucket"), ("firebase", "demo-project")],
        )
        con.executemany(
            """
            INSERT INTO cloud_validation_results
                (engagement_id, asset_type, identifier, validation_status)
            VALUES (1001, ?, ?, ?)
            """,
            [
                ("aws_s3", "ops-bucket", "VALIDATED"),
                ("firebase", "demo-project", "UNVALIDATED"),
            ],
        )
        con.execute(
            """
            INSERT INTO vulnerability_findings
                (engagement_id, vuln_type, target_url, severity, title)
            VALUES (1001, 'xss', 'https://app.example/search', 'HIGH', 'Reflected XSS')
            """
        )
        con.executemany(
            """
            INSERT INTO artifact_queue (engagement_id, source_url, artifact_type, status)
            VALUES (1001, ?, 'document', ?)
            """,
            [
                ("https://cdn.example/a.pdf", "queued"),
                ("https://cdn.example/b.pdf", "parsed"),
                ("https://cdn.example/c.pdf", "failed"),
            ],
        )
        con.commit()
    finally:
        con.close()

    counts = engagement_progress_counts(db_path, 1001, {"hosts": 4, "emails": 2})

    assert counts["hosts"] == 4
    assert counts["emails"] == 2
    assert counts["cloud_assets"] == 2
    assert counts["cloud_validations"] == 2
    assert counts["vulnerability_findings"] == 1
    assert counts["artifact_queue"] == 3


def test_engagement_progress_queue_metrics_reads_statuses_and_transients(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap(db_path)
    con = sqlite3.connect(db_path)
    try:
        con.executemany(
            """
            INSERT INTO artifact_queue (engagement_id, source_url, artifact_type, status)
            VALUES (1001, ?, 'document', ?)
            """,
            [
                ("https://cdn.example/a.pdf", "queued"),
                ("https://cdn.example/b.pdf", "parsed"),
                ("https://cdn.example/c.pdf", "parsed"),
                ("https://cdn.example/d.pdf", "failed"),
            ],
        )
        con.executemany(
            """
            INSERT INTO cloud_validation_results
                (engagement_id, asset_type, identifier, validation_status)
            VALUES (1001, ?, ?, ?)
            """,
            [
                ("aws_s3", "ops-bucket", "VALIDATED"),
                ("firebase", "demo-project", "VALIDATED"),
                ("supabase", "demo-ref", "UNVALIDATED"),
            ],
        )
        con.commit()
    finally:
        con.close()

    metrics = engagement_progress_queue_metrics(
        db_path,
        1001,
        {
            "artifact_queue": {"stale": 99},
            "fanout_batch": {"subdomains": "2", "": 5},
            "artifact_processor": {"downloaded": 1},
            "ignored_group": {"kept": 1},
        },
    )

    assert metrics["artifact_queue"] == {"queued": 1, "parsed": 2, "failed": 1}
    assert metrics["cloud_validation"] == {"VALIDATED": 2, "UNVALIDATED": 1}
    assert metrics["fanout_batch"] == {"subdomains": 2}
    assert metrics["artifact_processor"] == {"downloaded": 1}
    assert "ignored_group" not in metrics


def test_engagement_progress_helpers_tolerate_missing_progress_tables(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "legacy.db"
    sqlite3.connect(db_path).close()

    assert engagement_progress_counts(db_path, 1001, {"hosts": 1}) == {
        "hosts": 1,
        "cloud_assets": 0,
        "cloud_validations": 0,
        "vulnerability_findings": 0,
        "artifact_queue": 0,
    }
    assert engagement_progress_queue_metrics(
        db_path,
        1001,
        {"finalization_batch": {"reports": 1}},
    ) == {"finalization_batch": {"reports": 1}}


def test_record_run_progress_queue_group_updates_batch_metrics_and_stage() -> None:
    state: dict[str, object] = {
        "queue_metrics": {"artifact_processor": {"processed": 3}},
        "active_batch_label": "old",
    }

    changed = record_run_progress_queue_group(
        state,
        queue_group="finalization_batch",
        active_label_key="active_finalization_stage_label",
        active_eta_key="active_finalization_eta_seconds",
        label="report generate",
        metrics={
            "total": "4",
            "workers": 1,
            "running": 1,
            "pending": 2,
            "queue_depth": 2,
            "completed": 1,
            "failed": 0,
            "eta_seconds": 12.345,
            "ignored": 99,
        },
    )

    assert changed is True
    assert state["active_finalization_stage_label"] == "report generate"
    assert state["active_finalization_eta_seconds"] == 12.3
    assert state["queue_metrics"] == {
        "artifact_processor": {"processed": 3},
        "finalization_batch": {
            "total": 4,
            "workers": 1,
            "running": 1,
            "pending": 2,
            "queue_depth": 2,
            "completed": 1,
            "failed": 0,
        },
    }


def test_record_run_progress_queue_group_ignores_empty_label_and_bad_eta() -> None:
    state: dict[str, object] = {"queue_metrics": "bad"}

    assert (
        record_run_progress_queue_group(
            state,
            queue_group="fanout_batch",
            active_label_key="active_batch_label",
            active_eta_key="active_batch_eta_seconds",
            label="",
            metrics={"total": 10, "eta_seconds": 2},
        )
        is False
    )
    assert state == {"queue_metrics": "bad"}

    assert (
        record_run_progress_queue_group(
            state,
            queue_group="fanout_batch",
            active_label_key="active_batch_label",
            active_eta_key="active_batch_eta_seconds",
            label="subdomain batch",
            metrics={"total": 10, "eta_seconds": True},
        )
        is True
    )
    assert state["active_batch_label"] == "subdomain batch"
    assert state["active_batch_eta_seconds"] is None
    assert state["queue_metrics"] == {
        "fanout_batch": {
            "total": 10,
            "workers": 0,
            "running": 0,
            "pending": 0,
            "queue_depth": 0,
            "completed": 0,
            "failed": 0,
        }
    }


def test_strip_console_markup_collapses_rich_tags_and_whitespace() -> None:
    assert (
        strip_console_markup(" [green]done[/green]\n\t[dim]  queued   [/dim] ")
        == "done queued"
    )
    assert strip_console_markup(None) == ""


def test_infer_kill_chain_run_phase_matches_cli_step_patterns() -> None:
    assert infer_kill_chain_run_phase("[cyan]Iteration 3[/cyan] URL mining") == "iteration_3"
    assert infer_kill_chain_run_phase("2.E email fan-out") == "iteration_2"
    assert infer_kill_chain_run_phase("Final report: generate") == "final_report_generate"
    assert infer_kill_chain_run_phase("", fallback_phase="paused") == "paused"
    assert infer_kill_chain_run_phase("[dim][/dim]", fallback_phase="running") == "running"


def test_update_kill_chain_run_progress_state_mutates_event_fields_and_trims_history() -> None:
    state: dict[str, object] = {
        "phase": "bootstrap",
        "recent_steps": [{"step": str(index)} for index in range(8)],
    }

    changed = update_kill_chain_run_progress_state(
        state,
        step="[green]Iteration 4[/green] URL mining",
        message="[dim]queued[/dim]\n targets",
        elapsed_seconds=12.3456,
        current_iteration=4,
        timestamp="2026-08-15T01:02:03Z",
    )

    assert changed is True
    assert state["phase"] == "iteration_4"
    assert state["last_step"] == "Iteration 4 URL mining"
    assert state["last_message"] == "queued targets"
    assert state["last_step_elapsed_seconds"] == 12.346
    assert state["last_step_at"] == "2026-08-15T01:02:03Z"
    assert state["recent_steps"] == [
        {"step": str(index)} for index in range(1, 8)
    ] + [
        {
            "step": "Iteration 4 URL mining",
            "message": "queued targets",
            "phase": "iteration_4",
            "iteration": 4,
            "elapsed_seconds": 12.346,
            "at": "2026-08-15T01:02:03Z",
        }
    ]


def test_update_kill_chain_run_progress_state_skips_duplicate_unless_forced() -> None:
    state: dict[str, object] = {
        "phase": "iteration_1",
        "last_step": "1.A subdomains",
        "last_message": "done",
        "recent_steps": [],
    }

    assert (
        update_kill_chain_run_progress_state(
            state,
            step="1.A subdomains",
            message="done",
            elapsed_seconds=1.0,
            current_iteration=1,
            timestamp="2026-08-15T01:02:03Z",
        )
        is False
    )
    assert state["recent_steps"] == []

    assert (
        update_kill_chain_run_progress_state(
            state,
            step="1.A subdomains",
            message="done",
            elapsed_seconds=1.0,
            current_iteration=1,
            timestamp="2026-08-15T01:02:04Z",
            force=True,
        )
        is True
    )
    assert state["recent_steps"] == [
        {
            "step": "1.A subdomains",
            "message": "done",
            "phase": "iteration_1",
            "iteration": 1,
            "elapsed_seconds": 1.0,
            "at": "2026-08-15T01:02:04Z",
        }
    ]


def test_update_kill_chain_run_progress_state_skips_empty_cleaned_step() -> None:
    state: dict[str, object] = {"phase": "running"}

    assert (
        update_kill_chain_run_progress_state(
            state,
            step="[dim][/dim]",
            message="ignored",
            elapsed_seconds=1.0,
            current_iteration=1,
            timestamp="2026-08-15T01:02:03Z",
        )
        is False
    )
    assert state == {"phase": "running"}


def test_update_artifact_processor_cumulative_metrics_adds_queue_and_summary_counts() -> None:
    state: dict[str, object] = {
        "queue_metrics": {
            "artifact_processor_cumulative": {
                "local_intake_queued": "2",
                "invocations": 1,
                "processed": 3,
                "failed": 1,
                "skipped": 2,
                "firebase_projects": 1,
                "supabase_configs": 0,
                "discovered_seeds": 4,
            },
            "fanout_batch": {"total": 5},
        }
    }

    changed = update_artifact_processor_cumulative_metrics(
        state,
        queued_local=3,
        artifact_summary=SimpleNamespace(
            processed=5,
            failed=-1,
            skipped=2,
            firebase_projects=3,
            supabase_configs=4,
            discovered_seeds=6,
        ),
    )

    assert changed is True
    assert state["queue_metrics"] == {
        "artifact_processor_cumulative": {
            "local_intake_queued": 5,
            "invocations": 2,
            "processed": 8,
            "failed": 1,
            "skipped": 4,
            "firebase_projects": 4,
            "supabase_configs": 4,
            "discovered_seeds": 10,
        },
        "fanout_batch": {"total": 5},
    }


def test_update_artifact_processor_cumulative_metrics_recovers_bad_queue_state() -> None:
    state: dict[str, object] = {"queue_metrics": "bad"}

    update_artifact_processor_cumulative_metrics(state, queued_local=-3)

    assert state["queue_metrics"] == {
        "artifact_processor_cumulative": {
            "local_intake_queued": 0,
            "invocations": 0,
            "processed": 0,
            "failed": 0,
            "skipped": 0,
            "firebase_projects": 0,
            "supabase_configs": 0,
            "discovered_seeds": 0,
        }
    }


def test_restore_prior_artifact_queue_metrics_copies_artifact_groups() -> None:
    state: dict[str, object] = {
        "queue_metrics": {
            "fanout_batch": {"total": 3},
            "artifact_processor": {"stale": 99},
        }
    }

    changed = restore_prior_artifact_queue_metrics(
        state,
        {
            "queue_metrics": {
                "artifact_processor": {"processed": "4", "failed": None},
                "artifact_processor_cumulative": {
                    "local_intake_queued": "2",
                    "processed": 5,
                },
                "ignored": {"total": 9},
            }
        },
    )

    assert changed is True
    assert state["queue_metrics"] == {
        "fanout_batch": {"total": 3},
        "artifact_processor": {"processed": 4, "failed": 0},
        "artifact_processor_cumulative": {
            "local_intake_queued": 2,
            "processed": 5,
        },
    }


def test_restore_prior_artifact_queue_metrics_restores_partial_group_from_bad_state() -> None:
    state: dict[str, object] = {"queue_metrics": "bad"}

    assert (
        restore_prior_artifact_queue_metrics(
            state,
            {"queue_metrics": {"artifact_processor": {"downloaded": 7}}},
        )
        is True
    )
    assert state["queue_metrics"] == {"artifact_processor": {"downloaded": 7}}


def test_restore_prior_artifact_queue_metrics_ignores_malformed_payloads() -> None:
    for payload in (
        None,
        {},
        {"queue_metrics": "bad"},
        {"queue_metrics": {"fanout_batch": {"total": 3}}},
    ):
        state: dict[str, object] = {"queue_metrics": {"existing": {"kept": 1}}}

        assert restore_prior_artifact_queue_metrics(state, payload) is False
        assert state == {"queue_metrics": {"existing": {"kept": 1}}}


def test_clear_run_control_marker_paths_removes_known_markers_only(
    tmp_path: Path,
) -> None:
    stop_path = tmp_path / "engagement_1001_stop.json"
    pause_path = tmp_path / "engagement_1001_pause.json"
    unrelated_path = tmp_path / "engagement_1002_stop.json"
    stop_path.write_text("stale", encoding="utf-8")
    pause_path.write_text("stale", encoding="utf-8")
    unrelated_path.write_text("keep", encoding="utf-8")

    clear_run_control_marker_paths((stop_path, pause_path))

    assert not stop_path.exists()
    assert not pause_path.exists()
    assert unrelated_path.read_text(encoding="utf-8") == "keep"


def test_read_run_control_marker_request_preserves_payload_and_fallback(
    tmp_path: Path,
) -> None:
    marker_path = tmp_path / "engagement_1001_pause.json"

    assert (
        read_run_control_marker_request(
            marker_path,
            fallback_reason="pause marker present",
        )
        is None
    )

    marker_path.write_text(
        json.dumps({"reason": "review", "requested_by": "operator-web"}),
        encoding="utf-8",
    )
    assert read_run_control_marker_request(
        marker_path,
        fallback_reason="pause marker present",
    ) == {"reason": "review", "requested_by": "operator-web"}

    marker_path.write_text("{bad", encoding="utf-8")
    assert read_run_control_marker_request(
        marker_path,
        fallback_reason="pause marker present",
    ) == {"reason": "pause marker present", "requested_by": "unknown"}

    marker_path.write_text("[1, 2]", encoding="utf-8")
    assert read_run_control_marker_request(
        marker_path,
        fallback_reason="pause marker present",
    ) == {"reason": "pause marker present", "requested_by": "unknown"}


def test_run_control_request_from_run_metadata_reads_flagged_payload(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.sqlite"
    _bootstrap(db_path)
    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO engagement_runs (
                id, engagement_id, status, metadata_json, started_at, updated_at
            )
            VALUES (7, 1001, 'running', ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """,
            (
                json.dumps(
                    {
                        "pause_requested": True,
                        "requested_by": "operator-web",
                        "reason": "checkpoint",
                    },
                    sort_keys=True,
                ),
            ),
        )
        con.commit()
    finally:
        con.close()

    assert run_control_request_from_run_metadata(
        db_path,
        engagement_id=1001,
        run_id=7,
        flag_name="pause_requested",
    ) == {
        "pause_requested": True,
        "requested_by": "operator-web",
        "reason": "checkpoint",
    }
    assert (
        run_control_request_from_run_metadata(
            db_path,
            engagement_id=1001,
            run_id=7,
            flag_name="stop_requested",
        )
        is None
    )
    assert (
        run_control_request_from_run_metadata(
            db_path,
            engagement_id=1001,
            run_id=404,
            flag_name="pause_requested",
        )
        is None
    )


def test_run_control_request_from_run_metadata_ignores_bad_metadata(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.sqlite"
    _bootstrap(db_path)
    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO engagement_runs (
                id, engagement_id, status, metadata_json, started_at, updated_at
            )
            VALUES (8, 1001, 'running', '{bad', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """
        )
        con.commit()
    finally:
        con.close()

    assert (
        run_control_request_from_run_metadata(
            db_path,
            engagement_id=1001,
            run_id=8,
            flag_name="pause_requested",
        )
        is None
    )


def test_run_control_interrupt_transition_prefers_stop_over_pause() -> None:
    transition = run_control_interrupt_transition(
        "preflight",
        stop_request={"requested_by": "operator-web", "reason": "abort now"},
        pause_request={"requested_by": "other", "reason": "pause later"},
    )

    assert transition == RunControlInterruptTransition(
        control_kind="stop",
        status="cancelled",
        lifecycle_phase="cancelled",
        lifecycle_state="cancelled",
        audit_action="kill_chain_cancelled",
        requested_by="operator-web",
        reason="abort now",
        metadata={
            "lifecycle_state": "cancelled",
            "cancel_requested_by": "operator-web",
            "cancel_reason": "abort now",
        },
        dashboard_reason="cancelled",
        console_label="cancelled",
    )


def test_run_control_interrupt_transition_shapes_pause_resume_metadata() -> None:
    transition = run_control_interrupt_transition(
        "iteration_2",
        stop_request=None,
        pause_request={"requested_by": "operator-web", "reason": "checkpoint"},
    )

    assert transition == RunControlInterruptTransition(
        control_kind="pause",
        status="cancelled",
        lifecycle_phase="paused",
        lifecycle_state="paused",
        audit_action="kill_chain_paused",
        requested_by="operator-web",
        reason="checkpoint",
        metadata={
            "lifecycle_state": "paused",
            "pause_requested_by": "operator-web",
            "pause_reason": "checkpoint",
            "resume_recommended": True,
        },
        dashboard_reason="paused",
        console_label="paused",
    )


def test_run_control_interrupt_transition_defaults_request_context() -> None:
    stop_transition = run_control_interrupt_transition(
        "preflight",
        stop_request={},
        pause_request=None,
    )
    pause_transition = run_control_interrupt_transition(
        "preflight",
        stop_request=None,
        pause_request={},
    )

    assert stop_transition is not None
    assert stop_transition.requested_by == "unknown"
    assert stop_transition.reason == "operator stop requested"
    assert stop_transition.metadata["cancel_requested_by"] == "unknown"
    assert stop_transition.metadata["cancel_reason"] == "operator stop requested"

    assert pause_transition is not None
    assert pause_transition.requested_by == "unknown"
    assert pause_transition.reason == "operator pause requested"
    assert pause_transition.metadata["pause_requested_by"] == "unknown"
    assert pause_transition.metadata["pause_reason"] == "operator pause requested"


def test_run_control_interrupt_transition_noops_without_request() -> None:
    assert (
        run_control_interrupt_transition(
            "iteration_3",
            stop_request=None,
            pause_request=None,
        )
        is None
    )


def test_kill_chain_engagement_run_metadata_normalizes_progress_state() -> None:
    state: dict[str, object] = {
        "phase": "iteration_2",
        "last_step": "2.E email fan-out",
        "last_message": "queued",
        "last_step_elapsed_seconds": "12.25",
        "last_step_at": "2026-08-15T01:02:03Z",
        "active_batch_label": "email batch",
        "active_batch_eta_seconds": 2.345,
        "active_artifact_stage_label": "artifact parse",
        "active_artifact_eta_seconds": True,
        "active_validation_stage_label": "validate",
        "active_validation_eta_seconds": 0,
        "active_finalization_stage_label": "report",
        "active_finalization_eta_seconds": 5.55,
        "recent_steps": [{"step": str(index)} for index in range(10)],
        "counts": {"hosts": 3},
        "queue_metrics": {
            "fanout_batch": {"total": "4", "failed": None},
            "bad": "ignored",
        },
        "pending_work_counts": {"emails": "2"},
        "pending_work_total": "2",
        "last_iteration_delta": {"hosts": 1},
        "last_iteration_stable": False,
    }

    metadata = kill_chain_engagement_run_metadata(
        state,
        phase=None,
        seed_values=["acme.example"],
        root_domains=["acme.example"],
        processed_counts={"processed_emails": 7},
        runtime_metadata={
            "parallel_fanout": 4,
            "report_provider": "template",
        },
        live_execution_policy={"live_probing_allowed": False},
    )

    assert metadata["phase"] == "iteration_2"
    assert metadata["seed_values"] == ["acme.example"]
    assert metadata["root_domains"] == ["acme.example"]
    assert metadata["processed_emails"] == 7
    assert metadata["parallel_fanout"] == 4
    assert metadata["report_provider"] == "template"
    assert metadata["live_execution_policy"] == {"live_probing_allowed": False}
    assert metadata["last_step_elapsed_seconds"] == 12.25
    assert metadata["active_batch_eta_seconds"] == 2.3
    assert metadata["active_artifact_eta_seconds"] is None
    assert metadata["active_validation_eta_seconds"] == 0.0
    assert metadata["active_finalization_eta_seconds"] == 5.5
    assert metadata["recent_steps"] == [{"step": str(index)} for index in range(2, 10)]
    assert metadata["queue_metrics"] == {
        "fanout_batch": {
            "total": 4,
            "failed": 0,
        }
    }
    assert metadata["pending_work_counts"] == {"emails": 2}
    assert metadata["pending_work_total"] == 2
    assert metadata["last_iteration_delta"] == {"hosts": 1}
    assert metadata["last_iteration_stable"] is False


def test_current_run_progress_payload_normalizes_dashboard_event_shape() -> None:
    payload = current_run_progress_payload(
        {
            "phase": "iteration_1",
            "last_step": "1.A subdomains",
            "last_message": "done",
            "last_step_elapsed_seconds": 1.23456,
            "last_step_at": "2026-08-15T01:02:03Z",
            "counts": {"hosts": 2},
            "queue_metrics": {"fanout_batch": {"total": 3}, "bad": "ignored"},
            "pending_work_counts": {"emails": 1},
            "pending_work_total": "1",
            "last_iteration_delta": {"hosts": 2},
            "last_iteration_stable": True,
            "active_batch_label": "subdomains",
            "active_batch_eta_seconds": 1.26,
            "active_artifact_stage_label": "artifact parse",
            "active_artifact_eta_seconds": False,
            "active_validation_stage_label": "validation",
            "active_validation_eta_seconds": 2,
            "active_finalization_stage_label": "report",
            "active_finalization_eta_seconds": 3.49,
        },
        current_iteration=1,
        run_kind="kill_chain",
    )

    assert payload == {
        "phase": "iteration_1",
        "last_step": "1.A subdomains",
        "last_message": "done",
        "last_step_elapsed_seconds": 1.235,
        "last_step_at": "2026-08-15T01:02:03Z",
        "current_iteration": 1,
        "run_kind": "kill_chain",
        "counts": {"hosts": 2},
        "queue_metrics": {"fanout_batch": {"total": 3}},
        "pending_work_counts": {"emails": 1},
        "pending_work_total": 1,
        "last_iteration_delta": {"hosts": 2},
        "last_iteration_stable": True,
        "active_batch_label": "subdomains",
        "active_batch_eta_seconds": 1.3,
        "active_artifact_stage_label": "artifact parse",
        "active_artifact_eta_seconds": None,
        "active_validation_stage_label": "validation",
        "active_validation_eta_seconds": 2.0,
        "active_finalization_stage_label": "report",
        "active_finalization_eta_seconds": 3.5,
    }


def test_direct_run_trackers_record_lifecycle(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap(db_path)

    seed_tracker = SeedRunTracker(db_path, 1001)
    seed_handle = seed_tracker.start_run(
        "acme.example",
        "domain",
        "fanout_a_subdomains",
        source="operator",
        metadata={"iteration": 1},
    )
    seed_tracker.finish_run(
        seed_handle,
        status="completed",
        output_count=2,
        metadata={"iteration": 1, "source": "direct-module-test"},
    )

    run_tracker = EngagementRunTracker(db_path, 1001)
    run_handle = run_tracker.start_run(
        run_kind="kill_chain",
        seed_value="acme.example",
        seed_type="domain",
        seed_count=1,
        max_iterations=3,
        resume_enabled=True,
        dry_run=True,
        metadata={"phase": "start"},
    )
    run_tracker.update_run(
        run_handle,
        current_iteration=1,
        metadata={"phase": "iteration_1"},
    )
    run_tracker.finish_run(
        run_handle,
        status="completed",
        current_iteration=1,
        metadata={"phase": "completed"},
    )

    con = sqlite3.connect(db_path)
    try:
        seed_row = con.execute(
            """
            SELECT sr.status, sr.output_count, es.status, sr.metadata_json
            FROM seed_runs sr
            JOIN engagement_seeds es ON es.id=sr.seed_id
            WHERE sr.id=? AND sr.engagement_id=1001
            """,
            (seed_handle.run_id,),
        ).fetchone()
        run_row = con.execute(
            """
            SELECT status, current_iteration, resume_enabled, dry_run, metadata_json
            FROM engagement_runs
            WHERE id=? AND engagement_id=1001
            """,
            (run_handle.run_id,),
        ).fetchone()
        manifest_count = con.execute(
            """
            SELECT COUNT(*)
            FROM run_audit_manifests
            WHERE engagement_id=1001 AND run_id=?
            """,
            (run_handle.run_id,),
        ).fetchone()
    finally:
        con.close()

    assert seed_row is not None
    assert seed_row[0] == "completed"
    assert seed_row[1] == 2
    assert seed_row[2] == "completed"
    assert json.loads(str(seed_row[3]))["source"] == "direct-module-test"
    assert run_row is not None
    assert run_row[0] == "completed"
    assert run_row[1] == 1
    assert run_row[2] == 1
    assert run_row[3] == 1
    assert json.loads(str(run_row[4]))["phase"] == "completed"
    assert manifest_count is not None
    assert int(manifest_count[0]) == 1
