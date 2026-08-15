from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from forge.orchestration import (
    AggregateStatsSidecarResult,
    FinalizationExecutionState,
    KillChainCloseoutResult,
    KillChainFinalizationExecutionResult,
    KillChainFinalizationPreparationResult,
    KillChainFinalSummaryResult,
    KillChainGraphArtifactPaths,
    KillChainFinalizationPlan,
    ProviderKeyValidationSweepResult,
    build_data_driven_offensive_finalization_specs,
    build_kill_chain_finalization_plan,
    emit_kill_chain_cloud_scan_summary,
    emit_kill_chain_complete_audit,
    emit_kill_chain_dry_run_finalization_skip,
    emit_kill_chain_final_summary,
    emit_kill_chain_final_summary_from_progress,
    ensure_kill_chain_report_artifact,
    ensure_report_artifact,
    finalize_kill_chain_closeout,
    finalization_label_returncode,
    kill_chain_cloud_scan_summary_result,
    kill_chain_completion_report_kwargs,
    kill_chain_completion_report_kwargs_from_closeout,
    kill_chain_complete_audit_result,
    kill_chain_finalization_dispatch_spec_factory,
    kill_chain_graph_artifact_paths,
    kill_chain_finalization_report_path,
    kill_chain_finalization_report_path_now,
    nonempty_report_artifact,
    preferred_report_artifact,
    prepare_kill_chain_finalization,
    report_generate_args,
    run_kill_chain_final_sidecars,
    run_kill_chain_finalization_execution,
    run_kill_chain_parallel_finalization_stage,
    run_kill_chain_sequential_finalization_stage,
    run_provider_key_validation_sweep,
    write_aggregate_stats_sidecar,
)


def _append_scope(args: list[str], scope_manifest: str | None) -> list[str]:
    if scope_manifest:
        return [*args, "--scope-manifest", scope_manifest]
    return list(args)


def test_report_generate_args_and_path_are_deterministic() -> None:
    report_path = kill_chain_finalization_report_path(
        engagement="1001",
        timestamp="20260812T010203",
    )

    assert report_path == "reports/engagement_1001_kill_chain_20260812T010203.md"
    assert report_generate_args(
        engagement="1001",
        output_path=report_path,
        report_provider="template",
        report_max_loops=0,
    ) == [
        "report",
        "generate",
        "--engagement",
        "1001",
        "--yes",
        "--output",
        report_path,
        "--provider",
        "template",
        "--max-loops",
        "0",
    ]


def test_kill_chain_finalization_report_path_now_uses_utc_clock() -> None:
    report_path = kill_chain_finalization_report_path_now(
        engagement="1001",
        clock=lambda: datetime(2026, 8, 12, 9, 2, 3, tzinfo=timezone.utc),
    )

    assert report_path == "reports/engagement_1001_kill_chain_20260812T090203.md"


def test_build_kill_chain_finalization_plan_dry_run_skips_network_specs() -> None:
    plan = build_kill_chain_finalization_plan(
        engagement="1001",
        domain="acme.example",
        planned_report_path="reports/engagement_1001.md",
        dry_run_all=True,
        credential_validate=True,
        attack_mode=False,
        report_provider=None,
        report_max_loops=None,
        roe_id="",
        scope_manifest=None,
        append_scope_manifest_arg=_append_scope,
    )

    assert isinstance(plan, KillChainFinalizationPlan)
    assert plan.pre_validation_specs[0] == (
        ["osint", "hibp", "--engagement", "1001", "--dry-run"],
        "final HIBP domain",
    )
    assert [label for _, label in plan.pre_validation_specs[1:]] == [
        "cred validate (ssh)",
        "cred validate (smb)",
        "cred validate (rdp)",
        "cred validate (ftp)",
        "cred validate (http)",
    ]
    assert plan.parallel_post_validation_specs == []
    assert [label for _, label in plan.network_capable_post_validation_specs] == [
        "vuln passive fingerprint",
        "exploit correlate",
    ]
    assert plan.dry_run_skipped_labels == "vuln passive fingerprint, exploit correlate"
    assert [label for _, label in plan.post_validation_specs] == [
        "attack-path graph family",
        "report generate",
    ]
    assert plan.finalization_specs == [
        *plan.pre_validation_specs,
        *plan.post_validation_specs,
    ]


def test_build_kill_chain_finalization_plan_adds_active_validation_specs() -> None:
    data_driven_specs = [
        (["vuln", "idor", "--target", "https://app.acme.example/"], "phase4 vuln idor"),
    ]

    plan = build_kill_chain_finalization_plan(
        engagement=1001,
        domain="acme.example",
        planned_report_path="reports/engagement_1001.md",
        dry_run_all=False,
        credential_validate=False,
        attack_mode=True,
        report_provider="template",
        report_max_loops=2,
        roe_id="ROE-1001",
        scope_manifest="scope.json",
        append_scope_manifest_arg=_append_scope,
        env={
            "FORGE_KILLCHAIN_PHASE3_TECHNIQUE": "std",
            "FORGE_KILLCHAIN_PHASE3_OS": "linux",
            "FORGE_LHOST": "10.10.10.10",
            "FORGE_LPORT": "4444",
        },
        data_driven_offensive_specs=data_driven_specs,
    )

    labels = [label for _, label in plan.parallel_post_validation_specs]
    assert labels == [
        "vuln passive fingerprint",
        "exploit correlate",
        "phase3 evasion generate",
        "phase5 post-shell payload",
        "phase4 vuln idor",
    ]
    assert plan.parallel_post_validation_specs[2][0] == [
        "evasion",
        "generate",
        "--engagement",
        "1001",
        "--technique",
        "std",
        "--os",
        "linux",
        "--scope-manifest",
        "scope.json",
    ]
    assert plan.parallel_post_validation_specs[3][0] == [
        "post",
        "shell",
        "--engagement",
        "1001",
        "--lhost",
        "10.10.10.10",
        "--lport",
        "4444",
        "--roe-id",
        "ROE-1001",
        "--scope-manifest",
        "scope.json",
    ]
    assert plan.sequential_post_validation_specs[-1] == (
        [
            "report",
            "generate",
            "--engagement",
            "1001",
            "--yes",
            "--output",
            "reports/engagement_1001.md",
            "--provider",
            "template",
            "--max-loops",
            "2",
        ],
        "report generate",
    )


def test_report_finalization_side_effect_helpers_remain_package_exported() -> None:
    from forge import orchestration as orchestration_package  # noqa: PLC0415

    assert orchestration_package.AggregateStatsSidecarResult is AggregateStatsSidecarResult
    assert orchestration_package.FinalizationExecutionState is FinalizationExecutionState
    assert orchestration_package.KillChainFinalSummaryResult is KillChainFinalSummaryResult
    assert orchestration_package.KillChainGraphArtifactPaths is KillChainGraphArtifactPaths
    assert (
        orchestration_package.build_data_driven_offensive_finalization_specs
        is build_data_driven_offensive_finalization_specs
    )
    assert (
        orchestration_package.emit_kill_chain_cloud_scan_summary
        is emit_kill_chain_cloud_scan_summary
    )
    assert orchestration_package.emit_kill_chain_complete_audit is emit_kill_chain_complete_audit
    assert (
        orchestration_package.emit_kill_chain_dry_run_finalization_skip
        is emit_kill_chain_dry_run_finalization_skip
    )
    assert orchestration_package.emit_kill_chain_final_summary is emit_kill_chain_final_summary
    assert (
        orchestration_package.emit_kill_chain_final_summary_from_progress
        is emit_kill_chain_final_summary_from_progress
    )
    assert orchestration_package.ensure_kill_chain_report_artifact is ensure_kill_chain_report_artifact
    assert orchestration_package.finalize_kill_chain_closeout is finalize_kill_chain_closeout
    assert orchestration_package.KillChainCloseoutResult is KillChainCloseoutResult
    assert (
        orchestration_package.KillChainFinalizationExecutionResult
        is KillChainFinalizationExecutionResult
    )
    assert (
        orchestration_package.KillChainFinalizationPreparationResult
        is KillChainFinalizationPreparationResult
    )
    assert (
        orchestration_package.kill_chain_cloud_scan_summary_result
        is kill_chain_cloud_scan_summary_result
    )
    assert (
        orchestration_package.kill_chain_completion_report_kwargs
        is kill_chain_completion_report_kwargs
    )
    assert (
        orchestration_package.kill_chain_completion_report_kwargs_from_closeout
        is kill_chain_completion_report_kwargs_from_closeout
    )
    assert (
        orchestration_package.kill_chain_complete_audit_result
        is kill_chain_complete_audit_result
    )
    assert (
        orchestration_package.kill_chain_finalization_dispatch_spec_factory
        is kill_chain_finalization_dispatch_spec_factory
    )
    assert orchestration_package.kill_chain_graph_artifact_paths is kill_chain_graph_artifact_paths
    assert (
        orchestration_package.kill_chain_finalization_report_path_now
        is kill_chain_finalization_report_path_now
    )
    assert (
        orchestration_package.finalization_label_returncode
        is finalization_label_returncode
    )
    assert (
        orchestration_package.run_kill_chain_parallel_finalization_stage
        is run_kill_chain_parallel_finalization_stage
    )
    assert (
        orchestration_package.run_kill_chain_sequential_finalization_stage
        is run_kill_chain_sequential_finalization_stage
    )
    assert (
        orchestration_package.ProviderKeyValidationSweepResult
        is ProviderKeyValidationSweepResult
    )
    assert (
        orchestration_package.run_provider_key_validation_sweep
        is run_provider_key_validation_sweep
    )
    assert orchestration_package.write_aggregate_stats_sidecar is write_aggregate_stats_sidecar
    assert orchestration_package.run_kill_chain_final_sidecars is run_kill_chain_final_sidecars
    assert (
        orchestration_package.prepare_kill_chain_finalization
        is prepare_kill_chain_finalization
    )
    assert (
        orchestration_package.run_kill_chain_finalization_execution
        is run_kill_chain_finalization_execution
    )


def test_kill_chain_cloud_scan_summary_result_preserves_labels_and_order() -> None:
    result = kill_chain_cloud_scan_summary_result(
        {
            "supabase": ["sb1", "sb2"],
            "firebase": ["fb1"],
            "aws_s3": ["s3"],
            "gcs": [],
            "azure_blob": ["az"],
            "amplify": ["amp"],
            "gcp_appspot": ["appspot"],
            "gcp_cloudfunctions": ["fn1", "fn2"],
            "cloudflare_pages": ["pages"],
            "cloudflare_worker": ["worker"],
            "cloudflare_r2": ["r2"],
            "github_pages": ["gh"],
            "gitlab_pages": ["gl"],
            "vercel": ["vc"],
            "netlify": ["nf"],
        },
        {"sb1", "fb1", "fn1"},
    )

    assert result == (
        "supabase=2 firebase=1 aws_s3=1 gcs=0 azure_blob=1 amplify=1 "
        "gcp_appspot=1 gcp_cf=2 cf_pages=1 cf_workers=1 cf_r2=1 "
        "github_pages=1 gitlab_pages=1 vercel=1 netlify=1 scans_run=3"
    )


def test_kill_chain_cloud_scan_summary_result_defaults_missing_refs_to_zero() -> None:
    assert kill_chain_cloud_scan_summary_result({}, []) == (
        "supabase=0 firebase=0 aws_s3=0 gcs=0 azure_blob=0 amplify=0 "
        "gcp_appspot=0 gcp_cf=0 cf_pages=0 cf_workers=0 cf_r2=0 "
        "github_pages=0 gitlab_pages=0 vercel=0 netlify=0 scans_run=0"
    )


def test_emit_kill_chain_cloud_scan_summary_runs_callbacks_and_audit(tmp_path: Path) -> None:
    calls: list[tuple[object, ...]] = []

    result = emit_kill_chain_cloud_scan_summary(
        skip_cloud=False,
        cloud_refs={"supabase": ["sb1"], "firebase": ["fb1"]},
        processed_refs={"sb1"},
        run_pending_cloud_key_validation=lambda label: calls.append(("pending", label)),
        run_finding_synthesis=lambda label: calls.append(("synthesis", label)),
        audit_callback=lambda *args, **kwargs: calls.append(("audit", args, kwargs)),
        db_path=tmp_path / "engagement.db",
        engagement_id=1001,
        target="acme.example",
    )

    assert result.startswith("supabase=1 firebase=1 ")
    assert result.endswith(" scans_run=1")
    assert calls[0] == ("pending", "final cloud key validation")
    assert calls[1] == ("synthesis", "final finding synthesis")
    assert calls[2][0] == "audit"
    assert calls[2][1] == (
        tmp_path / "engagement.db",
        1001,
        "orchestrator",
        "kill_chain",
        "cloud_scan_summary",
    )
    assert calls[2][2] == {"target": "acme.example", "result": result}


def test_emit_kill_chain_cloud_scan_summary_skips_all_callbacks(tmp_path: Path) -> None:
    calls: list[object] = []

    result = emit_kill_chain_cloud_scan_summary(
        skip_cloud=True,
        cloud_refs={"supabase": ["sb1"]},
        processed_refs={"sb1"},
        run_pending_cloud_key_validation=lambda label: calls.append(("pending", label)),
        run_finding_synthesis=lambda label: calls.append(("synthesis", label)),
        audit_callback=lambda *args, **kwargs: calls.append(("audit", args, kwargs)),
        db_path=tmp_path / "engagement.db",
        engagement_id=1001,
        target="acme.example",
    )

    assert result is None
    assert calls == []


def test_kill_chain_complete_audit_result_formats_elapsed_and_email_count() -> None:
    assert kill_chain_complete_audit_result(
        elapsed_seconds=12.345,
        emails_chained=["a@example.com", "b@example.com"],
    ) == "elapsed_s=12.3 emails_chained=2"
    assert kill_chain_complete_audit_result(
        elapsed_seconds=12.35,
        emails_chained=[],
    ) == "elapsed_s=12.3 emails_chained=0"
    assert kill_chain_complete_audit_result(
        elapsed_seconds=0,
        emails_chained=7,
    ) == "elapsed_s=0.0 emails_chained=7"


def test_emit_kill_chain_complete_audit_invokes_audit_callback(tmp_path: Path) -> None:
    audit_events: list[tuple[tuple[object, ...], dict[str, object]]] = []

    result = emit_kill_chain_complete_audit(
        audit_callback=lambda *args, **kwargs: audit_events.append((args, kwargs)),
        db_path=tmp_path / "engagement.db",
        engagement_id=1001,
        target="acme.example",
        elapsed_seconds=42.06,
        emails_chained=["ops@acme.example"],
    )

    assert result == "elapsed_s=42.1 emails_chained=1"
    assert audit_events == [
        (
            (
                tmp_path / "engagement.db",
                1001,
                "orchestrator",
                "kill_chain",
                "kill_chain_complete",
            ),
            {
                "target": "acme.example",
                "result": "elapsed_s=42.1 emails_chained=1",
            },
        )
    ]


def test_kill_chain_completion_report_kwargs_preserves_completion_shape(
    tmp_path: Path,
) -> None:
    metadata = {"report_artifact_verified": True, "status": "completed"}
    kwargs = kill_chain_completion_report_kwargs(
        report_artifact_path=tmp_path / "reports" / "final.md",
        planned_report_path=tmp_path / "reports" / "planned.md",
        report_provider="template",
        report_max_loops=2,
        finalization_failed=1,
        report_finalization_metadata=metadata,
    )

    assert kwargs == {
        "report_path": str(tmp_path / "reports" / "final.md"),
        "report_ready": True,
        "report_provider": "template",
        "report_max_loops": 2,
        "finalization_failed": 1,
        "report_finalization_metadata": metadata,
    }
    assert kwargs["report_finalization_metadata"] is not metadata


def test_kill_chain_completion_report_kwargs_uses_planned_path_when_missing() -> None:
    assert kill_chain_completion_report_kwargs(
        report_artifact_path=None,
        planned_report_path="reports/planned.md",
        report_provider=None,
        report_max_loops=None,
        finalization_failed=0,
        report_finalization_metadata={},
    ) == {
        "report_path": "reports/planned.md",
        "report_ready": False,
        "report_provider": None,
        "report_max_loops": None,
        "finalization_failed": 0,
        "report_finalization_metadata": {},
    }


def test_kill_chain_completion_report_kwargs_from_closeout_copies_metadata(
    tmp_path: Path,
) -> None:
    metadata = {"report_artifact_verified": True}
    closeout = KillChainCloseoutResult(
        report_artifact_path=tmp_path / "reports" / "final.md",
        report_finalization_metadata=metadata,
        final_pending_total=0,
        final_summary=KillChainFinalSummaryResult(
            final_pending_total=0,
            graph_paths=kill_chain_graph_artifact_paths("1001"),
        ),
        provider_key_validation=ProviderKeyValidationSweepResult(scanned=1),
        aggregate_stats_sidecar=AggregateStatsSidecarResult(written=True),
    )

    kwargs = kill_chain_completion_report_kwargs_from_closeout(
        closeout=closeout,
        planned_report_path="reports/planned.md",
        report_provider="template",
        report_max_loops=1,
        finalization_failed=2,
    )

    assert kwargs == {
        "report_path": str(tmp_path / "reports" / "final.md"),
        "report_ready": True,
        "report_provider": "template",
        "report_max_loops": 1,
        "finalization_failed": 2,
        "report_finalization_metadata": metadata,
    }
    assert kwargs["report_finalization_metadata"] is not metadata


def test_kill_chain_finalization_dispatch_spec_factory_preserves_cli_shape() -> None:
    @dataclass(frozen=True)
    class DispatchSpec:
        cmd_argv: list[str]
        label: str

    make_dispatch_spec = kill_chain_finalization_dispatch_spec_factory(DispatchSpec)

    assert make_dispatch_spec(["report", "generate"], "final report") == DispatchSpec(
        cmd_argv=["report", "generate"],
        label="final report",
    )


def test_emit_kill_chain_dry_run_finalization_skip_logs_and_audits(
    tmp_path: Path,
) -> None:
    log_events: list[tuple[str, str]] = []
    audit_events: list[tuple[tuple[object, ...], dict[str, object]]] = []

    result = emit_kill_chain_dry_run_finalization_skip(
        dry_run_all=True,
        skipped_labels="vuln passive fingerprint, exploit correlate",
        log_callback=lambda step, message: log_events.append((step, message)),
        audit_callback=lambda *args, **kwargs: audit_events.append((args, kwargs)),
        db_path=tmp_path / "engagement.db",
        engagement_id=1001,
        target="acme.example",
    )

    assert result == "vuln passive fingerprint, exploit correlate"
    assert log_events == [
        (
            "finalization dry-run",
            (
                "[dim]skipped network-capable finalizers: "
                "vuln passive fingerprint, exploit correlate[/dim]"
            ),
        )
    ]
    assert audit_events == [
        (
            (
                tmp_path / "engagement.db",
                1001,
                "orchestrator",
                "kill_chain",
                "dry_run_finalization_skipped",
            ),
            {
                "target": "acme.example",
                "result": "labels=vuln passive fingerprint, exploit correlate",
            },
        )
    ]


def test_emit_kill_chain_dry_run_finalization_skip_noops_when_live(
    tmp_path: Path,
) -> None:
    log_events: list[tuple[str, str]] = []
    audit_events: list[object] = []

    result = emit_kill_chain_dry_run_finalization_skip(
        dry_run_all=False,
        skipped_labels="vuln passive fingerprint, exploit correlate",
        log_callback=lambda step, message: log_events.append((step, message)),
        audit_callback=lambda *args, **kwargs: audit_events.append((args, kwargs)),
        db_path=tmp_path / "engagement.db",
        engagement_id=1001,
        target="acme.example",
    )

    assert result is None
    assert log_events == []
    assert audit_events == []


def test_run_kill_chain_final_sidecars_invokes_provider_and_stats_helpers(
    tmp_path: Path,
) -> None:
    calls: list[tuple[str, dict[str, object]]] = []
    logger = SimpleNamespace(debug=lambda *_args: None)

    def _provider_sweep(**kwargs) -> ProviderKeyValidationSweepResult:  # noqa: ANN003
        calls.append(("provider", dict(kwargs)))
        return ProviderKeyValidationSweepResult(scanned=3, updated=2)

    def _stats_sidecar(**kwargs) -> AggregateStatsSidecarResult:  # noqa: ANN003
        calls.append(("stats", dict(kwargs)))
        return AggregateStatsSidecarResult(
            written=True,
            path=Path(kwargs["reports_dir"]) / "engagement_1001_stats.json",
        )

    log_callback = lambda _step, _message: None  # noqa: E731
    provider_result, stats_result = run_kill_chain_final_sidecars(
        db_path=tmp_path / "engagement.db",
        engagement_id=1001,
        reports_dir=tmp_path / "reports",
        log_callback=log_callback,
        logger=logger,
        provider_key_validation_sweep=_provider_sweep,
        aggregate_stats_sidecar=_stats_sidecar,
    )

    assert provider_result == ProviderKeyValidationSweepResult(scanned=3, updated=2)
    assert stats_result == AggregateStatsSidecarResult(
        written=True,
        path=tmp_path / "reports" / "engagement_1001_stats.json",
    )
    assert calls == [
        (
            "provider",
            {
                "db_path": tmp_path / "engagement.db",
                "engagement_id": 1001,
                "log_callback": log_callback,
                "logger": logger,
            },
        ),
        (
            "stats",
            {
                "db_path": tmp_path / "engagement.db",
                "engagement_id": 1001,
                "reports_dir": tmp_path / "reports",
                "logger": logger,
            },
        ),
    ]


def test_build_data_driven_offensive_finalization_specs_skips_inactive_modes(
    tmp_path: Path,
) -> None:
    def _connect(*_args, **_kwargs):  # noqa: ANN002, ANN003, ANN202
        raise AssertionError("inactive modes should not open the DB")

    common = {
        "db_path": tmp_path / "engagement.db",
        "engagement_id": 1001,
        "engagement": "1001",
        "roe_id": "ROE-1001",
        "scope_manifest": "scope.json",
        "append_scope_manifest_arg": _append_scope,
        "connect": _connect,
    }

    assert build_data_driven_offensive_finalization_specs(
        **common,
        attack_mode=False,
        dry_run_all=False,
    ) == []
    assert build_data_driven_offensive_finalization_specs(
        **common,
        attack_mode=True,
        dry_run_all=True,
    ) == []


def test_build_data_driven_offensive_finalization_specs_ignores_missing_tables(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    sqlite3.connect(db_path).close()

    specs = build_data_driven_offensive_finalization_specs(
        db_path=db_path,
        engagement_id=1001,
        engagement="1001",
        attack_mode=True,
        dry_run_all=False,
        roe_id="ROE-1001",
        scope_manifest="scope.json",
        append_scope_manifest_arg=_append_scope,
        connect=lambda path, **kwargs: sqlite3.connect(path, **kwargs),
    )

    assert specs == []


def test_build_data_driven_offensive_finalization_specs_builds_scoped_targets(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    con = sqlite3.connect(db_path)
    try:
        con.executescript(
            """
            CREATE TABLE hosts (
                id INTEGER PRIMARY KEY,
                engagement_id INTEGER,
                ip TEXT,
                hostname TEXT
            );
            CREATE TABLE services (
                host_id INTEGER,
                port INTEGER,
                service_name TEXT
            );
            CREATE TABLE credentials (
                engagement_id INTEGER,
                validated_host TEXT,
                validated INTEGER,
                validated_at TEXT
            );
            INSERT INTO hosts (id, engagement_id, ip, hostname)
            VALUES
                (1, 1001, '10.0.0.5', 'app.acme.example'),
                (2, 1001, '10.0.0.6', 'files.acme.example');
            INSERT INTO services (host_id, port, service_name)
            VALUES (1, 8443, 'https');
            INSERT INTO credentials (engagement_id, validated_host, validated, validated_at)
            VALUES (1001, '10.0.0.6', 1, '2026-08-13T00:00:00Z');
            """
        )
        con.commit()
    finally:
        con.close()

    specs = build_data_driven_offensive_finalization_specs(
        db_path=db_path,
        engagement_id=1001,
        engagement="1001",
        attack_mode=True,
        dry_run_all=False,
        roe_id="ROE-1001",
        scope_manifest="scope.json",
        append_scope_manifest_arg=_append_scope,
        connect=lambda path, **kwargs: sqlite3.connect(path, **kwargs),
    )

    assert specs == [
        (
            [
                "vuln",
                "idor",
                "--engagement",
                "1001",
                "--target",
                "https://app.acme.example:8443/",
                "--depth",
                "2",
                "--roe-id",
                "ROE-1001",
                "--scope-manifest",
                "scope.json",
            ],
            "phase4 vuln idor (https://app.acme.example:8443/)",
        ),
        (
            [
                "auth",
                "brute",
                "--engagement",
                "1001",
                "--target",
                "https://app.acme.example:8443/",
                "--max-attempts",
                "10",
                "--roe-id",
                "ROE-1001",
                "--scope-manifest",
                "scope.json",
            ],
            "phase4 auth brute (https://app.acme.example:8443/)",
        ),
        (
            [
                "auth",
                "bypass",
                "--engagement",
                "1001",
                "--target",
                "https://app.acme.example:8443/",
                "--roe-id",
                "ROE-1001",
                "--scope-manifest",
                "scope.json",
            ],
            "phase4 auth bypass (https://app.acme.example:8443/)",
        ),
        (
            [
                "post",
                "lateral",
                "--engagement",
                "1001",
                "--target",
                "files.acme.example",
                "--technique",
                "smb_exec",
                "--roe-id",
                "ROE-1001",
                "--scope-manifest",
                "scope.json",
            ],
            "phase5 post lateral (files.acme.example)",
        ),
    ]


def test_prepare_kill_chain_finalization_builds_plan_and_audits_dry_run_skip(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    con = sqlite3.connect(db_path)
    try:
        con.executescript(
            """
            CREATE TABLE hosts (
                id INTEGER PRIMARY KEY,
                engagement_id INTEGER,
                ip TEXT,
                hostname TEXT
            );
            CREATE TABLE services (
                host_id INTEGER,
                port INTEGER,
                service_name TEXT
            );
            CREATE TABLE credentials (
                engagement_id INTEGER,
                validated_host TEXT,
                validated INTEGER,
                validated_at TEXT
            );
            INSERT INTO hosts (id, engagement_id, ip, hostname)
            VALUES (1, 1001, '10.0.0.5', 'app.acme.example');
            INSERT INTO services (host_id, port, service_name)
            VALUES (1, 443, 'https');
            """
        )
        con.commit()
    finally:
        con.close()
    log_events: list[tuple[str, str]] = []
    audit_events: list[tuple[tuple[object, ...], dict[str, object]]] = []

    result = prepare_kill_chain_finalization(
        db_path=db_path,
        engagement_id=1001,
        engagement="1001",
        domain="acme.example",
        planned_report_path="reports/engagement_1001.md",
        dry_run_all=True,
        credential_validate=True,
        attack_mode=True,
        report_provider="template",
        report_max_loops=2,
        roe_id="ROE-1001",
        scope_manifest="scope.json",
        append_scope_manifest_arg=_append_scope,
        log_callback=lambda step, message: log_events.append((step, message)),
        audit_callback=lambda *args, **kwargs: audit_events.append((args, kwargs)),
        env={"FORGE_LHOST": "10.0.0.10"},
        connect=lambda path, **kwargs: sqlite3.connect(path, **kwargs),
    )

    assert result == KillChainFinalizationPreparationResult(
        data_driven_offensive_specs=[],
        finalization_plan=result.finalization_plan,
    )
    assert result.finalization_plan.parallel_post_validation_specs == []
    assert result.finalization_plan.dry_run_skipped_labels == (
        "vuln passive fingerprint, exploit correlate"
    )
    assert result.finalization_plan.report_args == [
        "report",
        "generate",
        "--engagement",
        "1001",
        "--yes",
        "--output",
        "reports/engagement_1001.md",
        "--provider",
        "template",
        "--max-loops",
        "2",
    ]
    assert log_events == [
        (
            "finalization dry-run",
            "[dim]skipped network-capable finalizers: vuln passive fingerprint, exploit correlate[/dim]",
        )
    ]
    assert audit_events == [
        (
            (
                db_path,
                1001,
                "orchestrator",
                "kill_chain",
                "dry_run_finalization_skipped",
            ),
            {
                "target": "acme.example",
                "result": "labels=vuln passive fingerprint, exploit correlate",
            },
        )
    ]


def test_emit_kill_chain_final_summary_prints_complete_and_graph_paths() -> None:
    lines: list[str] = []
    paths = kill_chain_graph_artifact_paths("1001")

    returned_paths = emit_kill_chain_final_summary(
        engagement="1001",
        elapsed_seconds=12.34,
        report_artifact_path="reports/final.md",
        planned_report_path="reports/planned.md",
        final_pending_total=0,
        print_callback=lines.append,
        path_exists=lambda value: value in {paths.mtgx, paths.graphml},
    )

    assert returned_paths == KillChainGraphArtifactPaths(
        mtgx="reports/1001_attack_graph.mtgx",
        graphml="reports/1001_attack_graph.graphml",
        nodes_csv="reports/1001_attack_graph_nodes.csv",
        edges_csv="reports/1001_attack_graph_edges.csv",
    )
    assert lines == [
        "\n[bold green]Kill-chain complete[/bold green] in 12.3s",
        "[dim]Report:[/dim] reports/final.md",
        "[dim]Evidence:[/dim] .forge_data/engagements/1001.db",
        "[dim]Maltego workspace:[/dim] reports/1001_attack_graph.mtgx",
        "[dim]Maltego graphml:[/dim] reports/1001_attack_graph.graphml",
        (
            "[dim]Maltego CSVs:[/dim] reports/1001_attack_graph_nodes.csv  |  "
            "reports/1001_attack_graph_edges.csv"
        ),
        (
            "[dim]  -> open the .mtgx in Maltego Graph (Desktop), or import the "
            ".graphml in Community Edition if you need the lightweight path.[/dim]"
        ),
    ]


def test_emit_kill_chain_final_summary_prints_failure_and_pending_variants() -> None:
    failed_lines: list[str] = []
    emit_kill_chain_final_summary(
        engagement=1001,
        elapsed_seconds=3.0,
        report_artifact_path=None,
        planned_report_path="reports/planned.md",
        final_pending_total=0,
        print_callback=failed_lines.append,
        path_exists=lambda _value: False,
    )

    assert failed_lines == [
        (
            "\n[bold red]Kill-chain finalization failed[/bold red] in 3.0s "
            "[dim](no report artifact persisted)[/dim]"
        ),
        "[dim]Report:[/dim] reports/planned.md",
        "[dim]Evidence:[/dim] .forge_data/engagements/1001.db",
    ]

    pending_lines: list[str] = []
    emit_kill_chain_final_summary(
        engagement=1001,
        elapsed_seconds=7.25,
        report_artifact_path="reports/final.md",
        planned_report_path="reports/planned.md",
        final_pending_total=4,
        print_callback=pending_lines.append,
        path_exists=lambda _value: False,
    )

    assert pending_lines == [
        (
            "\n[bold yellow]Kill-chain stopped with pending recursive work[/bold yellow] "
            "in 7.2s [dim](pending=4)[/dim]"
        ),
        "[dim]Report:[/dim] reports/final.md",
        "[dim]Evidence:[/dim] .forge_data/engagements/1001.db",
    ]


def test_emit_kill_chain_final_summary_from_progress_returns_pending_total() -> None:
    lines: list[str] = []

    result = emit_kill_chain_final_summary_from_progress(
        engagement=1001,
        elapsed_seconds=8.88,
        report_artifact_path="reports/final.md",
        planned_report_path="reports/planned.md",
        run_progress_state={"pending_work_total": "5"},
        print_callback=lines.append,
        path_exists=lambda _value: False,
    )

    assert result == KillChainFinalSummaryResult(
        final_pending_total=5,
        graph_paths=KillChainGraphArtifactPaths(
            mtgx="reports/1001_attack_graph.mtgx",
            graphml="reports/1001_attack_graph.graphml",
            nodes_csv="reports/1001_attack_graph_nodes.csv",
            edges_csv="reports/1001_attack_graph_edges.csv",
        ),
    )
    assert lines[0] == (
        "\n[bold yellow]Kill-chain stopped with pending recursive work[/bold yellow] "
        "in 8.9s [dim](pending=5)[/dim]"
    )


def test_run_kill_chain_parallel_finalization_stage_preserves_dispatch_contract() -> None:
    state = FinalizationExecutionState(total=4, started_at=10.0)
    log_events: list[tuple[str, str]] = []
    prep_calls: list[dict[str, object]] = []
    module_batch_calls: list[dict[str, object]] = []
    finalization_progress: list[tuple[str, dict[str, object]]] = []

    def _snapshot(**kwargs: object) -> dict[str, object]:
        return dict(kwargs)

    def _run_inprocess_batch(items, worker, **kwargs):  # noqa: ANN001, ANN202
        prep_calls.append({"items": list(items), "kwargs": kwargs})
        return [worker(item) for item in items]

    def _run_module_batch(specs, run_module, **kwargs):  # noqa: ANN001, ANN202
        module_batch_calls.append({"specs": list(specs), "kwargs": kwargs})
        kwargs["progress_callback"]("stage", {"workers": 2, "completed": 1, "failed": 0})
        return [0, 1]

    results = run_kill_chain_parallel_finalization_stage(
        [(["one"], "first"), (["two"], "second")],
        state=state,
        parallel_workers=2,
        spec_prep_label="prep",
        dispatch_label="dispatch",
        batch_label="batch",
        log_callback=lambda step, message: log_events.append((step, message)),
        run_inprocess_batch=_run_inprocess_batch,
        run_module_batch=_run_module_batch,
        run_module=lambda *_args, **_kwargs: 0,
        make_dispatch_spec=lambda cmd_argv, label: SimpleNamespace(
            cmd_argv=cmd_argv,
            label=label,
        ),
        record_batch_progress=lambda _label, _metrics: None,
        record_finalization_progress=lambda label, metrics: finalization_progress.append(
            (label, metrics)
        ),
        batch_progress_snapshot=_snapshot,
    )

    assert results == [0, 1]
    assert state.completed == 2
    assert state.failed == 1
    assert log_events == [
        ("prep", "[dim]parallel parse x2[/dim]"),
        ("dispatch", "[dim]parallel dispatch x2[/dim]"),
    ]
    assert prep_calls[0]["items"] == [(["one"], "first"), (["two"], "second")]
    assert [spec.cmd_argv for spec in module_batch_calls[0]["specs"]] == [
        ["one"],
        ["two"],
    ]
    assert [spec.label for spec in module_batch_calls[0]["specs"]] == [
        "first",
        "second",
    ]
    assert module_batch_calls[0]["kwargs"]["progress_label"] == "batch"
    assert finalization_progress == [
        (
            "stage",
            {
                "total": 4,
                "workers": 2,
                "completed": 1,
                "failed": 0,
                "started_at": 10.0,
            },
        )
    ]


def test_run_kill_chain_sequential_finalization_stage_tracks_report_returncode() -> None:
    state = FinalizationExecutionState(total=2, started_at=20.0)
    log_events: list[tuple[str, str]] = []
    calls: list[tuple[list[str], str]] = []
    finalization_progress: list[tuple[str, dict[str, object]]] = []
    specs = [
        (["graph", "build"], "attack-path graph family"),
        (["report", "generate"], "report generate"),
    ]

    def _snapshot(**kwargs: object) -> dict[str, object]:
        return dict(kwargs)

    def _run_inprocess_batch(items, worker, **_kwargs):  # noqa: ANN001, ANN202
        return [worker(item) for item in items]

    def _run_module(cmd_argv: list[str], label: str) -> int:
        calls.append((cmd_argv, label))
        return 2 if label == "report generate" else 0

    results = run_kill_chain_sequential_finalization_stage(
        specs,
        state=state,
        log_callback=lambda step, message: log_events.append((step, message)),
        run_inprocess_batch=_run_inprocess_batch,
        run_module=_run_module,
        record_finalization_progress=lambda label, metrics: finalization_progress.append(
            (label, metrics)
        ),
        batch_progress_snapshot=_snapshot,
    )

    assert results == [0, 2]
    assert calls == [
        (["graph", "build"], "attack-path graph family"),
        (["report", "generate"], "report generate"),
    ]
    assert state.completed == 2
    assert state.failed == 1
    assert finalization_label_returncode(specs, results, label="report generate") == 2
    assert finalization_label_returncode(specs, results, label="missing") is None
    assert log_events == [
        (
            "finalization postgraph",
            "[dim]sequential dispatch x1[/dim]  [dim]graph/report order preserved[/dim]",
        )
    ]
    assert finalization_progress[0][0] == "attack-path graph family"
    assert finalization_progress[-1] == (
        "report generate",
        {
            "total": 2,
            "workers": 1,
            "completed": 2,
            "failed": 1,
            "started_at": 20.0,
        },
    )


def test_run_kill_chain_finalization_execution_runs_ordered_pipeline(
    tmp_path: Path,
) -> None:
    log_events: list[tuple[str, str]] = []
    module_calls: list[tuple[list[str], str]] = []
    batch_calls: list[tuple[str, list[str]]] = []
    cloud_callbacks: list[str] = []
    audit_events: list[tuple[tuple[object, ...], dict[str, object]]] = []
    finalization_progress: list[tuple[str, dict[str, object]]] = []
    batch_progress: list[tuple[str, dict[str, object]]] = []

    @dataclass(frozen=True)
    class _DispatchSpec:
        cmd_argv: list[str]
        label: str

    plan = KillChainFinalizationPlan(
        report_args=["report", "generate"],
        pre_validation_specs=[
            (["osint", "hibp"], "final HIBP domain"),
            (["osint", "validate", "--service", "ssh"], "cred validate (ssh)"),
        ],
        parallel_post_validation_specs=[
            (["vuln", "passive"], "vuln passive fingerprint"),
        ],
        sequential_post_validation_specs=[
            (["graph", "build"], "attack-path graph family"),
            (["report", "generate"], "report generate"),
        ],
        finalization_specs=[
            (["osint", "hibp"], "final HIBP domain"),
            (["osint", "validate", "--service", "ssh"], "cred validate (ssh)"),
            (["vuln", "passive"], "vuln passive fingerprint"),
            (["graph", "build"], "attack-path graph family"),
            (["report", "generate"], "report generate"),
        ],
    )

    def _snapshot(**kwargs: object) -> dict[str, object]:
        return dict(kwargs)

    def _run_inprocess_batch(items, worker, **kwargs):  # noqa: ANN001, ANN202
        inputs = list(items)
        batch_progress.append((str(kwargs.get("progress_label")), {"count": len(inputs)}))
        return [worker(item) for item in inputs]

    def _run_module_batch(specs, run_module, **kwargs):  # noqa: ANN001, ANN202
        dispatch_specs = list(specs)
        batch_calls.append(
            (str(kwargs["progress_label"]), [spec.label for spec in dispatch_specs])
        )
        callback = kwargs.get("progress_callback")
        if callback is not None:
            callback("batch", {"workers": 2, "completed": len(dispatch_specs), "failed": 1})
        return [run_module(spec) for spec in dispatch_specs]

    def _run_module(*args):  # noqa: ANN002, ANN202
        if len(args) == 1:
            spec = args[0]
            cmd_argv = list(spec.cmd_argv)
            label = str(spec.label)
        else:
            cmd_argv = list(args[0])
            label = str(args[1])
        module_calls.append((cmd_argv, label))
        return 2 if label == "report generate" else 0

    result = run_kill_chain_finalization_execution(
        finalization_plan=plan,
        credential_validate=True,
        skip_cloud=False,
        cloud_refs={"aws_s3": ["bucket-a"]},
        processed_refs={"aws_s3:bucket-a"},
        run_pending_cloud_key_validation=lambda label: cloud_callbacks.append(label),
        run_finding_synthesis=lambda label: cloud_callbacks.append(label),
        audit_callback=lambda *args, **kwargs: audit_events.append((args, kwargs)),
        db_path=tmp_path / "engagement.db",
        engagement_id=1001,
        target="acme.example",
        parallel_workers=2,
        log_callback=lambda step, message: log_events.append((step, message)),
        run_inprocess_batch=_run_inprocess_batch,
        run_module_batch=_run_module_batch,
        run_module=_run_module,
        dispatch_spec_type=_DispatchSpec,
        record_batch_progress=lambda label, metrics: batch_progress.append((label, metrics)),
        record_finalization_progress=lambda label, metrics: finalization_progress.append(
            (label, metrics)
        ),
        batch_progress_snapshot=_snapshot,
        perf_counter=lambda: 42.0,
    )

    assert result == KillChainFinalizationExecutionResult(
        state=result.state,
        credential_results=[0],
        pregraph_results=[0, 0],
        sequential_results=[0, 2],
        report_returncode=2,
    )
    assert result.state.total == 5
    assert result.state.started_at == 42.0
    assert result.state.completed == 5
    assert result.state.failed == 1
    assert module_calls == [
        (["osint", "validate", "--service", "ssh"], "cred validate (ssh)"),
        (["osint", "hibp"], "final HIBP domain"),
        (["vuln", "passive"], "vuln passive fingerprint"),
        (["graph", "build"], "attack-path graph family"),
        (["report", "generate"], "report generate"),
    ]
    assert batch_calls == [
        ("cred validate batch", ["cred validate (ssh)"]),
        ("finalization pregraph batch", ["final HIBP domain", "vuln passive fingerprint"]),
    ]
    assert cloud_callbacks == ["final cloud key validation", "final finding synthesis"]
    expected_summary = (
        "supabase=0 firebase=0 aws_s3=1 gcs=0 azure_blob=0 amplify=0 "
        "gcp_appspot=0 gcp_cf=0 cf_pages=0 cf_workers=0 cf_r2=0 "
        "github_pages=0 gitlab_pages=0 vercel=0 netlify=0 scans_run=1"
    )
    assert audit_events == [
        (
            (
                tmp_path / "engagement.db",
                1001,
                "orchestrator",
                "kill_chain",
                "cloud_scan_summary",
            ),
            {"target": "acme.example", "result": expected_summary},
        )
    ]
    assert log_events[0] == (
        "cred validate",
        "[yellow]--credential-validate set - attempting live logins[/yellow]",
    )
    assert any(label == "report generate" for label, _metrics in finalization_progress)


def test_run_provider_key_validation_sweep_updates_pending_findings(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            CREATE TABLE key_scanner_findings (
                id INTEGER PRIMARY KEY,
                engagement_id INTEGER,
                raw_key TEXT,
                validation_state TEXT,
                validation_detail TEXT
            )
            """
        )
        con.executemany(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, raw_key, validation_state, validation_detail)
            VALUES (?, 1001, ?, ?, NULL)
            """,
            [
                (1, "verified-key", None),
                (2, "unverified-key", ""),
                (3, "unknown-key", None),
                (4, "already-done", "EXISTING"),
            ],
        )
        con.commit()
    finally:
        con.close()

    log_events: list[tuple[str, str]] = []

    def _try_validate(raw_key: str) -> object | None:
        if raw_key == "verified-key":
            return SimpleNamespace(provider="stripe", verified=True, reason="valid")
        if raw_key == "unverified-key":
            return SimpleNamespace(provider="slack", verified=False, reason="bad token")
        return None

    result = run_provider_key_validation_sweep(
        db_path=db_path,
        engagement_id=1001,
        connect=sqlite3.connect,
        try_validate=_try_validate,
        log_callback=lambda step, message: log_events.append((step, message)),
    )

    verify_con = sqlite3.connect(db_path)
    try:
        rows = {
            int(row[0]): (row[1], row[2])
            for row in verify_con.execute(
                "SELECT id, validation_state, validation_detail FROM key_scanner_findings"
            ).fetchall()
        }
    finally:
        verify_con.close()

    assert result == ProviderKeyValidationSweepResult(scanned=3, updated=2)
    assert rows[1] == ("stripe", "valid")
    assert rows[2] == ("UNVERIFIED", "bad token")
    assert rows[3] == (None, None)
    assert rows[4] == ("EXISTING", None)
    assert log_events == [
        (
            "key validation",
            "[green]2 credentials auto-validated via provider probes[/green]",
        )
    ]


def test_run_provider_key_validation_sweep_reports_skipped_errors() -> None:
    debug_calls: list[tuple[str, object]] = []

    def _connect(_db_path: str | Path) -> sqlite3.Connection:
        raise RuntimeError("database unavailable")

    result = run_provider_key_validation_sweep(
        db_path="missing.db",
        engagement_id=1001,
        connect=_connect,
        logger=SimpleNamespace(debug=lambda message, value: debug_calls.append((message, value))),
    )

    assert result.skipped is True
    assert "database unavailable" in str(result.error)
    assert debug_calls and debug_calls[0][0] == "provider-key-validator sweep skipped: %s"


def test_write_aggregate_stats_sidecar_invokes_compute_and_writer(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    sqlite3.connect(db_path).close()
    reports_dir = tmp_path / "reports"
    seen: dict[str, object] = {}

    def _compute_stats(
        con: sqlite3.Connection,
        engagement_id: int,
        *,
        reports_dir: Path,
    ) -> dict[str, object]:
        seen["connection_open"] = con.execute("SELECT 1").fetchone()[0]
        seen["engagement_id"] = engagement_id
        seen["reports_dir"] = reports_dir
        return {"engagement_id": engagement_id}

    def _write_json_sidecar(stats: object, output_dir: Path) -> Path:
        seen["stats"] = stats
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / "engagement_1001_stats.json"
        path.write_text('{"engagement_id":1001}', encoding="utf-8")
        return path

    result = write_aggregate_stats_sidecar(
        db_path=db_path,
        engagement_id=1001,
        reports_dir=reports_dir,
        connect=sqlite3.connect,
        compute_stats=_compute_stats,
        write_json_sidecar=_write_json_sidecar,
    )

    assert result == AggregateStatsSidecarResult(
        written=True,
        path=reports_dir / "engagement_1001_stats.json",
    )
    assert seen == {
        "connection_open": 1,
        "engagement_id": 1001,
        "reports_dir": reports_dir,
        "stats": {"engagement_id": 1001},
    }


def test_preferred_report_artifact_uses_planned_and_companion_order(tmp_path: Path) -> None:
    planned = tmp_path / "engagement_1001_report.md"
    csv_path = planned.with_suffix(".csv")
    json_path = planned.with_suffix(".json")
    csv_path.write_text("record_type,engagement_id\nsummary,1001\n", encoding="utf-8")
    json_path.write_text('{"provider":"raw_export"}', encoding="utf-8")

    assert nonempty_report_artifact(csv_path) is True
    assert preferred_report_artifact(planned) == json_path

    planned.write_text("# report\n", encoding="utf-8")
    assert preferred_report_artifact(planned) == planned


def test_ensure_report_artifact_accepts_completed_existing_report(tmp_path: Path) -> None:
    planned = tmp_path / "engagement_1001_report.md"
    planned.write_text("# completed report\n", encoding="utf-8")
    audit_events: list[tuple[str, str, str]] = []
    log_events: list[tuple[str, str]] = []

    artifact, metadata = ensure_report_artifact(
        planned_report_path=planned,
        report_returncode=0,
        engagement="1001",
        log_callback=lambda step, message: log_events.append((step, message)),
        audit_callback=lambda action, target, result: audit_events.append((action, target, result)),
    )

    assert artifact == planned
    assert metadata == {
        "report_artifact_verified": True,
        "report_finalization_status": "completed",
        "report_generate_returncode": 0,
    }
    assert audit_events == []
    assert log_events == []


def test_ensure_kill_chain_report_artifact_wraps_cli_audit_context(
    tmp_path: Path,
) -> None:
    planned = tmp_path / "engagement_1001_report.md"
    audit_events: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def _synthesise(**kwargs):  # noqa: ANN003
        path = Path(str(kwargs["output_path"]))
        path.write_text("# fallback report\n", encoding="utf-8")
        return path

    artifact, metadata = ensure_kill_chain_report_artifact(
        planned_report_path=planned,
        report_returncode=1,
        engagement="1001",
        audit_callback=lambda *args, **kwargs: audit_events.append((args, kwargs)),
        db_path=tmp_path / "engagement.db",
        engagement_id=1001,
        synthesise_report=_synthesise,
    )

    assert artifact == planned
    assert metadata["report_finalization_status"] == "template_fallback"
    assert audit_events == [
        (
            (
                tmp_path / "engagement.db",
                1001,
                "orchestrator",
                "kill_chain",
                "report_template_fallback_start",
            ),
            {"target": str(planned), "result": "report generate exited 1"},
        ),
        (
            (
                tmp_path / "engagement.db",
                1001,
                "orchestrator",
                "kill_chain",
                "report_template_fallback_complete",
            ),
            {
                "target": str(planned),
                "result": "status=template_fallback reason=report generate exited 1",
            },
        ),
    ]


def test_finalize_kill_chain_closeout_runs_terminal_side_effects(
    tmp_path: Path,
) -> None:
    planned = tmp_path / "engagement_1001_report.md"
    planned.write_text("# completed report\n", encoding="utf-8")
    audit_events: list[tuple[tuple[object, ...], dict[str, object]]] = []
    log_events: list[tuple[str, str]] = []
    printed: list[object] = []
    provider_calls: list[dict[str, object]] = []
    stats_calls: list[dict[str, object]] = []

    def _provider_sweep(**kwargs):  # noqa: ANN003
        provider_calls.append(kwargs)
        return ProviderKeyValidationSweepResult(scanned=3, updated=2)

    def _stats_sidecar(**kwargs):  # noqa: ANN003
        stats_calls.append(kwargs)
        return AggregateStatsSidecarResult(written=True, path=tmp_path / "stats.json")

    result = finalize_kill_chain_closeout(
        planned_report_path=planned,
        report_returncode=0,
        engagement="1001",
        db_path=tmp_path / "engagement.db",
        engagement_id=1001,
        target="acme.example",
        elapsed_seconds=7.5,
        emails_chained=2,
        run_progress_state={"pending_work_total": 4},
        print_callback=lambda *args, **_kwargs: printed.extend(args),
        log_callback=lambda step, message: log_events.append((step, message)),
        audit_callback=lambda *args, **kwargs: audit_events.append((args, kwargs)),
        reports_dir=tmp_path / "reports",
        logger=None,
        provider_key_validation_sweep=_provider_sweep,
        aggregate_stats_sidecar=_stats_sidecar,
    )

    assert result == KillChainCloseoutResult(
        report_artifact_path=planned,
        report_finalization_metadata={
            "report_artifact_verified": True,
            "report_finalization_status": "completed",
            "report_generate_returncode": 0,
        },
        final_pending_total=4,
        final_summary=KillChainFinalSummaryResult(
            final_pending_total=4,
            graph_paths=kill_chain_graph_artifact_paths("1001"),
        ),
        provider_key_validation=ProviderKeyValidationSweepResult(scanned=3, updated=2),
        aggregate_stats_sidecar=AggregateStatsSidecarResult(
            written=True,
            path=tmp_path / "stats.json",
        ),
    )
    assert audit_events == [
        (
            (
                tmp_path / "engagement.db",
                1001,
                "orchestrator",
                "kill_chain",
                "kill_chain_complete",
            ),
            {"target": "acme.example", "result": "elapsed_s=7.5 emails_chained=2"},
        )
    ]
    assert log_events == []
    assert len(provider_calls) == 1
    assert provider_calls[0]["db_path"] == tmp_path / "engagement.db"
    assert provider_calls[0]["engagement_id"] == 1001
    assert provider_calls[0]["log_callback"] is not None
    assert provider_calls[0]["logger"] is None
    assert stats_calls == [
        {
            "db_path": tmp_path / "engagement.db",
            "engagement_id": 1001,
            "reports_dir": tmp_path / "reports",
            "logger": None,
        }
    ]
    assert any("Kill-chain stopped with pending recursive work" in str(item) for item in printed)


def test_ensure_report_artifact_forces_template_fallback_on_report_failure(
    tmp_path: Path,
) -> None:
    planned = tmp_path / "engagement_1001_report.md"
    audit_events: list[tuple[str, str, str]] = []
    log_events: list[tuple[str, str]] = []

    def _synthesise(**kwargs):  # noqa: ANN003
        path = Path(str(kwargs["output_path"]))
        path.write_text("# fallback report\n", encoding="utf-8")
        return path

    artifact, metadata = ensure_report_artifact(
        planned_report_path=planned,
        report_returncode=1,
        engagement="1001",
        log_callback=lambda step, message: log_events.append((step, message)),
        audit_callback=lambda action, target, result: audit_events.append((action, target, result)),
        synthesise_report=_synthesise,
    )

    assert artifact == planned
    assert metadata["report_artifact_verified"] is True
    assert metadata["report_finalization_status"] == "template_fallback"
    assert metadata["report_generate_returncode"] == 1
    assert metadata["report_fallback_provider"] == "template"
    assert metadata["report_fallback_reason"] == "report generate exited 1"
    assert metadata["report_fallback_path"] == str(planned)
    assert log_events == [
        (
            "report fallback",
            "[yellow]report generate exited 1; forcing deterministic template fallback[/yellow]",
        )
    ]
    assert audit_events == [
        ("report_template_fallback_start", str(planned), "report generate exited 1"),
        (
            "report_template_fallback_complete",
            str(planned),
            "status=template_fallback reason=report generate exited 1",
        ),
    ]


def test_ensure_report_artifact_reports_fallback_failures(tmp_path: Path) -> None:
    planned = tmp_path / "engagement_1001_report.md"
    audit_events: list[tuple[str, str, str]] = []

    def _boom(**_kwargs):  # noqa: ANN003
        raise RuntimeError("simulated template fallback failure")

    artifact, metadata = ensure_report_artifact(
        planned_report_path=planned,
        report_returncode=1,
        engagement="1001",
        audit_callback=lambda action, target, result: audit_events.append((action, target, result)),
        synthesise_report=_boom,
    )

    assert artifact is None
    assert metadata["report_artifact_verified"] is False
    assert metadata["report_finalization_status"] == "failed"
    assert metadata["report_generate_returncode"] == 1
    assert metadata["report_fallback_reason"] == "report generate exited 1"
    assert "simulated template fallback failure" in str(metadata["report_fallback_error"])
    assert audit_events == [
        ("report_template_fallback_start", str(planned), "report generate exited 1"),
        (
            "report_template_fallback_failed",
            str(planned),
            "RuntimeError: simulated template fallback failure",
        ),
    ]


def test_ensure_report_artifact_accepts_raw_export_companion_after_fallback(
    tmp_path: Path,
) -> None:
    planned = tmp_path / "engagement_1001_report.md"
    csv_path = planned.with_suffix(".csv")
    audit_events: list[tuple[str, str, str]] = []

    def _raw_export(**_kwargs):  # noqa: ANN003
        csv_path.write_text("record_type,engagement_id\nsummary,1001\n", encoding="utf-8")
        return csv_path

    artifact, metadata = ensure_report_artifact(
        planned_report_path=planned,
        report_returncode=0,
        engagement="1001",
        audit_callback=lambda action, target, result: audit_events.append((action, target, result)),
        synthesise_report=_raw_export,
    )

    assert artifact == csv_path
    assert metadata["report_artifact_verified"] is True
    assert metadata["report_finalization_status"] == "raw_export_fallback"
    assert metadata["report_fallback_reason"] == (
        "report generate completed without a report artifact"
    )
    assert audit_events[-1] == (
        "report_template_fallback_complete",
        str(csv_path),
        "status=raw_export_fallback reason=report generate completed without a report artifact",
    )


def test_ensure_report_artifact_reports_empty_template_fallback(tmp_path: Path) -> None:
    planned = tmp_path / "engagement_1001_report.md"

    def _empty(**kwargs):  # noqa: ANN003
        path = Path(str(kwargs["output_path"]))
        path.write_text("", encoding="utf-8")
        return path

    artifact, metadata = ensure_report_artifact(
        planned_report_path=planned,
        report_returncode=1,
        engagement="1001",
        synthesise_report=_empty,
    )

    assert artifact is None
    assert metadata["report_artifact_verified"] is False
    assert metadata["report_finalization_status"] == "failed"
    assert metadata["report_fallback_error"] == (
        "template fallback returned without a report artifact"
    )
