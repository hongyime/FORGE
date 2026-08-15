"""Report artifact finalization helpers for kill-chain orchestration."""
from __future__ import annotations

import os
import sqlite3
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

AuditCallback = Callable[[str, str, str], None]
CloudScanSummaryAuditCallback = Callable[..., object]
DryRunFinalizationAuditCallback = Callable[..., object]
KillChainCompleteAuditCallback = Callable[..., object]
KillChainReportArtifactAuditCallback = Callable[..., object]
LogCallback = Callable[[str, str], None]
SynthesiseReport = Callable[..., str | Path]
FinalizationSpec = tuple[list[str], str]
ScopeManifestAppender = Callable[[list[str], str | None], list[str]]
ConnectionFactory = Callable[[str | Path], sqlite3.Connection]
ProviderKeyValidator = Callable[[str], Any]
StatsComputer = Callable[..., Any]
StatsSidecarWriter = Callable[[Any, Path], Path]
ReadOnlyConnectionFactory = Callable[..., sqlite3.Connection]
ProviderKeyValidationSweepRunner = Callable[..., "ProviderKeyValidationSweepResult"]
AggregateStatsSidecarRunner = Callable[..., "AggregateStatsSidecarResult"]
FinalizationDispatchSpecFactory = Callable[[list[str], str], object]


@dataclass(frozen=True)
class KillChainFinalizationPlan:
    report_args: list[str]
    pre_validation_specs: list[FinalizationSpec] = field(default_factory=list)
    network_capable_post_validation_specs: list[FinalizationSpec] = field(default_factory=list)
    parallel_post_validation_specs: list[FinalizationSpec] = field(default_factory=list)
    sequential_post_validation_specs: list[FinalizationSpec] = field(default_factory=list)
    post_validation_specs: list[FinalizationSpec] = field(default_factory=list)
    finalization_specs: list[FinalizationSpec] = field(default_factory=list)
    dry_run_skipped_labels: str = ""


@dataclass(frozen=True)
class ProviderKeyValidationSweepResult:
    scanned: int = 0
    updated: int = 0
    skipped: bool = False
    error: str | None = None


@dataclass(frozen=True)
class AggregateStatsSidecarResult:
    written: bool = False
    path: Path | None = None
    skipped: bool = False
    error: str | None = None


@dataclass
class FinalizationExecutionState:
    total: int
    started_at: float
    completed: int = 0
    failed: int = 0

    def record_results(self, results: Sequence[object]) -> None:
        self.completed += len(results)
        self.failed += sum(1 for result in results if int(result) != 0)


@dataclass(frozen=True)
class KillChainGraphArtifactPaths:
    mtgx: str
    graphml: str
    nodes_csv: str
    edges_csv: str


@dataclass(frozen=True)
class KillChainFinalSummaryResult:
    final_pending_total: int
    graph_paths: KillChainGraphArtifactPaths


@dataclass(frozen=True)
class KillChainCloseoutResult:
    report_artifact_path: Path | None
    report_finalization_metadata: dict[str, object]
    final_pending_total: int
    final_summary: KillChainFinalSummaryResult
    provider_key_validation: ProviderKeyValidationSweepResult
    aggregate_stats_sidecar: AggregateStatsSidecarResult


@dataclass(frozen=True)
class KillChainFinalizationExecutionResult:
    state: FinalizationExecutionState
    credential_results: list[int]
    pregraph_results: list[int]
    sequential_results: list[int]
    report_returncode: int | None


@dataclass(frozen=True)
class KillChainFinalizationPreparationResult:
    data_driven_offensive_specs: list[FinalizationSpec]
    finalization_plan: KillChainFinalizationPlan


KILL_CHAIN_CLOUD_SCAN_SUMMARY_FIELDS: tuple[tuple[str, str], ...] = (
    ("supabase", "supabase"),
    ("firebase", "firebase"),
    ("aws_s3", "aws_s3"),
    ("gcs", "gcs"),
    ("azure_blob", "azure_blob"),
    ("amplify", "amplify"),
    ("gcp_appspot", "gcp_appspot"),
    ("gcp_cloudfunctions", "gcp_cf"),
    ("cloudflare_pages", "cf_pages"),
    ("cloudflare_worker", "cf_workers"),
    ("cloudflare_r2", "cf_r2"),
    ("github_pages", "github_pages"),
    ("gitlab_pages", "gitlab_pages"),
    ("vercel", "vercel"),
    ("netlify", "netlify"),
)


def kill_chain_cloud_scan_summary_result(
    cloud_refs: Mapping[str, Collection[object]],
    processed_refs: Collection[object],
) -> str:
    parts = [
        f"{label}={len(cloud_refs.get(key, ()))}"
        for key, label in KILL_CHAIN_CLOUD_SCAN_SUMMARY_FIELDS
    ]
    parts.append(f"scans_run={len(processed_refs)}")
    return " ".join(parts)


def kill_chain_finalization_dispatch_spec_factory(
    dispatch_spec_type: Callable[..., object],
) -> FinalizationDispatchSpecFactory:
    def _make_dispatch_spec(cmd_argv: list[str], label: str) -> object:
        return dispatch_spec_type(cmd_argv=cmd_argv, label=label)

    return _make_dispatch_spec


def emit_kill_chain_cloud_scan_summary(
    *,
    skip_cloud: bool,
    cloud_refs: Mapping[str, Collection[object]],
    processed_refs: Collection[object],
    run_pending_cloud_key_validation: Callable[[str], object],
    run_finding_synthesis: Callable[[str], object],
    audit_callback: CloudScanSummaryAuditCallback,
    db_path: str | Path,
    engagement_id: int,
    target: str,
) -> str | None:
    if skip_cloud:
        return None

    run_pending_cloud_key_validation("final cloud key validation")
    run_finding_synthesis("final finding synthesis")
    result = kill_chain_cloud_scan_summary_result(cloud_refs, processed_refs)
    audit_callback(
        db_path,
        engagement_id,
        "orchestrator",
        "kill_chain",
        "cloud_scan_summary",
        target=target,
        result=result,
    )
    return result


def emit_kill_chain_dry_run_finalization_skip(
    *,
    dry_run_all: bool,
    skipped_labels: str,
    log_callback: LogCallback,
    audit_callback: DryRunFinalizationAuditCallback,
    db_path: str | Path,
    engagement_id: int,
    target: str,
) -> str | None:
    if not dry_run_all:
        return None

    log_callback(
        "finalization dry-run",
        f"[dim]skipped network-capable finalizers: {skipped_labels}[/dim]",
    )
    audit_callback(
        db_path,
        engagement_id,
        "orchestrator",
        "kill_chain",
        "dry_run_finalization_skipped",
        target=target,
        result=f"labels={skipped_labels}",
    )
    return skipped_labels


def kill_chain_complete_audit_result(
    *,
    elapsed_seconds: float,
    emails_chained: Sequence[object] | int | None,
) -> str:
    if isinstance(emails_chained, int):
        email_count = emails_chained
    elif emails_chained:
        email_count = len(emails_chained)
    else:
        email_count = 0
    return f"elapsed_s={elapsed_seconds:.1f} emails_chained={email_count}"


def emit_kill_chain_complete_audit(
    *,
    audit_callback: KillChainCompleteAuditCallback,
    db_path: str | Path,
    engagement_id: int,
    target: str,
    elapsed_seconds: float,
    emails_chained: Sequence[object] | int | None,
) -> str:
    result = kill_chain_complete_audit_result(
        elapsed_seconds=elapsed_seconds,
        emails_chained=emails_chained,
    )
    audit_callback(
        db_path,
        engagement_id,
        "orchestrator",
        "kill_chain",
        "kill_chain_complete",
        target=target,
        result=result,
    )
    return result


def kill_chain_completion_report_kwargs(
    *,
    report_artifact_path: str | Path | None,
    planned_report_path: str | Path,
    report_provider: str | None,
    report_max_loops: int | None,
    finalization_failed: int,
    report_finalization_metadata: Mapping[str, object],
) -> dict[str, object]:
    return {
        "report_path": str(report_artifact_path or planned_report_path),
        "report_ready": report_artifact_path is not None,
        "report_provider": report_provider,
        "report_max_loops": report_max_loops,
        "finalization_failed": finalization_failed,
        "report_finalization_metadata": dict(report_finalization_metadata),
    }


def kill_chain_completion_report_kwargs_from_closeout(
    *,
    closeout: KillChainCloseoutResult,
    planned_report_path: str | Path,
    report_provider: str | None,
    report_max_loops: int | None,
    finalization_failed: int,
) -> dict[str, object]:
    return kill_chain_completion_report_kwargs(
        report_artifact_path=closeout.report_artifact_path,
        planned_report_path=planned_report_path,
        report_provider=report_provider,
        report_max_loops=report_max_loops,
        finalization_failed=finalization_failed,
        report_finalization_metadata=closeout.report_finalization_metadata,
    )


def nonempty_report_artifact(path: Path) -> bool:
    try:
        return path.is_file() and path.stat().st_size > 0
    except OSError:
        return False


def preferred_report_artifact(planned_report_path: str | Path) -> Path | None:
    planned = Path(planned_report_path)
    candidates = (
        planned,
        planned.with_suffix(".json"),
        planned.with_suffix(".csv"),
        planned.with_suffix(".pdf"),
    )
    for candidate in candidates:
        if nonempty_report_artifact(candidate):
            return candidate
    return None


def kill_chain_finalization_report_path_now(
    *,
    engagement: str | int,
    clock: Callable[[], datetime] | None = None,
) -> str:
    now = datetime.now(tz=timezone.utc) if clock is None else clock()
    timestamp = now.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%S")
    return kill_chain_finalization_report_path(
        engagement=engagement,
        timestamp=timestamp,
    )


def report_generate_args(
    *,
    engagement: str | int,
    output_path: str | Path,
    report_provider: str | None = None,
    report_max_loops: int | None = None,
) -> list[str]:
    args = [
        "report",
        "generate",
        "--engagement",
        str(engagement),
        "--yes",
        "--output",
        str(output_path),
    ]
    if report_provider:
        args += ["--provider", str(report_provider)]
    if report_max_loops is not None:
        args += ["--max-loops", str(int(report_max_loops))]
    return args


def kill_chain_finalization_report_path(
    *,
    engagement: str | int,
    timestamp: str,
) -> str:
    return f"reports/engagement_{engagement}_kill_chain_{timestamp}.md"


def kill_chain_graph_artifact_paths(engagement: str | int) -> KillChainGraphArtifactPaths:
    return KillChainGraphArtifactPaths(
        mtgx=f"reports/{engagement}_attack_graph.mtgx",
        graphml=f"reports/{engagement}_attack_graph.graphml",
        nodes_csv=f"reports/{engagement}_attack_graph_nodes.csv",
        edges_csv=f"reports/{engagement}_attack_graph_edges.csv",
    )


def emit_kill_chain_final_summary(
    *,
    engagement: str | int,
    elapsed_seconds: float,
    report_artifact_path: str | Path | None,
    planned_report_path: str | Path,
    final_pending_total: int,
    print_callback: Callable[[str], object],
    path_exists: Callable[[str], bool] | None = None,
) -> KillChainGraphArtifactPaths:
    if path_exists is None:
        path_exists = lambda value: Path(value).is_file()

    if report_artifact_path is None:
        print_callback(
            f"\n[bold red]Kill-chain finalization failed[/bold red] in {elapsed_seconds:.1f}s "
            "[dim](no report artifact persisted)[/dim]"
        )
    elif final_pending_total > 0:
        print_callback(
            f"\n[bold yellow]Kill-chain stopped with pending recursive work[/bold yellow] "
            f"in {elapsed_seconds:.1f}s [dim](pending={int(final_pending_total)})[/dim]"
        )
    else:
        print_callback(f"\n[bold green]Kill-chain complete[/bold green] in {elapsed_seconds:.1f}s")

    print_callback(f"[dim]Report:[/dim] {report_artifact_path or planned_report_path}")
    print_callback(f"[dim]Evidence:[/dim] .forge_data/engagements/{engagement}.db")

    graph_paths = kill_chain_graph_artifact_paths(engagement)
    if path_exists(graph_paths.graphml) or path_exists(graph_paths.mtgx):
        if path_exists(graph_paths.mtgx):
            print_callback(f"[dim]Maltego workspace:[/dim] {graph_paths.mtgx}")
        if path_exists(graph_paths.graphml):
            print_callback(f"[dim]Maltego graphml:[/dim] {graph_paths.graphml}")
        print_callback(
            f"[dim]Maltego CSVs:[/dim] {graph_paths.nodes_csv}  |  {graph_paths.edges_csv}"
        )
        print_callback(
            "[dim]  -> open the .mtgx in Maltego Graph (Desktop), or import the "
            ".graphml in Community Edition if you need the lightweight path.[/dim]"
        )
    return graph_paths


def emit_kill_chain_final_summary_from_progress(
    *,
    engagement: str | int,
    elapsed_seconds: float,
    report_artifact_path: str | Path | None,
    planned_report_path: str | Path,
    run_progress_state: Mapping[str, object],
    print_callback: Callable[[str], object],
    path_exists: Callable[[str], bool] | None = None,
) -> KillChainFinalSummaryResult:
    final_pending_total = int(run_progress_state.get("pending_work_total") or 0)
    graph_paths = emit_kill_chain_final_summary(
        engagement=engagement,
        elapsed_seconds=elapsed_seconds,
        report_artifact_path=report_artifact_path,
        planned_report_path=planned_report_path,
        final_pending_total=final_pending_total,
        print_callback=print_callback,
        path_exists=path_exists,
    )
    return KillChainFinalSummaryResult(
        final_pending_total=final_pending_total,
        graph_paths=graph_paths,
    )


def _scoped_args(
    args: list[str],
    *,
    scope_manifest: str | None,
    append_scope_manifest_arg: ScopeManifestAppender,
) -> list[str]:
    return list(append_scope_manifest_arg(list(args), scope_manifest))


def build_kill_chain_finalization_plan(
    *,
    engagement: str | int,
    domain: str,
    planned_report_path: str | Path,
    dry_run_all: bool,
    credential_validate: bool,
    attack_mode: bool,
    report_provider: str | None,
    report_max_loops: int | None,
    roe_id: str,
    scope_manifest: str | None,
    append_scope_manifest_arg: ScopeManifestAppender,
    env: Mapping[str, str] | None = None,
    data_driven_offensive_specs: Sequence[FinalizationSpec] = (),
) -> KillChainFinalizationPlan:
    engagement_value = str(engagement)
    env_values = os.environ if env is None else env
    report_args = report_generate_args(
        engagement=engagement_value,
        output_path=planned_report_path,
        report_provider=report_provider,
        report_max_loops=report_max_loops,
    )
    hibp_args = ["osint", "hibp", "--engagement", engagement_value]
    if dry_run_all:
        hibp_args.append("--dry-run")
    pre_validation_specs: list[FinalizationSpec] = [
        (hibp_args, "final HIBP domain"),
    ]
    if credential_validate:
        for svc in ("ssh", "smb", "rdp", "ftp", "http"):
            pre_validation_specs.append(
                (
                    [
                        "osint",
                        "validate",
                        "--engagement",
                        engagement_value,
                        "--service",
                        svc,
                        "--host",
                        str(domain),
                    ],
                    f"cred validate ({svc})",
                )
            )

    offensive_specs: list[FinalizationSpec] = []
    if attack_mode and not dry_run_all:
        offensive_specs.append(
            (
                _scoped_args(
                    [
                        "evasion",
                        "generate",
                        "--engagement",
                        engagement_value,
                        "--technique",
                        str(env_values.get("FORGE_KILLCHAIN_PHASE3_TECHNIQUE", "std")),
                        "--os",
                        str(env_values.get("FORGE_KILLCHAIN_PHASE3_OS", "windows")),
                    ],
                    scope_manifest=scope_manifest,
                    append_scope_manifest_arg=append_scope_manifest_arg,
                ),
                "phase3 evasion generate",
            )
        )
        offensive_specs.append(
            (
                _scoped_args(
                    [
                        "post",
                        "shell",
                        "--engagement",
                        engagement_value,
                        "--lhost",
                        str(env_values.get("FORGE_LHOST", "127.0.0.1")),
                        "--lport",
                        str(env_values.get("FORGE_LPORT", "443")),
                        "--roe-id",
                        str(roe_id),
                    ],
                    scope_manifest=scope_manifest,
                    append_scope_manifest_arg=append_scope_manifest_arg,
                ),
                "phase5 post-shell payload",
            )
        )

    network_capable_post_validation_specs: list[FinalizationSpec] = [
        (["vuln", "passive", "--engagement", engagement_value], "vuln passive fingerprint"),
        (["exploit", "correlate", "--engagement", engagement_value], "exploit correlate"),
        *offensive_specs,
        *[(list(cmd), str(label)) for cmd, label in data_driven_offensive_specs],
    ]
    sequential_post_validation_specs: list[FinalizationSpec] = [
        (
            [
                "graph",
                "build",
                "--engagement",
                engagement_value,
                "--format",
                "all",
                "--output-dir",
                "reports",
                "--snapshot",
            ],
            "attack-path graph family",
        ),
        (list(report_args), "report generate"),
    ]
    parallel_post_validation_specs = (
        [] if dry_run_all else list(network_capable_post_validation_specs)
    )
    post_validation_specs = [
        *parallel_post_validation_specs,
        *sequential_post_validation_specs,
    ]
    dry_run_skipped_labels = ", ".join(
        label for _, label in network_capable_post_validation_specs
    )
    return KillChainFinalizationPlan(
        report_args=report_args,
        pre_validation_specs=pre_validation_specs,
        network_capable_post_validation_specs=network_capable_post_validation_specs,
        parallel_post_validation_specs=parallel_post_validation_specs,
        sequential_post_validation_specs=sequential_post_validation_specs,
        post_validation_specs=post_validation_specs,
        finalization_specs=[*pre_validation_specs, *post_validation_specs],
        dry_run_skipped_labels=dry_run_skipped_labels,
    )


def build_data_driven_offensive_finalization_specs(
    *,
    db_path: str | Path,
    engagement_id: int,
    engagement: str | int,
    attack_mode: bool,
    dry_run_all: bool,
    roe_id: str,
    scope_manifest: str | None,
    append_scope_manifest_arg: ScopeManifestAppender,
    connect: ReadOnlyConnectionFactory | None = None,
) -> list[FinalizationSpec]:
    """Build active-validation finalizers from current engagement evidence."""
    specs: list[FinalizationSpec] = []
    if not attack_mode or dry_run_all:
        return specs
    if connect is None:
        from forge.db.direct_connect import direct_connect as _connect  # noqa: PLC0415

        connect = _connect
    try:
        db_uri = f"file:{Path(db_path).as_posix()}?mode=ro"
        con = connect(db_uri, uri=True)
    except Exception:  # noqa: BLE001
        return specs
    engagement_value = str(engagement)
    try:
        try:
            web_row = con.execute(
                """
                SELECT h.ip, h.hostname, s.port
                FROM services s
                JOIN hosts h ON s.host_id = h.id
                WHERE h.engagement_id=?
                  AND (
                      s.service_name IN ('http', 'https')
                      OR s.port IN (80, 443, 8080, 8443)
                  )
                ORDER BY s.port DESC
                LIMIT 1
                """,
                (int(engagement_id),),
            ).fetchone()
        except sqlite3.OperationalError:
            web_row = None
        web_target: str | None = None
        if web_row:
            host_value = str(web_row[1] or web_row[0] or "").strip()
            port_value = int(web_row[2] or 0)
            if host_value:
                scheme = "https" if port_value in (443, 8443) else "http"
                if port_value in (0, 80, 443):
                    web_target = f"{scheme}://{host_value}/"
                else:
                    web_target = f"{scheme}://{host_value}:{port_value}/"
        if web_target:
            specs.extend(
                [
                    (
                        _scoped_args(
                            [
                                "vuln",
                                "idor",
                                "--engagement",
                                engagement_value,
                                "--target",
                                web_target,
                                "--depth",
                                "2",
                                "--roe-id",
                                str(roe_id),
                            ],
                            scope_manifest=scope_manifest,
                            append_scope_manifest_arg=append_scope_manifest_arg,
                        ),
                        f"phase4 vuln idor ({web_target})",
                    ),
                    (
                        _scoped_args(
                            [
                                "auth",
                                "brute",
                                "--engagement",
                                engagement_value,
                                "--target",
                                web_target,
                                "--max-attempts",
                                "10",
                                "--roe-id",
                                str(roe_id),
                            ],
                            scope_manifest=scope_manifest,
                            append_scope_manifest_arg=append_scope_manifest_arg,
                        ),
                        f"phase4 auth brute ({web_target})",
                    ),
                    (
                        _scoped_args(
                            [
                                "auth",
                                "bypass",
                                "--engagement",
                                engagement_value,
                                "--target",
                                web_target,
                                "--roe-id",
                                str(roe_id),
                            ],
                            scope_manifest=scope_manifest,
                            append_scope_manifest_arg=append_scope_manifest_arg,
                        ),
                        f"phase4 auth bypass ({web_target})",
                    ),
                ]
            )
        try:
            lateral_row = con.execute(
                """
                SELECT h.ip, h.hostname
                FROM credentials c
                JOIN hosts h ON h.ip = c.validated_host
                WHERE c.engagement_id=? AND c.validated=1 AND c.validated_host != ''
                ORDER BY c.validated_at DESC
                LIMIT 1
                """,
                (int(engagement_id),),
            ).fetchone()
        except sqlite3.OperationalError:
            lateral_row = None
        if lateral_row:
            lateral_target = str(lateral_row[1] or lateral_row[0] or "").strip()
            if lateral_target:
                specs.append(
                    (
                        _scoped_args(
                            [
                                "post",
                                "lateral",
                                "--engagement",
                                engagement_value,
                                "--target",
                                lateral_target,
                                "--technique",
                                "smb_exec",
                                "--roe-id",
                                str(roe_id),
                            ],
                            scope_manifest=scope_manifest,
                            append_scope_manifest_arg=append_scope_manifest_arg,
                        ),
                        f"phase5 post lateral ({lateral_target})",
                    )
                )
    finally:
        con.close()
    return specs


def prepare_kill_chain_finalization(
    *,
    db_path: str | Path,
    engagement_id: int,
    engagement: str | int,
    domain: str,
    planned_report_path: str | Path,
    dry_run_all: bool,
    credential_validate: bool,
    attack_mode: bool,
    report_provider: str | None,
    report_max_loops: int | None,
    roe_id: str,
    scope_manifest: str | None,
    append_scope_manifest_arg: ScopeManifestAppender,
    log_callback: LogCallback,
    audit_callback: DryRunFinalizationAuditCallback,
    env: Mapping[str, str] | None = None,
    connect: ReadOnlyConnectionFactory | None = None,
) -> KillChainFinalizationPreparationResult:
    data_driven_offensive_specs = build_data_driven_offensive_finalization_specs(
        db_path=db_path,
        engagement_id=engagement_id,
        engagement=engagement,
        attack_mode=attack_mode,
        dry_run_all=dry_run_all,
        roe_id=roe_id,
        scope_manifest=scope_manifest,
        append_scope_manifest_arg=append_scope_manifest_arg,
        connect=connect,
    )
    finalization_plan = build_kill_chain_finalization_plan(
        engagement=engagement,
        domain=domain,
        planned_report_path=planned_report_path,
        dry_run_all=dry_run_all,
        credential_validate=credential_validate,
        attack_mode=attack_mode,
        report_provider=report_provider,
        report_max_loops=report_max_loops,
        roe_id=roe_id,
        scope_manifest=scope_manifest,
        append_scope_manifest_arg=append_scope_manifest_arg,
        env=env,
        data_driven_offensive_specs=data_driven_offensive_specs,
    )
    emit_kill_chain_dry_run_finalization_skip(
        dry_run_all=dry_run_all,
        skipped_labels=finalization_plan.dry_run_skipped_labels,
        log_callback=log_callback,
        audit_callback=audit_callback,
        db_path=db_path,
        engagement_id=engagement_id,
        target=domain,
    )
    return KillChainFinalizationPreparationResult(
        data_driven_offensive_specs=data_driven_offensive_specs,
        finalization_plan=finalization_plan,
    )


def _record_finalization_progress_snapshot(
    state: FinalizationExecutionState,
    label: str,
    *,
    record_progress: Callable[[str, dict[str, object]], None],
    batch_progress_snapshot: Callable[..., dict[str, object]],
    workers: int = 1,
    completed: int | None = None,
    failed: int | None = None,
) -> None:
    record_progress(
        label,
        batch_progress_snapshot(
            total=state.total,
            workers=max(1, int(workers or 1)),
            completed=state.completed if completed is None else completed,
            failed=state.failed if failed is None else failed,
            started_at=state.started_at,
        ),
    )


def run_kill_chain_finalization_spec(
    spec: FinalizationSpec,
    *,
    state: FinalizationExecutionState,
    run_module: Callable[[list[str], str], object],
    record_progress: Callable[[str, dict[str, object]], None],
    batch_progress_snapshot: Callable[..., dict[str, object]],
) -> int:
    cmd_argv, label = spec
    label_value = str(label)
    _record_finalization_progress_snapshot(
        state,
        label_value,
        record_progress=record_progress,
        batch_progress_snapshot=batch_progress_snapshot,
    )
    result = int(run_module(list(cmd_argv), label_value))
    state.record_results([result])
    _record_finalization_progress_snapshot(
        state,
        label_value,
        record_progress=record_progress,
        batch_progress_snapshot=batch_progress_snapshot,
    )
    return result


def run_kill_chain_parallel_finalization_stage(
    specs: Sequence[FinalizationSpec],
    *,
    state: FinalizationExecutionState,
    parallel_workers: int,
    spec_prep_label: str,
    dispatch_label: str,
    batch_label: str,
    log_callback: LogCallback,
    run_inprocess_batch: Callable[..., Sequence[Any]],
    run_module_batch: Callable[..., Sequence[object]],
    run_module: Callable[[Any], object],
    make_dispatch_spec: Callable[[list[str], str], Any],
    record_batch_progress: Callable[[str, dict[str, object]], None],
    record_finalization_progress: Callable[[str, dict[str, object]], None],
    batch_progress_snapshot: Callable[..., dict[str, object]],
) -> list[int]:
    inputs = list(specs)
    if not inputs:
        return []
    worker_count = max(1, int(parallel_workers or 1))
    if len(inputs) > 1 and worker_count > 1:
        log_callback(
            spec_prep_label,
            f"[dim]parallel parse x{min(worker_count, len(inputs))}[/dim]",
        )
    dispatch_specs = list(
        run_inprocess_batch(
            inputs,
            lambda item: make_dispatch_spec(list(item[0]), str(item[1])),
            max_workers=worker_count,
            progress_label=spec_prep_label,
            progress_callback=record_batch_progress,
        )
    )
    if len(dispatch_specs) > 1 and worker_count > 1:
        log_callback(
            dispatch_label,
            f"[dim]parallel dispatch x{min(worker_count, len(dispatch_specs))}[/dim]",
        )
    completed_offset = state.completed
    failed_offset = state.failed

    def _record_batch_progress(label: str, metrics: dict[str, object]) -> None:
        _record_finalization_progress_snapshot(
            state,
            label,
            record_progress=record_finalization_progress,
            batch_progress_snapshot=batch_progress_snapshot,
            workers=int(metrics.get("workers") or 1),
            completed=completed_offset + int(metrics.get("completed") or 0),
            failed=failed_offset + int(metrics.get("failed") or 0),
        )

    results = list(
        run_module_batch(
            dispatch_specs,
            run_module,
            max_workers=worker_count,
            progress_label=batch_label,
            progress_callback=_record_batch_progress,
        )
    )
    state.record_results(results)
    return [int(result) for result in results]


def run_kill_chain_sequential_finalization_stage(
    specs: Sequence[FinalizationSpec],
    *,
    state: FinalizationExecutionState,
    log_callback: LogCallback,
    run_inprocess_batch: Callable[..., Sequence[Any]],
    run_module: Callable[[list[str], str], object],
    record_finalization_progress: Callable[[str, dict[str, object]], None],
    batch_progress_snapshot: Callable[..., dict[str, object]],
    progress_label: str = "finalization postgraph",
) -> list[int]:
    inputs = list(specs)
    if not inputs:
        return []
    if len(inputs) > 1:
        log_callback(
            progress_label,
            "[dim]sequential dispatch x1[/dim]  [dim]graph/report order preserved[/dim]",
        )
    results = list(
        run_inprocess_batch(
            inputs,
            lambda item: run_kill_chain_finalization_spec(
                (list(item[0]), str(item[1])),
                state=state,
                run_module=run_module,
                record_progress=record_finalization_progress,
                batch_progress_snapshot=batch_progress_snapshot,
            ),
            max_workers=1,
            progress_label=progress_label,
        )
    )
    return [int(result) for result in results]


def finalization_label_returncode(
    specs: Sequence[FinalizationSpec],
    results: Sequence[object],
    *,
    label: str,
) -> int | None:
    for (_cmd_argv, spec_label), result in zip(specs, results):
        if spec_label == label:
            return int(result)
    return None


def run_kill_chain_finalization_execution(
    *,
    finalization_plan: KillChainFinalizationPlan,
    credential_validate: bool,
    skip_cloud: bool,
    cloud_refs: Mapping[str, Collection[object]],
    processed_refs: Collection[object],
    run_pending_cloud_key_validation: Callable[[str], object],
    run_finding_synthesis: Callable[[str], object],
    audit_callback: CloudScanSummaryAuditCallback,
    db_path: str | Path,
    engagement_id: int,
    target: str,
    parallel_workers: int,
    log_callback: LogCallback,
    run_inprocess_batch: Callable[..., Sequence[Any]],
    run_module_batch: Callable[..., Sequence[object]],
    run_module: Callable[..., object],
    dispatch_spec_type: Callable[..., object],
    record_batch_progress: Callable[[str, dict[str, object]], None],
    record_finalization_progress: Callable[[str, dict[str, object]], None],
    batch_progress_snapshot: Callable[..., dict[str, object]],
    perf_counter: Callable[[], float],
) -> KillChainFinalizationExecutionResult:
    pre_validation_specs = finalization_plan.pre_validation_specs
    parallel_post_validation_specs = finalization_plan.parallel_post_validation_specs
    sequential_post_validation_specs = finalization_plan.sequential_post_validation_specs
    finalization_state = FinalizationExecutionState(
        total=len(finalization_plan.finalization_specs),
        started_at=perf_counter(),
    )
    make_dispatch_spec = kill_chain_finalization_dispatch_spec_factory(dispatch_spec_type)

    if credential_validate:
        log_callback(
            "cred validate",
            "[yellow]--credential-validate set - attempting live logins[/yellow]",
        )
        credential_results = run_kill_chain_parallel_finalization_stage(
            pre_validation_specs[1:],
            state=finalization_state,
            parallel_workers=parallel_workers,
            spec_prep_label="cred validate spec prep",
            dispatch_label="cred validate",
            batch_label="cred validate batch",
            log_callback=log_callback,
            run_inprocess_batch=run_inprocess_batch,
            run_module_batch=run_module_batch,
            run_module=run_module,
            make_dispatch_spec=make_dispatch_spec,
            record_batch_progress=record_batch_progress,
            record_finalization_progress=record_finalization_progress,
            batch_progress_snapshot=batch_progress_snapshot,
        )
    else:
        log_callback("cred validate", "[dim]skipped (pass --credential-validate to enable)[/dim]")
        credential_results = []

    emit_kill_chain_cloud_scan_summary(
        skip_cloud=skip_cloud,
        cloud_refs=cloud_refs,
        processed_refs=processed_refs,
        run_pending_cloud_key_validation=run_pending_cloud_key_validation,
        run_finding_synthesis=run_finding_synthesis,
        audit_callback=audit_callback,
        db_path=db_path,
        engagement_id=engagement_id,
        target=target,
    )

    pregraph_results = run_kill_chain_parallel_finalization_stage(
        [
            pre_validation_specs[0],
            *parallel_post_validation_specs,
        ],
        state=finalization_state,
        parallel_workers=parallel_workers,
        spec_prep_label="finalization pregraph spec prep",
        dispatch_label="finalization pregraph",
        batch_label="finalization pregraph batch",
        log_callback=log_callback,
        run_inprocess_batch=run_inprocess_batch,
        run_module_batch=run_module_batch,
        run_module=run_module,
        make_dispatch_spec=make_dispatch_spec,
        record_batch_progress=record_batch_progress,
        record_finalization_progress=record_finalization_progress,
        batch_progress_snapshot=batch_progress_snapshot,
    )

    sequential_results = run_kill_chain_sequential_finalization_stage(
        sequential_post_validation_specs,
        state=finalization_state,
        log_callback=log_callback,
        run_inprocess_batch=run_inprocess_batch,
        run_module=run_module,
        record_finalization_progress=record_finalization_progress,
        batch_progress_snapshot=batch_progress_snapshot,
    )
    report_returncode = finalization_label_returncode(
        sequential_post_validation_specs,
        sequential_results,
        label="report generate",
    )
    return KillChainFinalizationExecutionResult(
        state=finalization_state,
        credential_results=credential_results,
        pregraph_results=pregraph_results,
        sequential_results=sequential_results,
        report_returncode=report_returncode,
    )


def run_provider_key_validation_sweep(
    *,
    db_path: str | Path,
    engagement_id: int,
    connect: ConnectionFactory | None = None,
    try_validate: ProviderKeyValidator | None = None,
    log_callback: LogCallback | None = None,
    logger: Any | None = None,
) -> ProviderKeyValidationSweepResult:
    """Best-effort provider-key validation sweep for finalization."""
    try:
        if connect is None:
            from forge.db.direct_connect import direct_connect as _connect  # noqa: PLC0415

            connect = _connect
        if try_validate is None:
            from forge.phase4.provider_key_validators import (  # noqa: PLC0415
                try_validate as _try_validate,
            )

            try_validate = _try_validate
        con = connect(db_path)
        try:
            rows = con.execute(
                "SELECT id, raw_key FROM key_scanner_findings "
                "WHERE engagement_id=? AND (validation_state IS NULL OR validation_state='')",
                (int(engagement_id),),
            ).fetchall()
            updated = 0
            for row in rows:
                validation = try_validate(str(row[1] or ""))
                if not validation:
                    continue
                con.execute(
                    "UPDATE key_scanner_findings SET validation_state=?, validation_detail=? WHERE id=?",
                    (
                        str(getattr(validation, "provider", ""))
                        if bool(getattr(validation, "verified", False))
                        else "UNVERIFIED",
                        str(getattr(validation, "reason", ""))[:500],
                        row[0],
                    ),
                )
                updated += 1
            if updated:
                con.commit()
                if log_callback is not None:
                    log_callback(
                        "key validation",
                        (
                            f"[green]{updated} credentials auto-validated via "
                            "provider probes[/green]"
                        ),
                    )
            return ProviderKeyValidationSweepResult(scanned=len(rows), updated=updated)
        finally:
            con.close()
    except Exception as exc:  # noqa: BLE001
        if logger is not None:
            logger.debug("provider-key-validator sweep skipped: %s", exc)
        return ProviderKeyValidationSweepResult(
            skipped=True,
            error=f"{type(exc).__name__}: {str(exc)[:180]}",
        )


def write_aggregate_stats_sidecar(
    *,
    db_path: str | Path,
    engagement_id: int,
    reports_dir: str | Path = "reports",
    connect: ConnectionFactory | None = None,
    compute_stats: StatsComputer | None = None,
    write_json_sidecar: StatsSidecarWriter | None = None,
    logger: Any | None = None,
) -> AggregateStatsSidecarResult:
    """Best-effort aggregate stats sidecar generation for finalization."""
    reports_path = Path(reports_dir)
    try:
        if connect is None:
            from forge.db.direct_connect import direct_connect as _connect  # noqa: PLC0415

            connect = _connect
        if compute_stats is None or write_json_sidecar is None:
            from forge.phase6.aggregate_stats import (  # noqa: PLC0415
                compute_stats as _compute_stats,
                write_json_sidecar as _write_json_sidecar,
            )

            compute_stats = compute_stats or _compute_stats
            write_json_sidecar = write_json_sidecar or _write_json_sidecar
        con = connect(db_path)
        try:
            stats = compute_stats(con, int(engagement_id), reports_dir=reports_path)
            path = write_json_sidecar(stats, reports_path)
            return AggregateStatsSidecarResult(written=True, path=Path(path))
        finally:
            con.close()
    except Exception as exc:  # noqa: BLE001
        if logger is not None:
            logger.debug("aggregate stats computation skipped: %s", exc)
        return AggregateStatsSidecarResult(
            skipped=True,
            error=f"{type(exc).__name__}: {str(exc)[:180]}",
        )


def run_kill_chain_final_sidecars(
    *,
    db_path: str | Path,
    engagement_id: int,
    reports_dir: str | Path = "reports",
    log_callback: LogCallback | None = None,
    logger: Any | None = None,
    provider_key_validation_sweep: ProviderKeyValidationSweepRunner = (
        run_provider_key_validation_sweep
    ),
    aggregate_stats_sidecar: AggregateStatsSidecarRunner = write_aggregate_stats_sidecar,
) -> tuple[ProviderKeyValidationSweepResult, AggregateStatsSidecarResult]:
    provider_result = provider_key_validation_sweep(
        db_path=db_path,
        engagement_id=engagement_id,
        log_callback=log_callback,
        logger=logger,
    )
    stats_result = aggregate_stats_sidecar(
        db_path=db_path,
        engagement_id=engagement_id,
        reports_dir=reports_dir,
        logger=logger,
    )
    return provider_result, stats_result


def _default_synthesise_report(**kwargs: Any) -> str | Path:
    from forge.phase6.report_synthesizer import synthesise  # noqa: PLC0415

    return synthesise(**kwargs)


def ensure_report_artifact(
    *,
    planned_report_path: str | Path,
    report_returncode: int | None,
    engagement: str | int,
    log_callback: LogCallback | None = None,
    audit_callback: AuditCallback | None = None,
    synthesise_report: SynthesiseReport | None = None,
) -> tuple[Path | None, dict[str, object]]:
    artifact = preferred_report_artifact(planned_report_path)
    if artifact is not None and report_returncode in (None, 0):
        return artifact, {
            "report_artifact_verified": True,
            "report_finalization_status": "completed",
            "report_generate_returncode": report_returncode,
        }

    if report_returncode not in (None, 0):
        reason = f"report generate exited {report_returncode}"
    else:
        reason = "report generate completed without a report artifact"

    planned = str(planned_report_path)
    if log_callback is not None:
        log_callback(
            "report fallback",
            f"[yellow]{reason}; forcing deterministic template fallback[/yellow]",
        )
    if audit_callback is not None:
        audit_callback("report_template_fallback_start", planned, reason)

    synthesise = synthesise_report or _default_synthesise_report
    try:
        fallback_path = synthesise(
            engagement_id=engagement,
            output_path=planned,
            assume_yes=True,
            provider="template",
            max_correction_loops=0,
        )
    except Exception as exc:  # noqa: BLE001
        fallback_error = f"{type(exc).__name__}: {str(exc)[:180]}"
        if audit_callback is not None:
            audit_callback("report_template_fallback_failed", planned, fallback_error)
        return None, {
            "report_artifact_verified": False,
            "report_finalization_status": "failed",
            "report_generate_returncode": report_returncode,
            "report_fallback_provider": "template",
            "report_fallback_reason": reason,
            "report_fallback_error": fallback_error,
        }

    artifact = preferred_report_artifact(planned_report_path)
    fallback_artifact = Path(fallback_path)
    if artifact is None and nonempty_report_artifact(fallback_artifact):
        artifact = fallback_artifact
    if artifact is None:
        error = "template fallback returned without a report artifact"
        if audit_callback is not None:
            audit_callback("report_template_fallback_failed", planned, error)
        return None, {
            "report_artifact_verified": False,
            "report_finalization_status": "failed",
            "report_generate_returncode": report_returncode,
            "report_fallback_provider": "template",
            "report_fallback_reason": reason,
            "report_fallback_error": error,
        }

    status = "template_fallback" if artifact.suffix.lower() == ".md" else "raw_export_fallback"
    if audit_callback is not None:
        audit_callback(
            "report_template_fallback_complete",
            str(artifact),
            f"status={status} reason={reason}",
        )
    return artifact, {
        "report_artifact_verified": True,
        "report_finalization_status": status,
        "report_generate_returncode": report_returncode,
        "report_fallback_provider": "template",
        "report_fallback_reason": reason,
        "report_fallback_path": str(artifact),
    }


def ensure_kill_chain_report_artifact(
    *,
    planned_report_path: str | Path,
    report_returncode: int | None,
    engagement: str | int,
    log_callback: LogCallback | None = None,
    audit_callback: KillChainReportArtifactAuditCallback,
    db_path: str | Path,
    engagement_id: int,
    synthesise_report: SynthesiseReport | None = None,
) -> tuple[Path | None, dict[str, object]]:
    def _audit_report_finalization(action: str, target: str, result: str) -> None:
        audit_callback(
            db_path,
            engagement_id,
            "orchestrator",
            "kill_chain",
            action,
            target=target,
            result=result,
        )

    return ensure_report_artifact(
        planned_report_path=planned_report_path,
        report_returncode=report_returncode,
        engagement=engagement,
        log_callback=log_callback,
        audit_callback=_audit_report_finalization,
        synthesise_report=synthesise_report,
    )


def finalize_kill_chain_closeout(
    *,
    planned_report_path: str | Path,
    report_returncode: int | None,
    engagement: str | int,
    db_path: str | Path,
    engagement_id: int,
    target: str,
    elapsed_seconds: float,
    emails_chained: int,
    run_progress_state: Mapping[str, object],
    print_callback: Callable[..., object],
    audit_callback: KillChainReportArtifactAuditCallback,
    log_callback: LogCallback | None = None,
    reports_dir: str | Path = "reports",
    logger: Any | None = None,
    synthesise_report: SynthesiseReport | None = None,
    provider_key_validation_sweep: ProviderKeyValidationSweepRunner = (
        run_provider_key_validation_sweep
    ),
    aggregate_stats_sidecar: AggregateStatsSidecarRunner = write_aggregate_stats_sidecar,
) -> KillChainCloseoutResult:
    report_artifact_path, report_finalization_metadata = ensure_kill_chain_report_artifact(
        planned_report_path=planned_report_path,
        report_returncode=report_returncode,
        engagement=engagement,
        log_callback=log_callback,
        audit_callback=audit_callback,
        db_path=db_path,
        engagement_id=engagement_id,
        synthesise_report=synthesise_report,
    )
    emit_kill_chain_complete_audit(
        audit_callback=audit_callback,
        db_path=db_path,
        engagement_id=engagement_id,
        target=target,
        elapsed_seconds=elapsed_seconds,
        emails_chained=emails_chained,
    )
    provider_result, stats_result = run_kill_chain_final_sidecars(
        db_path=db_path,
        engagement_id=engagement_id,
        reports_dir=reports_dir,
        log_callback=log_callback,
        logger=logger,
        provider_key_validation_sweep=provider_key_validation_sweep,
        aggregate_stats_sidecar=aggregate_stats_sidecar,
    )
    final_summary = emit_kill_chain_final_summary_from_progress(
        engagement=engagement,
        elapsed_seconds=elapsed_seconds,
        report_artifact_path=report_artifact_path,
        planned_report_path=planned_report_path,
        run_progress_state=run_progress_state,
        print_callback=print_callback,
    )
    return KillChainCloseoutResult(
        report_artifact_path=report_artifact_path,
        report_finalization_metadata=report_finalization_metadata,
        final_pending_total=final_summary.final_pending_total,
        final_summary=final_summary,
        provider_key_validation=provider_result,
        aggregate_stats_sidecar=stats_result,
    )


__all__ = [
    "AggregateStatsSidecarResult",
    "build_kill_chain_finalization_plan",
    "build_data_driven_offensive_finalization_specs",
    "emit_kill_chain_cloud_scan_summary",
    "emit_kill_chain_complete_audit",
    "emit_kill_chain_dry_run_finalization_skip",
    "emit_kill_chain_final_summary",
    "emit_kill_chain_final_summary_from_progress",
    "ensure_kill_chain_report_artifact",
    "ensure_report_artifact",
    "finalize_kill_chain_closeout",
    "FinalizationSpec",
    "FinalizationExecutionState",
    "finalization_label_returncode",
    "KillChainCloseoutResult",
    "KillChainFinalizationExecutionResult",
    "KillChainFinalizationPreparationResult",
    "KillChainFinalSummaryResult",
    "KillChainGraphArtifactPaths",
    "KillChainFinalizationPlan",
    "kill_chain_cloud_scan_summary_result",
    "kill_chain_completion_report_kwargs",
    "kill_chain_completion_report_kwargs_from_closeout",
    "kill_chain_complete_audit_result",
    "kill_chain_graph_artifact_paths",
    "kill_chain_finalization_report_path",
    "kill_chain_finalization_report_path_now",
    "nonempty_report_artifact",
    "preferred_report_artifact",
    "prepare_kill_chain_finalization",
    "ProviderKeyValidationSweepResult",
    "ReadOnlyConnectionFactory",
    "report_generate_args",
    "run_kill_chain_final_sidecars",
    "run_kill_chain_finalization_execution",
    "run_kill_chain_finalization_spec",
    "run_kill_chain_parallel_finalization_stage",
    "run_kill_chain_sequential_finalization_stage",
    "run_provider_key_validation_sweep",
    "write_aggregate_stats_sidecar",
]
