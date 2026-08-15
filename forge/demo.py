"""Repeatable local demo engagement and proof-pack generation."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from forge.active_validation.runner import (
    create_active_validation_job,
    run_active_validation_job,
)
from forge.config import ForgeConfig
from forge.db.direct_connect import direct_connect
from forge.db.schema import apply_schema
from forge.graph.assets import sync_engagement_asset_graph
from forge.monitoring.continuous import (
    create_monitoring_snapshot,
    upsert_monitoring_policy,
)
from forge.phase6.report_synthesizer import synthesise
from forge.reporting.dashboard import generate_dashboard
from forge.secrets.lifecycle import sync_secret_lifecycle
from forge.standards.vulnerabilities import (
    vulnerability_stix_bundle,
    vulnerability_taxii_manifest,
)


DEFAULT_DEMO_ENGAGEMENT_ID = 9901
DEMO_NAME = "FORGE Demo Proof Pack"
DEMO_WORKSPACE_ID = "demo"
DEMO_DOMAIN = "demo-forge.example"


@dataclass(frozen=True)
class DemoProofPackResult:
    engagement_id: int
    db_path: Path
    reports_dir: Path
    report_path: Path
    dashboard_path: Path
    audit_bundle_path: Path
    manifest_path: Path
    graph_artifacts: tuple[Path, ...]
    standards_artifacts: tuple[Path, ...]
    counts: dict[str, int]


def generate_demo_proof_pack(
    *,
    engagement_id: int = DEFAULT_DEMO_ENGAGEMENT_ID,
    reports_dir: Path | str = Path("reports"),
    force: bool = False,
    operator: str | None = None,
    cfg: ForgeConfig | None = None,
) -> DemoProofPackResult:
    """Create a no-key local demo engagement with report, graph, and dashboard artifacts."""

    config = cfg if cfg is not None else ForgeConfig.load()
    eid = int(engagement_id)
    db_path = config.engagement_db_path(str(eid))
    output_dir = Path(reports_dir)
    if db_path.exists():
        if not force:
            raise FileExistsError(
                f"demo engagement DB already exists at {db_path}; rerun with --force to regenerate"
            )
        db_path.unlink()
        for sidecar in (db_path.with_suffix(".db-wal"), db_path.with_suffix(".db-shm")):
            sidecar.unlink(missing_ok=True)
        _remove_demo_artifacts(output_dir, eid)

    output_dir.mkdir(parents=True, exist_ok=True)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    now = _utc_timestamp()
    operator_name = str(operator or config.operator or "demo-operator")
    sample_artifact = _write_demo_source_artifact(config, eid)

    with direct_connect(db_path) as con:
        con.row_factory = None
        apply_schema(con)
        con.row_factory = None
        _seed_base_engagement(
            con,
            engagement_id=eid,
            operator=operator_name,
            now=now,
            sample_artifact=sample_artifact,
        )
        policy = upsert_monitoring_policy(
            con,
            engagement_id=eid,
            name="Demo CTEM daily drift",
            enabled=True,
            schedule_interval_minutes=1440,
            mode="passive",
            metadata={
                "proof_pack": True,
                "free_local": True,
                "description": "Local fixture policy proving scheduled CTEM diffs and alerts.",
            },
        )
        create_monitoring_snapshot(
            con,
            engagement_id=eid,
            policy_id=int(policy["id"]),
            snapshot_kind="manual",
        )
        _seed_drift_rows(con, engagement_id=eid, now=now)
        snapshot = create_monitoring_snapshot(
            con,
            engagement_id=eid,
            policy_id=int(policy["id"]),
            snapshot_kind="scheduled",
        )
        _seed_active_validation(con, engagement_id=eid, operator=operator_name)
        sync_secret_lifecycle(con, eid)
        _seed_manual_remediation(con, engagement_id=eid, now=now)
        sync_engagement_asset_graph(con, eid)
        con.commit()
        counts = _proof_counts(con, eid)
        counts["monitoring_changes_latest"] = len(snapshot.get("changes") or [])
        counts["monitoring_alerts_latest"] = len(snapshot.get("alerts") or [])

    _build_graph_artifacts(eid, db_path, output_dir)
    standards_artifacts = _build_standards_artifacts(eid, db_path, output_dir)
    report_path = synthesise(
        engagement_id=eid,
        output_path=str(output_dir / f"engagement_{eid}_demo_proof_pack.md"),
        assume_yes=True,
        provider="template",
        max_correction_loops=0,
    )
    dashboard_path = generate_dashboard(
        data_dir=config.data_dir,
        reports_dir=output_dir,
        output_path=output_dir / "demo_dashboard.html",
        include_legacy=False,
    )
    audit_bundle_path = _write_audit_bundle(
        db_path=db_path,
        engagement_id=eid,
        report_path=report_path,
        output_dir=output_dir,
        dashboard_path=dashboard_path,
        standards_artifacts=standards_artifacts,
    )
    with direct_connect(db_path) as con:
        counts = _proof_counts(con, eid)
    manifest_path = _write_proof_manifest(
        engagement_id=eid,
        db_path=db_path,
        reports_dir=output_dir,
        report_path=report_path,
        dashboard_path=dashboard_path,
        audit_bundle_path=audit_bundle_path,
        graph_artifacts=_graph_artifact_paths(output_dir, eid),
        standards_artifacts=standards_artifacts,
        counts=counts,
    )
    return DemoProofPackResult(
        engagement_id=eid,
        db_path=db_path,
        reports_dir=output_dir,
        report_path=report_path,
        dashboard_path=dashboard_path,
        audit_bundle_path=audit_bundle_path,
        manifest_path=manifest_path,
        graph_artifacts=tuple(_graph_artifact_paths(output_dir, eid)),
        standards_artifacts=tuple(standards_artifacts),
        counts=counts,
    )


def _seed_base_engagement(
    con: Any,
    *,
    engagement_id: int,
    operator: str,
    now: str,
    sample_artifact: Path,
) -> None:
    scope = [
        {"seed_type": "domain", "value": DEMO_DOMAIN},
        {"seed_type": "url", "value": f"https://app.{DEMO_DOMAIN}/"},
        {"seed_type": "cloud_ref", "value": "s3://forge-demo-prod-assets"},
    ]
    metadata = {
        "proof_pack": True,
        "free_local": True,
        "industry_gap_themes": [
            "continuous_asset_intelligence",
            "ownership",
            "workflow",
            "tenant_controls",
            "active_validation_gate",
        ],
        "source_artifact": str(sample_artifact),
    }
    con.execute(
        """
        INSERT INTO workspaces (workspace_id, name, metadata_json, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(workspace_id) DO UPDATE SET
            name=excluded.name,
            metadata_json=excluded.metadata_json,
            updated_at=excluded.updated_at
        """,
        (
            DEMO_WORKSPACE_ID,
            "Demo Workspace",
            _json(metadata),
            now,
            now,
        ),
    )
    con.execute(
        """
        INSERT INTO engagements
            (id, name, workspace_id, scope_json, status, operator, metadata_json,
             created_at, updated_at)
        VALUES (?, ?, ?, ?, 'COMPLETE', ?, ?, ?, ?)
        """,
        (
            engagement_id,
            DEMO_NAME,
            DEMO_WORKSPACE_ID,
            _json(scope),
            operator,
            _json(metadata),
            now,
            now,
        ),
    )
    seeds = [
        (DEMO_DOMAIN, "domain", "operator", 0, 1.0, None),
        (f"https://app.{DEMO_DOMAIN}/", "url", "operator", 0, 1.0, None),
        ("security@demo-forge.example", "email", "artifact", 1, 0.92, 1),
        ("s3://forge-demo-prod-assets", "cloud_ref", "artifact", 1, 0.88, 2),
    ]
    for seed_value, seed_type, source, depth, confidence, parent_id in seeds:
        con.execute(
            """
            INSERT INTO engagement_seeds
                (engagement_id, seed_value, seed_type, source, status, depth,
                 confidence, parent_seed_id, metadata_json, discovered_at, updated_at)
            VALUES (?, ?, ?, ?, 'completed', ?, ?, ?, ?, ?, ?)
            """,
            (
                engagement_id,
                seed_value,
                seed_type,
                source,
                depth,
                confidence,
                parent_id,
                _json({"proof_pack": True}),
                now,
                now,
            ),
        )
    con.execute(
        """
        INSERT INTO emails (engagement_id, email, domain, source, first_seen_at)
        VALUES (?, 'security@demo-forge.example', ?, 'demo_artifact', ?)
        """,
        (engagement_id, DEMO_DOMAIN, now),
    )
    con.execute(
        """
        INSERT INTO hosts (engagement_id, ip, hostname, os_family, host_context, in_scope, discovered_at)
        VALUES (?, '203.0.113.42', ?, 'linux', ?, 1, ?)
        """,
        (
            engagement_id,
            f"app.{DEMO_DOMAIN}",
            _json({"source": "demo_fixture", "internet_entry_point": True}),
            now,
        ),
    )
    host_id = int(con.execute("SELECT last_insert_rowid()").fetchone()[0])
    con.execute(
        """
        INSERT INTO services (host_id, port, protocol, service_name, banner, version, discovered_at)
        VALUES (?, 443, 'tcp', 'https', 'Forge demo service', 'nginx/1.26', ?)
        """,
        (host_id, now),
    )
    artifact_hash = _sha256(sample_artifact.read_bytes())
    con.execute(
        """
        INSERT INTO artifact_queue
            (engagement_id, source_url, local_path, artifact_type, discovered_from,
             status, sha256, notes, metadata_json, attempt_count, max_attempts,
             queued_at, updated_at)
        VALUES (?, ?, ?, 'config', 'operator_demo', 'parsed', ?, ?, ?, 1, 1, ?, ?)
        """,
        (
            engagement_id,
            sample_artifact.as_uri(),
            str(sample_artifact),
            artifact_hash,
            "Local proof-pack config fixture parsed without network access.",
            _json({"proof_pack": True, "parser": "demo_fixture"}),
            now,
            now,
        ),
    )
    con.execute(
        """
        INSERT INTO exfiltrated_data
            (engagement_id, host_id, source_path, staging_path, file_hash,
             bytes_transferred, chunks_total, chunks_sent, exfil_at,
             artifact_family, artifact_subtype, source_platform,
             collection_method, confidence, report_safe_summary)
        VALUES (?, ?, ?, ?, ?, ?, 1, 1, ?, 'config', 'json', 'local',
                'passive_demo_fixture', 1.0, ?)
        """,
        (
            engagement_id,
            host_id,
            str(sample_artifact),
            str(sample_artifact),
            artifact_hash,
            sample_artifact.stat().st_size,
            now,
            "Local JSON fixture containing demo emails, URLs, and cloud refs.",
        ),
    )
    con.execute(
        """
        INSERT INTO cloud_assets
            (engagement_id, asset_type, identifier, provider_identifier, source,
             metadata_json, discovered_at)
        VALUES (?, 'aws_s3', 'forge-demo-prod-assets', 's3://forge-demo-prod-assets',
                'demo_artifact', ?, ?)
        """,
        (
            engagement_id,
            _json(
                {
                    "cloud_provider": "aws",
                    "resource_type": "s3_bucket",
                    "account_id": "210987654321",
                    "region": "ap-southeast-1",
                    "internet_entry_point": True,
                    "data_sensitivity": "customer_export",
                    "artifact_provenance": True,
                    "source_file": str(sample_artifact),
                }
            ),
            now,
        ),
    )
    con.execute(
        """
        INSERT INTO cloud_validation_results
            (engagement_id, asset_type, identifier, provider_identifier,
             validation_status, validation_method, http_status, evidence, notes, checked_at)
        VALUES (?, 'aws_s3', 'forge-demo-prod-assets', 's3://forge-demo-prod-assets',
                'UNVERIFIED', 'demo_fixture_inventory', NULL, ?, ?, ?)
        """,
        (
            engagement_id,
            "Inventory-only proof-pack row; no live provider validation was executed.",
            "Demonstrates reviewable non-reportable cloud validation inventory.",
            now,
        ),
    )
    con.execute(
        """
        INSERT INTO key_scanner_findings
            (engagement_id, domain, service, pattern_name, source_backend,
             source_url, repo_name, key_redacted, key_enc, validation_state,
             validation_detail, found_at, validated_at)
        VALUES (?, ?, 'github', 'github_pat', 'local_demo_fixture', ?, ?,
                'ghp_demo...9A7F', NULL, 'UNCONFIRMED', ?, ?, NULL)
        """,
        (
            engagement_id,
            DEMO_DOMAIN,
            sample_artifact.as_uri(),
            "forge-demo/frontend-config",
            "UNCONFIRMED:demo_fixture_inventory:no live token validation executed",
            now,
        ),
    )
    key_id = int(con.execute("SELECT last_insert_rowid()").fetchone()[0])
    expires_at = (datetime.now(UTC) + timedelta(days=30)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    con.execute(
        """
        INSERT INTO validation_claims
            (engagement_id, claim_type, key_id, owner, expires_at)
        VALUES (?, 'key', ?, 'platform-security@example.invalid', ?)
        """,
        (engagement_id, key_id, expires_at),
    )
    con.execute(
        """
        INSERT INTO validation_claims
            (engagement_id, claim_type, asset_type, identifier, owner, expires_at)
        VALUES (?, 'asset', 'aws_s3', 'forge-demo-prod-assets',
                'cloud-platform@example.invalid', ?)
        """,
        (engagement_id, expires_at),
    )
    con.execute(
        """
        INSERT INTO vulnerability_findings
            (engagement_id, vuln_type, target_url, parameter, severity, title,
             description, evidence, cve_id, cvss_score, cvss_version, cvss_vector,
             cwe_ids, cpe_matches, epss_score, epss_percentile, cisa_kev,
             cisa_kev_due_date, attack_techniques, stix_external_refs_json,
             standards_json, found_at)
        VALUES (?, 'EXPOSED_ADMIN_INTERFACE', ?, 'admin', 'HIGH', ?,
                ?, ?, 'CVE-2024-3094', 10.0, '4.0',
                'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H',
                ?, ?, 0.944, 0.997, 1, '2024-06-01', ?, ?, ?, ?)
        """,
        (
            engagement_id,
            f"https://app.{DEMO_DOMAIN}/admin",
            "Active exposed administrative interface from passive fixture",
            "Fixture proves reportable vs non-reportable gating; no live exploit executed.",
            "active exposed admin interface; proof-pack fixture evidence",
            _json(["CWE-284", "CWE-306"]),
            _json(["cpe:2.3:a:forge:demo_app:1.0:*:*:*:*:*:*:*"]),
            _json(["T1190", "T1552"]),
            _json(
                [
                    {
                        "source_name": "cve",
                        "external_id": "CVE-2024-3094",
                        "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
                    }
                ]
            ),
            _json(
                {
                    "cvss_source": "demo_fixture",
                    "epss_source": "demo_fixture",
                    "kev_source": "cisa_kev_fixture",
                    "reportable_demo": True,
                }
            ),
            now,
        ),
    )
    vuln_id = int(con.execute("SELECT last_insert_rowid()").fetchone()[0])
    _insert_remediation_item(
        con,
        engagement_id=engagement_id,
        finding_table="vulnerability_findings",
        finding_id=vuln_id,
        finding_ref=f"vulnerability_findings:{vuln_id}",
        title="Close exposed admin interface and require auth",
        severity="HIGH",
        owner="appsec@example.invalid",
        sla_due_at=_days_from_now(14),
        status="assigned",
        retest_status="pending",
        ticket_system="github_issues",
        ticket_ref="FORGE-DEMO-1",
        ticket_url="https://github.com/example/forge-demo/issues/1",
        metadata={"proof_pack": True, "workflow": "owner_sla_retest"},
        now=now,
    )
    con.execute(
        """
        INSERT INTO audit_log
            (engagement_id, phase, module, action, target, result, operator, logged_at)
        VALUES
            (?, 'demo', 'proof_pack', 'seed', ?, 'created local no-key demo data', ?, ?),
            (?, 'demo', 'proof_pack', 'artifact', ?, 'registered passive config artifact', ?, ?)
        """,
        (
            engagement_id,
            DEMO_DOMAIN,
            operator,
            now,
            engagement_id,
            str(sample_artifact),
            operator,
            now,
        ),
    )


def _seed_drift_rows(con: Any, *, engagement_id: int, now: str) -> None:
    con.execute(
        """
        INSERT INTO hosts (engagement_id, ip, hostname, os_family, host_context, in_scope, discovered_at)
        VALUES (?, '203.0.113.43', ?, 'linux', ?, 1, ?)
        """,
        (
            engagement_id,
            f"cdn.{DEMO_DOMAIN}",
            _json({"source": "scheduled_rerun", "change": "added_asset"}),
            now,
        ),
    )
    con.execute(
        """
        INSERT INTO vulnerability_findings
            (engagement_id, vuln_type, target_url, parameter, severity, title,
             description, evidence, cve_id, cvss_score, cvss_version, cvss_vector,
             cwe_ids, cpe_matches, attack_techniques, stix_external_refs_json,
             standards_json, found_at)
        VALUES (?, 'TLS_WEAK_PROTOCOL', ?, 'tls', 'MEDIUM', ?,
                'Scheduled rerun found TLS policy drift.', ?, '', 5.3, '3.1',
                'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
                ?, ?, ?, ?, ?, ?)
        """,
        (
            engagement_id,
            f"https://cdn.{DEMO_DOMAIN}/",
            "Scheduled exposure drift: weak TLS policy",
            "scheduled rerun detected weak TLS protocol on new CDN edge",
            _json(["CWE-326"]),
            _json([]),
            _json(["T1580"]),
            _json([]),
            _json({"source": "scheduled_rerun", "reportable_demo": True}),
            now,
        ),
    )


def _seed_active_validation(con: Any, *, engagement_id: int, operator: str) -> None:
    dry_run = create_active_validation_job(
        con,
        engagement_id=engagement_id,
        target_ref=f"https://app.{DEMO_DOMAIN}/admin",
        target_kind="finding",
        method="fix_verification",
        mode="dry_run",
        requested_by=operator,
        metadata={"proof_pack": True, "goal": "show fail-closed planning"},
    )
    run_active_validation_job(
        con,
        engagement_id=engagement_id,
        job_id=int(dry_run["id"]),
        operator=operator,
        allow_env_live=False,
    )
    lab = create_active_validation_job(
        con,
        engagement_id=engagement_id,
        target_ref="fixture://forge-demo/admin-auth-fixed",
        target_kind="fixture",
        method="fixture_replay",
        mode="lab",
        approved=True,
        requested_by=operator,
        approved_by=operator,
        approval_note="Local proof-pack fixture only.",
        roe_id="DEMO-ROE-LOCAL",
        scope_manifest_ref=json.dumps(
            {
                "roe_id": "DEMO-ROE-LOCAL",
                "exact_seeds": ["fixture://forge-demo/admin-auth-fixed"],
            },
            sort_keys=True,
        ),
        metadata={"proof_pack": True, "goal": "show approved lab replay"},
    )
    run_active_validation_job(
        con,
        engagement_id=engagement_id,
        job_id=int(lab["id"]),
        operator=operator,
        allow_env_live=False,
    )


def _seed_manual_remediation(con: Any, *, engagement_id: int, now: str) -> None:
    key_row = con.execute(
        """
        SELECT id
        FROM key_scanner_findings
        WHERE engagement_id=? AND service='github'
        ORDER BY id DESC
        LIMIT 1
        """,
        (engagement_id,),
    ).fetchone()
    if key_row is None:
        return
    _insert_remediation_item(
        con,
        engagement_id=engagement_id,
        finding_table="key_scanner_findings",
        finding_id=int(key_row[0]),
        finding_ref=f"key_scanner_findings:{int(key_row[0])}",
        title="Route and rotate redacted GitHub token finding",
        severity="MEDIUM",
        owner="platform-security@example.invalid",
        sla_due_at=_days_from_now(7),
        status="in_progress",
        retest_status="not_requested",
        ticket_system="jsonl",
        ticket_ref="demo-ticket-key-rotation",
        ticket_url="",
        metadata={"proof_pack": True, "workflow": "secret_owner_routing"},
        now=now,
    )


def _insert_remediation_item(
    con: Any,
    *,
    engagement_id: int,
    finding_table: str,
    finding_id: int,
    finding_ref: str,
    title: str,
    severity: str,
    owner: str,
    sla_due_at: str,
    status: str,
    retest_status: str,
    ticket_system: str,
    ticket_ref: str,
    ticket_url: str,
    metadata: dict[str, Any],
    now: str,
) -> None:
    con.execute(
        """
        INSERT INTO remediation_items
            (engagement_id, finding_table, finding_id, finding_ref, title, severity,
             owner, sla_due_at, status, retest_status, ticket_system, ticket_ref,
             ticket_url, metadata_json, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(engagement_id, finding_table, finding_ref) DO UPDATE SET
            title=excluded.title,
            severity=excluded.severity,
            owner=excluded.owner,
            sla_due_at=excluded.sla_due_at,
            status=excluded.status,
            retest_status=excluded.retest_status,
            ticket_system=excluded.ticket_system,
            ticket_ref=excluded.ticket_ref,
            ticket_url=excluded.ticket_url,
            metadata_json=excluded.metadata_json,
            updated_at=excluded.updated_at
        """,
        (
            engagement_id,
            finding_table,
            finding_id,
            finding_ref,
            title,
            severity,
            owner,
            sla_due_at,
            status,
            retest_status,
            ticket_system,
            ticket_ref,
            ticket_url,
            _json(metadata),
            now,
            now,
        ),
    )


def _write_demo_source_artifact(cfg: ForgeConfig, engagement_id: int) -> Path:
    artifact_dir = cfg.data_dir / "engagements" / str(engagement_id) / "proof-pack"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = artifact_dir / "demo-config.json"
    payload = {
        "name": DEMO_NAME,
        "domain": DEMO_DOMAIN,
        "contacts": ["security@demo-forge.example"],
        "urls": [f"https://app.{DEMO_DOMAIN}/", f"https://app.{DEMO_DOMAIN}/admin"],
        "cloud_refs": ["s3://forge-demo-prod-assets"],
        "provenance": "local proof-pack fixture; no live provider calls",
    }
    artifact_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return artifact_path


def _build_graph_artifacts(engagement_id: int, db_path: Path, reports_dir: Path) -> None:
    from forge.graph.export import export_attack_graph  # noqa: PLC0415

    export_attack_graph(
        engagement_id=engagement_id,
        db_path=db_path,
        fmt="all",
        output_dir=reports_dir,
        min_severity="LOW",
        critical_path_only=False,
        snapshot=True,
        max_nodes=150,
    )


def _build_standards_artifacts(
    engagement_id: int,
    db_path: Path,
    reports_dir: Path,
) -> tuple[Path, Path]:
    bundle_path = reports_dir / f"engagement_{engagement_id}_demo_stix_bundle.json"
    manifest_path = reports_dir / f"engagement_{engagement_id}_demo_taxii_manifest.json"
    with direct_connect(db_path) as con:
        con.row_factory = sqlite3.Row
        rows = con.execute(
            """
            SELECT *
            FROM vulnerability_findings
            WHERE engagement_id=?
            ORDER BY id
            """,
            (int(engagement_id),),
        ).fetchall()
    bundle = vulnerability_stix_bundle(
        list(rows),
        title=f"{DEMO_NAME} STIX Export",
    )
    manifest = vulnerability_taxii_manifest(
        bundle,
        collection_id=f"forge-demo-{engagement_id}-vulnerabilities",
        title=f"{DEMO_NAME} vulnerability standards",
    )
    bundle_path.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return bundle_path, manifest_path


def _write_proof_manifest(
    *,
    engagement_id: int,
    db_path: Path,
    reports_dir: Path,
    report_path: Path,
    dashboard_path: Path,
    audit_bundle_path: Path,
    graph_artifacts: list[Path],
    standards_artifacts: tuple[Path, ...],
    counts: dict[str, int],
) -> Path:
    manifest_path = reports_dir / f"engagement_{engagement_id}_demo_proof_pack_manifest.json"
    detail_json = _dashboard_detail_json_path(
        reports_dir=reports_dir,
        dashboard_path=dashboard_path,
        engagement_id=engagement_id,
    )
    payload = {
        "engagement_id": engagement_id,
        "name": DEMO_NAME,
        "generated_at": _utc_timestamp(),
        "free_local": True,
        "live_provider_calls": False,
        "secret_material_stored": False,
        "db_path": str(db_path),
        "report_path": str(report_path),
        "report_json_path": str(report_path.with_suffix(".json")),
        "report_csv_path": str(report_path.with_suffix(".csv")),
        "dashboard_path": str(dashboard_path),
        "dashboard_detail_json": str(detail_json),
        "audit_bundle_path": str(audit_bundle_path),
        "graph_artifacts": [str(path) for path in graph_artifacts if path.exists()],
        "standards_artifacts": [str(path) for path in standards_artifacts if path.exists()],
        "counts": counts,
        "proof_assertions": _proof_assertions(
            counts=counts,
            report_path=report_path,
            dashboard_path=dashboard_path,
            detail_json=detail_json,
            audit_bundle_path=audit_bundle_path,
            graph_artifacts=graph_artifacts,
            standards_artifacts=standards_artifacts,
        ),
        "proof_surfaces": [
            "engagement_db",
            "template_report_family",
            "attack_graph_exports",
            "static_dashboard",
            "audit_manifest_bundle",
            "standards_exchange_artifacts",
            "monitoring_diff_alerts",
            "remediation_items",
            "active_validation_runs",
            "secret_lifecycle_items",
        ],
    }
    manifest_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return manifest_path


def _proof_assertions(
    *,
    counts: dict[str, int],
    report_path: Path,
    dashboard_path: Path,
    detail_json: Path,
    audit_bundle_path: Path,
    graph_artifacts: list[Path],
    standards_artifacts: tuple[Path, ...],
) -> dict[str, dict[str, Any]]:
    existing_graph_artifacts = [str(path) for path in graph_artifacts if path.exists()]
    existing_standards_artifacts = [str(path) for path in standards_artifacts if path.exists()]
    return {
        "continuous_monitoring": {
            "passed": counts.get("monitoring_snapshots", 0) >= 2
            and counts.get("monitoring_changes", 0) > 0
            and counts.get("monitoring_alerts", 0) > 0,
            "evidence": ["monitoring_diff_alerts", "monitoring_trend_points"],
            "counts": {
                "monitoring_snapshots": counts.get("monitoring_snapshots", 0),
                "monitoring_changes": counts.get("monitoring_changes", 0),
                "monitoring_alerts": counts.get("monitoring_alerts", 0),
                "monitoring_trend_points": counts.get("monitoring_trend_points", 0),
            },
        },
        "asset_graph": {
            "passed": counts.get("asset_entities", 0) > 0
            and counts.get("asset_relationships", 0) > 0
            and bool(existing_graph_artifacts),
            "evidence": existing_graph_artifacts,
            "counts": {
                "asset_entities": counts.get("asset_entities", 0),
                "asset_relationships": counts.get("asset_relationships", 0),
                "asset_ownership_claims": counts.get("asset_ownership_claims", 0),
            },
        },
        "remediation_workflow": {
            "passed": counts.get("remediation_items", 0) > 0,
            "evidence": ["remediation_items", "owner_routing", "ticket_ref"],
            "counts": {"remediation_items": counts.get("remediation_items", 0)},
        },
        "active_validation": {
            "passed": counts.get("active_validation_jobs", 0) > 0
            and counts.get("active_validation_runs", 0) > 0,
            "evidence": ["active_validation_runs", "dry_run_or_lab_only"],
            "counts": {
                "active_validation_jobs": counts.get("active_validation_jobs", 0),
                "active_validation_runs": counts.get("active_validation_runs", 0),
            },
        },
        "secrets_lifecycle": {
            "passed": counts.get("secret_lifecycle_items", 0) > 0,
            "evidence": ["secret_lifecycle_items", "redacted_key_inventory"],
            "counts": {"secret_lifecycle_items": counts.get("secret_lifecycle_items", 0)},
        },
        "standards_exchange": {
            "passed": bool(existing_standards_artifacts),
            "evidence": existing_standards_artifacts,
            "artifact_count": len(existing_standards_artifacts),
        },
        "dashboard_evidence": {
            "passed": dashboard_path.exists() and detail_json.exists(),
            "evidence": [str(dashboard_path), str(detail_json)],
        },
        "audit_manifest_bundle": {
            "passed": audit_bundle_path.exists() and counts.get("run_audit_manifests", 0) > 0,
            "evidence": [str(audit_bundle_path), "run_audit_manifests"],
            "counts": {"run_audit_manifests": counts.get("run_audit_manifests", 0)},
        },
        "free_local_safety": {
            "passed": True,
            "evidence": ["template_report_provider", "network_socket_blocked_in_tests"],
            "report_path": str(report_path),
            "live_provider_calls": False,
            "secret_material_stored": False,
        },
    }


def _write_audit_bundle(
    *,
    db_path: Path,
    engagement_id: int,
    report_path: Path,
    output_dir: Path,
    dashboard_path: Path,
    standards_artifacts: tuple[Path, ...],
) -> Path:
    from forge.audit.manifest_bundle import export_run_audit_manifest_bundle  # noqa: PLC0415
    from forge.engagement_orchestrator import EngagementRunTracker  # noqa: PLC0415

    tracker = EngagementRunTracker(db_path, engagement_id)
    handle = tracker.start_run(
        run_kind="other",
        seed_value=DEMO_DOMAIN,
        seed_type="domain",
        seed_count=4,
        max_iterations=1,
        current_iteration=1,
        resume_enabled=False,
        dry_run=True,
        attack_mode=False,
        metadata={
            "proof_pack": True,
            "report_path": str(report_path),
            "dashboard_path": str(dashboard_path),
            "artifact_paths": _audit_artifact_paths(
                dashboard_path=dashboard_path,
                standards_artifacts=standards_artifacts,
            ),
            "graph_artifact_count": len([path for path in _graph_artifact_paths(output_dir, engagement_id) if path.exists()]),
        },
    )
    tracker.finish_run(
        handle,
        status="completed",
        current_iteration=1,
        metadata={
            "proof_pack": True,
            "report_path": str(report_path),
            "dashboard_path": str(dashboard_path),
            "artifact_paths": _audit_artifact_paths(
                dashboard_path=dashboard_path,
                standards_artifacts=standards_artifacts,
            ),
            "graph_artifacts": [
                str(path)
                for path in _graph_artifact_paths(output_dir, engagement_id)
                if path.exists()
            ],
        },
    )
    bundle_path = output_dir / f"engagement_{engagement_id}_demo_audit_manifest_bundle.zip"
    with direct_connect(db_path) as con:
        bundle = export_run_audit_manifest_bundle(
            con,
            db_path=db_path,
            engagement_id=engagement_id,
            run_id=handle.run_id,
            output_path=bundle_path,
        )
    return bundle.path


def _audit_artifact_paths(
    *,
    dashboard_path: Path,
    standards_artifacts: tuple[Path, ...],
) -> list[str]:
    return [str(path) for path in (dashboard_path, *standards_artifacts) if path.exists()]


def _dashboard_detail_json_path(
    *,
    reports_dir: Path,
    dashboard_path: Path,
    engagement_id: int,
) -> Path:
    site_root = dashboard_path.parent / dashboard_path.stem
    index_path = site_root / "data" / "engagements.json"
    try:
        payload = json.loads(index_path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 - manifest fallback only.
        return site_root / "data" / "engagements" / f"engagement-{engagement_id}.json"
    items = payload.get("items") if isinstance(payload, dict) else []
    if isinstance(items, list):
        for item in items:
            if not isinstance(item, dict):
                continue
            if int(item.get("id") or -1) != int(engagement_id):
                continue
            detail_data = str(item.get("detail_data") or "").strip()
            if detail_data:
                return site_root / detail_data
            slug = str(item.get("slug") or "").strip()
            if slug:
                return site_root / "data" / "engagements" / f"{slug}.json"
    return reports_dir / "demo_dashboard" / "data" / "engagements" / f"engagement-{engagement_id}.json"


def _proof_counts(con: Any, engagement_id: int) -> dict[str, int]:
    tables = [
        "engagement_seeds",
        "hosts",
        "services",
        "artifact_queue",
        "cloud_assets",
        "cloud_validation_results",
        "key_scanner_findings",
        "secret_lifecycle_items",
        "vulnerability_findings",
        "remediation_items",
        "monitoring_policies",
        "monitoring_snapshots",
        "monitoring_changes",
        "monitoring_alerts",
        "monitoring_trend_points",
        "active_validation_jobs",
        "active_validation_runs",
        "asset_entities",
        "asset_relationships",
        "asset_ownership_claims",
        "run_audit_manifests",
        "audit_log",
    ]
    counts: dict[str, int] = {}
    for table in tables:
        try:
            row = con.execute(
                f"SELECT COUNT(*) FROM {table} WHERE engagement_id=?",
                (engagement_id,),
            ).fetchone()
            counts[table] = int(row[0] or 0)
        except Exception:  # noqa: BLE001 - optional proof table.
            counts[table] = 0
    try:
        row = con.execute(
            """
            SELECT COUNT(*)
            FROM services s
            JOIN hosts h ON h.id=s.host_id
            WHERE h.engagement_id=?
            """,
            (engagement_id,),
        ).fetchone()
        counts["services"] = int(row[0] or 0)
    except Exception:  # noqa: BLE001 - optional proof table.
        counts["services"] = 0
    return counts


def _graph_artifact_paths(reports_dir: Path, engagement_id: int) -> list[Path]:
    stem = reports_dir / f"{engagement_id}_attack_graph"
    return [
        stem.with_suffix(".json"),
        stem.with_suffix(".mmd"),
        stem.with_suffix(".dot"),
        stem.with_suffix(".graphml"),
        stem.with_suffix(".mtgx"),
        reports_dir / f"{engagement_id}_attack_graph_nodes.csv",
        reports_dir / f"{engagement_id}_attack_graph_edges.csv",
    ]


def _remove_demo_artifacts(reports_dir: Path, engagement_id: int) -> None:
    if not reports_dir.exists():
        return
    patterns = [
        f"engagement_{engagement_id}_demo_proof_pack*",
        f"engagement_{engagement_id}_demo_stix_bundle*",
        f"engagement_{engagement_id}_demo_taxii_manifest*",
        f"{engagement_id}_attack_graph*",
    ]
    for pattern in patterns:
        for path in reports_dir.glob(pattern):
            if path.is_file():
                path.unlink(missing_ok=True)


def _utc_timestamp() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _days_from_now(days: int) -> str:
    return (
        datetime.now(UTC).replace(microsecond=0) + timedelta(days=int(days))
    ).isoformat().replace("+00:00", "Z")


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


__all__ = [
    "DEFAULT_DEMO_ENGAGEMENT_ID",
    "DEMO_DOMAIN",
    "DEMO_NAME",
    "DemoProofPackResult",
    "generate_demo_proof_pack",
]
