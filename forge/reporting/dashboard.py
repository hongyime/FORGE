"""Static engagement dashboard + detail pages.

Builds a compact overview page across every engagement and a dedicated
detail page per engagement so the main dashboard stays readable.
"""
from __future__ import annotations

import html
import json
import re
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from xml.etree import ElementTree

from forge.active_validation.evidence import active_validation_proof_summary
from forge.active_validation.methods import get_active_validation_method
from forge.active_validation.runner import active_validation_control_coverage
from forge.audit.manifest import summarize_run_audit_manifest
from forge.graph.assets import list_asset_graph, ownership_conflicts_for_engagement
from forge.monitoring.exposure_metrics import exposure_metrics_for_engagement
from forge.opsec.scope_gate import scope_entries_from_payload
from forge.reporting.engagement_detail_blocks import (
    EngagementGraphBlocks,
    EngagementInputBlocks,
    EngagementReportPreviewContext,
    EngagementTimelineBlocks,
    engagement_graph_blocks,
    engagement_input_blocks,
    engagement_report_preview_context,
    engagement_timeline_blocks,
    render_engagement_artifact_block,
)
from forge.reporting.engagement_payloads import (
    engagement_detail_payload,
    engagement_index_payload,
)
from forge.reporting.audit_manifest_artifacts import (
    AuditManifestArtifactCallbacks,
    audit_files as list_audit_artifact_files,
    engagement_prefixed_artifact_files as list_engagement_prefixed_artifact_files,
    materialize_audit_manifest_artifacts as build_audit_manifest_artifacts,
    report_files as list_report_artifact_files,
)
from forge.reporting.artifact_payloads import (
    artifact_payload as build_artifact_payload,
    format_size as format_artifact_size,
    relative_href as build_relative_href,
    report_history_payload as build_report_history_payload,
    report_preview_payload as build_report_preview_payload,
    report_summary_payload as build_report_summary_payload,
)
from forge.reporting.engagement_summary import (
    EngagementSummaryCallbacks,
    engagement_summary as build_engagement_summary,
    summary_counts as build_summary_counts,
)
from forge.reporting.dashboard_generation import (
    DashboardSitePaths,
    assign_engagement_dashboard_routes,
    dashboard_site_root,
    prepare_dashboard_site,
    write_dashboard_overview_outputs,
    write_engagement_dashboard_outputs,
)
from forge.reporting.detail_section_rows import (
    DetailRowFormatters,
    distributed_task_section_row as build_distributed_task_section_row,
    distributed_task_type,
    monitoring_alert_route_section_row as build_monitoring_alert_route_section_row,
    monitoring_alert_section_row as build_monitoring_alert_section_row,
    monitoring_alert_suppression_section_row as build_monitoring_alert_suppression_section_row,
    monitoring_change_section_row as build_monitoring_change_section_row,
    monitoring_entity_label,
    monitoring_policy_section_row as build_monitoring_policy_section_row,
    monitoring_snapshot_section_row as build_monitoring_snapshot_section_row,
    monitoring_trend_section_row as build_monitoring_trend_section_row,
    retention_days_label,
    retention_policy_section_row as build_retention_policy_section_row,
    retention_run_item_section_row as build_retention_run_item_section_row,
    retention_run_section_row as build_retention_run_section_row,
)
from forge.reporting.detail_section_queries import (
    DetailSectionQueryCallbacks,
    account_existence_section_rows,
    active_validation_sections,
    artifact_queue_section_rows,
    audit_sections,
    auth_test_result_section_rows,
    asset_graph_sections,
    cloud_sections,
    crawl_result_section_rows,
    distributed_task_section_rows,
    email_intelligence_section_rows,
    engagement_run_section_rows,
    finding_sections,
    host_identity_key as query_host_identity_key,
    inventory_sections,
    key_scanner_inventory_rows as query_key_scanner_inventory_rows,
    key_scanner_rows as query_key_scanner_rows,
    merged_email_rows as query_merged_email_rows,
    merged_host_rows as query_merged_host_rows,
    monitoring_configuration_sections,
    monitoring_history_sections,
    passive_vuln_section_rows,
    port_scan_result_section_rows,
    reportable_key_scanner_rows as query_reportable_key_scanner_rows,
    reportable_vulnerability_rows as query_reportable_vulnerability_rows,
    remediation_workflow_sections,
    representative_vulnerability_rows as query_representative_vulnerability_rows,
    retention_sections,
    seed_sections,
    seed_email_candidates as query_seed_email_candidates,
    seed_host_candidates as query_seed_host_candidates,
    service_section_rows,
    social_profile_section_rows,
)
from forge.reporting.engagement_enrichment import (
    EngagementEnrichmentCallbacks,
    dashboard_engagement_summary,
    engagement_db_files as list_engagement_db_files,
    enrich_engagement_dashboard_summary,
)
from forge.reporting.graph_validation_metadata import latest_cloud_validation_metadata_index
from forge.reporting.graph_summaries import (
    GraphSummaryCallbacks,
    asset_graph_summary as build_asset_graph_summary,
    seed_graph_summary as build_seed_graph_summary,
)
from forge.reporting.graph_payloads import (
    GraphPayloadCallbacks,
    canonical_cloud_node_score as score_canonical_graph_cloud_node,
    dedupe_graph_payload_cloud_alias_nodes as dedupe_cloud_alias_graph_payload_nodes,
    filter_graph_payload_for_validation as filter_reportable_graph_payload,
    graph_edge_endpoint_values as graph_payload_edge_endpoint_values,
    graph_edge_endpoints as graph_payload_edge_endpoints,
    graph_node_is_cloud_review_node as is_graph_cloud_review_node,
    graph_node_is_unreportable_cloud_finding as is_unreportable_graph_cloud_finding,
    graph_node_is_unreportable_key_finding as is_unreportable_graph_key_finding,
    graph_node_key_validation_detail as graph_payload_node_key_validation_detail,
    graph_node_validation_key as graph_payload_node_validation_key,
    graph_payload_for_engagement as build_graph_payload_for_engagement,
    graph_payload_has_structure as has_graph_payload_structure,
    graph_payload_with_defaults as apply_graph_payload_defaults,
    graph_state_for_engagement as build_graph_state_for_engagement,
    graph_summary as summarize_graph_artifacts,
    graph_summary_from_payload as summarize_graph_payload,
    merge_cloud_node_metadata as merge_graph_cloud_node_metadata,
    parse_graph_payload as parse_json_graph_payload,
    refresh_graph_cloud_node_validation_metadata as refresh_graph_cloud_node_validation_metadata,
    set_graph_edge_endpoints as set_graph_payload_edge_endpoints,
)
from forge.reporting.seed_graph_payloads import (
    SeedGraphPayloadCallbacks,
    merge_seed_node_metadata as merge_seed_graph_node_metadata,
    seed_graph_node_type as build_seed_graph_node_type,
    seed_graph_payload_for_engagement as build_seed_graph_payload_for_engagement,
    seed_graph_severity as build_seed_graph_severity,
)
from forge.reporting.graph_artifacts import (
    graph_entity_properties as parse_graph_entity_properties,
    graph_entity_type_to_node_type as normalize_graph_entity_type_to_node_type,
    graph_files as list_graph_artifact_files,
    graph_link_properties as parse_graph_link_properties,
    graph_payload_from_graphml as build_graph_payload_from_graphml,
    graph_payload_from_root as build_graph_payload_from_root,
    graph_root_from_artifact as load_graph_root_from_artifact,
)
from forge.reporting.report_history import (
    latest_report_family_files,
    report_review_counts,
)
from forge.reporting.run_summaries import (
    RunSummaryCallbacks,
    annotate_audit_manifest_bundle as annotate_run_audit_manifest_bundle,
    engagement_run_section_row as build_engagement_run_section_row,
    effective_run_status as resolve_effective_run_status,
    latest_engagement_run as build_latest_engagement_run,
    run_policy_summary as build_run_policy_summary,
)
from forge.reporting.evidence_provenance import evidence_provenance_section_rows
from forge.reporting.display_sanitization import sanitize_report_display_text
from forge.reporting.page_composition import (
    render_engagement_detail_page,
    render_engagement_evidence_sections,
    render_overview_page,
)
from forge.reporting.report_rendering import (
    render_artifact_card,
    render_audit_timeline,
    render_graph_stage,
    render_graph_summary,
    render_meta_block,
    render_operational_timeline,
    render_report_backend_summary,
    render_report_callout,
    render_report_history,
    render_report_preview,
    render_table,
)
from forge.reporting.timeline import operational_timeline_events
from forge.remediation.workflow import remediation_review_queue, risk_acceptance_review_status
from forge.targets_resume_candidates import (
    TargetResumeCandidate,
    target_resume_candidate_for_db,
)
from forge.utils.cloud_asset_graph_metadata import stored_cloud_asset_graph_metadata
from forge.utils.artifact_url_sanitizer import strip_sensitive_url_query
from forge.utils.cloud_exposure_gate import (
    effective_validation_status,
    is_deterministic_cloud_exposure,
    is_legacy_cloud_audit_finding,
    is_reportable_cloud_validation,
    legacy_cloud_audit_finding_is_reportable,
    linked_cloud_validation_reportability,
    latest_cloud_validation_reportability_index,
    normalize_cloud_exposure_asset_type,
    vulnerability_finding_evidence_is_reportable,
)
from forge.utils.key_validation_gate import (
    key_validation_detail_is_reportable,
    key_validation_requires_linked_result,
    linked_key_validation_reportability,
)
from forge.utils.validation_proof import parse_validated_detail
from forge.db.direct_connect import direct_connect  # noqa: E402  # PRAGMA-configured wrapper for bare sqlite3.connect

SECTION_LIMIT = 12
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
_SCOPE_BOUNDARY_DENIAL_ACTIONS = (
    "scheduled_task_scope_denied",
    "recursive_seed_scope_denied",
    "remote_artifact_scope_denied",
    "cloud_validation_scope_denied",
    "key_validation_scope_denied",
    "automation_scope_denied",
)
_GRAPH_FORBIDDEN_METADATA_KEYS = {
    "api_key",
    "apikey",
    "access_token",
    "client_secret",
    "credential",
    "credentials",
    "key_enc",
    "key_raw",
    "password",
    "password_enc",
    "private_key",
    "raw_secret",
    "raw_token",
    "refresh_token",
    "secret",
    "secret_enc",
    "token",
    "token_enc",
}
def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or "engagement"


def _format_size(size_bytes: int) -> str:
    return format_artifact_size(size_bytes)


def _format_dt(value: str) -> str:
    if not value:
        return ""
    cleaned = value.replace("Z", "+00:00")
    for candidate in (cleaned, cleaned.replace(" ", "T", 1)):
        try:
            dt = datetime.fromisoformat(candidate)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
    return value


def _timestamp_epoch_ms(value: str) -> int:
    if not value:
        return 0
    cleaned = str(value).replace("Z", "+00:00").strip()
    for candidate in (cleaned, cleaned.replace(" ", "T", 1)):
        try:
            return int(datetime.fromisoformat(candidate).timestamp() * 1000)
        except ValueError:
            continue
    return 0


def _truncate(value: Any, limit: int = 140) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return f"{text[:limit - 3]}..."


def _safe_dashboard_source_url(value: Any, limit: int = 96) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    sanitized = strip_sensitive_url_query(text)
    parsed = urlparse(sanitized)
    if parsed.scheme in {"http", "https"} and (parsed.username or parsed.password):
        netloc = parsed.hostname or ""
        try:
            port = parsed.port
        except ValueError:
            port = None
        if port is not None:
            netloc = f"{netloc}:{port}"
        sanitized = parsed._replace(netloc=netloc).geturl()
    return _truncate(sanitized, limit)


_DASHBOARD_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?key|access[_-]?token|client[_-]?secret|key_enc|password|"
    r"private[_-]?key|raw[_-]?(?:secret|token)|refresh[_-]?token|secret|"
    r"scope_manifest(?:_json|_payload)?|token)\b\s*[:=]\s*[^,\s;]+"
)
_DASHBOARD_URL_RE = re.compile(r"https?://[^\s,;]+", re.IGNORECASE)


def _redact_dashboard_error(value: Any, limit: int = 140) -> str:
    text = sanitize_report_display_text(value)
    text = _DASHBOARD_SECRET_ASSIGNMENT_RE.sub(
        lambda match: f"{match.group(1)}=[redacted]",
        text,
    )
    text = _DASHBOARD_URL_RE.sub("[redacted-url]", text)
    text = " ".join(text.split())
    return _truncate(text, limit)


def _safe_json_loads(value: str) -> Any:
    try:
        return json.loads(value)
    except Exception:  # noqa: BLE001
        return None


def _is_sensitive_metadata_key(key: Any) -> bool:
    normalized = str(key or "").strip().lower()
    return (
        not normalized
        or normalized in _GRAPH_FORBIDDEN_METADATA_KEYS
        or normalized.endswith("_enc")
    )


def _safe_graph_metadata_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list):
        return [_safe_graph_metadata_value(item) for item in value[:50]]
    if isinstance(value, dict):
        return _safe_graph_metadata(value)
    return str(value)


def _safe_graph_metadata(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    clean: dict[str, Any] = {}
    for raw_key, raw_value in value.items():
        if _is_sensitive_metadata_key(raw_key):
            continue
        key = str(raw_key).strip()
        clean[key] = _safe_graph_metadata_value(raw_value)
    return clean


def _merge_seed_node_metadata(node_metadata: dict[str, Any], raw_metadata: Any) -> None:
    merge_seed_graph_node_metadata(
        node_metadata,
        raw_metadata,
        safe_graph_metadata=_safe_graph_metadata,
    )


def _normalize_engagement_tags(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        candidates = re.split(r"[\r\n,]+", raw)
    elif isinstance(raw, (list, tuple, set)):
        candidates = list(raw)
    else:
        return []
    tags: list[str] = []
    seen: set[str] = set()
    for item in candidates:
        tag = re.sub(r"\s+", " ", str(item or "")).strip()
        if not tag:
            continue
        dedupe_key = tag.casefold()
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        tags.append(tag[:48])
        if len(tags) >= 12:
            break
    return tags


def _engagement_metadata(con: sqlite3.Connection, engagement_id: int) -> dict[str, Any]:
    if "metadata_json" not in _table_columns(con, "engagements"):
        return {}
    try:
        row = con.execute(
            """
            SELECT metadata_json
            FROM engagements
            WHERE id=?
            """,
            (engagement_id,),
        ).fetchone()
    except sqlite3.OperationalError:
        return {}
    if row is None:
        return {}
    metadata = _safe_json_loads(str(row["metadata_json"] or "{}"))
    return metadata if isinstance(metadata, dict) else {}


def _engagement_tags(con: sqlite3.Connection, engagement_id: int) -> list[str]:
    metadata = _engagement_metadata(con, engagement_id)
    return _normalize_engagement_tags(metadata.get("tags"))


def _effective_run_status(status: str, metadata: Any) -> str:
    return resolve_effective_run_status(status, metadata)


def _run_policy_summary(metadata: Any, *, dry_run: bool, attack_mode: bool) -> dict[str, Any]:
    return build_run_policy_summary(metadata, dry_run=dry_run, attack_mode=attack_mode)


def _preview_json(value: Any, limit: int = 180) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        parsed = _safe_json_loads(value)
        if parsed is None:
            return _truncate(value, limit)
        value = parsed
    if isinstance(value, dict):
        keys = ", ".join(sorted(str(k) for k in value.keys())[:8])
        return _truncate(keys or json.dumps(value, ensure_ascii=False), limit)
    if isinstance(value, list):
        preview = ", ".join(_truncate(item, 36) for item in value[:6])
        return _truncate(preview, limit)
    return _truncate(value, limit)


def _crawl_source_summary(value: Any) -> str:
    parsed = _safe_json_loads(value) if isinstance(value, str) else value
    if not isinstance(parsed, dict):
        return ""
    sources: list[str] = []
    for key in ("archive_sources", "provider_sources"):
        raw_sources = parsed.get(key)
        if not isinstance(raw_sources, list):
            continue
        for raw_source in raw_sources:
            source = str(raw_source or "").strip()
            if source and source not in sources:
                sources.append(source)
    if sources:
        return ", ".join(sources)
    return str(parsed.get("discovered_from") or "").strip()


def _connect_readonly(db_path: Path) -> sqlite3.Connection | None:
    try:
        con = direct_connect(
            f"file:{db_path.as_posix()}?mode=ro",
            uri=True,
            timeout=2.0,
        )
    except sqlite3.OperationalError:
        return None
    con.row_factory = sqlite3.Row
    return con


def _table_columns(con: sqlite3.Connection, table_name: str) -> set[str]:
    try:
        rows = con.execute(f"PRAGMA table_info({table_name})").fetchall()
    except sqlite3.OperationalError:
        return set()
    return {str(row["name"]) if "name" in row.keys() else str(row[1]) for row in rows}


def _table_exists(con: sqlite3.Connection, table_name: str) -> bool:
    return bool(_table_columns(con, table_name))


def _fetch_rows(
    con: sqlite3.Connection,
    sql: str,
    params: tuple[Any, ...],
) -> list[sqlite3.Row]:
    try:
        return con.execute(sql, params).fetchall()
    except sqlite3.OperationalError:
        return []


def _fetch_count(
    con: sqlite3.Connection,
    sql: str,
    params: tuple[Any, ...],
) -> int:
    try:
        row = con.execute(sql, params).fetchone()
    except sqlite3.OperationalError:
        return 0
    if row is None:
        return 0
    return int(row[0] or 0)


def _host_identity_key(hostname: str, ip: str) -> str:
    return query_host_identity_key(hostname, ip)


def _seed_host_candidates(
    con: sqlite3.Connection,
    engagement_id: int,
) -> list[dict[str, str]]:
    return query_seed_host_candidates(
        con,
        engagement_id,
        callbacks=_detail_section_query_callbacks(),
    )


def _seed_email_candidates(
    con: sqlite3.Connection,
    engagement_id: int,
) -> list[dict[str, str]]:
    return query_seed_email_candidates(
        con,
        engagement_id,
        callbacks=_detail_section_query_callbacks(),
    )


def _merged_host_rows(con: sqlite3.Connection, engagement_id: int, *, limit: int | None = None) -> list[dict[str, str]]:
    return query_merged_host_rows(
        con,
        engagement_id,
        limit=limit,
        callbacks=_detail_section_query_callbacks(),
    )


def _merged_email_rows(con: sqlite3.Connection, engagement_id: int, *, limit: int | None = None) -> list[dict[str, str]]:
    return query_merged_email_rows(
        con,
        engagement_id,
        limit=limit,
        callbacks=_detail_section_query_callbacks(),
    )


def _reportable_cloud_validation_index(
    con: sqlite3.Connection,
    engagement_id: int,
) -> dict[tuple[str, str], bool]:
    return latest_cloud_validation_reportability_index(
        con,
        engagement_id,
        require_stable_proof=True,
    )


def _graph_payload_callbacks() -> GraphPayloadCallbacks:
    return GraphPayloadCallbacks(
        table_exists=_table_exists,
        fetch_rows=_fetch_rows,
        format_dt=_format_dt,
        reportable_cloud_validation_index=_reportable_cloud_validation_index,
        latest_cloud_validation_metadata_index=latest_cloud_validation_metadata_index,
        seed_graph_payload_for_engagement=_seed_graph_payload_for_engagement,
    )


def _seed_graph_payload_callbacks() -> SeedGraphPayloadCallbacks:
    return SeedGraphPayloadCallbacks(
        table_exists=_table_exists,
        table_columns=_table_columns,
        fetch_rows=_fetch_rows,
        safe_json_loads=_safe_json_loads,
        safe_graph_metadata=_safe_graph_metadata,
        format_dt=_format_dt,
    )


def _run_summary_callbacks() -> RunSummaryCallbacks:
    return RunSummaryCallbacks(
        table_exists=_table_exists,
        fetch_rows=_fetch_rows,
        format_dt=_format_dt,
        safe_json_loads=_safe_json_loads,
        truncate=_truncate,
        redact_error=_redact_dashboard_error,
        summarize_run_audit_manifest=summarize_run_audit_manifest,
    )


def _audit_manifest_artifact_callbacks() -> AuditManifestArtifactCallbacks:
    return AuditManifestArtifactCallbacks(
        table_exists=_table_exists,
        fetch_rows=_fetch_rows,
        summarize_run_audit_manifest=summarize_run_audit_manifest,
    )


def _validation_asset_types_for_key_service(service: str) -> list[str]:
    normalized = normalize_cloud_exposure_asset_type(service)
    return {
        "amazon": ["aws_s3"],
        "aws": ["aws_s3"],
        "azure": ["azure_blob"],
        "digitalocean": ["do_spaces"],
        "do": ["do_spaces"],
        "firebase": ["firebase"],
        "gcp": ["gcs"],
        "google": ["gcs"],
        "supabase": ["supabase"],
    }.get(normalized, [normalized] if normalized else [])


def _key_validation_detail_is_reportable(value: object) -> bool:
    return key_validation_detail_is_reportable("", value)


def _key_row_is_reportable(
    row: sqlite3.Row,
    validation_index: dict[tuple[str, str], bool],
) -> bool:
    state = str(row["validation_state"] or "").strip().upper() if "validation_state" in row.keys() else ""
    if state != "ACTIVE":
        return False
    identifier = str(row["domain"] or "").strip().lower() if "domain" in row.keys() else ""
    service = str(row["service"] or "").strip().lower() if "service" in row.keys() else ""
    validation_detail = row["validation_detail"] if "validation_detail" in row.keys() else ""
    linked_reportable = linked_key_validation_reportability(
        validation_index,
        service,
        identifier,
        validation_detail,
        asset_aliases=_validation_asset_types_for_key_service(service),
    )
    if linked_reportable is not None:
        return linked_reportable
    return key_validation_detail_is_reportable(service, validation_detail)


def _key_scanner_rows(
    con: sqlite3.Connection,
    engagement_id: int,
) -> list[sqlite3.Row]:
    return query_key_scanner_rows(
        con,
        engagement_id,
        callbacks=_detail_section_query_callbacks(),
    )


def _reportable_key_scanner_rows(
    con: sqlite3.Connection,
    engagement_id: int,
    *,
    limit: int | None = None,
) -> list[sqlite3.Row]:
    return query_reportable_key_scanner_rows(
        con,
        engagement_id,
        limit=limit,
        callbacks=_detail_section_query_callbacks(),
    )


def _key_scanner_inventory_rows(
    con: sqlite3.Connection,
    engagement_id: int,
    *,
    limit: int | None = None,
) -> list[sqlite3.Row]:
    return query_key_scanner_inventory_rows(
        con,
        engagement_id,
        limit=limit,
        callbacks=_detail_section_query_callbacks(),
    )


def _vulnerability_validation_asset(row: sqlite3.Row) -> str:
    provider = str(row["cloud_provider"] or "").strip().lower() if "cloud_provider" in row.keys() else ""
    parameter = str(row["parameter"] or "").strip().lower() if "parameter" in row.keys() else ""
    target_url = str(row["target_url"] or "").strip().lower() if "target_url" in row.keys() else ""
    hint = f"{parameter} {target_url}"
    if provider in {"firebase", "supabase"}:
        return provider
    if provider in {"aws", "amazon"} and ("s3" in hint or "aws_s3" in hint):
        return "aws_s3"
    if provider in {"gcp", "google"} and ("gcs" in hint or "gs://" in hint):
        return "gcs"
    if provider == "azure" and "blob" in hint:
        return "azure_blob"
    if provider in {"digitalocean", "do"} and "space" in hint:
        return "do_spaces"
    for value in (provider, parameter.split(":", 1)[0], urlparse(target_url).scheme):
        normalized = normalize_cloud_exposure_asset_type(value)
        if normalized:
            return normalized
    return ""


def _vulnerability_validation_identifier(row: sqlite3.Row) -> str:
    resource_id = str(row["resource_id"] or "").strip().lower() if "resource_id" in row.keys() else ""
    if resource_id:
        return resource_id
    target_url = str(row["target_url"] or "").strip()
    if target_url:
        parsed = urlparse(target_url)
        identifier = f"{parsed.netloc}/{parsed.path.strip('/')}".strip("/")
        if identifier:
            return identifier.lower()
    return ""


def _vulnerability_row_is_reportable(
    row: sqlite3.Row,
    validation_index: dict[tuple[str, str], bool],
) -> bool:
    vuln_type = str(row["vuln_type"] or "").strip().upper() if "vuln_type" in row.keys() else ""
    title = str(row["title"] or "").strip()
    asset = _vulnerability_validation_asset(row)
    identifier = _vulnerability_validation_identifier(row)
    linked_reportable = (
        linked_cloud_validation_reportability(validation_index, (asset,), identifier)
        if asset and identifier
        else None
    )
    if is_legacy_cloud_audit_finding(vuln_type):
        return legacy_cloud_audit_finding_is_reportable(
            vuln_type,
            title,
            str(row["evidence"] or "") if "evidence" in row.keys() else "",
            (asset,),
            linked_cloud_validation_reportable=linked_reportable,
        )
    if is_deterministic_cloud_exposure(vuln_type, title, (asset,)):
        if not asset or not identifier:
            return False
        reportable = validation_index.get((asset, identifier))
        return reportable is True
    if vuln_type == "DETERMINISTIC_KEY_EXPOSURE" or title.lower().startswith("active exposed "):
        identifier = _vulnerability_validation_identifier(row)
        evidence = str(row["evidence"] or "") if "evidence" in row.keys() else ""
        linked_reportable = linked_key_validation_reportability(
            validation_index,
            asset,
            identifier,
            evidence,
        )
        if linked_reportable is not None:
            return linked_reportable
        if key_validation_requires_linked_result(asset, evidence):
            return False
        proof = parse_validated_detail(evidence)
        return str(proof["validation_status"] or "").strip().upper() == "VALIDATED"
    return vulnerability_finding_evidence_is_reportable(
        vuln_type,
        title,
        str(row["evidence"] or "") if "evidence" in row.keys() else "",
        (asset,),
        linked_cloud_validation_reportable=linked_reportable,
    )


def _vulnerability_finding_section_row(row: sqlite3.Row) -> dict[str, str]:
    proof = parse_validated_detail(
        str(row["evidence"] or "") if "evidence" in row.keys() else "",
        include_raw_proof=True,
    )
    return {
        "Severity": str(row["severity"] or ""),
        "Type": str(row["vuln_type"] or ""),
        "Title": str(row["title"] or ""),
        "Target": str(row["target_url"] or ""),
        "Validation Status": str(proof["validation_status"] or ""),
        "Validation Method": str(proof["validation_method"] or ""),
        "Validation Proof": _truncate(proof["validation_proof"], 120),
        "Validation Notes": _truncate(
            proof["validation_proof"] or proof["validation_raw_proof"],
            120,
        ),
        "Seen": _format_dt(str(row["found_at"] or "")),
    }


def _reportable_vulnerability_rows(
    con: sqlite3.Connection,
    engagement_id: int,
    *,
    limit: int | None = None,
) -> list[sqlite3.Row]:
    return query_reportable_vulnerability_rows(
        con,
        engagement_id,
        limit=limit,
        callbacks=_detail_section_query_callbacks(),
    )


def _representative_vulnerability_rows(
    rows: list[sqlite3.Row],
    limit: int,
) -> list[sqlite3.Row]:
    return query_representative_vulnerability_rows(rows, limit)


def _severity_summary(con: sqlite3.Connection, engagement_id: int) -> dict[str, int]:
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for row in _reportable_vulnerability_rows(con, engagement_id):
        severity = str(row["severity"] or "INFO").upper()
        if severity not in counts:
            counts[severity] = 0
        counts[severity] += 1
    for row in _fetch_rows(
        con,
        """
        SELECT UPPER(COALESCE(severity, 'INFO')) AS severity, COUNT(*)
        FROM passive_vulns
        WHERE engagement_id=? AND COALESCE(false_positive, 0)=0
        GROUP BY UPPER(COALESCE(severity, 'INFO'))
        """,
        (engagement_id,),
    ):
        severity = str(row["severity"] or "INFO").upper()
        if severity not in counts:
            counts[severity] = 0
        counts[severity] += int(row[1] or 0)
    return counts


def _highest_severity(summary: dict[str, int]) -> str:
    for severity in SEVERITY_ORDER:
        if int(summary.get(severity, 0) or 0) > 0:
            return severity
    return "INFO"


def _severity_summary_text(summary: dict[str, int]) -> str:
    parts = [
        f"{severity[0]}:{int(summary.get(severity, 0) or 0)}"
        for severity in SEVERITY_ORDER
        if int(summary.get(severity, 0) or 0) > 0
    ]
    return " / ".join(parts) if parts else "none"


def _relative_href(source_page: Path, target_path: Path) -> str:
    return build_relative_href(source_page, target_path)


def _engagement_prefixed_artifact_files(
    reports_dir: Path,
    *,
    prefix: str,
    engagement_id: str,
    suffixes: tuple[str, ...],
) -> list[Path]:
    return list_engagement_prefixed_artifact_files(
        reports_dir,
        prefix=prefix,
        engagement_id=engagement_id,
        suffixes=suffixes,
    )


def _artifact_files(eng_id: str, reports_dir: Path) -> list[Path]:
    return list_report_artifact_files(eng_id, reports_dir)


def _audit_files(eng_id: str, reports_dir: Path) -> list[Path]:
    return list_audit_artifact_files(eng_id, reports_dir)


def _materialize_audit_manifest_artifacts(
    con: sqlite3.Connection,
    *,
    db_path: Path,
    reports_dir: Path,
    engagement_id: int,
    verify: bool,
) -> list[Path]:
    return build_audit_manifest_artifacts(
        con,
        db_path=db_path,
        reports_dir=reports_dir,
        engagement_id=engagement_id,
        verify=verify,
        callbacks=_audit_manifest_artifact_callbacks(),
    )


def _graph_files(eng_id: str, reports_dir: Path) -> list[Path]:
    return list_graph_artifact_files(eng_id, reports_dir)


def _graph_root_from_artifact(path: Path) -> ElementTree.Element | None:
    return load_graph_root_from_artifact(path)


def _graph_entity_type_to_node_type(entity_type: str) -> str:
    return normalize_graph_entity_type_to_node_type(entity_type)


def _graph_entity_properties(data: ElementTree.Element) -> tuple[str, dict[str, str]]:
    return parse_graph_entity_properties(data)


def _graph_link_properties(data: ElementTree.Element) -> dict[str, str]:
    return parse_graph_link_properties(data)


def _graph_payload_from_root(root: ElementTree.Element, *, source: str, generated_at: str) -> dict[str, Any] | None:
    return build_graph_payload_from_root(root, source=source, generated_at=generated_at)


def _graph_summary(files: list[Path]) -> dict[str, Any]:
    return summarize_graph_artifacts(files, format_dt=_format_dt)


def _graph_payload_with_defaults(
    payload: dict[str, Any] | None,
    *,
    source: str = "",
    generated_at: str = "",
) -> dict[str, Any] | None:
    return apply_graph_payload_defaults(
        payload,
        source=source,
        generated_at=generated_at,
    )


def _graph_edge_endpoints(edge: dict[str, Any]) -> tuple[str, str]:
    return graph_payload_edge_endpoints(edge)


def _graph_edge_endpoint_values(edge: dict[str, Any]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    return graph_payload_edge_endpoint_values(edge)


def _set_graph_edge_endpoints(edge: dict[str, Any], source: str, target: str) -> None:
    set_graph_payload_edge_endpoints(edge, source, target)


def _graph_node_validation_key(node: dict[str, Any]) -> tuple[str, str]:
    return graph_payload_node_validation_key(node)


def _graph_node_is_unreportable_cloud_finding(
    node: dict[str, Any],
    validation_index: dict[tuple[str, str], bool],
) -> bool:
    return is_unreportable_graph_cloud_finding(node, validation_index)


def _graph_node_key_validation_detail(node: dict[str, Any]) -> str:
    return graph_payload_node_key_validation_detail(node)


def _graph_node_is_unreportable_key_finding(
    node: dict[str, Any],
    validation_index: dict[tuple[str, str], bool],
) -> bool:
    return is_unreportable_graph_key_finding(node, validation_index)


def _graph_node_is_cloud_review_node(node: dict[str, Any]) -> bool:
    return is_graph_cloud_review_node(node)


def _refresh_graph_cloud_node_validation_metadata(
    node: dict[str, Any],
    validation_metadata_index: dict[tuple[str, str], dict[str, Any]],
) -> bool:
    return refresh_graph_cloud_node_validation_metadata(
        node,
        validation_metadata_index,
    )


def _canonical_cloud_node_score(
    node: dict[str, Any],
    asset: str,
    identifier: str,
) -> int:
    return score_canonical_graph_cloud_node(node, asset, identifier)


def _merge_cloud_node_metadata(
    target: dict[str, Any],
    duplicate: dict[str, Any],
    *,
    asset: str,
) -> None:
    merge_graph_cloud_node_metadata(target, duplicate, asset=asset)


def _dedupe_graph_payload_cloud_alias_nodes(
    payload: dict[str, Any],
) -> dict[str, Any]:
    return dedupe_cloud_alias_graph_payload_nodes(payload)


def _filter_graph_payload_for_validation(
    con: sqlite3.Connection,
    engagement_id: int,
    payload: dict[str, Any] | None,
) -> dict[str, Any] | None:
    return filter_reportable_graph_payload(
        con,
        engagement_id,
        payload,
        callbacks=_graph_payload_callbacks(),
    )


def _cloud_validation_section_row(row: sqlite3.Row) -> dict[str, str]:
    stored_type = str(row["asset_type"] or "").strip().lower()
    asset_type = normalize_cloud_exposure_asset_type(stored_type)
    stored_status = str(row["validation_status"] or "").strip().upper()
    method = str(row["validation_method"] or "").strip()
    evidence = row["evidence"]
    notes = row["notes"]
    reportable = is_reportable_cloud_validation(
        asset_type,
        stored_status,
        method,
        evidence=evidence,
        notes=notes,
        require_stable_proof=True,
    )
    return {
        "Asset": str(row["display_identifier"] or ""),
        "Type": asset_type,
        "Stored Type": stored_type,
        "Status": effective_validation_status(
            asset_type,
            stored_status,
            method,
            evidence=evidence,
            notes=notes,
            require_stable_proof=True,
        ),
        "Stored Status": stored_status,
        "Reportable": "yes" if reportable else "no",
        "Method": method,
        "HTTP": str(row["http_status"] or ""),
        "Evidence": _truncate(evidence, 120),
        "Notes": _truncate(notes, 120),
        "Checked": _format_dt(str(row["checked_at"] or "")),
    }


def _normalized_cloud_asset_type_sql(column: str) -> str:
    normalized = f"LOWER(TRIM(COALESCE({column}, '')))"
    return (
        f"CASE {normalized} "
        "WHEN 'azure_blob_storage' THEN 'azure_blob' "
        "WHEN 'digitalocean_spaces' THEN 'do_spaces' "
        "WHEN 'google_cloud_storage' THEN 'gcs' "
        "WHEN 's3' THEN 'aws_s3' "
        f"ELSE {normalized} END"
    )


def _cloud_asset_section_row(row: sqlite3.Row) -> dict[str, str]:
    stored_type = str(row["asset_type"] or "").strip().lower()
    asset_type = normalize_cloud_exposure_asset_type(stored_type)
    stored_status = str(row["validation_status"] or "").strip().upper()
    method = str(row["validation_method"] or "").strip()
    metadata = stored_cloud_asset_graph_metadata(row["metadata_json"])
    reportable = False
    if stored_status:
        reportable = is_reportable_cloud_validation(
            asset_type,
            stored_status,
            method,
            evidence=row["evidence"],
            notes=row["notes"],
            require_stable_proof=True,
        )
    return {
        "Asset": str(row["display_identifier"] or row["identifier"] or ""),
        "Type": asset_type,
        "Stored Type": stored_type,
        "Source": str(row["source"] or ""),
        "Validation": effective_validation_status(
            asset_type,
            stored_status or "UNVALIDATED",
            method,
            evidence=row["evidence"],
            notes=row["notes"],
            require_stable_proof=True,
        ),
        "Reportable": "yes" if reportable else "no",
        "Method": method,
        "Provenance": _relation_evidence_preview(metadata),
        "Discovered": _format_dt(str(row["discovered_at"] or "")),
        "Checked": _format_dt(str(row["checked_at"] or "")),
    }


def _audit_section_row(row: sqlite3.Row) -> dict[str, str]:
    action = str(row["action"] or "")
    result = (
        _redact_dashboard_error(row["result"], 96)
        if action in _SCOPE_BOUNDARY_DENIAL_ACTIONS
        else _truncate(row["result"], 96)
    )
    return {
        "When": _format_dt(str(row["logged_at"] or "")),
        "Phase": str(row["phase"] or ""),
        "Module": str(row["module"] or ""),
        "Action": action,
        "Target": _truncate(row["target"], 96),
        "Result": result,
    }


def _parse_graph_payload(raw: str) -> dict[str, Any] | None:
    return parse_json_graph_payload(raw)


def _graph_payload_has_structure(payload: dict[str, Any] | None) -> bool:
    return has_graph_payload_structure(payload)


def _graph_summary_from_payload(payload: dict[str, Any], source: str) -> dict[str, Any]:
    return summarize_graph_payload(payload, source)


def _graph_payload_from_graphml(graphml_path: Path) -> dict[str, Any] | None:
    return build_graph_payload_from_graphml(graphml_path)


def _seed_graph_node_type(seed_type: str) -> str:
    return build_seed_graph_node_type(seed_type)


def _seed_graph_severity(
    confidence_band: str,
    confidence: float,
) -> str:
    return build_seed_graph_severity(confidence_band, confidence)


def _seed_graph_payload_for_engagement(
    con: sqlite3.Connection,
    engagement_id: int,
) -> tuple[dict[str, Any] | None, str]:
    return build_seed_graph_payload_for_engagement(
        con,
        engagement_id,
        callbacks=_seed_graph_payload_callbacks(),
    )


def _graph_payload_for_engagement(
    con: sqlite3.Connection,
    engagement_id: int,
    graph_files: list[Path],
) -> tuple[dict[str, Any] | None, str]:
    return build_graph_payload_for_engagement(
        con,
        engagement_id,
        graph_files,
        callbacks=_graph_payload_callbacks(),
    )


def _graph_state_for_engagement(
    con: sqlite3.Connection,
    engagement_id: int,
    graph_files: list[Path],
) -> tuple[dict[str, Any], dict[str, Any] | None, str]:
    return build_graph_state_for_engagement(
        con,
        engagement_id,
        graph_files,
        callbacks=_graph_payload_callbacks(),
    )


def _site_root(output_path: Path) -> Path:
    return dashboard_site_root(output_path)


def _prepare_dashboard_site(output_path: Path) -> DashboardSitePaths:
    return prepare_dashboard_site(output_path)


def _assign_engagement_dashboard_routes(
    engagement: dict[str, Any],
    paths: DashboardSitePaths,
) -> dict[str, Any]:
    return assign_engagement_dashboard_routes(engagement, paths)


def _write_engagement_dashboard_outputs(
    engagement: dict[str, Any],
    paths: DashboardSitePaths,
) -> None:
    write_engagement_dashboard_outputs(
        engagement,
        paths,
        render_engagement_page=_render_engagement_page,
        engagement_detail_payload=_engagement_detail_payload,
    )


def _write_dashboard_overview_outputs(
    engagements: list[dict[str, Any]],
    output_path: Path,
    paths: DashboardSitePaths,
    *,
    generated_at: str,
) -> None:
    write_dashboard_overview_outputs(
        engagements,
        output_path,
        paths,
        generated_at=generated_at,
        render_overview_page=_render_overview_page,
        engagement_index_payload=_engagement_index_payload,
    )


def _artifact_payload(root_page: Path, artifact: Path, *, kind: str) -> dict[str, Any]:
    return build_artifact_payload(root_page, artifact, kind=kind, format_dt=_format_dt)


def _annotate_audit_manifest_bundle(
    run_summary: dict[str, Any] | None,
    artifacts: list[dict[str, Any]],
) -> dict[str, Any] | None:
    return annotate_run_audit_manifest_bundle(run_summary, artifacts)


def _report_preview_payload(root_page: Path, artifact: Path) -> dict[str, str]:
    return build_report_preview_payload(root_page, artifact)


def _engagement_db_files(data_dir: Path, *, include_legacy: bool = True) -> list[Path]:
    return list_engagement_db_files(data_dir, include_legacy=include_legacy)


def _seed_list(con: sqlite3.Connection, engagement_id: int, scope: list[str]) -> list[str]:
    seeds: list[str] = []
    seen: set[str] = set()
    if _table_exists(con, "engagement_seeds"):
        for row in _fetch_rows(
            con,
            """
            SELECT seed_value
            FROM engagement_seeds
            WHERE engagement_id=?
            ORDER BY depth ASC, id ASC
            """,
            (engagement_id,),
        ):
            value = str(row["seed_value"] or "").strip()
            if value and value not in seen:
                seeds.append(value)
                seen.add(value)
    for row in _fetch_rows(
        con,
        """
        SELECT target
        FROM audit_log
        WHERE engagement_id=? AND action='kill_chain_start'
        ORDER BY id ASC
        """,
        (engagement_id,),
    ):
        value = str(row["target"] or "").strip()
        if value and value not in seen:
            seeds.append(value)
            seen.add(value)

    for item in scope:
        value = str(item or "").strip()
        if value and value not in seen:
            seeds.append(value)
            seen.add(value)
    return seeds


def _summary_counts(con: sqlite3.Connection, engagement_id: int) -> dict[str, int]:
    return build_summary_counts(
        con,
        engagement_id,
        callbacks=_engagement_summary_callbacks(),
    )


def _latest_engagement_run(
    con: sqlite3.Connection,
    engagement_id: int,
    db_path: Path | None = None,
    verify_manifest: bool = True,
) -> dict[str, Any] | None:
    return build_latest_engagement_run(
        con,
        engagement_id,
        db_path=db_path,
        verify_manifest=verify_manifest,
        callbacks=_run_summary_callbacks(),
    )


def _seed_graph_summary(con: sqlite3.Connection, engagement_id: int) -> dict[str, Any]:
    return build_seed_graph_summary(
        con,
        engagement_id,
        callbacks=_graph_summary_callbacks(),
    )


def _relation_evidence_preview(evidence: Any) -> str:
    if isinstance(evidence, dict):
        rule = str(evidence.get("rule") or "").strip()
        extract_rule = str(evidence.get("extract_rule") or "").strip()
        artifactish = (
            rule == "artifact_seed_provenance"
            or rule.startswith("artifact_")
            or extract_rule.startswith("artifact_")
            or any(
                key in evidence
                for key in (
                    "source_file",
                    "extract_path",
                    "parser",
                    "format",
                    "payload_count",
                    "metadata_payload_count",
                    "relationship_payload_count",
                )
            )
        )
        if artifactish:
            parts: list[str] = []
            for key in ("rule", "extract_rule", "parser", "format", "artifact_type"):
                value = str(evidence.get(key) or "").strip()
                if value:
                    parts.append(f"{key}={value}")
            for key in (
                "payload_count",
                "metadata_payload_count",
                "relationship_payload_count",
                "ocr_payload_count",
            ):
                value = evidence.get(key)
                if value not in (None, ""):
                    parts.append(f"{key}={value}")
            source_summary = _crawl_source_summary(evidence)
            if source_summary:
                parts.append(f"sources={source_summary}")
            root_domain = str(evidence.get("root_domain") or "").strip()
            if root_domain:
                parts.append(f"root={root_domain}")
            source_url = str(evidence.get("source_url") or "").strip()
            if source_url:
                parts.append(f"source={_truncate(source_url, 64)}")
            source_file = str(evidence.get("source_file") or "").strip()
            if source_file and source_file != source_url:
                parts.append(f"file={_truncate(source_file, 48)}")
            extract_path = str(evidence.get("extract_path") or "").strip()
            if extract_path:
                parts.append(f"extract={_truncate(extract_path, 48)}")
            if parts:
                return _truncate(" ".join(parts), 180)
        preferred = []
        for key in ("rule", "service", "ref", "source_url", "artifact_type"):
            value = str(evidence.get(key) or "").strip()
            if value:
                preferred.append(f"{key}={value}")
        if preferred:
            return _truncate(", ".join(preferred), 96)
        compact = json.dumps(evidence, sort_keys=True)
        return _truncate(compact, 96)
    if evidence is None:
        return ""
    return _truncate(str(evidence), 96)


def _artifact_metadata_brief(metadata: Any) -> str:
    if not isinstance(metadata, dict):
        return ""
    parts: list[str] = []
    fmt = str(metadata.get("format") or "").strip()
    if fmt:
        parts.append(f"fmt={fmt}")
    payload_count = metadata.get("payload_count")
    if payload_count not in (None, ""):
        parts.append(f"payloads={payload_count}")
    meta_count = metadata.get("metadata_payload_count")
    if meta_count not in (None, ""):
        parts.append(f"meta={meta_count}")
    rel_count = metadata.get("relationship_payload_count")
    if rel_count not in (None, ""):
        parts.append(f"rels={rel_count}")
    content_type = str(metadata.get("content_type") or "").strip()
    if content_type:
        parts.append(f"type={_truncate(content_type, 48)}")
    download_filename = str(metadata.get("download_filename") or "").strip()
    if download_filename:
        filename = download_filename.replace("\\", "/").rsplit("/", 1)[-1]
        parts.append(f"file={_truncate(filename, 48)}")
    return " ".join(parts[:6])


def _artifact_queue_section_row(row: sqlite3.Row) -> dict[str, str]:
    return {
        "Artifact": str(row["source_url"] or ""),
        "Type": str(row["artifact_type"] or ""),
        "Status": str(row["status"] or ""),
        "Origin": str(row["discovered_from"] or ""),
        "Source": _crawl_source_summary(row["metadata_json"]),
        "Local": _truncate(row["local_path"], 96),
        "Meta": _artifact_metadata_brief(
            _safe_json_loads(str(row["metadata_json"] or "{}"))
        ),
        "Notes": _truncate(row["notes"], 96),
        "Queued": _format_dt(str(row["queued_at"] or "")),
    }


def _email_intelligence_brief(source: str, breach_names: Any, enrichment_data: Any) -> str:
    source_key = str(source or "").strip().lower()
    parsed_breach_names = breach_names
    if isinstance(parsed_breach_names, str):
        maybe_names = _safe_json_loads(parsed_breach_names)
        if maybe_names is not None:
            parsed_breach_names = maybe_names
    parsed_enrichment = enrichment_data
    if isinstance(parsed_enrichment, str):
        maybe_data = _safe_json_loads(parsed_enrichment)
        if maybe_data is not None:
            parsed_enrichment = maybe_data
    if source_key == "emailrep" and isinstance(parsed_enrichment, dict):
        details = (
            parsed_enrichment.get("details")
            if isinstance(parsed_enrichment.get("details"), dict)
            else {}
        )
        profiles = details.get("profiles") if isinstance(details, dict) else []
        parts: list[str] = []
        reputation = str(parsed_enrichment.get("reputation") or "").strip()
        if reputation:
            parts.append(f"rep={reputation}")
        suspicious = parsed_enrichment.get("suspicious")
        if isinstance(suspicious, bool):
            parts.append(f"suspicious={'yes' if suspicious else 'no'}")
        blacklisted = details.get("blacklisted") if isinstance(details, dict) else None
        if isinstance(blacklisted, bool):
            parts.append(f"blacklisted={'yes' if blacklisted else 'no'}")
        if isinstance(profiles, list) and profiles:
            parts.append(f"profiles={len(profiles)}")
        if parts:
            return " ".join(parts)
    if isinstance(parsed_breach_names, list) and parsed_breach_names:
        preview = ", ".join(str(item) for item in parsed_breach_names[:3] if str(item).strip())
        if preview:
            return _truncate(preview, 120)
    return _preview_json(parsed_enrichment, limit=120)


def _email_intelligence_section_row(row: sqlite3.Row) -> dict[str, str]:
    return {
        "Email": str(row["email"] or ""),
        "Source": str(row["source"] or ""),
        "Breaches": str(row["breach_count"] or 0),
        "Pastes": str(row["paste_count"] or 0),
        "Signals": _email_intelligence_brief(
            str(row["source"] or ""),
            row["breach_names"],
            row["enrichment_data"],
        ),
        "Seen": _format_dt(str(row["seen_at"] or "")),
    }


def _account_existence_section_row(row: sqlite3.Row) -> dict[str, str]:
    return {
        "Email": str(row["email"] or ""),
        "Service": str(row["service"] or ""),
        "Exists": "yes" if int(row["exists_flag"] or 0) == 1 else "no",
        "Rate Limited": "yes" if int(row["rate_limited"] or 0) == 1 else "no",
        "Source": str(row["source_tool"] or ""),
        "Seen": _format_dt(str(row["seen_at"] or "")),
    }


def _cti_observation_section_row(row: sqlite3.Row) -> dict[str, str]:
    tags = _safe_json_loads(str(row["tags_json"] or "[]"))
    if not isinstance(tags, list):
        tags = []
    return {
        "Provider": str(row["provider"] or ""),
        "Type": str(row["indicator_type"] or ""),
        "Indicator": str(row["indicator_value"] or ""),
        "Confidence": str(row["confidence"] or ""),
        "TLP": str(row["tlp"] or ""),
        "Method": str(row["collection_method"] or ""),
        "Reliability": str(row["source_reliability"] or ""),
        "Provenance": _truncate(row["provenance"], 120),
        "Source": _truncate(row["source_url"], 120),
        "Artifact Hash": _truncate(row["raw_artifact_hash"], 24),
        "Tags": _truncate(", ".join(str(tag) for tag in tags if str(tag).strip()), 120),
        "Reportable": "no",
        "Observed": _format_dt(str(row["observed_at"] or "")),
        "Imported": _format_dt(str(row["created_at"] or "")),
    }


def _engagement_seed_section_row(row: sqlite3.Row) -> dict[str, str]:
    metadata = _safe_json_loads(str(row["metadata_json"] or "{}"))
    synthesis = metadata.get("synthesis") if isinstance(metadata, dict) else {}
    corroborator_count = (
        int(synthesis.get("corroborating_seed_count") or 0)
        if isinstance(synthesis, dict)
        else 0
    )
    corroborator_types = (
        synthesis.get("corroborating_seed_types") if isinstance(synthesis, dict) else []
    )
    type_preview = (
        ", ".join(
            str(item)
            for item in list(corroborator_types)[:3]
            if str(item).strip()
        )
        if isinstance(corroborator_types, list)
        else ""
    )
    corroborated_by = str(corroborator_count)
    if type_preview:
        corroborated_by = f"{corroborated_by} ({type_preview})"
    return {
        "Seed": str(row["seed_value"] or ""),
        "Type": str(row["seed_type"] or ""),
        "Source": str(row["source"] or ""),
        "Status": str(row["status"] or ""),
        "Depth": str(row["depth"] or ""),
        "Conf": str(row["confidence"] or ""),
        "Band": (
            str(synthesis.get("confidence_band") or "")
            if isinstance(synthesis, dict)
            else ""
        ),
        "Relations": (
            str(synthesis.get("supporting_relations") or 0)
            if isinstance(synthesis, dict)
            else "0"
        ),
        "CorroboratedBy": corroborated_by,
    }


def _seed_relation_section_row(row: sqlite3.Row) -> dict[str, str]:
    return {
        "From": f"{str(row['source_seed'] or '')} [{str(row['source_type'] or '')}]",
        "Relation": str(row["relation_type"] or ""),
        "To": f"{str(row['target_seed'] or '')} [{str(row['target_type'] or '')}]",
        "Conf": str(row["confidence"] or ""),
        "Evidence": _relation_evidence_preview(
            _safe_json_loads(str(row["evidence_json"] or "{}"))
        ),
        "Seen": _format_dt(str(row["discovered_at"] or "")),
    }


def _seed_run_section_row(row: sqlite3.Row) -> dict[str, str]:
    return {
        "Seed": str(row["seed_value"] or ""),
        "Type": str(row["seed_type"] or ""),
        "Loop": str(row["loop_name"] or ""),
        "Status": str(row["status"] or ""),
        "In": str(row["input_count"] or ""),
        "Out": str(row["output_count"] or ""),
        "Started": _format_dt(str(row["started_at"] or "")),
        "Completed": _format_dt(str(row["completed_at"] or "")),
        "Error": _redact_dashboard_error(row["error"], 96),
    }


def _service_section_row(row: sqlite3.Row) -> dict[str, str]:
    return {
        "Host": str(row["hostname"] or row["ip"] or ""),
        "Port": str(row["port"] or ""),
        "Proto": str(row["protocol"] or ""),
        "Service": str(row["service_name"] or ""),
        "Version": str(row["version"] or ""),
        "Seen": _format_dt(str(row["discovered_at"] or "")),
    }


def _crawl_result_section_row(row: sqlite3.Row) -> dict[str, str]:
    return {
        "URL": str(row["resolved_url"] or ""),
        "Source": _crawl_source_summary(row["tech_stack_json"]),
        "Title": str(row["title"] or ""),
        "Screenshot": str(row["screenshot_path"] or ""),
        "Tech": _preview_json(row["tech_stack_json"]),
        "Seen": _format_dt(str(row["discovered_at"] or "")),
    }


def _social_profile_section_row(row: sqlite3.Row) -> dict[str, str]:
    return {
        "Email": str(row["email"] or ""),
        "Source": str(row["source"] or ""),
        "Details": _preview_json(row["profile_data"]),
        "Seen": _format_dt(str(row["queried_at"] or "")),
    }


def _port_scan_result_section_row(row: sqlite3.Row) -> dict[str, str]:
    return {
        "Host": str(row["host"] or ""),
        "Port": str(row["port"] or ""),
        "Proto": str(row["proto"] or ""),
        "Service": str(row["service"] or ""),
        "Version": str(row["version"] or ""),
        "Conf": str(row["confidence"] or ""),
        "Seen": _format_dt(str(row["scanned_at"] or "")),
    }


def _passive_vuln_section_row(row: sqlite3.Row) -> dict[str, str]:
    return {
        "Severity": str(row["severity"] or ""),
        "Plugin": str(row["plugin"] or ""),
        "Vuln": str(row["vuln_id"] or ""),
        "Verified": "yes" if int(row["verified"] or 0) else "no",
        "False+": "yes" if int(row["false_positive"] or 0) else "no",
        "URL": str(row["url"] or ""),
        "Seen": _format_dt(str(row["discovered_at"] or "")),
    }


def _auth_test_result_section_row(row: sqlite3.Row) -> dict[str, str]:
    return {
        "Target": str(row["target_url"] or ""),
        "Type": str(row["attack_type"] or ""),
        "Success": "yes" if int(row["success"] or 0) else "no",
        "Tested": _format_dt(str(row["tested_at"] or "")),
    }


def _key_scanner_finding_section_row(row: sqlite3.Row) -> dict[str, str]:
    proof = parse_validated_detail(row["validation_detail"], include_raw_proof=True)
    return {
        "Domain": str(row["domain"] or ""),
        "Service": str(row["service"] or ""),
        "Pattern": str(row["pattern_name"] or ""),
        "State": str(row["validation_state"] or ""),
        "Backend": str(row["source_backend"] or ""),
        "Source": _safe_dashboard_source_url(row["source_url"]),
        "Repository": str(row["repo_name"] or ""),
        "Validation Status": str(proof["validation_status"] or ""),
        "Validation Method": str(proof["validation_method"] or ""),
        "Validation Proof": _truncate(proof["validation_proof"], 120),
        "Validation Notes": _truncate(
            proof["validation_proof"] or proof["validation_raw_proof"],
            120,
        ),
        "Proof": _truncate(row["validation_detail"], 120),
        "Validated": _format_dt(str(row["validated_at"] or "")),
        "Seen": _format_dt(str(row["found_at"] or "")),
    }


def _host_inventory_section_row(row: dict[str, str]) -> dict[str, str]:
    return {
        "Host": str(row["hostname"] or ""),
        "IP": str(row["ip"] or ""),
        "OS": str(row["os_family"] or ""),
        "Source": str(row["source"] or ""),
        "Seen": _format_dt(str(row["discovered_at"] or "")),
    }


def _email_inventory_section_row(row: dict[str, str]) -> dict[str, str]:
    return {
        "Email": str(row["email"] or ""),
        "Domain": str(row["domain"] or ""),
        "Source": str(row["source"] or ""),
        "Seen": _format_dt(str(row["first_seen_at"] or "")),
    }


def _engagement_run_section_row(
    row: sqlite3.Row,
    manifest: dict[str, Any] | None = None,
) -> dict[str, str]:
    return build_engagement_run_section_row(
        row,
        manifest,
        safe_json_loads=_safe_json_loads,
        format_dt=_format_dt,
        truncate=_truncate,
        redact_error=_redact_dashboard_error,
    )


def _detail_row_formatters() -> DetailRowFormatters:
    return DetailRowFormatters(
        format_dt=_format_dt,
        truncate=_truncate,
        safe_json_loads=_safe_json_loads,
        redact_error=_redact_dashboard_error,
        preview_json=_preview_json,
        safe_graph_metadata=_safe_graph_metadata,
    )


def _detail_section_query_callbacks() -> DetailSectionQueryCallbacks:
    return DetailSectionQueryCallbacks(
        table_exists=_table_exists,
        table_columns=_table_columns,
        fetch_rows=_fetch_rows,
        distributed_task_row=_distributed_task_section_row,
        monitoring_policy_row=_monitoring_policy_section_row,
        monitoring_alert_route_row=_monitoring_alert_route_section_row,
        monitoring_alert_suppression_row=_monitoring_alert_suppression_section_row,
        monitoring_snapshot_row=_monitoring_snapshot_section_row,
        monitoring_trend_row=_monitoring_trend_section_row,
        monitoring_change_row=_monitoring_change_section_row,
        monitoring_alert_row=_monitoring_alert_section_row,
        remediation_item_row=_remediation_item_section_row,
        remediation_review_queue_row=_remediation_review_queue_section_row,
        remediation_review_queue=remediation_review_queue,
        asset_entity_row=_asset_entity_section_row,
        asset_relationship_row=_asset_relationship_section_row,
        asset_ownership_claim_row=_asset_ownership_claim_section_row,
        asset_ownership_conflict_row=_asset_ownership_conflict_section_row,
        asset_graph_attack_path_row=_asset_graph_attack_path_section_row,
        asset_graph_choke_point_row=_asset_graph_choke_point_section_row,
        asset_graph_fix_candidate_row=_asset_graph_fix_candidate_section_row,
        ownership_conflicts_for_engagement=ownership_conflicts_for_engagement,
        list_asset_graph=list_asset_graph,
        active_validation_coverage_rows=_active_validation_coverage_section_rows,
        active_validation_job_row=_active_validation_job_section_row,
        active_validation_run_row=_active_validation_run_section_row,
        audit_row=_audit_section_row,
        engagement_seed_row=_engagement_seed_section_row,
        seed_relation_row=_seed_relation_section_row,
        seed_run_row=_seed_run_section_row,
        host_inventory_row=_host_inventory_section_row,
        email_inventory_row=_email_inventory_section_row,
        email_intelligence_row=_email_intelligence_section_row,
        account_existence_row=_account_existence_section_row,
        engagement_run_row=_engagement_run_section_row,
        summarize_run_audit_manifest=summarize_run_audit_manifest,
        service_row=_service_section_row,
        crawl_result_row=_crawl_result_section_row,
        social_profile_row=_social_profile_section_row,
        port_scan_result_row=_port_scan_result_section_row,
        passive_vuln_row=_passive_vuln_section_row,
        auth_test_result_row=_auth_test_result_section_row,
        key_scanner_row=_key_scanner_finding_section_row,
        key_row_is_reportable=_key_row_is_reportable,
        secret_lifecycle_row=_secret_lifecycle_section_row,
        vulnerability_finding_row=_vulnerability_finding_section_row,
        vulnerability_row_is_reportable=_vulnerability_row_is_reportable,
        reportable_cloud_validation_index=_reportable_cloud_validation_index,
        artifact_queue_row=_artifact_queue_section_row,
        cti_observation_row=_cti_observation_section_row,
        cloud_asset_row=_cloud_asset_section_row,
        cloud_validation_row=_cloud_validation_section_row,
        normalized_cloud_asset_type_sql=_normalized_cloud_asset_type_sql,
        retention_policy_row=_retention_policy_section_row,
        retention_run_row=_retention_run_section_row,
        retention_run_item_row=_retention_run_item_section_row,
    )


def _engagement_summary_callbacks() -> EngagementSummaryCallbacks:
    return EngagementSummaryCallbacks(
        connect_readonly=_connect_readonly,
        table_exists=_table_exists,
        table_columns=_table_columns,
        fetch_rows=_fetch_rows,
        fetch_count=_fetch_count,
        format_dt=_format_dt,
        safe_json_loads=_safe_json_loads,
        scope_entries_from_payload=scope_entries_from_payload,
        engagement_tags=_engagement_tags,
        merged_host_rows=_merged_host_rows,
        merged_email_rows=_merged_email_rows,
        reportable_key_scanner_rows=_reportable_key_scanner_rows,
        reportable_vulnerability_rows=_reportable_vulnerability_rows,
        ownership_conflicts_for_engagement=ownership_conflicts_for_engagement,
        severity_summary=_severity_summary,
        highest_severity=_highest_severity,
        detail_sections=_detail_sections,
        latest_engagement_run=_latest_engagement_run,
        seed_graph_summary=_seed_graph_summary,
        asset_graph_summary=_asset_graph_summary,
        seed_list=_seed_list,
        slugify=_slugify,
    )


def _graph_summary_callbacks() -> GraphSummaryCallbacks:
    return GraphSummaryCallbacks(
        table_exists=_table_exists,
        fetch_rows=_fetch_rows,
        fetch_count=_fetch_count,
        safe_json_loads=_safe_json_loads,
        ownership_conflicts_for_engagement=ownership_conflicts_for_engagement,
        list_asset_graph=list_asset_graph,
    )


def _distributed_task_type(task_key: str, payload: Any) -> str:
    return distributed_task_type(task_key, payload, truncate=_truncate)


def _distributed_task_section_row(row: sqlite3.Row) -> dict[str, str]:
    return build_distributed_task_section_row(
        row,
        formatters=_detail_row_formatters(),
    )


def _monitoring_entity_label(payload: Any, fallback: str) -> str:
    return monitoring_entity_label(payload, fallback, truncate=_truncate)


def _monitoring_policy_section_row(row: sqlite3.Row) -> dict[str, str]:
    return build_monitoring_policy_section_row(row, format_dt=_format_dt)


def _monitoring_alert_route_section_row(row: sqlite3.Row) -> dict[str, str]:
    return build_monitoring_alert_route_section_row(
        row,
        format_dt=_format_dt,
        truncate=_truncate,
    )


def _monitoring_alert_suppression_section_row(row: sqlite3.Row) -> dict[str, str]:
    return build_monitoring_alert_suppression_section_row(
        row,
        format_dt=_format_dt,
        truncate=_truncate,
    )


def _remediation_item_section_row(row: sqlite3.Row) -> dict[str, str]:
    risk_review = risk_acceptance_review_status(
        str(row["status"] or ""),
        str(row["risk_acceptance_expires_at"] or ""),
    )
    return {
        "Severity": str(row["severity"] or ""),
        "Status": str(row["status"] or ""),
        "Owner": str(row["owner"] or ""),
        "SLA": _format_dt(str(row["sla_due_at"] or "")),
        "Risk Expiry": _format_dt(str(row["risk_acceptance_expires_at"] or "")),
        "Risk Review": risk_review or "-",
        "Finding": _truncate(f"{row['finding_table']}:{row['finding_ref']}", 120),
        "Title": _truncate(str(row["title"] or ""), 140),
        "Retest": str(row["retest_status"] or ""),
        "Ticket": _truncate(str(row["ticket_ref"] or row["ticket_url"] or ""), 120),
        "Updated": _format_dt(str(row["updated_at"] or "")),
    }


def _remediation_review_queue_section_row(item: dict[str, Any]) -> dict[str, str]:
    labels = item.get("queue_reason_labels") if isinstance(item.get("queue_reason_labels"), list) else []
    ticket_event = item.get("latest_ticket_event") if isinstance(item.get("latest_ticket_event"), dict) else {}
    ticket_sync = ""
    if ticket_event:
        ticket_sync = " ".join(
            part
            for part in (
                str(ticket_event.get("connector") or ""),
                str(ticket_event.get("status") or ""),
            )
            if part.strip()
        )
    return {
        "Priority": str(item.get("review_priority") or 0),
        "Reason": _truncate(", ".join(str(label) for label in labels if str(label).strip()), 180),
        "Severity": str(item.get("severity") or ""),
        "Status": str(item.get("status") or ""),
        "Owner": str(item.get("owner") or ""),
        "SLA": _format_dt(str(item.get("sla_due_at") or "")),
        "Retest": str(item.get("retest_status") or ""),
        "Ticket": _truncate(str(item.get("ticket_label") or ""), 120),
        "Ticket Sync": _truncate(ticket_sync, 120),
        "Sync Attempts": str(ticket_event.get("attempt_count") or "") if ticket_event else "",
        "Sync Error": _truncate(str(ticket_event.get("last_error") or ""), 180),
        "Finding": _truncate(f"{item.get('finding_table') or 'manual'}:{item.get('finding_ref') or ''}", 120),
        "Title": _truncate(str(item.get("title") or ""), 140),
        "Updated": _format_dt(str(item.get("updated_at") or "")),
    }


def _secret_revocation_summary(value: Any) -> str:
    parsed = _safe_json_loads(str(value or "{}")) if isinstance(value, str) else value
    if not isinstance(parsed, dict):
        return _preview_json(parsed, 180)
    summary = str(
        parsed.get("rotation_summary")
        or parsed.get("validation_after_revocation")
        or ""
    ).strip()
    docs = parsed.get("provider_docs")
    doc_preview = ""
    if isinstance(docs, list):
        doc_preview = ", ".join(str(item) for item in docs[:2] if str(item or "").strip())
    if summary and doc_preview:
        return _truncate(f"{summary} docs={doc_preview}", 180)
    if summary:
        return _truncate(summary, 180)
    return _preview_json(_safe_graph_metadata(parsed), 180)


def _secret_prevention_summary(value: Any) -> str:
    parsed = _safe_json_loads(str(value or "[]")) if isinstance(value, str) else value
    if not isinstance(parsed, list):
        return _preview_json(parsed, 180)
    labels: list[str] = []
    for item in parsed:
        if not isinstance(item, dict):
            continue
        tool = str(item.get("tool") or "").strip()
        workflow = str(item.get("workflow") or "").strip()
        cost = str(item.get("cost") or "").strip()
        label = ":".join(part for part in (tool, workflow) if part)
        if cost and label:
            label = f"{label} ({cost})"
        if label:
            labels.append(label)
    return _truncate(", ".join(labels[:5]), 180)


def _secret_lifecycle_section_row(row: sqlite3.Row) -> dict[str, str]:
    metadata = _safe_graph_metadata(_safe_json_loads(str(row["metadata_json"] or "{}")))
    remediation_status = str(row["remediation_status"] or "").strip()
    remediation_id = str(row["remediation_id"] or "").strip()
    remediation = "-"
    if remediation_id and remediation_status:
        remediation = f"#{remediation_id} {remediation_status}"
    elif remediation_status:
        remediation = remediation_status
    elif remediation_id:
        remediation = f"#{remediation_id}"
    return {
        "Key": str(row["key_finding_id"] or ""),
        "Service": str(row["service"] or ""),
        "Pattern": str(row["pattern_name"] or ""),
        "Lifecycle": str(row["lifecycle_status"] or ""),
        "Owner": str(row["owner"] or "") or "-",
        "Owner Source": str(row["owner_source"] or "") or "-",
        "Suppressed": "yes" if int(row["suppressed"] or 0) else "no",
        "Suppression": str(row["suppression_id"] or "") or "-",
        "Remediation": remediation,
        "Source": _safe_dashboard_source_url(row["source_url"]),
        "Repository": str(row["repo_name"] or ""),
        "Guidance": _secret_revocation_summary(row["revocation_guidance_json"]),
        "Prevention": _secret_prevention_summary(row["prevention_guidance_json"]),
        "Meta": _preview_json(metadata, 120),
        "Updated": _format_dt(str(row["updated_at"] or "")),
    }


def _monitoring_snapshot_section_row(row: sqlite3.Row) -> dict[str, str]:
    return build_monitoring_snapshot_section_row(
        row,
        formatters=_detail_row_formatters(),
    )


def _monitoring_trend_section_row(row: sqlite3.Row) -> dict[str, str]:
    return build_monitoring_trend_section_row(row, format_dt=_format_dt)


def _monitoring_change_section_row(row: sqlite3.Row) -> dict[str, str]:
    return build_monitoring_change_section_row(
        row,
        formatters=_detail_row_formatters(),
    )


def _monitoring_alert_section_row(row: sqlite3.Row) -> dict[str, str]:
    return build_monitoring_alert_section_row(
        row,
        formatters=_detail_row_formatters(),
    )


def _exposure_duration_metric_section_row(item: dict[str, Any]) -> dict[str, str]:
    open_days = item.get("open_days")
    mttr_hours = item.get("mttr_hours")
    return {
        "Key": _safe_dashboard_source_url(item.get("key"), 160),
        "Title": _truncate(item.get("title"), 120),
        "Severity": str(item.get("severity") or "INFO"),
        "State": "open" if item.get("is_open") else "closed",
        "First Seen": _format_dt(str(item.get("first_seen") or "")),
        "Last Seen": _format_dt(str(item.get("last_seen") or "")),
        "Closed": _format_dt(str(item.get("closed_at") or "")) or "-",
        "Open Days": "-" if open_days is None else str(open_days),
        "Recurrence": str(item.get("recurrence") or 0),
        "MTTR Hours": "-" if mttr_hours is None else str(mttr_hours),
        "Proof": ", ".join(str(value) for value in item.get("proof_types") or []) or "-",
        "Sources": ", ".join(str(value) for value in item.get("source_kinds") or []) or "-",
    }


def _retention_days_label(value: Any) -> str:
    return retention_days_label(value)


def _retention_policy_section_row(row: sqlite3.Row) -> dict[str, str]:
    return build_retention_policy_section_row(
        row,
        formatters=_detail_row_formatters(),
    )


def _retention_run_section_row(row: sqlite3.Row) -> dict[str, str]:
    return build_retention_run_section_row(
        row,
        formatters=_detail_row_formatters(),
    )


def _retention_run_item_section_row(row: sqlite3.Row) -> dict[str, str]:
    return build_retention_run_item_section_row(
        row,
        format_dt=_format_dt,
        truncate=_truncate,
    )


def _asset_entity_section_row(row: sqlite3.Row) -> dict[str, str]:
    metadata = _safe_json_loads(str(row["metadata_json"] or "{}"))
    return {
        "Type": str(row["entity_type"] or ""),
        "Label": _truncate(str(row["label"] or ""), 120),
        "Key": _truncate(str(row["entity_key"] or ""), 120),
        "Confidence": f"{float(row['confidence'] or 0):.2f}",
        "Source": _truncate(
            ":".join(
                part
                for part in (
                    str(row["source_table"] or ""),
                    str(row["source_id"] or "") if row["source_id"] is not None else "",
                )
                if part
            ),
            96,
        ),
        "Meta": _preview_json(_safe_graph_metadata(metadata), 120),
        "Updated": _format_dt(str(row["updated_at"] or "")),
    }


def _asset_relationship_section_row(row: sqlite3.Row) -> dict[str, str]:
    evidence = _safe_json_loads(str(row["evidence_json"] or "{}"))
    return {
        "Type": str(row["relationship_type"] or ""),
        "From": _truncate(str(row["source_label"] or row["source_key"] or ""), 96),
        "To": _truncate(str(row["target_label"] or row["target_key"] or ""), 96),
        "Confidence": f"{float(row['confidence'] or 0):.2f}",
        "Evidence": _preview_json(_safe_graph_metadata(evidence), 120),
        "Updated": _format_dt(str(row["updated_at"] or "")),
    }


def _asset_ownership_claim_section_row(row: sqlite3.Row) -> dict[str, str]:
    evidence = _safe_json_loads(str(row["evidence_json"] or "{}"))
    return {
        "Asset": _truncate(str(row["entity_label"] or row["entity_key"] or ""), 120),
        "Owner": _truncate(str(row["owner_display"] or row["owner_ref"] or ""), 120),
        "Kind": str(row["owner_kind"] or ""),
        "Claim": str(row["claim_type"] or ""),
        "Status": str(row["status"] or ""),
        "Confidence": f"{float(row['confidence'] or 0):.2f}",
        "Source": _truncate(str(row["source"] or ""), 80),
        "Evidence": _preview_json(_safe_graph_metadata(evidence), 120),
    }


def _asset_ownership_conflict_section_row(conflict: dict[str, Any]) -> dict[str, str]:
    owners = conflict.get("owners") if isinstance(conflict, dict) else []
    owner_labels: list[str] = []
    if isinstance(owners, list):
        for owner in owners[:5]:
            if not isinstance(owner, dict):
                continue
            display = str(owner.get("owner_display") or owner.get("owner_ref") or "").strip()
            owner_ref = str(owner.get("owner_ref") or "").strip()
            confidence = float(owner.get("confidence") or 0.0)
            label = display or owner_ref
            if owner_ref and owner_ref != display:
                label = f"{label} [{owner_ref}]"
            owner_labels.append(f"{label} ({confidence:.2f})")
    return {
        "Asset": _truncate(str(conflict.get("entity_label") or conflict.get("entity_key") or ""), 120),
        "Type": str(conflict.get("entity_type") or ""),
        "Owners": _truncate("; ".join(owner_labels), 240),
        "Owner Count": str(conflict.get("owner_count") or 0),
        "Claim Count": str(conflict.get("claim_count") or 0),
        "Top Confidence": f"{float(conflict.get('highest_confidence') or 0.0):.2f}",
    }


def _remediation_summary_label(remediation: Any) -> str:
    if not isinstance(remediation, dict) or not int(remediation.get("item_count") or 0):
        return "-"
    parts = [
        f"items={int(remediation.get('item_count') or 0)}",
        f"open={int(remediation.get('open_count') or 0)}",
        f"ticketed={int(remediation.get('ticketed_count') or 0)}",
    ]
    pending = int(remediation.get("retest_pending_count") or 0)
    if pending:
        parts.append(f"retest_pending={pending}")
    risk_state = str(remediation.get("risk_acceptance_state") or "").strip()
    if risk_state and risk_state != "none":
        parts.append(f"risk={risk_state}")
    return _truncate(", ".join(parts), 160)


def _remediation_action_label(remediation: Any) -> str:
    if not isinstance(remediation, dict):
        return "-"
    items = remediation.get("items")
    if not isinstance(items, list) or not items:
        return "-"
    labels: list[str] = []
    for item in items[:3]:
        if not isinstance(item, dict):
            continue
        ticket = str(item.get("ticket_ref") or item.get("ticket_url") or "").strip()
        owner = str(item.get("owner_display") or item.get("owner_ref") or "").strip()
        status = str(item.get("status") or "").strip()
        retest = str(item.get("retest_status") or "").strip()
        label_parts = [
            part
            for part in (
                ticket,
                owner,
                status,
                f"retest={retest}" if retest else "",
            )
            if part
        ]
        if label_parts:
            labels.append(" ".join(label_parts))
    return _truncate("; ".join(labels), 220) or "-"


def _asset_graph_attack_path_section_row(path: dict[str, Any]) -> dict[str, str]:
    nodes = path.get("nodes") if isinstance(path.get("nodes"), list) else []
    labels = [
        str(node.get("label") or node.get("entity_key") or "").strip()
        for node in nodes[:6]
        if isinstance(node, dict)
    ]
    remediation_nodes = [
        node.get("remediation")
        for node in nodes
        if isinstance(node, dict)
        and isinstance(node.get("remediation"), dict)
        and int(node["remediation"].get("item_count") or 0)
    ]
    remediation = remediation_nodes[0] if remediation_nodes else {}
    return {
        "Path": str(path.get("path_id") or ""),
        "Tier": str(path.get("risk_tier") or ""),
        "Score": f"{float(path.get('score') or 0.0):.1f}",
        "Terminal": _truncate(str(path.get("terminal_entity_key") or ""), 120),
        "Nodes": _truncate(" -> ".join(labels), 260),
        "Remediation": _remediation_summary_label(remediation),
        "Action": _remediation_action_label(remediation),
    }


def _asset_graph_blast_radius_risk_mix(summary: dict[str, Any]) -> str:
    entity_counts = (
        summary.get("entity_type_counts")
        if isinstance(summary.get("entity_type_counts"), dict)
        else {}
    )
    tier_counts = (
        summary.get("risk_tier_counts")
        if isinstance(summary.get("risk_tier_counts"), dict)
        else {}
    )
    parts: list[str] = []
    if entity_counts:
        parts.append(
            "entities "
            + ", ".join(
                f"{key}={value}"
                for key, value in sorted(entity_counts.items())
                if str(key).strip()
            )
        )
    if tier_counts:
        parts.append(
            "tiers "
            + ", ".join(
                f"{key}={value}"
                for key, value in sorted(tier_counts.items())
                if str(key).strip()
            )
        )
    return _truncate("; ".join(part for part in parts if part), 220) or "-"


def _asset_graph_blast_radius_cloud_context(summary: dict[str, Any]) -> str:
    cloud_context = (
        summary.get("cloud_context")
        if isinstance(summary.get("cloud_context"), dict)
        else {}
    )
    fields = (
        ("accounts", "account_refs"),
        ("regions", "regions"),
        ("sensitivity", "data_sensitivity_tiers"),
        ("workloads", "workloads"),
        ("identities", "identity_refs"),
    )
    parts: list[str] = []
    for label, key in fields:
        values = cloud_context.get(key)
        if not isinstance(values, list):
            continue
        clean_values = [str(value).strip() for value in values[:4] if str(value).strip()]
        if clean_values:
            parts.append(f"{label}=" + ", ".join(clean_values))
    return _truncate("; ".join(parts), 260) or "-"


def _asset_graph_choke_point_section_row(point: dict[str, Any]) -> dict[str, str]:
    remediation = point.get("remediation") if isinstance(point.get("remediation"), dict) else {}
    blast_summary = (
        point.get("blast_radius_summary")
        if isinstance(point.get("blast_radius_summary"), dict)
        else {}
    )
    critical_refs = (
        blast_summary.get("critical_asset_refs")
        if isinstance(blast_summary.get("critical_asset_refs"), list)
        else []
    )
    toxic_combinations = (
        blast_summary.get("toxic_combinations")
        if isinstance(blast_summary.get("toxic_combinations"), list)
        else []
    )
    return {
        "Entity": _truncate(str(point.get("label") or point.get("entity_key") or ""), 120),
        "Type": str(point.get("entity_type") or ""),
        "Paths": str(point.get("path_count") or 0),
        "Degree": str(point.get("degree") or 0),
        "Blast Radius": str(point.get("blast_radius_count") or 0),
        "Critical Assets": _truncate(
            "; ".join(str(item) for item in critical_refs[:4] if str(item).strip()),
            220,
        )
        or "-",
        "Risk Mix": _asset_graph_blast_radius_risk_mix(blast_summary),
        "Toxic Combinations": _truncate(
            "; ".join(str(item) for item in toxic_combinations[:5] if str(item).strip()),
            260,
        )
        or "-",
        "Cloud Context": _asset_graph_blast_radius_cloud_context(blast_summary),
        "Score": f"{float(point.get('score') or 0.0):.1f}",
        "Remediation": _remediation_summary_label(remediation),
        "Action": _remediation_action_label(remediation),
    }


def _asset_graph_fix_candidate_section_row(candidate: dict[str, Any]) -> dict[str, str]:
    remediation = (
        candidate.get("remediation") if isinstance(candidate.get("remediation"), dict) else {}
    )
    risk_factors = candidate.get("risk_factors") if isinstance(candidate.get("risk_factors"), list) else []
    recommended_actions = (
        candidate.get("recommended_actions")
        if isinstance(candidate.get("recommended_actions"), list)
        else []
    )
    action_label = _remediation_action_label(remediation)
    if action_label == "-" and recommended_actions:
        action_label = _truncate(
            "; ".join(str(item) for item in recommended_actions[:5] if str(item).strip()),
            220,
        ) or "-"
    return {
        "Entity": _truncate(str(candidate.get("label") or candidate.get("entity_key") or ""), 120),
        "Type": str(candidate.get("entity_type") or ""),
        "Reason": str(candidate.get("reason") or ""),
        "Risk Factors": _truncate("; ".join(str(item) for item in risk_factors[:5]), 180) or "-",
        "Owner": _truncate(
            str(candidate.get("owner_display") or candidate.get("owner_ref") or ""),
            120,
        ),
        "Paths": str(candidate.get("supporting_path_count") or 0),
        "Risk Reduction": f"{float(candidate.get('expected_risk_reduction') or 0.0):.1f}",
        "Remediation": _remediation_summary_label(remediation),
        "Action": action_label,
    }


def _active_validation_method_summary(method_id: object) -> tuple[str, str, str]:
    try:
        method = get_active_validation_method(str(method_id or ""))
    except ValueError:
        return "unknown", "-", "-"
    coverage = "; ".join((*method.attack_mappings, *method.control_families))
    return method.implementation_status, method.proof_kind, coverage


def _active_validation_job_section_row(row: sqlite3.Row) -> dict[str, str]:
    metadata = _safe_json_loads(str(row["metadata_json"] or "{}"))
    method_status, method_proof, method_coverage = _active_validation_method_summary(
        row["method"]
    )
    return {
        "Target": _safe_dashboard_source_url(row["target_ref"], 120),
        "Kind": str(row["target_kind"] or ""),
        "Method": str(row["method"] or ""),
        "Method Status": method_status,
        "Mode": str(row["mode"] or ""),
        "Status": str(row["status"] or ""),
        "Approved": "yes" if int(row["approved"] or 0) else "no",
        "ROE": _truncate(str(row["roe_id"] or ""), 80),
        "Scope": "yes" if str(row["scope_manifest_hash"] or "").strip() else "no",
        "Profile": str(row["safe_profile"] or ""),
        "Proof": method_proof,
        "Coverage": _truncate(method_coverage, 160),
        "Meta": _preview_json(_safe_graph_metadata(metadata), 120),
        "Updated": _format_dt(str(row["updated_at"] or "")),
    }


def _active_validation_run_section_row(row: sqlite3.Row) -> dict[str, str]:
    evidence = _safe_json_loads(str(row["evidence_json"] or "{}"))
    if not isinstance(evidence, dict):
        evidence = {}
    job = evidence.get("job") if isinstance(evidence.get("job"), dict) else {}
    method_status, method_proof, method_coverage = _active_validation_method_summary(
        job.get("method")
    )
    safety = []
    for label, key in (
        ("net", "network_execution"),
        ("destructive", "destructive_actions"),
        ("lateral", "lateral_movement"),
        ("post-ex", "post_exploitation"),
    ):
        safety.append(f"{label}={'yes' if evidence.get(key) else 'no'}")
    proof_summary = active_validation_proof_summary(evidence)
    return {
        "Job": str(row["job_id"] or ""),
        "Target": _safe_dashboard_source_url(job.get("target_ref"), 120),
        "Mode": str(job.get("mode") or ""),
        "Method": str(job.get("method") or ""),
        "Method Status": method_status,
        "Status": str(row["status"] or ""),
        "Result": _truncate(str(row["result"] or ""), 120),
        "Proof": method_proof,
        "Coverage": _truncate(method_coverage, 160),
        "Evidence": _truncate(str(proof_summary.get("evidence") or "-"), 180),
        "Live Proof": _truncate(str(proof_summary.get("live_proof") or "-"), 180),
        "Fix Match": _truncate(str(proof_summary.get("fix_match") or "-"), 180),
        "Safety": ", ".join(safety),
        "Operator": str(row["operator"] or ""),
        "Completed": _format_dt(str(row["completed_at"] or "")),
        "Error": _redact_dashboard_error(row["error"], 120),
    }


def _active_validation_coverage_section_rows(
    con: sqlite3.Connection,
    engagement_id: int,
) -> list[dict[str, str]]:
    if not (
        _table_exists(con, "active_validation_jobs")
        and _table_exists(con, "active_validation_runs")
    ):
        return []
    try:
        coverage = active_validation_control_coverage(con, engagement_id=engagement_id)
    except (sqlite3.Error, ValueError):
        return []
    rows: list[dict[str, str]] = []
    for group_name, label in (
        ("attack_mappings", "ATT&CK"),
        ("control_families", "Control"),
        ("methods", "Method"),
    ):
        for item in coverage.get(group_name, [])[:SECTION_LIMIT]:
            if not isinstance(item, dict):
                continue
            states = item.get("states") if isinstance(item.get("states"), dict) else {}
            proof_types = (
                item.get("proof_types") if isinstance(item.get("proof_types"), dict) else {}
            )
            proof_freshness = (
                item.get("proof_freshness")
                if isinstance(item.get("proof_freshness"), dict)
                else {}
            )
            rows.append(
                {
                    "Type": label,
                    "Coverage": _truncate(str(item.get("label") or item.get("id") or ""), 120),
                    "Jobs": str(item.get("job_count") or 0),
                    "Runs": str(item.get("run_count") or 0),
                    "States": _truncate(
                        ", ".join(
                            f"{state}={int(count or 0)}"
                            for state, count in sorted(states.items())
                        ),
                        160,
                    )
                    or "-",
                    "Proof Types": _truncate(
                        ", ".join(
                            f"{proof_type}={int(count or 0)}"
                            for proof_type, count in sorted(proof_types.items())
                        ),
                        160,
                    )
                    or "-",
                    "Proof Freshness": _truncate(
                        ", ".join(
                            f"{freshness}={int(count or 0)}"
                            for freshness, count in sorted(proof_freshness.items())
                        ),
                        160,
                    )
                    or "-",
                    "Methods": _truncate(
                        ", ".join(str(method) for method in item.get("methods", [])[:6])
                        if isinstance(item.get("methods"), list)
                        else str(item.get("id") or ""),
                        160,
                    )
                    or "-",
                    "Latest Jobs": _truncate(
                        ", ".join(str(job_id) for job_id in item.get("latest_job_ids", [])[:8])
                        if isinstance(item.get("latest_job_ids"), list)
                        else "",
                        80,
                    )
                    or "-",
                }
            )
    return rows[:SECTION_LIMIT * 3]


def _asset_graph_summary(con: sqlite3.Connection, engagement_id: int) -> dict[str, Any]:
    return build_asset_graph_summary(
        con,
        engagement_id,
        callbacks=_graph_summary_callbacks(),
    )


def _detail_sections(
    con: sqlite3.Connection,
    engagement_id: int,
    db_path: Path | None = None,
) -> dict[str, list[dict[str, str]]]:
    sections: dict[str, list[dict[str, str]]] = {}

    sections.update(
        inventory_sections(
            con,
            engagement_id,
            limit=SECTION_LIMIT,
            callbacks=_detail_section_query_callbacks(),
        )
    )

    sections["email_intelligence"] = email_intelligence_section_rows(
        con,
        engagement_id,
        limit=SECTION_LIMIT,
        callbacks=_detail_section_query_callbacks(),
    )

    sections["account_existence"] = account_existence_section_rows(
        con,
        engagement_id,
        limit=SECTION_LIMIT,
        callbacks=_detail_section_query_callbacks(),
    )

    sections.update(
        seed_sections(
            con,
            engagement_id,
            limit=SECTION_LIMIT,
            seed_run_limit=max(SECTION_LIMIT * 2, 20),
            callbacks=_detail_section_query_callbacks(),
        )
    )

    sections["engagement_runs"] = engagement_run_section_rows(
        con,
        engagement_id,
        db_path=db_path,
        limit=max(SECTION_LIMIT, 10),
        callbacks=_detail_section_query_callbacks(),
    )

    sections["distributed_tasks"] = []
    sections["distributed_tasks"] = distributed_task_section_rows(
        con,
        engagement_id,
        limit=SECTION_LIMIT,
        callbacks=_detail_section_query_callbacks(),
    )

    sections["services"] = service_section_rows(
        con,
        engagement_id,
        limit=SECTION_LIMIT,
        callbacks=_detail_section_query_callbacks(),
    )

    finding_section_rows = finding_sections(
        con,
        engagement_id,
        limit=SECTION_LIMIT,
        callbacks=_detail_section_query_callbacks(),
    )
    sections["key_scanner_findings"] = finding_section_rows["key_scanner_findings"]
    sections["secret_lifecycle_items"] = finding_section_rows["secret_lifecycle_items"]

    sections["artifact_queue"] = artifact_queue_section_rows(
        con,
        engagement_id,
        limit=SECTION_LIMIT,
        callbacks=_detail_section_query_callbacks(),
    )

    sections["crawl_results"] = crawl_result_section_rows(
        con,
        engagement_id,
        limit=SECTION_LIMIT,
        callbacks=_detail_section_query_callbacks(),
    )

    sections["social_profiles"] = social_profile_section_rows(
        con,
        engagement_id,
        limit=SECTION_LIMIT,
        callbacks=_detail_section_query_callbacks(),
    )

    sections["port_scan_results"] = port_scan_result_section_rows(
        con,
        engagement_id,
        limit=SECTION_LIMIT,
        callbacks=_detail_section_query_callbacks(),
    )

    sections["passive_vulns"] = passive_vuln_section_rows(
        con,
        engagement_id,
        limit=SECTION_LIMIT,
        callbacks=_detail_section_query_callbacks(),
    )

    sections["vulnerability_findings"] = finding_section_rows["vulnerability_findings"]

    sections["auth_test_results"] = auth_test_result_section_rows(
        con,
        engagement_id,
        limit=SECTION_LIMIT,
        callbacks=_detail_section_query_callbacks(),
    )

    sections.update(
        cloud_sections(
            con,
            engagement_id,
            limit=SECTION_LIMIT,
            callbacks=_detail_section_query_callbacks(),
        )
    )

    sections.update(
        monitoring_configuration_sections(
            con,
            engagement_id,
            limit=SECTION_LIMIT,
            callbacks=_detail_section_query_callbacks(),
        )
    )

    sections.update(
        remediation_workflow_sections(
            con,
            engagement_id,
            limit=SECTION_LIMIT,
            callbacks=_detail_section_query_callbacks(),
        )
    )
    exposure_metrics = exposure_metrics_for_engagement(
        con,
        engagement_id,
        limit=SECTION_LIMIT,
    )
    sections["exposure_duration_metrics"] = [
        _exposure_duration_metric_section_row(item)
        for item in exposure_metrics.get("metrics", [])
        if isinstance(item, dict)
    ]

    sections.update(
        retention_sections(
            con,
            engagement_id,
            limit=SECTION_LIMIT,
            callbacks=_detail_section_query_callbacks(),
        )
    )

    sections.update(
        asset_graph_sections(
            con,
            engagement_id,
            limit=SECTION_LIMIT,
            callbacks=_detail_section_query_callbacks(),
        )
    )

    sections.update(
        active_validation_sections(
            con,
            engagement_id,
            limit=SECTION_LIMIT,
            callbacks=_detail_section_query_callbacks(),
        )
    )

    sections.update(
        monitoring_history_sections(
            con,
            engagement_id,
            limit=SECTION_LIMIT,
            callbacks=_detail_section_query_callbacks(),
        )
    )

    sections.update(
        audit_sections(
            con,
            engagement_id,
            audit_limit=max(SECTION_LIMIT * 2, 20),
            scope_denial_limit=SECTION_LIMIT,
            scope_denial_actions=_SCOPE_BOUNDARY_DENIAL_ACTIONS,
            callbacks=_detail_section_query_callbacks(),
        )
    )

    sections["evidence_provenance"] = _evidence_provenance_section_rows(sections)

    return sections


def _engagement_summary(db_path: Path) -> dict[str, Any]:
    return build_engagement_summary(
        db_path,
        severity_order=SEVERITY_ORDER,
        callbacks=_engagement_summary_callbacks(),
    )


def _base_styles() -> str:
    return """
    :root{
      --bg:#0b1020;
      --panel:#11172a;
      --panel-alt:#16203a;
      --border:#26324f;
      --text:#e8edf7;
      --muted:#91a0bc;
      --accent:#66d9c2;
      --accent-strong:#97f6d2;
      --warn:#f7c95f;
      --danger:#ff7a7a;
      --good:#77d68a;
      --link:#8ec5ff;
      --shadow:0 18px 46px rgba(0,0,0,.30);
    }
    *{box-sizing:border-box}
    body{
      margin:0;
      background:
        radial-gradient(circle at top right, rgba(102,217,194,.12), transparent 28%),
        radial-gradient(circle at top left, rgba(142,197,255,.10), transparent 24%),
        linear-gradient(180deg, #0a0f1d 0%, #0b1020 56%, #090d18 100%);
      color:var(--text);
      font:14px/1.5 "Segoe UI", Inter, system-ui, sans-serif;
    }
    a{color:var(--link);text-decoration:none}
    a:hover{text-decoration:underline}
    .shell{max-width:1400px;margin:0 auto;padding:28px 22px 40px}
    .hero{
      display:flex;justify-content:space-between;gap:18px;align-items:flex-end;
      margin-bottom:24px;padding:24px;border:1px solid var(--border);
      border-radius:20px;background:linear-gradient(160deg, rgba(17,23,42,.98), rgba(12,17,31,.88));
      box-shadow:var(--shadow);
    }
    .hero h1{margin:0 0 6px;font-size:34px;line-height:1.05;letter-spacing:-.03em}
    .subtle,.muted{color:var(--muted)}
    .hero-meta{text-align:right;min-width:180px}
    .hero-meta .stamp{font-size:12px;color:var(--muted)}
    .chips{display:flex;flex-wrap:wrap;gap:8px;min-width:0;max-width:100%}
    .chip{
      display:inline-flex;gap:8px;align-items:center;padding:6px 10px;border-radius:999px;
      max-width:100%;min-width:0;white-space:normal;overflow-wrap:anywhere;word-break:break-word;
      border:1px solid var(--border);background:rgba(255,255,255,.03);color:var(--text)
    }
    .chip code{background:none;padding:0;color:var(--accent-strong);white-space:normal;overflow-wrap:anywhere}
    .stats{
      display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
      gap:12px;margin:18px 0 24px;
    }
    .stat{
      padding:14px 16px;border-radius:16px;border:1px solid var(--border);
      background:linear-gradient(180deg, rgba(17,23,42,.92), rgba(11,16,32,.92));
      box-shadow:var(--shadow);
    }
    .stat .label{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}
    .stat .value{margin-top:6px;font-size:28px;font-weight:700;letter-spacing:-.03em}
    .panel{
      border:1px solid var(--border);border-radius:18px;background:rgba(17,23,42,.92);
      box-shadow:var(--shadow);min-width:0;
    }
    .panel-head{
      display:flex;justify-content:space-between;gap:12px;align-items:center;
      padding:16px 18px;border-bottom:1px solid var(--border);background:rgba(255,255,255,.02);
    }
    .panel-head h2,.panel-head h3{margin:0;font-size:15px;letter-spacing:.02em}
    .panel-body{padding:18px}
    .panel-body ul{padding-left:18px;min-width:0;max-width:100%;overflow-wrap:anywhere;word-break:break-word}
    .panel-body li{min-width:0;max-width:100%;overflow-wrap:anywhere;word-break:break-word}
    .table-scroll{width:100%;max-width:100%;overflow-x:auto;overflow-y:hidden}
    table{width:100%;border-collapse:collapse}
    th{
      color:var(--muted);font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;
      text-align:left;padding:12px 12px 10px;border-bottom:1px solid var(--border);
      background:rgba(255,255,255,.02);position:sticky;top:0;
    }
    th,td{overflow-wrap:anywhere;word-break:break-word;min-width:0}
    td{padding:11px 12px;border-bottom:1px solid rgba(255,255,255,.05);vertical-align:top}
    tbody tr:hover{background:rgba(255,255,255,.025)}
    .right{text-align:right}
    .mono{font-family:"Cascadia Code","JetBrains Mono",Consolas,monospace}
    .tiny{font-size:12px}
    .pill{
      display:inline-block;padding:3px 8px;border-radius:999px;border:1px solid var(--border);
      max-width:100%;white-space:normal;overflow-wrap:anywhere;word-break:break-word;
      background:rgba(255,255,255,.04);font-size:11px;color:var(--text)
    }
    .pill.ok{color:var(--good);border-color:rgba(119,214,138,.35)}
    .pill.warn{color:var(--warn);border-color:rgba(247,201,95,.35)}
    .pill.danger{color:var(--danger);border-color:rgba(255,122,122,.35)}
    .pill.accent{color:var(--accent-strong);border-color:rgba(102,217,194,.35)}
    .search{
      width:min(440px,100%);padding:12px 14px;border-radius:12px;background:#0b1327;
      color:var(--text);border:1px solid var(--border);font:inherit;
    }
    .eng-link{
      display:inline-flex;align-items:center;gap:8px;padding:8px 12px;border-radius:10px;
      background:rgba(102,217,194,.12);border:1px solid rgba(102,217,194,.28);color:var(--accent-strong);
      font-weight:600;
    }
    .grid{
      display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:16px;
    }
    .meta-list{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}
    .meta{
      padding:12px 14px;border-radius:14px;background:rgba(255,255,255,.03);border:1px solid var(--border)
    }
    .meta .k{display:block;font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin-bottom:6px}
    .meta .v{display:block;font-size:14px;overflow-wrap:anywhere;word-break:break-word}
    .section-stack{display:flex;flex-direction:column;gap:16px}
    .artifact-list{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}
    .artifact{
      padding:14px;border-radius:14px;border:1px solid var(--border);
      background:rgba(255,255,255,.03);min-width:0
    }
    .artifact strong,.artifact a{display:block;margin-bottom:6px;max-width:100%;overflow-wrap:anywhere;word-break:break-word}
    .artifact-kind{
      display:inline-flex;align-items:center;padding:3px 8px;margin-bottom:8px;border-radius:999px;
      border:1px solid var(--border);background:rgba(255,255,255,.05);font-size:11px;text-transform:uppercase;
      letter-spacing:.08em;color:var(--muted)
    }
    .route-grid{
      display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:16px
    }
    .route-card{
      padding:18px;border-radius:16px;border:1px solid var(--border);
      background:linear-gradient(180deg, rgba(255,255,255,.035), rgba(255,255,255,.015));
      min-width:0;overflow-wrap:anywhere;word-break:break-word
    }
    .route-card strong,.route-card a,.route-card p{
      max-width:100%;min-width:0;overflow-wrap:anywhere;word-break:break-word
    }
    .route-card h3{margin:0 0 10px;font-size:14px;letter-spacing:.03em}
    .route-card p{margin:0}
    .timeline{display:flex;flex-direction:column;gap:12px}
    .timeline-item{
      display:grid;grid-template-columns:120px 1fr;gap:14px;padding:14px;border-radius:14px;
      border:1px solid var(--border);background:rgba(255,255,255,.03);
      min-width:0;overflow-wrap:anywhere;word-break:break-word
    }
    .timeline-item .time{color:var(--muted);font-size:12px}
    .timeline-item strong{display:block;margin-bottom:4px}
    .graph-stage{
      position:relative;overflow:hidden;min-height:220px;padding:18px;border-radius:16px;
      border:1px solid rgba(102,217,194,.24);
      background:
        linear-gradient(180deg, rgba(8,17,34,.96), rgba(10,18,35,.88)),
        radial-gradient(circle at 20% 20%, rgba(102,217,194,.10), transparent 28%);
    }
    .graph-stage::before{
      content:"";position:absolute;inset:0;
      background:
        linear-gradient(rgba(142,197,255,.07) 1px, transparent 1px),
        linear-gradient(90deg, rgba(142,197,255,.07) 1px, transparent 1px);
      background-size:34px 34px;mask-image:linear-gradient(180deg, rgba(0,0,0,.8), transparent);
      pointer-events:none;
    }
    .graph-nodes{
      position:relative;z-index:1;display:flex;flex-wrap:wrap;gap:12px;align-items:flex-start
    }
    .graph-node{
      max-width:180px;min-width:0;padding:10px 12px;border-radius:14px;
      border:1px solid rgba(102,217,194,.26);background:rgba(102,217,194,.10);
      box-shadow:0 14px 34px rgba(0,0,0,.18);
      overflow-wrap:anywhere;word-break:break-word
    }
    .graph-node span{display:block;font-size:12px;line-height:1.4;min-width:0;overflow-wrap:anywhere;word-break:break-word}
    .report-callout{display:flex;flex-direction:column;gap:10px}
    .report-callout .title{display:flex;justify-content:space-between;gap:12px;align-items:center;flex-wrap:wrap;min-width:0}
    .report-callout .title strong,.report-callout .title a{font-size:14px;min-width:0;overflow-wrap:anywhere;word-break:break-word}
    .lane-grid{
      display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px
    }
    .lane{
      padding:14px;border-radius:14px;border:1px solid var(--border);background:rgba(255,255,255,.03)
    }
    .lane .eyebrow{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}
    .lane .figure{margin-top:8px;font-size:26px;font-weight:700;letter-spacing:-.03em}
    .input-chip-details{margin-top:10px}
    .input-chip-details summary{
      cursor:pointer;color:var(--accent-strong);font-weight:600;overflow-wrap:anywhere
    }
    .input-chip-details .chips{margin-top:10px;max-height:280px;overflow:auto;padding-right:4px}
    .input-chip-omitted{margin-top:10px}
    .fallback-note{min-width:0;max-width:100%;overflow-wrap:anywhere;word-break:break-word}
    .fallback-note summary{cursor:pointer;color:var(--muted);overflow-wrap:anywhere;word-break:break-word}
    pre{
      margin:10px 0 0;padding:14px;border-radius:12px;background:#09101f;border:1px solid var(--border);
      color:#dfe8f8;overflow:auto;white-space:pre-wrap;word-break:break-word;font:12px/1.45 "Cascadia Code","JetBrains Mono",Consolas,monospace;
      max-height:420px;
    }
    .empty{
      padding:18px;border:1px dashed var(--border);border-radius:14px;color:var(--muted);
      background:rgba(255,255,255,.02)
    }
    .empty-section-details summary{
      cursor:pointer;color:var(--muted);font-weight:600;overflow-wrap:anywhere
    }
    .empty-section-details ul{margin:12px 0 0;columns:2;column-gap:28px}
    .toolbar{display:flex;justify-content:space-between;gap:12px;align-items:center;flex-wrap:wrap}
    .backlink{display:inline-flex;align-items:center;gap:8px;color:var(--accent-strong);font-weight:600}
    .summary-line{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
    .summary-line,.summary-line *{min-width:0;overflow-wrap:anywhere;word-break:break-word}
    .hide{display:none}
    @media (max-width: 820px){
      .hero{flex-direction:column;align-items:flex-start}
      .hero-meta{text-align:left}
      .shell{padding:18px 14px 32px}
      .timeline-item{grid-template-columns:1fr}
      .table-scroll{overflow:visible}
      table.responsive-table,table.responsive-table thead,table.responsive-table tbody,table.responsive-table tr,table.responsive-table th,table.responsive-table td{display:block}
      table.responsive-table thead{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0)}
      table.responsive-table tr{margin:0 0 12px;padding:12px;border:1px solid var(--border);border-radius:14px;background:rgba(255,255,255,.025)}
      table.responsive-table td{display:grid;grid-template-columns:minmax(92px,34%) minmax(0,1fr);gap:10px;padding:8px 0;border-bottom:1px solid rgba(255,255,255,.05)}
      table.responsive-table td:last-child{border-bottom:0}
      table.responsive-table td::before{content:attr(data-label);color:var(--muted);font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;overflow-wrap:anywhere}
    }
    @media (max-width: 640px){
      .hero{padding:18px}
      .hero h1{font-size:28px}
      .grid,.route-grid{grid-template-columns:minmax(0,1fr)}
      .artifact-list,.meta-list{grid-template-columns:minmax(0,1fr)}
      .empty-section-details ul{columns:1}
      th,td{padding:9px 10px}
    }
    """


def _render_overview_page(
    engagements: list[dict[str, Any]],
    output_path: Path,
    generated_at: str,
) -> str:
    return render_overview_page(
        engagements,
        output_path,
        generated_at,
        base_styles=_base_styles(),
        relative_href=_relative_href,
        severity_summary_text=_severity_summary_text,
        timestamp_epoch_ms=_timestamp_epoch_ms,
        severity_order=SEVERITY_ORDER,
    )


def _render_meta_block(label: str, value: str, mono: bool = False) -> str:
    return render_meta_block(label, value, mono=mono)


def _render_table(title: str, rows: list[dict[str, str]]) -> str:
    return render_table(title, rows)


def _render_artifact_card(page_path: Path, artifact: Path, kind: str) -> str:
    href = _relative_href(page_path, artifact)
    try:
        stat = artifact.stat()
        size_bytes = int(stat.st_size)
        modified_label = _format_dt(datetime.fromtimestamp(stat.st_mtime).isoformat())
    except OSError:
        size_bytes = 0
        modified_label = ""
    return render_artifact_card(
        kind=kind,
        name=artifact.name,
        href=href,
        size_label=_format_size(size_bytes),
        modified_label=modified_label,
    )


def _engagement_input_blocks(engagement: dict[str, Any]) -> EngagementInputBlocks:
    return engagement_input_blocks(engagement, render_meta_block=_render_meta_block)


def _render_engagement_artifact_block(
    page_path: Path,
    *,
    report_files: list[Path],
    graph_files: list[Path],
    audit_files: list[Path],
) -> str:
    return render_engagement_artifact_block(
        page_path,
        report_files=report_files,
        graph_files=graph_files,
        audit_files=audit_files,
        render_artifact_card=_render_artifact_card,
    )


def _report_history_payload(report_files: list[Path]) -> list[dict[str, Any]]:
    return build_report_history_payload(report_files)


def _report_summary_payload(report_files: list[Path]) -> dict[str, Any] | None:
    return build_report_summary_payload(report_files)


def _report_review_counts(report_history: list[dict[str, Any]]) -> dict[str, Any]:
    return report_review_counts(report_history)


def _latest_report_family_files(report_files: list[Path]) -> list[Path]:
    return latest_report_family_files(report_files)


def _render_report_history(report_history: list[dict[str, Any]]) -> str:
    return render_report_history(report_history)


def _render_report_preview(page_path: Path, artifact: Path) -> str:
    try:
        preview = artifact.read_text(encoding="utf-8", errors="replace")[:7000]
    except Exception:  # noqa: BLE001
        preview = "(unreadable)"
    href = _relative_href(page_path, artifact)
    return render_report_preview(name=artifact.name, href=href, preview=preview)


def _engagement_report_preview_context(
    page_path: Path,
    engagement: dict[str, Any],
) -> EngagementReportPreviewContext:
    return engagement_report_preview_context(
        page_path,
        engagement,
        latest_report_family_files=_latest_report_family_files,
        render_report_preview=_render_report_preview,
        report_preview_payload=_report_preview_payload,
    )


def _render_report_backend_summary(summary: dict[str, Any] | None) -> str:
    return render_report_backend_summary(summary)


def _render_graph_summary(summary: dict[str, Any]) -> str:
    return render_graph_summary(summary)


def _render_graph_stage(summary: dict[str, Any]) -> str:
    return render_graph_stage(summary)


def _engagement_graph_blocks(engagement: dict[str, Any]) -> EngagementGraphBlocks:
    return engagement_graph_blocks(
        engagement,
        render_graph_stage=_render_graph_stage,
        render_graph_summary=_render_graph_summary,
    )


def _render_audit_timeline(rows: list[dict[str, str]]) -> str:
    return render_audit_timeline(rows)


def _operational_timeline_events(
    sections: dict[str, list[dict[str, str]]],
    *,
    report_history: list[dict[str, Any]] | None = None,
    report_summary: dict[str, Any] | None = None,
) -> list[dict[str, str]]:
    return operational_timeline_events(
        sections,
        report_history=report_history,
        report_summary=report_summary,
    )


def _evidence_provenance_section_rows(
    sections: dict[str, list[dict[str, str]]],
) -> list[dict[str, str]]:
    return evidence_provenance_section_rows(sections)


def _render_operational_timeline(events: list[dict[str, str]]) -> str:
    return render_operational_timeline(events)


def _engagement_timeline_blocks(
    sections: dict[str, list[dict[str, str]]],
    *,
    report_history: list[dict[str, Any]] | None = None,
    report_summary: dict[str, Any] | None = None,
) -> EngagementTimelineBlocks:
    return engagement_timeline_blocks(
        sections,
        report_history=report_history,
        report_summary=report_summary,
        operational_timeline_events=_operational_timeline_events,
        render_operational_timeline=_render_operational_timeline,
        render_audit_timeline=_render_audit_timeline,
    )


def _render_engagement_evidence_sections(
    sections: dict[str, list[dict[str, str]]],
) -> str:
    return render_engagement_evidence_sections(sections, render_table=_render_table)


def _render_report_callout(
    previews: list[dict[str, str]],
    report_summary: dict[str, Any] | None = None,
) -> str:
    return render_report_callout(previews, report_summary)


def _render_engagement_page(
    engagement: dict[str, Any],
    index_path: Path,
    page_path: Path,
) -> str:
    graph_files = engagement["graph_files"]
    report_files = engagement["report_files"]
    audit_files = engagement.get("audit_files", [])
    input_blocks = _engagement_input_blocks(engagement)

    artifact_block = _render_engagement_artifact_block(
        page_path,
        report_files=report_files,
        graph_files=graph_files,
        audit_files=audit_files,
    )
    report_context = _engagement_report_preview_context(page_path, engagement)
    graph_blocks = _engagement_graph_blocks(engagement)

    evidence_sections = _render_engagement_evidence_sections(engagement["sections"])
    timeline_blocks = _engagement_timeline_blocks(
        engagement["sections"],
        report_history=engagement.get("report_history"),
        report_summary=engagement.get("report_summary"),
    )

    return render_engagement_detail_page(
        engagement,
        index_path,
        page_path,
        base_styles=_base_styles(),
        relative_href=_relative_href,
        format_size=_format_size,
        severity_order=SEVERITY_ORDER,
        meta_blocks=input_blocks.meta_blocks,
        seed_html=input_blocks.seed_html,
        scope_html=input_blocks.scope_html,
        artifact_block=artifact_block,
        report_callout_html=_render_report_callout(
            report_context.preview_payloads,
            report_context.report_summary,
        ),
        graph_stage_html=graph_blocks.stage_html,
        graph_summary_html=graph_blocks.summary_html,
        operational_timeline_html=timeline_blocks.operational_html,
        audit_timeline_html=timeline_blocks.audit_html,
        evidence_sections_html=evidence_sections,
        report_history_html=_render_report_history(_report_history_payload(report_files)),
        report_previews_html=report_context.preview_html,
    )


def _engagement_index_payload(engagement: dict[str, Any]) -> dict[str, Any]:
    return engagement_index_payload(engagement)


def _engagement_detail_payload(engagement: dict[str, Any], root_page: Path) -> dict[str, Any]:
    return engagement_detail_payload(
        engagement,
        root_page,
        index_payload=_engagement_index_payload,
        report_history_payload=_report_history_payload,
        latest_report_family_files=_latest_report_family_files,
        report_preview_payload=_report_preview_payload,
        artifact_payload=_artifact_payload,
        format_size=_format_size,
        operational_timeline_events=_operational_timeline_events,
        annotate_audit_manifest_bundle=_annotate_audit_manifest_bundle,
    )


def _engagement_enrichment_callbacks() -> EngagementEnrichmentCallbacks:
    return EngagementEnrichmentCallbacks(
        artifact_files=_artifact_files,
        graph_files=_graph_files,
        audit_files=_audit_files,
        connect_readonly=_connect_readonly,
        materialize_audit_manifest_artifacts=_materialize_audit_manifest_artifacts,
        graph_state_for_engagement=_graph_state_for_engagement,
        report_history_payload=_report_history_payload,
        report_review_counts=_report_review_counts,
        annotate_audit_manifest_bundle=_annotate_audit_manifest_bundle,
    )


def _enrich_engagement_dashboard_summary(
    engagement: dict[str, Any],
    *,
    db_path: Path,
    reports_dir: Path,
) -> dict[str, Any]:
    return enrich_engagement_dashboard_summary(
        engagement,
        db_path=db_path,
        reports_dir=reports_dir,
        callbacks=_engagement_enrichment_callbacks(),
    )


def _dashboard_engagement_summary(db_path: Path, reports_dir: Path) -> dict[str, Any]:
    engagement = dashboard_engagement_summary(
        db_path,
        reports_dir,
        engagement_summary=_engagement_summary,
        callbacks=_engagement_enrichment_callbacks(),
    )
    candidate = target_resume_candidate_for_db(db_path)
    if candidate is not None:
        safe_candidate = _dashboard_resume_candidate_payload(candidate)
        engagement["target_resume_candidate"] = safe_candidate
        engagement.setdefault("sections", {})["target_resume_candidate"] = [
            _dashboard_resume_candidate_section_row(safe_candidate)
        ]
    return engagement


def _dashboard_resume_candidate_payload(
    candidate: TargetResumeCandidate,
) -> dict[str, Any]:
    return {
        "run_id": candidate.run_id,
        "status": candidate.status,
        "reason": candidate.reason,
        "seed_value": _truncate(candidate.seed_value, 160),
        "seed_type": candidate.seed_type,
        "current_iteration": candidate.current_iteration,
        "max_iterations": candidate.max_iterations,
        "resume_enabled": candidate.resume_enabled,
        "attack_mode": candidate.attack_mode,
        "roe_present": bool(candidate.roe_id.strip()),
        "report_available": candidate.report_path_exists,
        "scope_present": candidate.scope_manifest_exists,
        "resume_ready": candidate.resume_ready,
        "resume_blockers": [
            _dashboard_resume_blocker_label(item)
            for item in candidate.resume_blockers[:8]
        ],
        "pending_work_total": candidate.pending_work_total,
        "completed_at": candidate.completed_at,
        "updated_at": candidate.updated_at,
        "error_summary": _redact_dashboard_error(candidate.error_summary, 240),
    }


def _dashboard_resume_candidate_section_row(
    candidate: dict[str, Any],
) -> dict[str, str]:
    return {
        "Run": str(candidate.get("run_id") or ""),
        "Status": str(candidate.get("status") or ""),
        "Reason": str(candidate.get("reason") or ""),
        "Seed": _safe_dashboard_source_url(candidate.get("seed_value"), 160),
        "Type": str(candidate.get("seed_type") or ""),
        "Iteration": (
            f"{int(candidate.get('current_iteration') or 0)}/"
            f"{int(candidate.get('max_iterations') or 0)}"
        ),
        "Pending": str(int(candidate.get("pending_work_total") or 0)),
        "Resume": "yes" if candidate.get("resume_enabled") else "no",
        "Attack": "yes" if candidate.get("attack_mode") else "no",
        "ROE": "yes" if candidate.get("roe_present") else "no",
        "Scope": "yes" if candidate.get("scope_present") else "no",
        "Ready": "yes" if candidate.get("resume_ready") else "no",
        "Blockers": ", ".join(str(item) for item in candidate.get("resume_blockers") or []),
        "Report": "yes" if candidate.get("report_available") else "no",
        "Error": str(candidate.get("error_summary") or ""),
        "Updated": _format_dt(str(candidate.get("updated_at") or "")),
    }


def _dashboard_resume_blocker_label(value: str) -> str:
    labels = {
        "scope_manifest_missing": "scope_missing",
        "scope_manifest_file_missing": "scope_file_missing",
    }
    return labels.get(str(value), str(value))


def generate_dashboard(
    data_dir: Path,
    reports_dir: Path,
    output_path: Path,
    *,
    include_legacy: bool = False,
) -> Path:
    """Build the overview dashboard and per-engagement detail pages."""
    dbs = _engagement_db_files(data_dir, include_legacy=include_legacy)
    site_paths = _prepare_dashboard_site(output_path)

    engagements: list[dict[str, Any]] = []
    for db_path in dbs:
        item = _dashboard_engagement_summary(db_path, reports_dir)
        _assign_engagement_dashboard_routes(item, site_paths)
        _write_engagement_dashboard_outputs(item, site_paths)
        engagements.append(item)

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    _write_dashboard_overview_outputs(
        engagements,
        output_path,
        site_paths,
        generated_at=generated_at,
    )
    return output_path
