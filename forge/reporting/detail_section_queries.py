"""Dashboard detail-section DB query assembly helpers."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any


RowBuilder = Callable[[Any], dict[str, str]]


@dataclass(frozen=True)
class DetailSectionQueryCallbacks:
    table_exists: Callable[[Any, str], bool]
    table_columns: Callable[[Any, str], set[str]]
    fetch_rows: Callable[[Any, str, tuple[Any, ...]], list[Any]]
    distributed_task_row: RowBuilder
    monitoring_policy_row: RowBuilder
    monitoring_alert_route_row: RowBuilder
    monitoring_alert_suppression_row: RowBuilder
    monitoring_snapshot_row: RowBuilder
    monitoring_trend_row: RowBuilder
    monitoring_change_row: RowBuilder
    monitoring_alert_row: RowBuilder
    remediation_item_row: RowBuilder
    remediation_review_queue_row: Callable[[dict[str, Any]], dict[str, str]]
    remediation_review_queue: Callable[..., dict[str, Any]]
    asset_entity_row: RowBuilder
    asset_relationship_row: RowBuilder
    asset_ownership_claim_row: RowBuilder
    asset_ownership_conflict_row: Callable[[dict[str, Any]], dict[str, str]]
    asset_graph_attack_path_row: Callable[[dict[str, Any]], dict[str, str]]
    asset_graph_choke_point_row: Callable[[dict[str, Any]], dict[str, str]]
    asset_graph_fix_candidate_row: Callable[[dict[str, Any]], dict[str, str]]
    ownership_conflicts_for_engagement: Callable[..., list[dict[str, Any]]]
    list_asset_graph: Callable[..., dict[str, Any]]
    active_validation_coverage_rows: Callable[[Any, int], list[dict[str, str]]]
    active_validation_job_row: RowBuilder
    active_validation_run_row: RowBuilder
    audit_row: RowBuilder
    engagement_seed_row: RowBuilder
    seed_relation_row: RowBuilder
    seed_run_row: RowBuilder
    host_inventory_row: RowBuilder
    email_inventory_row: RowBuilder
    email_intelligence_row: RowBuilder
    account_existence_row: RowBuilder
    engagement_run_row: Callable[[Any, dict[str, Any] | None], dict[str, str]]
    summarize_run_audit_manifest: Callable[..., dict[str, Any]]
    service_row: RowBuilder
    crawl_result_row: RowBuilder
    social_profile_row: RowBuilder
    port_scan_result_row: RowBuilder
    passive_vuln_row: RowBuilder
    auth_test_result_row: RowBuilder
    key_scanner_row: RowBuilder
    key_row_is_reportable: Callable[[Any, dict[tuple[str, str], bool]], bool]
    secret_lifecycle_row: RowBuilder
    vulnerability_finding_row: RowBuilder
    vulnerability_row_is_reportable: Callable[[Any, dict[tuple[str, str], bool]], bool]
    reportable_cloud_validation_index: Callable[[Any, int], dict[tuple[str, str], bool]]
    artifact_queue_row: RowBuilder
    cloud_asset_row: RowBuilder
    cloud_validation_row: RowBuilder
    normalized_cloud_asset_type_sql: Callable[[str], str]
    retention_policy_row: RowBuilder
    retention_run_row: RowBuilder
    retention_run_item_row: RowBuilder


def distributed_task_section_rows(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> list[dict[str, str]]:
    """Return dashboard rows for queued/running distributed tasks."""
    if not callbacks.table_exists(con, "distributed_tasks"):
        return []
    distributed_task_columns = callbacks.table_columns(con, "distributed_tasks")

    def task_column(column: str, fallback: str) -> str:
        if column in distributed_task_columns:
            return f"{column} AS {column}"
        return f"{fallback} AS {column}"

    payload_expr = (
        "payload AS payload_json"
        if "payload" in distributed_task_columns
        else "NULL AS payload_json"
    )
    order_terms: list[str] = []
    if "status" in distributed_task_columns:
        order_terms.append(
            """
            CASE status
                WHEN 'running' THEN 0
                WHEN 'queued' THEN 1
                WHEN 'failed' THEN 2
                WHEN 'done' THEN 3
                WHEN 'completed' THEN 3
                ELSE 4
            END
            """
        )
    if "priority" in distributed_task_columns:
        order_terms.append("priority ASC")
    if "updated_at" in distributed_task_columns:
        order_terms.append("updated_at DESC")
    order_terms.append("rowid DESC")

    return [
        callbacks.distributed_task_row(row)
        for row in callbacks.fetch_rows(
            con,
            f"""
            SELECT {task_column("task_key", "''")},
                   {task_column("status", "''")},
                   {task_column("priority", "100")},
                   {task_column("worker_id", "''")},
                   {task_column("error", "''")},
                   {task_column("created_at", "''")},
                   {task_column("updated_at", "''")},
                   {payload_expr}
            FROM distributed_tasks
            WHERE engagement_id=?
            ORDER BY {", ".join(order_terms)}
            LIMIT ?
            """,
            (engagement_id, limit),
        )
    ]


def host_identity_key(hostname: str, ip: str) -> str:
    normalized_host = str(hostname or "").strip().lower()
    normalized_ip = str(ip or "").strip().lower()
    if normalized_host and normalized_host != normalized_ip:
        return f"host:{normalized_host}"
    if normalized_ip:
        return f"ip:{normalized_ip}"
    return ""


def seed_host_candidates(
    con: Any,
    engagement_id: int,
    *,
    callbacks: DetailSectionQueryCallbacks,
) -> list[dict[str, str]]:
    if not callbacks.table_exists(con, "engagement_seeds"):
        return []
    columns = callbacks.table_columns(con, "engagement_seeds")
    required = {
        "engagement_id",
        "seed_value",
        "seed_type",
        "source",
        "status",
        "discovered_at",
        "updated_at",
        "depth",
        "id",
    }
    if not required.issubset(columns):
        return []
    rows = callbacks.fetch_rows(
        con,
        """
        SELECT seed_value, seed_type, source, status, discovered_at, updated_at
        FROM engagement_seeds
        WHERE engagement_id=?
          AND seed_type IN ('domain', 'subdomain', 'cloud_ref')
          AND COALESCE(status, 'pending') != 'failed'
        ORDER BY depth ASC, id DESC
        """,
        (engagement_id,),
    )
    candidates: list[dict[str, str]] = []
    for row in rows:
        seed_value = str(row["seed_value"] or "").strip().lower()
        if not seed_value or "." not in seed_value:
            continue
        candidates.append(
            {
                "hostname": seed_value,
                "ip": "",
                "os_family": "",
                "discovered_at": str(row["updated_at"] or row["discovered_at"] or ""),
                "source": str(row["source"] or ""),
            }
        )
    return [
        candidate
        for candidate in candidates
        if str(candidate["source"] or "").strip().lower() not in {"scope", "operator"}
    ]


def seed_email_candidates(
    con: Any,
    engagement_id: int,
    *,
    callbacks: DetailSectionQueryCallbacks,
) -> list[dict[str, str]]:
    if not callbacks.table_exists(con, "engagement_seeds"):
        return []
    columns = callbacks.table_columns(con, "engagement_seeds")
    required = {
        "engagement_id",
        "seed_value",
        "seed_type",
        "source",
        "status",
        "discovered_at",
        "updated_at",
        "depth",
        "id",
    }
    if not required.issubset(columns):
        return []
    rows = callbacks.fetch_rows(
        con,
        """
        SELECT seed_value, source, discovered_at, updated_at
        FROM engagement_seeds
        WHERE engagement_id=?
          AND seed_type='email'
          AND COALESCE(status, 'pending') != 'failed'
        ORDER BY depth ASC, id DESC
        """,
        (engagement_id,),
    )
    candidates: list[dict[str, str]] = []
    for row in rows:
        email = str(row["seed_value"] or "").strip().lower()
        if "@" not in email:
            continue
        candidates.append(
            {
                "email": email,
                "domain": email.split("@", 1)[1],
                "source": str(row["source"] or ""),
                "first_seen_at": str(row["updated_at"] or row["discovered_at"] or ""),
            }
        )
    return candidates


def merged_host_rows(
    con: Any,
    engagement_id: int,
    *,
    limit: int | None = None,
    callbacks: DetailSectionQueryCallbacks,
) -> list[dict[str, str]]:
    host_rows = []
    if callbacks.table_exists(con, "hosts"):
        columns = callbacks.table_columns(con, "hosts")
        required = {
            "id",
            "engagement_id",
            "hostname",
            "ip",
            "os_family",
            "discovered_at",
        }
        if required.issubset(columns):
            host_rows = callbacks.fetch_rows(
                con,
                """
                SELECT hostname, ip, os_family, discovered_at
                FROM hosts
                WHERE engagement_id=?
                ORDER BY id DESC
                """,
                (engagement_id,),
            )
    merged: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in host_rows:
        item = {
            "hostname": str(row["hostname"] or ""),
            "ip": str(row["ip"] or ""),
            "os_family": str(row["os_family"] or ""),
            "discovered_at": str(row["discovered_at"] or ""),
            "source": "",
        }
        key = host_identity_key(item["hostname"], item["ip"])
        if not key or key in seen:
            continue
        seen.add(key)
        merged.append(item)
    for candidate in seed_host_candidates(con, engagement_id, callbacks=callbacks):
        key = host_identity_key(candidate["hostname"], candidate["ip"])
        if not key or key in seen:
            continue
        seen.add(key)
        merged.append(candidate)
    return merged[:limit] if limit is not None else merged


def merged_email_rows(
    con: Any,
    engagement_id: int,
    *,
    limit: int | None = None,
    callbacks: DetailSectionQueryCallbacks,
) -> list[dict[str, str]]:
    email_rows = []
    if callbacks.table_exists(con, "emails"):
        columns = callbacks.table_columns(con, "emails")
        required = {"id", "engagement_id", "email", "domain", "source", "first_seen_at"}
        if required.issubset(columns):
            email_rows = callbacks.fetch_rows(
                con,
                """
                SELECT email, domain, source, first_seen_at
                FROM emails
                WHERE engagement_id=?
                ORDER BY id DESC
                """,
                (engagement_id,),
            )
    merged: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in email_rows:
        item = {
            "email": str(row["email"] or "").lower(),
            "domain": str(row["domain"] or ""),
            "source": str(row["source"] or ""),
            "first_seen_at": str(row["first_seen_at"] or ""),
        }
        if not item["email"] or item["email"] in seen:
            continue
        seen.add(item["email"])
        merged.append(item)
    for candidate in seed_email_candidates(con, engagement_id, callbacks=callbacks):
        if not candidate["email"] or candidate["email"] in seen:
            continue
        seen.add(candidate["email"])
        merged.append(candidate)
    return merged[:limit] if limit is not None else merged


def host_section_rows(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> list[dict[str, str]]:
    return [
        callbacks.host_inventory_row(row)
        for row in merged_host_rows(
            con,
            engagement_id,
            limit=limit,
            callbacks=callbacks,
        )
    ]


def email_section_rows(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> list[dict[str, str]]:
    return [
        callbacks.email_inventory_row(row)
        for row in merged_email_rows(
            con,
            engagement_id,
            limit=limit,
            callbacks=callbacks,
        )
    ]


def inventory_sections(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> dict[str, list[dict[str, str]]]:
    """Return merged inventory sections derived from concrete rows and seeds."""
    return {
        "hosts": host_section_rows(
            con,
            engagement_id,
            limit=limit,
            callbacks=callbacks,
        ),
        "emails": email_section_rows(
            con,
            engagement_id,
            limit=limit,
            callbacks=callbacks,
        ),
    }


def engagement_run_section_rows(
    con: Any,
    engagement_id: int,
    *,
    db_path: Any | None,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> list[dict[str, str]]:
    if not callbacks.table_exists(con, "engagement_runs"):
        return []
    columns = callbacks.table_columns(con, "engagement_runs")
    required = {
        "id",
        "engagement_id",
        "run_kind",
        "status",
        "seed_value",
        "seed_type",
        "seed_count",
        "max_iterations",
        "current_iteration",
        "resume_enabled",
        "dry_run",
        "attack_mode",
        "metadata_json",
        "started_at",
        "completed_at",
        "error",
    }
    if not required.issubset(columns):
        return []
    rows = callbacks.fetch_rows(
        con,
        """
        SELECT id,
               run_kind,
               status,
               seed_value,
               seed_type,
               seed_count,
               max_iterations,
               current_iteration,
               resume_enabled,
               dry_run,
               attack_mode,
               metadata_json,
               started_at,
               completed_at,
               error
        FROM engagement_runs
        WHERE engagement_id=?
        ORDER BY started_at DESC, id DESC
        LIMIT ?
        """,
        (engagement_id, limit),
    )
    return [
        callbacks.engagement_run_row(
            row,
            callbacks.summarize_run_audit_manifest(
                con,
                db_path=db_path,
                engagement_id=engagement_id,
                run_id=int(row["id"]),
                verify=db_path is not None,
            ),
        )
        for row in rows
    ]


def monitoring_policy_section_rows(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> list[dict[str, str]]:
    if not callbacks.table_exists(con, "monitoring_policies"):
        return []
    return [
        callbacks.monitoring_policy_row(row)
        for row in callbacks.fetch_rows(
            con,
            """
            SELECT name,
                   enabled,
                   schedule_interval_minutes,
                   mode,
                   last_snapshot_id,
                   last_run_at,
                   next_run_at,
                   updated_at
            FROM monitoring_policies
            WHERE engagement_id=?
            ORDER BY enabled DESC, COALESCE(next_run_at, '') ASC, id DESC
            LIMIT ?
            """,
            (engagement_id, limit),
        )
    ]


def monitoring_alert_route_section_rows(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> list[dict[str, str]]:
    if not callbacks.table_exists(con, "monitoring_alert_routes"):
        return []
    return [
        callbacks.monitoring_alert_route_row(row)
        for row in callbacks.fetch_rows(
            con,
            """
            SELECT name,
                   enabled,
                   min_severity,
                   alert_type,
                   entity_prefix,
                   channel,
                   destination,
                   owner,
                   escalation,
                   updated_at
            FROM monitoring_alert_routes
            WHERE engagement_id=?
            ORDER BY
                enabled DESC,
                CASE min_severity
                    WHEN 'CRITICAL' THEN 0
                    WHEN 'HIGH' THEN 1
                    WHEN 'MEDIUM' THEN 2
                    WHEN 'LOW' THEN 3
                    ELSE 4
                END,
                id DESC
            LIMIT ?
            """,
            (engagement_id, limit),
        )
    ]


def monitoring_alert_suppression_section_rows(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
    now: str | None = None,
) -> list[dict[str, str]]:
    if not callbacks.table_exists(con, "monitoring_alert_suppressions"):
        return []
    now = now or datetime.now().replace(microsecond=0).isoformat()
    return [
        callbacks.monitoring_alert_suppression_row(row)
        for row in callbacks.fetch_rows(
            con,
            """
            SELECT alert_type,
                   entity_key,
                   entity_prefix,
                   severity,
                   reason,
                   created_by,
                   expires_at,
                   updated_at
            FROM monitoring_alert_suppressions
            WHERE engagement_id=?
            ORDER BY
                CASE
                    WHEN expires_at IS NULL OR expires_at='' OR expires_at >= ? THEN 0
                    ELSE 1
                END,
                id DESC
            LIMIT ?
            """,
            (engagement_id, now, limit),
        )
    ]


def monitoring_configuration_sections(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> dict[str, list[dict[str, str]]]:
    """Return monitoring policy, route, and suppression sections."""
    return {
        "monitoring_policies": monitoring_policy_section_rows(
            con,
            engagement_id,
            limit=limit,
            callbacks=callbacks,
        ),
        "monitoring_alert_routes": monitoring_alert_route_section_rows(
            con,
            engagement_id,
            limit=limit,
            callbacks=callbacks,
        ),
        "monitoring_alert_suppressions": monitoring_alert_suppression_section_rows(
            con,
            engagement_id,
            limit=limit,
            callbacks=callbacks,
        ),
    }


def monitoring_snapshot_section_rows(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> list[dict[str, str]]:
    if not callbacks.table_exists(con, "monitoring_snapshots"):
        return []
    return [
        callbacks.monitoring_snapshot_row(row)
        for row in callbacks.fetch_rows(
            con,
            """
            SELECT id,
                   snapshot_kind,
                   state_hash,
                   summary_json,
                   created_at
            FROM monitoring_snapshots
            WHERE engagement_id=?
            ORDER BY id DESC
            LIMIT ?
            """,
            (engagement_id, limit),
        )
    ]


def monitoring_trend_section_rows(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> list[dict[str, str]]:
    if not callbacks.table_exists(con, "monitoring_trend_points"):
        return []
    return [
        callbacks.monitoring_trend_row(row)
        for row in callbacks.fetch_rows(
            con,
            """
            SELECT snapshot_id,
                   observed_at,
                   asset_count,
                   finding_count,
                   critical_count,
                   high_count,
                   added_count,
                   removed_count,
                   changed_count,
                   alert_count,
                   open_alert_count
            FROM monitoring_trend_points
            WHERE engagement_id=?
            ORDER BY observed_at DESC, id DESC
            LIMIT ?
            """,
            (engagement_id, limit),
        )
    ]


def monitoring_change_section_rows(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> list[dict[str, str]]:
    if not callbacks.table_exists(con, "monitoring_changes"):
        return []
    return [
        callbacks.monitoring_change_row(row)
        for row in callbacks.fetch_rows(
            con,
            """
            SELECT snapshot_id,
                   entity_type,
                   entity_key,
                   change_type,
                   severity,
                   before_json,
                   after_json,
                   created_at
            FROM monitoring_changes
            WHERE engagement_id=?
            ORDER BY id DESC
            LIMIT ?
            """,
            (engagement_id, limit),
        )
    ]


def monitoring_alert_section_rows(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> list[dict[str, str]]:
    if not callbacks.table_exists(con, "monitoring_alerts"):
        return []
    return [
        callbacks.monitoring_alert_row(row)
        for row in callbacks.fetch_rows(
            con,
            """
            SELECT snapshot_id,
                   change_id,
                   alert_type,
                   severity,
                   title,
                   status,
                   metadata_json,
                   created_at,
                   updated_at
            FROM monitoring_alerts
            WHERE engagement_id=?
            ORDER BY
              CASE status
                  WHEN 'open' THEN 0
                  WHEN 'acknowledged' THEN 1
                  ELSE 2
              END,
              CASE severity
                  WHEN 'CRITICAL' THEN 0
                  WHEN 'HIGH' THEN 1
                  WHEN 'MEDIUM' THEN 2
                  WHEN 'LOW' THEN 3
                  ELSE 4
              END,
              id DESC
            LIMIT ?
            """,
            (engagement_id, limit),
        )
    ]


def monitoring_history_sections(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> dict[str, list[dict[str, str]]]:
    """Return monitoring snapshot, trend, change, and alert history sections."""
    return {
        "monitoring_snapshots": monitoring_snapshot_section_rows(
            con,
            engagement_id,
            limit=limit,
            callbacks=callbacks,
        ),
        "monitoring_trend_points": monitoring_trend_section_rows(
            con,
            engagement_id,
            limit=limit,
            callbacks=callbacks,
        ),
        "monitoring_changes": monitoring_change_section_rows(
            con,
            engagement_id,
            limit=limit,
            callbacks=callbacks,
        ),
        "monitoring_alerts": monitoring_alert_section_rows(
            con,
            engagement_id,
            limit=limit,
            callbacks=callbacks,
        ),
    }


def remediation_item_section_rows(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> list[dict[str, str]]:
    remediation_columns = callbacks.table_columns(con, "remediation_items")
    if not remediation_columns:
        return []
    risk_expiry_select = (
        "risk_acceptance_expires_at"
        if "risk_acceptance_expires_at" in remediation_columns
        else "NULL AS risk_acceptance_expires_at"
    )
    return [
        callbacks.remediation_item_row(row)
        for row in callbacks.fetch_rows(
            con,
            f"""
            SELECT finding_table,
                   finding_ref,
                   title,
                   severity,
                   owner,
                   sla_due_at,
                   {risk_expiry_select},
                   status,
                   retest_status,
                   ticket_ref,
                   ticket_url,
                   updated_at
            FROM remediation_items
            WHERE engagement_id=?
            ORDER BY
              CASE status
                  WHEN 'open' THEN 0
                  WHEN 'assigned' THEN 1
                  WHEN 'in_progress' THEN 2
                  WHEN 'retest_pending' THEN 3
                  ELSE 4
              END,
              CASE severity
                  WHEN 'CRITICAL' THEN 0
                  WHEN 'HIGH' THEN 1
                  WHEN 'MEDIUM' THEN 2
                  WHEN 'LOW' THEN 3
                  ELSE 4
              END,
              COALESCE(sla_due_at, '9999-12-31') ASC,
              id DESC
            LIMIT ?
            """,
            (engagement_id, limit),
        )
    ]


def remediation_review_queue_section_rows(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> list[dict[str, str]]:
    remediation_columns = callbacks.table_columns(con, "remediation_items")
    if "risk_acceptance_expires_at" not in remediation_columns:
        return []
    queue = callbacks.remediation_review_queue(
        con,
        engagement_id=engagement_id,
        limit=limit,
    )
    return [
        callbacks.remediation_review_queue_row(item)
        for item in queue.get("items", [])
        if isinstance(item, dict)
    ]


def remediation_workflow_sections(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> dict[str, list[dict[str, str]]]:
    """Return remediation item and review-queue sections."""
    return {
        "remediation_items": remediation_item_section_rows(
            con,
            engagement_id,
            limit=limit,
            callbacks=callbacks,
        ),
        "remediation_review_queue": remediation_review_queue_section_rows(
            con,
            engagement_id,
            limit=limit,
            callbacks=callbacks,
        ),
    }


def asset_entity_section_rows(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> list[dict[str, str]]:
    if not callbacks.table_exists(con, "asset_entities"):
        return []
    return [
        callbacks.asset_entity_row(row)
        for row in callbacks.fetch_rows(
            con,
            """
            SELECT entity_key,
                   entity_type,
                   label,
                   source_table,
                   source_id,
                   confidence,
                   metadata_json,
                   updated_at
            FROM asset_entities
            WHERE engagement_id=?
            ORDER BY
              CASE entity_type
                  WHEN 'finding' THEN 0
                  WHEN 'cloud' THEN 1
                  WHEN 'secret' THEN 2
                  WHEN 'host' THEN 3
                  WHEN 'identity' THEN 4
                  WHEN 'owner' THEN 5
                  ELSE 6
              END,
              confidence DESC,
              updated_at DESC,
              id DESC
            LIMIT ?
            """,
            (engagement_id, limit),
        )
    ]


def asset_relationship_section_rows(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> list[dict[str, str]]:
    if not (
        callbacks.table_exists(con, "asset_relationships")
        and callbacks.table_exists(con, "asset_entities")
    ):
        return []
    return [
        callbacks.asset_relationship_row(row)
        for row in callbacks.fetch_rows(
            con,
            """
            SELECT rel.relationship_type,
                   rel.confidence,
                   rel.evidence_json,
                   rel.updated_at,
                   src.entity_key AS source_key,
                   src.label AS source_label,
                   dst.entity_key AS target_key,
                   dst.label AS target_label
            FROM asset_relationships rel
            JOIN asset_entities src ON src.id=rel.source_entity_id
            JOIN asset_entities dst ON dst.id=rel.target_entity_id
            WHERE rel.engagement_id=?
            ORDER BY
              CASE rel.relationship_type
                  WHEN 'has_finding' THEN 0
                  WHEN 'owned_by' THEN 1
                  WHEN 'references_cloud' THEN 2
                  WHEN 'validated_by' THEN 3
                  WHEN 'tracked_by' THEN 4
                  ELSE 5
              END,
              rel.confidence DESC,
              rel.updated_at DESC,
              rel.id DESC
            LIMIT ?
            """,
            (engagement_id, limit),
        )
    ]


def asset_ownership_claim_section_rows(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> list[dict[str, str]]:
    if not (
        callbacks.table_exists(con, "asset_ownership_claims")
        and callbacks.table_exists(con, "asset_entities")
    ):
        return []
    return [
        callbacks.asset_ownership_claim_row(row)
        for row in callbacks.fetch_rows(
            con,
            """
            SELECT c.owner_kind,
                   c.owner_ref,
                   c.owner_display,
                   c.claim_type,
                   c.confidence,
                   c.source,
                   c.status,
                   c.evidence_json,
                   e.entity_key,
                   e.label AS entity_label
            FROM asset_ownership_claims c
            JOIN asset_entities e ON e.id=c.entity_id
            WHERE c.engagement_id=?
            ORDER BY
              CASE c.status
                  WHEN 'active' THEN 0
                  WHEN 'accepted' THEN 1
                  WHEN 'rejected' THEN 2
                  ELSE 3
              END,
              c.confidence DESC,
              c.updated_at DESC,
              c.id DESC
            LIMIT ?
            """,
            (engagement_id, limit),
        )
    ]


def asset_ownership_conflict_section_rows(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> list[dict[str, str]]:
    return [
        callbacks.asset_ownership_conflict_row(conflict)
        for conflict in callbacks.ownership_conflicts_for_engagement(
            con,
            engagement_id,
            limit=limit,
        )
    ]


def asset_graph_analysis_sections(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> dict[str, list[dict[str, str]]]:
    sections: dict[str, list[dict[str, str]]] = {
        "asset_graph_attack_paths": [],
        "asset_graph_choke_points": [],
        "asset_graph_fix_candidates": [],
    }
    if not (
        callbacks.table_exists(con, "asset_entities")
        and callbacks.table_exists(con, "asset_relationships")
    ):
        return sections

    asset_graph = callbacks.list_asset_graph(con, engagement_id, limit=max(limit, 50))
    sections["asset_graph_attack_paths"] = [
        callbacks.asset_graph_attack_path_row(path)
        for path in (asset_graph.get("attack_paths") or [])[:limit]
        if isinstance(path, dict)
    ]
    sections["asset_graph_choke_points"] = [
        callbacks.asset_graph_choke_point_row(point)
        for point in (asset_graph.get("choke_points") or [])[:limit]
        if isinstance(point, dict)
    ]
    sections["asset_graph_fix_candidates"] = [
        callbacks.asset_graph_fix_candidate_row(candidate)
        for candidate in (asset_graph.get("minimal_fix_set_candidates") or [])[:limit]
        if isinstance(candidate, dict)
    ]
    return sections


def asset_graph_sections(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> dict[str, list[dict[str, str]]]:
    """Return asset entity, ownership, and graph-analysis sections."""
    sections = {
        "asset_entities": asset_entity_section_rows(
            con,
            engagement_id,
            limit=limit,
            callbacks=callbacks,
        ),
        "asset_relationships": asset_relationship_section_rows(
            con,
            engagement_id,
            limit=limit,
            callbacks=callbacks,
        ),
        "asset_ownership_claims": asset_ownership_claim_section_rows(
            con,
            engagement_id,
            limit=limit,
            callbacks=callbacks,
        ),
        "asset_ownership_conflicts": asset_ownership_conflict_section_rows(
            con,
            engagement_id,
            limit=limit,
            callbacks=callbacks,
        ),
    }
    sections.update(
        asset_graph_analysis_sections(
            con,
            engagement_id,
            limit=limit,
            callbacks=callbacks,
        )
    )
    return sections


def active_validation_job_section_rows(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> list[dict[str, str]]:
    if not callbacks.table_exists(con, "active_validation_jobs"):
        return []
    return [
        callbacks.active_validation_job_row(row)
        for row in callbacks.fetch_rows(
            con,
            """
            SELECT target_ref,
                   target_kind,
                   method,
                   mode,
                   status,
                   approved,
                   roe_id,
                   scope_manifest_hash,
                   safe_profile,
                   metadata_json,
                   updated_at
            FROM active_validation_jobs
            WHERE engagement_id=?
            ORDER BY
              CASE status
                  WHEN 'approved' THEN 0
                  WHEN 'queued' THEN 1
                  WHEN 'running' THEN 2
                  WHEN 'blocked' THEN 3
                  WHEN 'failed' THEN 4
                  ELSE 5
              END,
              updated_at DESC,
              id DESC
            LIMIT ?
            """,
            (engagement_id, limit),
        )
    ]


def active_validation_run_section_rows(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> list[dict[str, str]]:
    if not callbacks.table_exists(con, "active_validation_runs"):
        return []
    return [
        callbacks.active_validation_run_row(row)
        for row in callbacks.fetch_rows(
            con,
            """
            SELECT job_id,
                   status,
                   result,
                   operator,
                   evidence_json,
                   error,
                   completed_at
            FROM active_validation_runs
            WHERE engagement_id=?
            ORDER BY id DESC
            LIMIT ?
            """,
            (engagement_id, limit),
        )
    ]


def active_validation_sections(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> dict[str, list[dict[str, str]]]:
    """Return active-validation coverage, job, and run sections."""
    return {
        "active_validation_coverage": callbacks.active_validation_coverage_rows(
            con,
            engagement_id,
        ),
        "active_validation_jobs": active_validation_job_section_rows(
            con,
            engagement_id,
            limit=limit,
            callbacks=callbacks,
        ),
        "active_validation_runs": active_validation_run_section_rows(
            con,
            engagement_id,
            limit=limit,
            callbacks=callbacks,
        ),
    }


def audit_log_section_rows(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> list[dict[str, str]]:
    if not callbacks.table_exists(con, "audit_log"):
        return []
    return [
        callbacks.audit_row(row)
        for row in callbacks.fetch_rows(
            con,
            """
            SELECT logged_at, phase, module, action, target, result
            FROM audit_log
            WHERE engagement_id=?
            ORDER BY id DESC
            LIMIT ?
            """,
            (engagement_id, limit),
        )
    ]


def scope_denial_section_rows(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    scope_denial_actions: tuple[str, ...],
    callbacks: DetailSectionQueryCallbacks,
) -> list[dict[str, str]]:
    if not scope_denial_actions or not callbacks.table_exists(con, "audit_log"):
        return []
    placeholders = ",".join("?" for _ in scope_denial_actions)
    return [
        callbacks.audit_row(row)
        for row in callbacks.fetch_rows(
            con,
            f"""
            SELECT logged_at, phase, module, action, target, result
            FROM audit_log
            WHERE engagement_id=? AND action IN ({placeholders})
            ORDER BY id DESC
            LIMIT ?
            """,
            (engagement_id, *scope_denial_actions, limit),
        )
    ]


def audit_sections(
    con: Any,
    engagement_id: int,
    *,
    audit_limit: int,
    scope_denial_limit: int,
    scope_denial_actions: tuple[str, ...],
    callbacks: DetailSectionQueryCallbacks,
) -> dict[str, list[dict[str, str]]]:
    """Return recent audit rows and filtered scope-denial rows."""
    return {
        "audit_log": audit_log_section_rows(
            con,
            engagement_id,
            limit=audit_limit,
            callbacks=callbacks,
        ),
        "scope_denials": scope_denial_section_rows(
            con,
            engagement_id,
            limit=scope_denial_limit,
            scope_denial_actions=scope_denial_actions,
            callbacks=callbacks,
        ),
    }


def engagement_seed_section_rows(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> list[dict[str, str]]:
    if not callbacks.table_exists(con, "engagement_seeds"):
        return []
    return [
        callbacks.engagement_seed_row(row)
        for row in callbacks.fetch_rows(
            con,
            """
            SELECT seed_value, seed_type, source, status, depth, confidence, metadata_json
            FROM engagement_seeds
            WHERE engagement_id=?
            ORDER BY depth ASC, id DESC
            LIMIT ?
            """,
            (engagement_id, limit),
        )
    ]


def seed_relation_section_rows(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> list[dict[str, str]]:
    if not callbacks.table_exists(con, "seed_relations") or not callbacks.table_exists(
        con,
        "engagement_seeds",
    ):
        return []
    return [
        callbacks.seed_relation_row(row)
        for row in callbacks.fetch_rows(
            con,
            """
            SELECT src.seed_value AS source_seed,
                   src.seed_type AS source_type,
                   tgt.seed_value AS target_seed,
                   tgt.seed_type AS target_type,
                   sr.relation_type,
                   sr.confidence,
                   sr.evidence_json,
                   sr.discovered_at
            FROM seed_relations sr
            JOIN engagement_seeds src ON src.id=sr.source_seed_id
            JOIN engagement_seeds tgt ON tgt.id=sr.target_seed_id
            WHERE sr.engagement_id=?
            ORDER BY sr.confidence DESC, sr.id DESC
            LIMIT ?
            """,
            (engagement_id, limit),
        )
    ]


def seed_run_section_rows(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> list[dict[str, str]]:
    if not callbacks.table_exists(con, "seed_runs") or not callbacks.table_exists(
        con,
        "engagement_seeds",
    ):
        return []
    return [
        callbacks.seed_run_row(row)
        for row in callbacks.fetch_rows(
            con,
            """
            SELECT es.seed_value,
                   es.seed_type,
                   sr.loop_name,
                   sr.status,
                   sr.input_count,
                   sr.output_count,
                   sr.started_at,
                   sr.completed_at,
                   sr.error
            FROM seed_runs sr
            JOIN engagement_seeds es ON es.id=sr.seed_id
            WHERE sr.engagement_id=?
            ORDER BY sr.started_at DESC, sr.id DESC
            LIMIT ?
            """,
            (engagement_id, limit),
        )
    ]


def seed_sections(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    seed_run_limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> dict[str, list[dict[str, str]]]:
    """Return seed inventory, relationship, and recursive-run sections."""
    return {
        "engagement_seeds": engagement_seed_section_rows(
            con,
            engagement_id,
            limit=limit,
            callbacks=callbacks,
        ),
        "seed_relations": seed_relation_section_rows(
            con,
            engagement_id,
            limit=limit,
            callbacks=callbacks,
        ),
        "seed_runs": seed_run_section_rows(
            con,
            engagement_id,
            limit=seed_run_limit,
            callbacks=callbacks,
        ),
    }


def email_intelligence_section_rows(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> list[dict[str, str]]:
    if not callbacks.table_exists(con, "email_intelligence"):
        return []
    columns = callbacks.table_columns(con, "email_intelligence")
    paste_expr = "paste_count" if "paste_count" in columns else "0"
    breach_names_expr = "breach_names" if "breach_names" in columns else "'[]'"
    enrichment_expr = "enrichment_data" if "enrichment_data" in columns else "'{}'"
    seen_column = (
        "last_synced"
        if "last_synced" in columns
        else "queried_at"
        if "queried_at" in columns
        else "discovered_at"
        if "discovered_at" in columns
        else ""
    )
    seen_expr = f"{seen_column} AS seen_at" if seen_column else "'' AS seen_at"
    order_by = f"{seen_column} DESC, id DESC" if seen_column else "id DESC"
    return [
        callbacks.email_intelligence_row(row)
        for row in callbacks.fetch_rows(
            con,
            f"""
            SELECT email,
                   source,
                   breach_count,
                   {paste_expr} AS paste_count,
                   {breach_names_expr} AS breach_names,
                   {enrichment_expr} AS enrichment_data,
                   {seen_expr}
            FROM email_intelligence
            WHERE engagement_id=?
            ORDER BY {order_by}
            LIMIT ?
            """,
            (engagement_id, limit),
        )
    ]


def account_existence_section_rows(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> list[dict[str, str]]:
    if not callbacks.table_exists(con, "account_existence"):
        return []
    columns = callbacks.table_columns(con, "account_existence")
    if not {"email", "service"}.issubset(columns):
        return []
    exists_expr = "exists_flag" if "exists_flag" in columns else "1"
    rate_expr = "rate_limited" if "rate_limited" in columns else "0"
    source_expr = "source_tool" if "source_tool" in columns else "'holehe'"
    seen_column = "queried_at" if "queried_at" in columns else ""
    seen_expr = f"{seen_column} AS seen_at" if seen_column else "'' AS seen_at"
    order_by = f"{seen_column} DESC, id DESC" if seen_column else "id DESC"
    return [
        callbacks.account_existence_row(row)
        for row in callbacks.fetch_rows(
            con,
            f"""
            SELECT email,
                   service,
                   {exists_expr} AS exists_flag,
                   {rate_expr} AS rate_limited,
                   {source_expr} AS source_tool,
                   {seen_expr}
            FROM account_existence
            WHERE engagement_id=?
            ORDER BY {order_by}
            LIMIT ?
            """,
            (engagement_id, limit),
        )
    ]


def service_section_rows(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> list[dict[str, str]]:
    if not callbacks.table_exists(con, "services") or not callbacks.table_exists(
        con,
        "hosts",
    ):
        return []
    return [
        callbacks.service_row(row)
        for row in callbacks.fetch_rows(
            con,
            """
            SELECT h.hostname,
                   h.ip,
                   s.port,
                   s.protocol,
                   s.service_name,
                   s.version,
                   s.discovered_at
            FROM services s
            JOIN hosts h ON h.id=s.host_id
            WHERE h.engagement_id=?
            ORDER BY s.id DESC
            LIMIT ?
            """,
            (engagement_id, limit),
        )
    ]


def crawl_result_section_rows(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> list[dict[str, str]]:
    if not callbacks.table_exists(con, "crawl_results"):
        return []
    return [
        callbacks.crawl_result_row(row)
        for row in callbacks.fetch_rows(
            con,
            """
            SELECT COALESCE(final_url, url) AS resolved_url,
                   title,
                   screenshot_path,
                   tech_stack_json,
                   discovered_at
            FROM crawl_results
            WHERE engagement_id=?
            ORDER BY id DESC
            LIMIT ?
            """,
            (engagement_id, limit),
        )
    ]


def social_profile_section_rows(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> list[dict[str, str]]:
    if not callbacks.table_exists(con, "social_profiles"):
        return []
    return [
        callbacks.social_profile_row(row)
        for row in callbacks.fetch_rows(
            con,
            """
            SELECT email, source, profile_data, queried_at
            FROM social_profiles
            WHERE engagement_id=?
            ORDER BY id DESC
            LIMIT ?
            """,
            (engagement_id, limit),
        )
    ]


def port_scan_result_section_rows(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> list[dict[str, str]]:
    if not callbacks.table_exists(con, "port_scan_results"):
        return []
    return [
        callbacks.port_scan_result_row(row)
        for row in callbacks.fetch_rows(
            con,
            """
            SELECT host, port, proto, service, version, confidence, scanned_at
            FROM port_scan_results
            WHERE engagement_id=?
            ORDER BY id DESC
            LIMIT ?
            """,
            (engagement_id, limit),
        )
    ]


def passive_vuln_section_rows(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> list[dict[str, str]]:
    if not callbacks.table_exists(con, "passive_vulns"):
        return []
    return [
        callbacks.passive_vuln_row(row)
        for row in callbacks.fetch_rows(
            con,
            """
            SELECT severity, plugin, vuln_id, verified, false_positive, url, discovered_at
            FROM passive_vulns
            WHERE engagement_id=?
            ORDER BY id DESC
            LIMIT ?
            """,
            (engagement_id, limit),
        )
    ]


def auth_test_result_section_rows(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> list[dict[str, str]]:
    if not callbacks.table_exists(con, "auth_test_results"):
        return []
    return [
        callbacks.auth_test_result_row(row)
        for row in callbacks.fetch_rows(
            con,
            """
            SELECT target_url, attack_type, success, tested_at
            FROM auth_test_results
            WHERE engagement_id=?
            ORDER BY id DESC
            LIMIT ?
            """,
            (engagement_id, limit),
        )
    ]


def _select_expr(
    columns: set[str],
    table_alias: str,
    column: str,
    output: str,
    default: str = "NULL",
) -> str:
    if column in columns:
        return f"{table_alias}.{column} AS {output}"
    return f"{default} AS {output}"


def key_scanner_rows(
    con: Any,
    engagement_id: int,
    *,
    callbacks: DetailSectionQueryCallbacks,
) -> list[Any]:
    columns = callbacks.table_columns(con, "key_scanner_findings")
    if not {"engagement_id", "validation_state"}.issubset(columns):
        return []
    select_parts = [
        "domain" if "domain" in columns else "NULL AS domain",
        "service" if "service" in columns else "NULL AS service",
        "pattern_name" if "pattern_name" in columns else "NULL AS pattern_name",
        "validation_state",
        "found_at" if "found_at" in columns else "NULL AS found_at",
        "source_backend" if "source_backend" in columns else "NULL AS source_backend",
        "source_url" if "source_url" in columns else "NULL AS source_url",
        "repo_name" if "repo_name" in columns else "NULL AS repo_name",
        "validation_detail" if "validation_detail" in columns else "NULL AS validation_detail",
        "validated_at" if "validated_at" in columns else "NULL AS validated_at",
    ]
    order_by = "id DESC" if "id" in columns else "rowid DESC"
    return callbacks.fetch_rows(
        con,
        f"""
        SELECT {', '.join(select_parts)}
        FROM key_scanner_findings
        WHERE engagement_id=?
        ORDER BY {order_by}
        """,
        (engagement_id,),
    )


def reportable_key_scanner_rows(
    con: Any,
    engagement_id: int,
    *,
    limit: int | None = None,
    callbacks: DetailSectionQueryCallbacks,
) -> list[Any]:
    validation_index = callbacks.reportable_cloud_validation_index(con, engagement_id)
    rows = [
        row
        for row in key_scanner_rows(con, engagement_id, callbacks=callbacks)
        if callbacks.key_row_is_reportable(row, validation_index)
    ]
    return rows[:limit] if limit is not None else rows


def key_scanner_inventory_rows(
    con: Any,
    engagement_id: int,
    *,
    limit: int | None = None,
    callbacks: DetailSectionQueryCallbacks,
) -> list[Any]:
    return reportable_key_scanner_rows(
        con,
        engagement_id,
        limit=limit,
        callbacks=callbacks,
    )


def key_scanner_finding_section_rows(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> list[dict[str, str]]:
    return [
        callbacks.key_scanner_row(row)
        for row in key_scanner_inventory_rows(
            con,
            engagement_id,
            limit=limit,
            callbacks=callbacks,
        )
    ]


def secret_lifecycle_section_rows(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> list[dict[str, str]]:
    if not callbacks.table_exists(con, "secret_lifecycle_items"):
        return []
    lifecycle_columns = callbacks.table_columns(con, "secret_lifecycle_items")
    key_columns = (
        callbacks.table_columns(con, "key_scanner_findings")
        if callbacks.table_exists(con, "key_scanner_findings")
        else set()
    )
    remediation_columns = (
        callbacks.table_columns(con, "remediation_items")
        if callbacks.table_exists(con, "remediation_items")
        else set()
    )

    key_join = ""
    if {"id", "engagement_id"}.issubset(key_columns) and "key_finding_id" in lifecycle_columns:
        key_join = """
            LEFT JOIN key_scanner_findings k
                   ON k.id=sli.key_finding_id
                  AND k.engagement_id=sli.engagement_id
            """
    remediation_join = ""
    if {
        "engagement_id",
        "finding_table",
        "finding_ref",
    }.issubset(remediation_columns) and "key_finding_id" in lifecycle_columns:
        remediation_join = """
            LEFT JOIN remediation_items r
                   ON r.engagement_id=sli.engagement_id
                  AND r.finding_table='key_scanner_findings'
                  AND r.finding_ref=CAST(sli.key_finding_id AS TEXT)
            """
    key_selects = (
        [
            _select_expr(key_columns, "k", "service", "service"),
            _select_expr(key_columns, "k", "pattern_name", "pattern_name"),
            _select_expr(key_columns, "k", "source_url", "source_url"),
            _select_expr(key_columns, "k", "repo_name", "repo_name"),
        ]
        if key_join
        else [
            "NULL AS service",
            "NULL AS pattern_name",
            "NULL AS source_url",
            "NULL AS repo_name",
        ]
    )
    remediation_selects = (
        [
            _select_expr(remediation_columns, "r", "id", "remediation_id"),
            _select_expr(remediation_columns, "r", "status", "remediation_status"),
        ]
        if remediation_join
        else ["NULL AS remediation_id", "NULL AS remediation_status"]
    )
    order_terms: list[str] = []
    if "lifecycle_status" in lifecycle_columns:
        order_terms.append(
            """
            CASE sli.lifecycle_status
                WHEN 'owner_routed' THEN 0
                WHEN 'revocation_guided' THEN 1
                WHEN 'open' THEN 2
                WHEN 'risk_accepted' THEN 3
                WHEN 'suppressed' THEN 4
                WHEN 'revoked' THEN 5
                ELSE 6
            END
            """
        )
    if "suppressed" in lifecycle_columns:
        order_terms.append("sli.suppressed ASC")
    if "updated_at" in lifecycle_columns:
        order_terms.append("sli.updated_at DESC")
    if "id" in lifecycle_columns:
        order_terms.append("sli.id DESC")
    order_by = ", ".join(order_terms) if order_terms else "sli.rowid DESC"
    select_parts = [
        _select_expr(lifecycle_columns, "sli", "key_finding_id", "key_finding_id"),
        _select_expr(lifecycle_columns, "sli", "lifecycle_status", "lifecycle_status", "''"),
        _select_expr(lifecycle_columns, "sli", "owner", "owner", "''"),
        _select_expr(lifecycle_columns, "sli", "owner_source", "owner_source", "''"),
        _select_expr(lifecycle_columns, "sli", "suppression_id", "suppression_id"),
        _select_expr(lifecycle_columns, "sli", "suppressed", "suppressed", "0"),
        _select_expr(
            lifecycle_columns,
            "sli",
            "revocation_guidance_json",
            "revocation_guidance_json",
            "'{}'",
        ),
        _select_expr(
            lifecycle_columns,
            "sli",
            "prevention_guidance_json",
            "prevention_guidance_json",
            "'[]'",
        ),
        _select_expr(lifecycle_columns, "sli", "metadata_json", "metadata_json", "'{}'"),
        _select_expr(lifecycle_columns, "sli", "updated_at", "updated_at", "''"),
        *key_selects,
        *remediation_selects,
    ]
    return [
        callbacks.secret_lifecycle_row(row)
        for row in callbacks.fetch_rows(
            con,
            f"""
            SELECT {", ".join(select_parts)}
            FROM secret_lifecycle_items sli
            {key_join}
            {remediation_join}
            WHERE sli.engagement_id=?
            ORDER BY {order_by}
            LIMIT ?
            """,
            (engagement_id, limit),
        )
    ]


def reportable_vulnerability_rows(
    con: Any,
    engagement_id: int,
    *,
    limit: int | None = None,
    callbacks: DetailSectionQueryCallbacks,
) -> list[Any]:
    columns = callbacks.table_columns(con, "vulnerability_findings")
    if not columns or "engagement_id" not in columns:
        return []
    select_parts = [
        "id" if "id" in columns else "NULL AS id",
        "host_id" if "host_id" in columns else "NULL AS host_id",
        "severity" if "severity" in columns else "'INFO' AS severity",
        "vuln_type" if "vuln_type" in columns else "NULL AS vuln_type",
        "title" if "title" in columns else "NULL AS title",
        "target_url" if "target_url" in columns else "NULL AS target_url",
        "parameter" if "parameter" in columns else "NULL AS parameter",
        "evidence" if "evidence" in columns else "NULL AS evidence",
        "cloud_provider" if "cloud_provider" in columns else "NULL AS cloud_provider",
        "resource_id" if "resource_id" in columns else "NULL AS resource_id",
        "found_at" if "found_at" in columns else "NULL AS found_at",
    ]
    rows = callbacks.fetch_rows(
        con,
        f"""
        SELECT {', '.join(select_parts)}
        FROM vulnerability_findings
        WHERE engagement_id=?
        ORDER BY id DESC
        """,
        (engagement_id,),
    )
    validation_index = callbacks.reportable_cloud_validation_index(con, engagement_id)
    reportable = [
        row for row in rows if callbacks.vulnerability_row_is_reportable(row, validation_index)
    ]
    return reportable[:limit] if limit is not None else reportable


def representative_vulnerability_rows(rows: list[Any], limit: int) -> list[Any]:
    if len(rows) <= limit:
        return rows
    selected: list[Any] = []
    selected_ids: set[str] = set()
    seen_titles: set[str] = set()

    def _row_key(row: Any) -> str:
        return str(row["id"] or f"{row['title']}|{row['target_url']}")

    for row in rows:
        title = str(row["title"] or "").strip().lower()
        if not title or title in seen_titles:
            continue
        selected.append(row)
        selected_ids.add(_row_key(row))
        seen_titles.add(title)
        if len(selected) >= limit:
            return selected
    for row in rows:
        key = _row_key(row)
        if key in selected_ids:
            continue
        selected.append(row)
        if len(selected) >= limit:
            break
    return selected


def vulnerability_finding_section_rows(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> list[dict[str, str]]:
    rows = representative_vulnerability_rows(
        reportable_vulnerability_rows(
            con,
            engagement_id,
            callbacks=callbacks,
        ),
        limit,
    )
    return [callbacks.vulnerability_finding_row(row) for row in rows]


def finding_sections(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> dict[str, list[dict[str, str]]]:
    """Return secret, lifecycle, and validated vulnerability finding sections."""
    return {
        "key_scanner_findings": key_scanner_finding_section_rows(
            con,
            engagement_id,
            limit=limit,
            callbacks=callbacks,
        ),
        "secret_lifecycle_items": secret_lifecycle_section_rows(
            con,
            engagement_id,
            limit=limit,
            callbacks=callbacks,
        ),
        "vulnerability_findings": vulnerability_finding_section_rows(
            con,
            engagement_id,
            limit=limit,
            callbacks=callbacks,
        ),
    }


def artifact_queue_section_rows(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> list[dict[str, str]]:
    if not callbacks.table_exists(con, "artifact_queue"):
        return []
    columns = callbacks.table_columns(con, "artifact_queue")
    local_path_expr = "local_path" if "local_path" in columns else "NULL AS local_path"
    discovered_from_expr = (
        "discovered_from" if "discovered_from" in columns else "NULL AS discovered_from"
    )
    return [
        callbacks.artifact_queue_row(row)
        for row in callbacks.fetch_rows(
            con,
            f"""
            SELECT source_url,
                   artifact_type,
                   status,
                   notes,
                   metadata_json,
                   queued_at,
                   {local_path_expr},
                   {discovered_from_expr}
            FROM artifact_queue
            WHERE engagement_id=?
            ORDER BY id DESC
            LIMIT ?
            """,
            (engagement_id, limit),
        )
    ]


def cloud_asset_section_rows(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> list[dict[str, str]]:
    if not callbacks.table_exists(con, "cloud_assets"):
        return []
    cloud_columns = callbacks.table_columns(con, "cloud_assets")
    ca_asset_type_key = callbacks.normalized_cloud_asset_type_sql("ca.asset_type")
    cvr_asset_type_key = callbacks.normalized_cloud_asset_type_sql(
        "cvr_latest.asset_type"
    )
    provider_expr = (
        "COALESCE(NULLIF(ca.provider_identifier, ''), ca.identifier) AS display_identifier"
        if "provider_identifier" in cloud_columns
        else "ca.identifier AS display_identifier"
    )
    source_expr = "ca.source" if "source" in cloud_columns else "NULL AS source"
    discovered_expr = (
        "ca.discovered_at" if "discovered_at" in cloud_columns else "NULL AS discovered_at"
    )
    metadata_expr = (
        "ca.metadata_json" if "metadata_json" in cloud_columns else "'{}' AS metadata_json"
    )
    order_expr = (
        "COALESCE(ca.discovered_at, '') DESC, ca.id DESC"
        if "discovered_at" in cloud_columns
        else "ca.id DESC"
    )
    if callbacks.table_exists(con, "cloud_validation_results"):
        validation_select = """
               cvr.validation_status,
               cvr.validation_method,
               cvr.http_status,
               cvr.evidence,
               cvr.notes,
               cvr.checked_at
        """
        validation_join = f"""
        LEFT JOIN cloud_validation_results cvr
          ON cvr.id = (
              SELECT cvr_latest.id
              FROM cloud_validation_results cvr_latest
              WHERE cvr_latest.engagement_id=ca.engagement_id
                AND {cvr_asset_type_key}={ca_asset_type_key}
                AND cvr_latest.identifier=ca.identifier
              ORDER BY COALESCE(cvr_latest.checked_at, '') DESC, cvr_latest.id DESC
              LIMIT 1
          )
        """
    else:
        validation_select = """
               NULL AS validation_status,
               NULL AS validation_method,
               NULL AS http_status,
               NULL AS evidence,
               NULL AS notes,
               NULL AS checked_at
        """
        validation_join = ""
    return [
        callbacks.cloud_asset_row(row)
        for row in callbacks.fetch_rows(
            con,
            f"""
            SELECT ca.asset_type,
                   ca.identifier,
                   {provider_expr},
                   {source_expr},
                   {metadata_expr},
                   {discovered_expr},
                   {validation_select}
            FROM cloud_assets ca
            {validation_join}
            WHERE ca.engagement_id=?
            ORDER BY {order_expr}
            LIMIT ?
            """,
            (engagement_id, limit),
        )
    ]


def cloud_validation_result_section_rows(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> list[dict[str, str]]:
    if not callbacks.table_exists(con, "cloud_validation_results"):
        return []
    validation_columns = callbacks.table_columns(con, "cloud_validation_results")
    validation_asset_expr = (
        "COALESCE(NULLIF(provider_identifier, ''), identifier) AS display_identifier"
        if "provider_identifier" in validation_columns
        else "identifier AS display_identifier"
    )
    return [
        callbacks.cloud_validation_row(row)
        for row in callbacks.fetch_rows(
            con,
            f"""
            SELECT {validation_asset_expr},
                   asset_type,
                   validation_status,
                   validation_method,
                   http_status,
                   evidence,
                   notes,
                   checked_at
            FROM cloud_validation_results
            WHERE engagement_id=?
            ORDER BY COALESCE(checked_at, '') DESC, id DESC
            LIMIT ?
            """,
            (engagement_id, limit),
        )
    ]


def cloud_sections(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> dict[str, list[dict[str, str]]]:
    """Return cloud asset inventory and validation-result sections."""
    return {
        "cloud_assets": cloud_asset_section_rows(
            con,
            engagement_id,
            limit=limit,
            callbacks=callbacks,
        ),
        "cloud_validation_results": cloud_validation_result_section_rows(
            con,
            engagement_id,
            limit=limit,
            callbacks=callbacks,
        ),
    }


def retention_policy_section_rows(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> list[dict[str, str]]:
    if not callbacks.table_exists(con, "retention_policies"):
        return []
    return [
        callbacks.retention_policy_row(row)
        for row in callbacks.fetch_rows(
            con,
            """
            SELECT name,
                   enabled,
                   audit_review_days,
                   monitoring_days,
                   remediation_event_days,
                   retention_run_days,
                   legal_hold_override,
                   metadata_json,
                   updated_at
            FROM retention_policies
            WHERE engagement_id=?
            ORDER BY enabled DESC, name ASC, updated_at DESC, id DESC
            LIMIT ?
            """,
            (engagement_id, limit),
        )
    ]


def retention_run_section_rows(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> list[dict[str, str]]:
    if not callbacks.table_exists(con, "retention_runs"):
        return []
    return [
        callbacks.retention_run_row(row)
        for row in callbacks.fetch_rows(
            con,
            """
            SELECT id,
                   policy_name,
                   mode,
                   status,
                   operator,
                   summary_json,
                   created_at
            FROM retention_runs
            WHERE engagement_id=?
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            """,
            (engagement_id, limit),
        )
    ]


def retention_run_item_section_rows(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> list[dict[str, str]]:
    if not callbacks.table_exists(con, "retention_run_items"):
        return []
    return [
        callbacks.retention_run_item_row(row)
        for row in callbacks.fetch_rows(
            con,
            """
            SELECT retention_run_id,
                   category,
                   table_name,
                   retention_days,
                   cutoff_at,
                   eligible_count,
                   deleted_count,
                   skipped_count,
                   reason,
                   created_at
            FROM retention_run_items
            WHERE engagement_id=?
            ORDER BY retention_run_id DESC,
                     eligible_count DESC,
                     category ASC,
                     id DESC
            LIMIT ?
            """,
            (engagement_id, limit),
        )
    ]


def retention_sections(
    con: Any,
    engagement_id: int,
    *,
    limit: int,
    callbacks: DetailSectionQueryCallbacks,
) -> dict[str, list[dict[str, str]]]:
    """Return retention policy/run sections."""
    return {
        "retention_policies": retention_policy_section_rows(
            con,
            engagement_id,
            limit=limit,
            callbacks=callbacks,
        ),
        "retention_runs": retention_run_section_rows(
            con,
            engagement_id,
            limit=limit,
            callbacks=callbacks,
        ),
        "retention_run_items": retention_run_item_section_rows(
            con,
            engagement_id,
            limit=limit,
            callbacks=callbacks,
        ),
    }


__all__ = [
    "DetailSectionQueryCallbacks",
    "account_existence_section_rows",
    "active_validation_job_section_rows",
    "active_validation_run_section_rows",
    "active_validation_sections",
    "artifact_queue_section_rows",
    "audit_log_section_rows",
    "audit_sections",
    "auth_test_result_section_rows",
    "asset_entity_section_rows",
    "asset_graph_analysis_sections",
    "asset_graph_sections",
    "asset_ownership_claim_section_rows",
    "asset_ownership_conflict_section_rows",
    "asset_relationship_section_rows",
    "cloud_asset_section_rows",
    "cloud_sections",
    "cloud_validation_result_section_rows",
    "crawl_result_section_rows",
    "distributed_task_section_rows",
    "email_intelligence_section_rows",
    "email_section_rows",
    "engagement_run_section_rows",
    "engagement_seed_section_rows",
    "finding_sections",
    "host_identity_key",
    "host_section_rows",
    "inventory_sections",
    "key_scanner_finding_section_rows",
    "key_scanner_inventory_rows",
    "key_scanner_rows",
    "merged_email_rows",
    "merged_host_rows",
    "monitoring_alert_route_section_rows",
    "monitoring_alert_section_rows",
    "monitoring_alert_suppression_section_rows",
    "monitoring_change_section_rows",
    "monitoring_configuration_sections",
    "monitoring_history_sections",
    "monitoring_policy_section_rows",
    "monitoring_snapshot_section_rows",
    "monitoring_trend_section_rows",
    "passive_vuln_section_rows",
    "port_scan_result_section_rows",
    "reportable_key_scanner_rows",
    "reportable_vulnerability_rows",
    "remediation_item_section_rows",
    "remediation_review_queue_section_rows",
    "remediation_workflow_sections",
    "representative_vulnerability_rows",
    "retention_policy_section_rows",
    "retention_run_item_section_rows",
    "retention_run_section_rows",
    "retention_sections",
    "scope_denial_section_rows",
    "seed_relation_section_rows",
    "seed_run_section_rows",
    "seed_sections",
    "seed_email_candidates",
    "seed_host_candidates",
    "secret_lifecycle_section_rows",
    "service_section_rows",
    "social_profile_section_rows",
    "vulnerability_finding_section_rows",
]
