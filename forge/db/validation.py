from __future__ import annotations

import re
import sqlite3

from forge.db.migrations import TARGET_VERSION

_SAFE_ID_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _assert_safe_identifier(name: str) -> None:
    """Raise ValueError if *name* is not a safe SQL identifier (table or column)."""
    if not _SAFE_ID_RE.match(name):
        raise ValueError(f"Unsafe SQL identifier rejected: {name!r}")

_REQUIRED_TABLE_COLUMNS: dict[str, set[str]] = {
    "engagements": {
        "id",
        "name",
        "scope_json",
        "status",
        "operator",
        "metadata_json",
        "created_at",
        "updated_at",
    },
    "engagement_seeds": {
        "id",
        "engagement_id",
        "seed_value",
        "seed_type",
        "source",
        "status",
        "depth",
        "confidence",
        "parent_seed_id",
        "metadata_json",
        "discovered_at",
        "updated_at",
    },
    "seed_runs": {
        "id",
        "engagement_id",
        "seed_id",
        "loop_name",
        "status",
        "input_count",
        "output_count",
        "error",
        "metadata_json",
        "started_at",
        "completed_at",
    },
    "engagement_runs": {
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
        "error",
        "metadata_json",
        "started_at",
        "completed_at",
        "updated_at",
    },
    "run_audit_manifests": {
        "id",
        "engagement_id",
        "run_id",
        "manifest_hash",
        "previous_manifest_hash",
        "manifest_json",
        "generated_at",
    },
    "seed_relations": {
        "id",
        "engagement_id",
        "source_seed_id",
        "target_seed_id",
        "relation_type",
        "confidence",
        "evidence_json",
        "discovered_at",
    },
    "artifact_queue": {
        "id",
        "engagement_id",
        "source_url",
        "local_path",
        "artifact_type",
        "discovered_from",
        "status",
        "sha256",
        "notes",
        "metadata_json",
        "attempt_count",
        "max_attempts",
        "queued_at",
        "updated_at",
    },
    "hosts": {"id", "engagement_id", "ip", "hostname", "os_family", "host_context", "in_scope", "discovered_at"},
    "services": {"id", "host_id", "port", "protocol", "service_name", "banner", "version", "discovered_at"},
    "credentials": {
        "id",
        "engagement_id",
        "email",
        "password_hash",
        "password_plaintext_enc",
        "hash_type",
        "hash_plaintext",
        "hash_crack_source",
        "breach_name",
        "breach_date",
        "source",
        "confidence",
        "discovered_at",
        "validated",
        "validated_service",
        "validated_host",
        "validated_at",
        "validation_error",
        "enrichment_data",
    },
    "query_audit": {"id", "engagement_id", "source", "email_queried", "queried_at", "matched", "records_found", "operator"},
    "audit_log": {"id", "engagement_id", "phase", "module", "action", "target", "result", "operator", "logged_at"},
    "task_progress": {"id", "engagement_id", "task_key", "status", "checkpoint", "started_at", "completed_at"},
    "payloads": {"id", "engagement_id", "payload_type", "target_os", "technique", "obfuscation_chain", "delivery_url", "content_hash", "generated_at", "lots_host", "metadata_stripped"},
    "agents": {"id", "engagement_id", "host_id", "beacon_interval", "jitter_pct", "c2_urls", "channel", "sleep_mask", "checkin_at", "created_at"},
    "exfiltrated_data": {"id", "engagement_id", "host_id", "source_path", "staging_path", "file_hash", "bytes_transferred", "chunks_total", "chunks_sent", "exfil_at"},
    "persistence": {"id", "engagement_id", "host_id", "technique", "target_os", "install_cmd", "cleanup_cmd", "lolbins_used", "obfuscation_applied", "installed", "verified", "created_at"},
    "lateral_movement": {"id", "engagement_id", "source_host_id", "target_host_id", "technique", "credential_id", "command", "success", "output", "scope_verified", "operator_confirmed", "executed_at"},
    "llm_feedback": {"id", "engagement_id", "model", "prompt_hash", "response_hash", "quality_score", "validator_ok", "generated_at"},
    "key_scanner_findings": {"id", "engagement_id", "domain", "service", "pattern_name", "source_backend", "source_url", "repo_name", "key_redacted", "key_enc", "validation_state", "validation_detail", "found_at", "validated_at"},
    "emails": {"id", "engagement_id", "email", "domain", "source", "first_seen_at"},
    "email_intelligence": {"id", "engagement_id", "email", "source", "breach_count", "breach_names", "paste_count", "enrichment_data", "last_synced"},
    "dehashed_sync_state": {"id", "engagement_id", "query_type", "query_value", "last_synced", "total_count"},
    "scavenger_findings": {"id", "engagement_id", "url", "pattern_name", "matched_value_enc", "context", "backend", "discovered_at"},
    "vulnerability_findings": {"id", "engagement_id", "vuln_type", "target_url", "parameter", "severity", "title", "description", "evidence", "cvss_score", "found_at"},
    "cloud_assets": {
        "id",
        "engagement_id",
        "asset_type",
        "identifier",
        "provider_identifier",
        "source",
        "discovered_at",
    },
    "cloud_validation_results": {
        "id",
        "engagement_id",
        "asset_type",
        "identifier",
        "provider_identifier",
        "validation_status",
        "validation_method",
        "http_status",
        "evidence",
        "notes",
        "checked_at",
    },
    "validation_claims": {
        "id",
        "engagement_id",
        "claim_type",
        "key_id",
        "asset_type",
        "identifier",
        "owner",
        "claimed_at",
        "expires_at",
        "updated_at",
    },
    "attack_graph_snapshots": {"id", "engagement_id", "snapshot_at", "node_count", "edge_count", "critical_path_weight", "min_severity", "pruned", "graph_json", "mermaid_output", "dot_output"},
    "command_center_actions": {
        "action_id",
        "engagement_id",
        "target_type",
        "target_ref",
        "action_type",
        "confidence_score",
        "risk_level",
        "requires_approval",
        "status",
        "created_at",
        "updated_at",
        "reasoning",
        "opsec_warnings_json",
        "params_json",
        "execution_mode",
        "policy_outcome",
        "policy_reason",
    },
    "command_center_timeline": {
        "event_id",
        "engagement_id",
        "event_type",
        "severity",
        "acknowledged",
        "timestamp",
        "expires_at",
        "payload_json",
    },
    "sentry_state": {
        "engagement_id",
        "enabled",
        "emergency_stop",
        "auto_execute_threshold",
        "max_concurrent_auto",
        "require_operator_approval",
        "pause_on_new_critical_finding",
        "paused_reason",
        "whitelisted_action_types_json",
        "action_overrides_json",
        "engagement_overrides_json",
        "updated_at",
    },
}


def _table_columns(conn: sqlite3.Connection, table_name: str) -> set[str]:
    _assert_safe_identifier(table_name)
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    return {str(row[1]) for row in rows}


def validate_canonical_schema(conn: sqlite3.Connection) -> None:
    row = conn.execute("SELECT MAX(version) FROM _schema_version").fetchone()
    current_version = int(row[0] or 0) if row else 0
    if current_version < TARGET_VERSION:
        raise sqlite3.OperationalError(
            f"Non-canonical engagement DB schema: version={current_version}, required={TARGET_VERSION}. "
            "Rebuild engagement DB from a fresh file."
        )

    missing_tables: list[str] = []
    missing_columns: list[tuple[str, list[str]]] = []
    for table_name, required_columns in _REQUIRED_TABLE_COLUMNS.items():
        actual_columns = _table_columns(conn, table_name)
        if not actual_columns:
            missing_tables.append(table_name)
            continue
        missing = sorted(required_columns - actual_columns)
        if missing:
            missing_columns.append((table_name, missing))

    if not missing_tables and not missing_columns:
        return

    parts: list[str] = ["Non-canonical engagement DB schema detected."]
    if missing_tables:
        parts.append("missing tables: " + ", ".join(sorted(missing_tables)))
    if missing_columns:
        col_text = "; ".join(f"{table} missing [{', '.join(cols)}]" for table, cols in missing_columns)
        parts.append("missing columns: " + col_text)
    parts.append("Rebuild engagement DB from a fresh file.")
    raise sqlite3.OperationalError(" ".join(parts))
