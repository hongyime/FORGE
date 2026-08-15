import sqlite3
from typing import Any

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
    inventory_sections,
    monitoring_configuration_sections,
    monitoring_history_sections,
    passive_vuln_section_rows,
    port_scan_result_section_rows,
    remediation_workflow_sections,
    representative_vulnerability_rows,
    retention_sections,
    seed_sections,
    service_section_rows,
    social_profile_section_rows,
)


def _connect() -> sqlite3.Connection:
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    return con


def _table_exists(con: sqlite3.Connection, table: str) -> bool:
    row = con.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone()
    return row is not None


def _table_columns(con: sqlite3.Connection, table: str) -> set[str]:
    if not _table_exists(con, table):
        return set()
    return {str(row["name"]) for row in con.execute(f"PRAGMA table_info({table})")}


def _fetch_rows(
    con: sqlite3.Connection,
    sql: str,
    params: tuple[Any, ...],
) -> list[sqlite3.Row]:
    return list(con.execute(sql, params).fetchall())


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


def _callbacks(
    *,
    active_validation_coverage: list[dict[str, str]] | None = None,
    review_queue_items: list[dict[str, Any]] | None = None,
    ownership_conflicts: list[dict[str, Any]] | None = None,
    asset_graph: dict[str, Any] | None = None,
    key_reportable_services: set[str] | None = None,
    vulnerability_reportable_titles: set[str] | None = None,
    cloud_validation_index: dict[tuple[str, str], bool] | None = None,
    manifest_calls: list[dict[str, Any]] | None = None,
    manifest_summaries: dict[int, dict[str, Any]] | None = None,
) -> DetailSectionQueryCallbacks:
    def summarize_manifest(_con: sqlite3.Connection, **kwargs: Any) -> dict[str, Any]:
        if manifest_calls is not None:
            manifest_calls.append(dict(kwargs))
        run_id = int(kwargs.get("run_id") or 0)
        return (manifest_summaries or {}).get(
            run_id,
            {"short_hash": "", "verified": False, "verification_status": "missing"},
        )

    return DetailSectionQueryCallbacks(
        table_exists=_table_exists,
        table_columns=_table_columns,
        fetch_rows=_fetch_rows,
        distributed_task_row=lambda row: {
            "task": str(row["task_key"]),
            "status": str(row["status"]),
            "priority": str(row["priority"]),
            "worker": str(row["worker_id"]),
            "payload": str(row["payload_json"]),
        },
        monitoring_policy_row=lambda row: {
            "policy": str(row["name"]),
            "next": str(row["next_run_at"]),
        },
        monitoring_alert_route_row=lambda row: {
            "route": str(row["name"]),
            "severity": str(row["min_severity"]),
        },
        monitoring_alert_suppression_row=lambda row: {
            "reason": str(row["reason"]),
            "expires": str(row["expires_at"]),
        },
        monitoring_snapshot_row=lambda row: {
            "snapshot": str(row["id"]),
            "kind": str(row["snapshot_kind"]),
        },
        monitoring_trend_row=lambda row: {
            "snapshot": str(row["snapshot_id"]),
            "observed": str(row["observed_at"]),
        },
        monitoring_change_row=lambda row: {
            "entity": str(row["entity_key"]),
            "change": str(row["change_type"]),
        },
        monitoring_alert_row=lambda row: {
            "title": str(row["title"]),
            "severity": str(row["severity"]),
            "status": str(row["status"]),
        },
        remediation_item_row=lambda row: {
            "finding": f"{row['finding_table']}:{row['finding_ref']}",
            "severity": str(row["severity"]),
            "status": str(row["status"]),
            "sla": str(row["sla_due_at"]),
            "risk_expiry": str(row["risk_acceptance_expires_at"]),
        },
        remediation_review_queue_row=lambda item: {
            "title": str(item.get("title") or ""),
            "priority": str(item.get("review_priority") or ""),
        },
        remediation_review_queue=lambda _con, *, engagement_id, limit: {
            "engagement_id": engagement_id,
            "limit": limit,
            "items": review_queue_items or [],
        },
        asset_entity_row=lambda row: {
            "key": str(row["entity_key"]),
            "type": str(row["entity_type"]),
            "confidence": str(row["confidence"]),
        },
        asset_relationship_row=lambda row: {
            "type": str(row["relationship_type"]),
            "from": str(row["source_label"] or row["source_key"]),
            "to": str(row["target_label"] or row["target_key"]),
        },
        asset_ownership_claim_row=lambda row: {
            "asset": str(row["entity_label"] or row["entity_key"]),
            "owner": str(row["owner_display"] or row["owner_ref"]),
            "status": str(row["status"]),
        },
        asset_ownership_conflict_row=lambda conflict: {
            "asset": str(conflict.get("entity_key") or ""),
            "owners": str(conflict.get("owner_count") or 0),
        },
        asset_graph_attack_path_row=lambda path: {
            "path": str(path.get("path_id") or ""),
        },
        asset_graph_choke_point_row=lambda point: {
            "entity": str(point.get("entity_key") or ""),
        },
        asset_graph_fix_candidate_row=lambda candidate: {
            "entity": str(candidate.get("entity_key") or ""),
        },
        ownership_conflicts_for_engagement=lambda _con, _engagement_id, *, limit: (
            ownership_conflicts or []
        )[:limit],
        list_asset_graph=lambda _con, _engagement_id, *, limit: asset_graph or {},
        active_validation_coverage_rows=lambda _con, _engagement_id: (
            active_validation_coverage or []
        ),
        active_validation_job_row=lambda row: {
            "target": str(row["target_ref"]),
            "status": str(row["status"]),
            "method": str(row["method"]),
            "updated": str(row["updated_at"]),
        },
        active_validation_run_row=lambda row: {
            "job": str(row["job_id"]),
            "status": str(row["status"]),
            "result": str(row["result"]),
        },
        audit_row=lambda row: {
            "when": str(row["logged_at"]),
            "action": str(row["action"]),
            "module": str(row["module"]),
            "target": str(row["target"]),
            "result": str(row["result"]),
        },
        engagement_seed_row=lambda row: {
            "seed": str(row["seed_value"]),
            "type": str(row["seed_type"]),
            "depth": str(row["depth"]),
            "metadata": str(row["metadata_json"]),
        },
        seed_relation_row=lambda row: {
            "from": str(row["source_seed"]),
            "to": str(row["target_seed"]),
            "confidence": str(row["confidence"]),
        },
        seed_run_row=lambda row: {
            "seed": str(row["seed_value"]),
            "loop": str(row["loop_name"]),
            "status": str(row["status"]),
        },
        host_inventory_row=lambda row: {
            "host": str(row["hostname"]),
            "ip": str(row["ip"]),
            "os": str(row["os_family"]),
            "source": str(row["source"]),
            "seen": str(row["discovered_at"]),
        },
        email_inventory_row=lambda row: {
            "email": str(row["email"]),
            "domain": str(row["domain"]),
            "source": str(row["source"]),
            "seen": str(row["first_seen_at"]),
        },
        email_intelligence_row=lambda row: {
            "email": str(row["email"]),
            "source": str(row["source"]),
            "breaches": str(row["breach_count"]),
            "pastes": str(row["paste_count"]),
            "seen": str(row["seen_at"]),
        },
        account_existence_row=lambda row: {
            "email": str(row["email"]),
            "service": str(row["service"]),
            "exists": str(row["exists_flag"]),
            "rate_limited": str(row["rate_limited"]),
            "source": str(row["source_tool"]),
            "seen": str(row["seen_at"]),
        },
        engagement_run_row=lambda row, manifest: {
            "run": str(row["id"]),
            "kind": str(row["run_kind"]),
            "status": str(row["status"]),
            "seed": str(row["seed_value"]),
            "iteration": f"{row['current_iteration']}/{row['max_iterations']}",
            "manifest": str((manifest or {}).get("short_hash") or ""),
            "verified": str((manifest or {}).get("verified")),
        },
        summarize_run_audit_manifest=summarize_manifest,
        service_row=lambda row: {
            "host": str(row["hostname"] or row["ip"]),
            "port": str(row["port"]),
        },
        crawl_result_row=lambda row: {
            "url": str(row["resolved_url"]),
            "title": str(row["title"]),
        },
        social_profile_row=lambda row: {
            "email": str(row["email"]),
            "source": str(row["source"]),
        },
        port_scan_result_row=lambda row: {
            "host": str(row["host"]),
            "port": str(row["port"]),
        },
        passive_vuln_row=lambda row: {
            "vuln": str(row["vuln_id"]),
            "severity": str(row["severity"]),
        },
        auth_test_result_row=lambda row: {
            "target": str(row["target_url"]),
            "success": str(row["success"]),
        },
        key_scanner_row=lambda row: {
            "domain": str(row["domain"]),
            "service": str(row["service"]),
            "pattern": str(row["pattern_name"]),
            "state": str(row["validation_state"]),
            "backend": str(row["source_backend"]),
            "source": str(row["source_url"]),
            "repo": str(row["repo_name"]),
            "validated": str(row["validated_at"]),
            "seen": str(row["found_at"]),
        },
        key_row_is_reportable=lambda row, _validation_index: str(
            row["service"] or ""
        )
        in (key_reportable_services or set()),
        secret_lifecycle_row=lambda row: {
            "key": str(row["key_finding_id"]),
            "service": str(row["service"]),
            "pattern": str(row["pattern_name"]),
            "lifecycle": str(row["lifecycle_status"]),
            "owner": str(row["owner"]),
            "owner_source": str(row["owner_source"]),
            "suppression": str(row["suppression_id"]),
            "suppressed": str(row["suppressed"]),
            "revocation": str(row["revocation_guidance_json"]),
            "prevention": str(row["prevention_guidance_json"]),
            "metadata": str(row["metadata_json"]),
            "updated": str(row["updated_at"]),
            "remediation": str(row["remediation_id"]),
            "remediation_status": str(row["remediation_status"]),
            "source": str(row["source_url"]),
            "repo": str(row["repo_name"]),
        },
        vulnerability_finding_row=lambda row: {
            "id": str(row["id"]),
            "title": str(row["title"]),
            "severity": str(row["severity"]),
            "type": str(row["vuln_type"]),
            "target": str(row["target_url"]),
            "parameter": str(row["parameter"]),
            "provider": str(row["cloud_provider"]),
            "resource": str(row["resource_id"]),
            "found": str(row["found_at"]),
        },
        vulnerability_row_is_reportable=lambda row, _validation_index: str(
            row["title"] or ""
        )
        in (vulnerability_reportable_titles or set()),
        reportable_cloud_validation_index=lambda _con, _engagement_id: (
            cloud_validation_index or {}
        ),
        artifact_queue_row=lambda row: {
            "artifact": str(row["source_url"]),
            "type": str(row["artifact_type"]),
            "status": str(row["status"]),
            "local": str(row["local_path"]),
            "origin": str(row["discovered_from"]),
        },
        cloud_asset_row=lambda row: {
            "asset": str(row["display_identifier"] or row["identifier"]),
            "type": str(row["asset_type"]),
            "validation": str(row["validation_status"]),
            "method": str(row["validation_method"]),
            "checked": str(row["checked_at"]),
            "source": str(row["source"]),
        },
        cloud_validation_row=lambda row: {
            "asset": str(row["display_identifier"]),
            "type": str(row["asset_type"]),
            "status": str(row["validation_status"]),
            "checked": str(row["checked_at"]),
        },
        normalized_cloud_asset_type_sql=_normalized_cloud_asset_type_sql,
        retention_policy_row=lambda row: {
            "policy": str(row["name"]),
            "audit": str(row["audit_review_days"]),
        },
        retention_run_row=lambda row: {
            "run": str(row["id"]),
            "created": str(row["created_at"]),
        },
        retention_run_item_row=lambda row: {
            "table": str(row["table_name"]),
            "eligible": str(row["eligible_count"]),
        },
    )


def test_distributed_task_section_rows_support_legacy_missing_columns() -> None:
    con = _connect()
    con.executescript(
        """
        CREATE TABLE distributed_tasks (
            engagement_id INTEGER,
            task_key TEXT,
            status TEXT
        );
        INSERT INTO distributed_tasks VALUES (1001, 'third', 'done');
        INSERT INTO distributed_tasks VALUES (1001, 'first', 'running');
        INSERT INTO distributed_tasks VALUES (1001, 'second', 'queued');
        INSERT INTO distributed_tasks VALUES (1002, 'other', 'running');
        """
    )

    rows = distributed_task_section_rows(
        con,
        1001,
        limit=10,
        callbacks=_callbacks(),
    )

    assert rows == [
        {
            "task": "first",
            "status": "running",
            "priority": "100",
            "worker": "",
            "payload": "None",
        },
        {
            "task": "second",
            "status": "queued",
            "priority": "100",
            "worker": "",
            "payload": "None",
        },
        {
            "task": "third",
            "status": "done",
            "priority": "100",
            "worker": "",
            "payload": "None",
        },
    ]


def test_seed_sections_query_expected_groups_and_order() -> None:
    con = _connect()
    con.executescript(
        """
        CREATE TABLE engagement_seeds (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            seed_value TEXT,
            seed_type TEXT,
            source TEXT,
            status TEXT,
            depth INTEGER,
            confidence REAL,
            metadata_json TEXT
        );
        CREATE TABLE seed_relations (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            source_seed_id INTEGER,
            target_seed_id INTEGER,
            relation_type TEXT,
            confidence REAL,
            evidence_json TEXT,
            discovered_at TEXT
        );
        CREATE TABLE seed_runs (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            seed_id INTEGER,
            loop_name TEXT,
            status TEXT,
            input_count INTEGER,
            output_count INTEGER,
            started_at TEXT,
            completed_at TEXT,
            error TEXT
        );
        INSERT INTO engagement_seeds VALUES
            (1, 1001, 'domain-a.example', 'domain', 'manual', 'active', 1, 0.80, '{}'),
            (2, 1001, 'https://b.example', 'url', 'crawl', 'active', 0, 0.90, '{}'),
            (3, 1001, 'user@c.example', 'email', 'identity', 'active', 0, 0.70, '{}'),
            (4, 1002, 'other.example', 'domain', 'manual', 'active', 0, 0.99, '{}');
        INSERT INTO seed_relations VALUES
            (1, 1001, 1, 2, 'linked_to', 0.50, '{}', '2026-08-12T01:00:00'),
            (2, 1001, 2, 3, 'mentions', 0.90, '{}', '2026-08-12T02:00:00'),
            (3, 1002, 4, 1, 'other', 1.00, '{}', '2026-08-12T03:00:00');
        INSERT INTO seed_runs VALUES
            (1, 1001, 1, 'fanout_domain', 'complete', 1, 2,
             '2026-08-12T01:00:00', '2026-08-12T01:01:00', ''),
            (2, 1001, 2, 'fanout_url_a', 'complete', 1, 3,
             '2026-08-12T03:00:00', '2026-08-12T03:01:00', ''),
            (3, 1001, 3, 'fanout_url_b', 'failed', 1, 0,
             '2026-08-12T03:00:00', '2026-08-12T03:02:00', 'blocked'),
            (4, 1002, 4, 'other', 'complete', 1, 1,
             '2026-08-12T04:00:00', '2026-08-12T04:01:00', '');
        """
    )

    sections = seed_sections(
        con,
        1001,
        limit=10,
        seed_run_limit=10,
        callbacks=_callbacks(),
    )

    assert [row["seed"] for row in sections["engagement_seeds"]] == [
        "user@c.example",
        "https://b.example",
        "domain-a.example",
    ]
    assert [row["from"] for row in sections["seed_relations"]] == [
        "https://b.example",
        "domain-a.example",
    ]
    assert [row["loop"] for row in sections["seed_runs"]] == [
        "fanout_url_b",
        "fanout_url_a",
        "fanout_domain",
    ]


def test_inventory_sections_merge_rows_and_seed_candidates_with_dedupe() -> None:
    con = _connect()
    con.executescript(
        """
        CREATE TABLE hosts (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            hostname TEXT,
            ip TEXT,
            os_family TEXT,
            discovered_at TEXT
        );
        CREATE TABLE emails (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            email TEXT,
            domain TEXT,
            source TEXT,
            first_seen_at TEXT
        );
        CREATE TABLE engagement_seeds (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            seed_value TEXT,
            seed_type TEXT,
            source TEXT,
            status TEXT,
            depth INTEGER,
            discovered_at TEXT,
            updated_at TEXT
        );
        INSERT INTO hosts VALUES
            (1, 1001, 'app.example', '10.0.0.10', 'linux', '2026-08-12T01:00:00'),
            (2, 1001, 'api.example', '10.0.0.11', 'linux', '2026-08-12T02:00:00'),
            (3, 1002, 'other.example', '10.0.0.12', 'linux', '2026-08-12T03:00:00');
        INSERT INTO emails VALUES
            (1, 1001, 'User@Example.com', 'example.com', 'harvest',
             '2026-08-12T01:00:00'),
            (2, 1001, 'admin@example.com', 'example.com', 'breach',
             '2026-08-12T02:00:00'),
            (3, 1002, 'other@example.com', 'example.com', 'other',
             '2026-08-12T03:00:00');
        INSERT INTO engagement_seeds VALUES
            (10, 1001, 'api.example', 'subdomain', 'resolver', 'active', 0,
             '2026-08-12T04:00:00', '2026-08-12T04:05:00'),
            (11, 1001, 'New.EXAMPLE', 'domain', 'dns', 'active', 0,
             '2026-08-12T05:00:00', '2026-08-12T05:05:00'),
            (12, 1001, 'scope.example', 'domain', 'scope', 'active', 0,
             '2026-08-12T06:00:00', '2026-08-12T06:05:00'),
            (13, 1001, 'rawseed', 'domain', 'dns', 'active', 0,
             '2026-08-12T07:00:00', '2026-08-12T07:05:00'),
            (14, 1001, 'user@example.com', 'email', 'operator', 'active', 0,
             '2026-08-12T08:00:00', '2026-08-12T08:05:00'),
            (15, 1001, 'owner@example.com', 'email', 'operator', 'active', 0,
             '2026-08-12T09:00:00', '2026-08-12T09:05:00'),
            (16, 1001, 'failed@example.com', 'email', 'operator', 'failed', 0,
             '2026-08-12T10:00:00', '2026-08-12T10:05:00');
        """
    )

    sections = inventory_sections(
        con,
        1001,
        limit=10,
        callbacks=_callbacks(),
    )

    assert sections["hosts"] == [
        {
            "host": "api.example",
            "ip": "10.0.0.11",
            "os": "linux",
            "source": "",
            "seen": "2026-08-12T02:00:00",
        },
        {
            "host": "app.example",
            "ip": "10.0.0.10",
            "os": "linux",
            "source": "",
            "seen": "2026-08-12T01:00:00",
        },
        {
            "host": "new.example",
            "ip": "",
            "os": "",
            "source": "dns",
            "seen": "2026-08-12T05:05:00",
        },
    ]
    assert [row["email"] for row in sections["emails"]] == [
        "admin@example.com",
        "user@example.com",
        "owner@example.com",
    ]
    assert sections["emails"][2]["source"] == "operator"
    assert sections["emails"][2]["seen"] == "2026-08-12T09:05:00"


def test_engagement_run_section_rows_query_order_and_manifest_summary() -> None:
    con = _connect()
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
            metadata_json TEXT,
            started_at TEXT,
            completed_at TEXT,
            error TEXT
        );
        INSERT INTO engagement_runs VALUES
            (1, 1001, 'kill_chain', 'completed', 'app.example', 'domain',
             2, 5, 5, 1, 0, 0, '{}', '2026-08-12T01:00:00',
             '2026-08-12T01:10:00', ''),
            (2, 1001, 'monitoring', 'running', 'api.example', 'domain',
             1, 10, 3, 1, 1, 0, '{}', '2026-08-12T03:00:00',
             '', ''),
            (3, 1002, 'other', 'completed', 'other.example', 'domain',
             1, 1, 1, 0, 0, 0, '{}', '2026-08-12T04:00:00',
             '2026-08-12T04:01:00', '');
        """
    )
    manifest_calls: list[dict[str, Any]] = []

    rows = engagement_run_section_rows(
        con,
        1001,
        db_path="1001.db",
        limit=2,
        callbacks=_callbacks(
            manifest_calls=manifest_calls,
            manifest_summaries={
                1: {"short_hash": "hash-one", "verified": False},
                2: {"short_hash": "hash-two", "verified": True},
            },
        ),
    )

    assert rows == [
        {
            "run": "2",
            "kind": "monitoring",
            "status": "running",
            "seed": "api.example",
            "iteration": "3/10",
            "manifest": "hash-two",
            "verified": "True",
        },
        {
            "run": "1",
            "kind": "kill_chain",
            "status": "completed",
            "seed": "app.example",
            "iteration": "5/5",
            "manifest": "hash-one",
            "verified": "False",
        },
    ]
    assert [call["run_id"] for call in manifest_calls] == [2, 1]
    assert all(call["db_path"] == "1001.db" for call in manifest_calls)
    assert all(call["verify"] is True for call in manifest_calls)


def test_identity_sections_query_expected_order_and_defaults() -> None:
    con = _connect()
    con.executescript(
        """
        CREATE TABLE email_intelligence (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            email TEXT,
            source TEXT,
            breach_count INTEGER,
            paste_count INTEGER,
            breach_names TEXT,
            enrichment_data TEXT,
            last_synced TEXT
        );
        CREATE TABLE account_existence (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            email TEXT,
            service TEXT,
            exists_flag INTEGER,
            rate_limited INTEGER,
            source_tool TEXT,
            queried_at TEXT
        );
        INSERT INTO email_intelligence VALUES
            (1, 1001, 'old@example.com', 'hibp', 1, 0, '[]', '{}',
             '2026-08-12T01:00:00'),
            (2, 1001, 'new@example.com', 'emailrep', 2, 1, '["A"]', '{}',
             '2026-08-12T02:00:00'),
            (3, 1002, 'other@example.com', 'hibp', 9, 9, '[]', '{}',
             '2026-08-12T03:00:00');
        INSERT INTO account_existence VALUES
            (1, 1001, 'old@example.com', 'github.com', 1, 0, 'holehe',
             '2026-08-12T01:00:00'),
            (2, 1001, 'new@example.com', 'twitter.com', 0, 1, 'holehe',
             '2026-08-12T02:00:00'),
            (3, 1002, 'other@example.com', 'github.com', 1, 0, 'holehe',
             '2026-08-12T03:00:00');
        """
    )

    callbacks = _callbacks()

    assert [
        row["email"]
        for row in email_intelligence_section_rows(
            con,
            1001,
            limit=10,
            callbacks=callbacks,
        )
    ] == ["new@example.com", "old@example.com"]
    assert [
        row["service"]
        for row in account_existence_section_rows(
            con,
            1001,
            limit=10,
            callbacks=callbacks,
        )
    ] == ["twitter.com", "github.com"]


def test_identity_sections_support_legacy_missing_columns() -> None:
    con = _connect()
    con.executescript(
        """
        CREATE TABLE email_intelligence (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            email TEXT,
            source TEXT,
            breach_count INTEGER,
            discovered_at TEXT
        );
        CREATE TABLE account_existence (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            email TEXT,
            service TEXT
        );
        INSERT INTO email_intelligence VALUES
            (1, 1001, 'legacy@example.com', 'hibp', 3, '2026-08-12T01:00:00');
        INSERT INTO account_existence VALUES
            (1, 1001, 'legacy@example.com', 'github.com');
        """
    )

    callbacks = _callbacks()

    assert email_intelligence_section_rows(
        con,
        1001,
        limit=10,
        callbacks=callbacks,
    ) == [
        {
            "email": "legacy@example.com",
            "source": "hibp",
            "breaches": "3",
            "pastes": "0",
            "seen": "2026-08-12T01:00:00",
        }
    ]
    assert account_existence_section_rows(
        con,
        1001,
        limit=10,
        callbacks=callbacks,
    ) == [
        {
            "email": "legacy@example.com",
            "service": "github.com",
            "exists": "1",
            "rate_limited": "0",
            "source": "holehe",
            "seen": "",
        }
    ]


def test_service_surface_section_rows_query_expected_order() -> None:
    con = _connect()
    con.executescript(
        """
        CREATE TABLE hosts (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            hostname TEXT,
            ip TEXT
        );
        CREATE TABLE services (
            id INTEGER PRIMARY KEY,
            host_id INTEGER,
            port INTEGER,
            protocol TEXT,
            service_name TEXT,
            version TEXT,
            discovered_at TEXT
        );
        CREATE TABLE crawl_results (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            url TEXT,
            final_url TEXT,
            title TEXT,
            screenshot_path TEXT,
            tech_stack_json TEXT,
            discovered_at TEXT
        );
        CREATE TABLE social_profiles (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            email TEXT,
            source TEXT,
            profile_data TEXT,
            queried_at TEXT
        );
        CREATE TABLE port_scan_results (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            host TEXT,
            port INTEGER,
            proto TEXT,
            service TEXT,
            version TEXT,
            confidence REAL,
            scanned_at TEXT
        );
        CREATE TABLE passive_vulns (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            severity TEXT,
            plugin TEXT,
            vuln_id TEXT,
            verified INTEGER,
            false_positive INTEGER,
            url TEXT,
            discovered_at TEXT
        );
        CREATE TABLE auth_test_results (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            target_url TEXT,
            attack_type TEXT,
            success INTEGER,
            tested_at TEXT
        );
        INSERT INTO hosts VALUES
            (1, 1001, 'host-a.example', '192.0.2.10'),
            (2, 1001, '', '192.0.2.20'),
            (3, 1002, 'other.example', '192.0.2.30');
        INSERT INTO services VALUES
            (1, 1, 80, 'tcp', 'http', '1.0', '2026-08-12T01:00:00'),
            (2, 2, 443, 'tcp', 'https', '2.0', '2026-08-12T02:00:00'),
            (3, 3, 22, 'tcp', 'ssh', '9.0', '2026-08-12T03:00:00');
        INSERT INTO crawl_results VALUES
            (1, 1001, 'https://a.example', NULL, 'A', '', '{}', '2026-08-12T01:00:00'),
            (2, 1001, 'https://b.example', 'https://final.example', 'B', '', '{}', '2026-08-12T02:00:00'),
            (3, 1002, 'https://other.example', '', 'Other', '', '{}', '2026-08-12T03:00:00');
        INSERT INTO social_profiles VALUES
            (1, 1001, 'a@example.com', 'github', '{}', '2026-08-12T01:00:00'),
            (2, 1001, 'b@example.com', 'linkedin', '{}', '2026-08-12T02:00:00'),
            (3, 1002, 'other@example.com', 'github', '{}', '2026-08-12T03:00:00');
        INSERT INTO port_scan_results VALUES
            (1, 1001, 'host-a.example', 80, 'tcp', 'http', '1.0', 0.8, '2026-08-12T01:00:00'),
            (2, 1001, 'host-b.example', 443, 'tcp', 'https', '2.0', 0.9, '2026-08-12T02:00:00'),
            (3, 1002, 'other.example', 22, 'tcp', 'ssh', '9.0', 0.7, '2026-08-12T03:00:00');
        INSERT INTO passive_vulns VALUES
            (1, 1001, 'LOW', 'nuclei', 'CVE-OLD', 0, 0, 'https://a.example', '2026-08-12T01:00:00'),
            (2, 1001, 'HIGH', 'nuclei', 'CVE-NEW', 1, 0, 'https://b.example', '2026-08-12T02:00:00'),
            (3, 1002, 'CRITICAL', 'nuclei', 'CVE-OTHER', 1, 0, 'https://other.example', '2026-08-12T03:00:00');
        INSERT INTO auth_test_results VALUES
            (1, 1001, 'https://a.example/login', 'login', 0, '2026-08-12T01:00:00'),
            (2, 1001, 'https://b.example/login', 'login', 1, '2026-08-12T02:00:00'),
            (3, 1002, 'https://other.example/login', 'login', 1, '2026-08-12T03:00:00');
        """
    )

    callbacks = _callbacks()

    assert [
        row["host"]
        for row in service_section_rows(con, 1001, limit=10, callbacks=callbacks)
    ] == ["192.0.2.20", "host-a.example"]
    assert [
        row["url"]
        for row in crawl_result_section_rows(con, 1001, limit=10, callbacks=callbacks)
    ] == ["https://final.example", "https://a.example"]
    assert [
        row["email"]
        for row in social_profile_section_rows(con, 1001, limit=10, callbacks=callbacks)
    ] == ["b@example.com", "a@example.com"]
    assert [
        row["port"]
        for row in port_scan_result_section_rows(con, 1001, limit=10, callbacks=callbacks)
    ] == ["443", "80"]
    assert [
        row["vuln"]
        for row in passive_vuln_section_rows(con, 1001, limit=10, callbacks=callbacks)
    ] == ["CVE-NEW", "CVE-OLD"]
    assert [
        row["target"]
        for row in auth_test_result_section_rows(con, 1001, limit=10, callbacks=callbacks)
    ] == ["https://b.example/login", "https://a.example/login"]


def test_artifact_queue_section_rows_query_order_and_optional_columns() -> None:
    con = _connect()
    con.executescript(
        """
        CREATE TABLE artifact_queue (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            source_url TEXT,
            artifact_type TEXT,
            status TEXT,
            notes TEXT,
            metadata_json TEXT,
            queued_at TEXT,
            local_path TEXT,
            discovered_from TEXT
        );
        INSERT INTO artifact_queue VALUES
            (1, 1001, 'https://a.example/app.apk', 'apk', 'queued', 'first',
             '{}', '2026-08-12T01:00:00', 'C:/tmp/a.apk', 'crawl'),
            (2, 1001, 'https://b.example/archive.zip', 'archive', 'done', 'second',
             '{}', '2026-08-12T02:00:00', 'C:/tmp/b.zip', 'seed'),
            (3, 1002, 'https://other.example/file', 'doc', 'done', 'other',
             '{}', '2026-08-12T03:00:00', 'C:/tmp/other', 'other');
        """
    )

    rows = artifact_queue_section_rows(
        con,
        1001,
        limit=10,
        callbacks=_callbacks(),
    )

    assert [row["artifact"] for row in rows] == [
        "https://b.example/archive.zip",
        "https://a.example/app.apk",
    ]
    assert rows[0]["local"] == "C:/tmp/b.zip"
    assert rows[0]["origin"] == "seed"


def test_artifact_queue_section_rows_support_legacy_missing_optional_columns() -> None:
    con = _connect()
    con.executescript(
        """
        CREATE TABLE artifact_queue (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            source_url TEXT,
            artifact_type TEXT,
            status TEXT,
            notes TEXT,
            metadata_json TEXT,
            queued_at TEXT
        );
        INSERT INTO artifact_queue VALUES
            (1, 1001, 'https://legacy.example/file', 'document', 'queued',
             'legacy', '{}', '2026-08-12T01:00:00');
        """
    )

    rows = artifact_queue_section_rows(
        con,
        1001,
        limit=10,
        callbacks=_callbacks(),
    )

    assert rows == [
        {
            "artifact": "https://legacy.example/file",
            "type": "document",
            "status": "queued",
            "local": "None",
            "origin": "None",
        }
    ]


def test_finding_sections_filter_key_scanner_rows_before_limit() -> None:
    con = _connect()
    con.executescript(
        """
        CREATE TABLE key_scanner_findings (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            domain TEXT,
            service TEXT,
            pattern_name TEXT,
            validation_state TEXT,
            found_at TEXT,
            source_backend TEXT,
            source_url TEXT,
            repo_name TEXT,
            validation_detail TEXT,
            validated_at TEXT
        );
        INSERT INTO key_scanner_findings VALUES
            (1, 1001, 'app.example', 'github', 'github_pat', 'ACTIVE',
             '2026-08-12T01:00:00', 'scanner', 'https://example/repo',
             'acme/app', 'VALIDATED:github:ok', '2026-08-12T01:05:00'),
            (2, 1001, 'app.example', 'slack', 'slack_bot', 'ACTIVE',
             '2026-08-12T02:00:00', 'scanner', 'https://example/slack',
             'acme/app', 'VALIDATED:slack:ok', '2026-08-12T02:05:00'),
            (3, 1001, 'app.example', 'discord', 'discord_bot', 'ACTIVE',
             '2026-08-12T03:00:00', 'scanner', 'https://example/discord',
             'acme/app', 'UNVERIFIED:discord:no', '2026-08-12T03:05:00'),
            (4, 1002, 'other.example', 'github', 'github_pat', 'ACTIVE',
             '2026-08-12T04:00:00', 'scanner', 'https://example/other',
             'other/app', 'VALIDATED:github:ok', '2026-08-12T04:05:00');
        """
    )

    sections = finding_sections(
        con,
        1001,
        limit=1,
        callbacks=_callbacks(key_reportable_services={"github", "slack"}),
    )

    assert sections["key_scanner_findings"] == [
        {
            "domain": "app.example",
            "service": "slack",
            "pattern": "slack_bot",
            "state": "ACTIVE",
            "backend": "scanner",
            "source": "https://example/slack",
            "repo": "acme/app",
            "validated": "2026-08-12T02:05:00",
            "seen": "2026-08-12T02:00:00",
        }
    ]
    assert sections["secret_lifecycle_items"] == []
    assert sections["vulnerability_findings"] == []


def test_finding_sections_query_secret_lifecycle_joins_and_order() -> None:
    con = _connect()
    con.executescript(
        """
        CREATE TABLE key_scanner_findings (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            service TEXT,
            pattern_name TEXT,
            source_url TEXT,
            repo_name TEXT
        );
        CREATE TABLE remediation_items (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            finding_table TEXT,
            finding_ref TEXT,
            status TEXT
        );
        CREATE TABLE secret_lifecycle_items (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            key_finding_id INTEGER,
            lifecycle_status TEXT,
            owner TEXT,
            owner_source TEXT,
            suppression_id INTEGER,
            suppressed INTEGER,
            revocation_guidance_json TEXT,
            prevention_guidance_json TEXT,
            metadata_json TEXT,
            updated_at TEXT
        );
        INSERT INTO key_scanner_findings VALUES
            (10, 1001, 'github', 'github_pat', 'https://example/repo', 'acme/app');
        INSERT INTO remediation_items VALUES
            (20, 1001, 'key_scanner_findings', '10', 'assigned');
        INSERT INTO secret_lifecycle_items VALUES
            (1, 1001, 10, 'open', 'ops@example.com', 'manual', NULL, 0,
             '{"rotate":true}', '[{"tool":"gitleaks"}]', '{"risk":"high"}',
             '2026-08-12T03:00:00'),
            (2, 1001, 10, 'owner_routed', 'appsec@example.com', 'claims', 7, 0,
             '{"route":true}', '[{"tool":"trufflehog"}]', '{}',
             '2026-08-12T01:00:00'),
            (3, 1001, 10, 'revoked', '', '', NULL, 0,
             '{}', '[]', '{}', '2026-08-12T04:00:00');
        """
    )

    sections = finding_sections(
        con,
        1001,
        limit=10,
        callbacks=_callbacks(),
    )
    lifecycle = sections["secret_lifecycle_items"]

    assert [row["lifecycle"] for row in lifecycle] == [
        "owner_routed",
        "open",
        "revoked",
    ]
    assert lifecycle[0]["key"] == "10"
    assert lifecycle[0]["service"] == "github"
    assert lifecycle[0]["pattern"] == "github_pat"
    assert lifecycle[0]["source"] == "https://example/repo"
    assert lifecycle[0]["repo"] == "acme/app"
    assert lifecycle[0]["remediation"] == "20"
    assert lifecycle[0]["remediation_status"] == "assigned"


def test_finding_sections_support_legacy_secret_lifecycle_defaults() -> None:
    con = _connect()
    con.executescript(
        """
        CREATE TABLE secret_lifecycle_items (
            engagement_id INTEGER
        );
        INSERT INTO secret_lifecycle_items VALUES (1001);
        """
    )

    sections = finding_sections(
        con,
        1001,
        limit=10,
        callbacks=_callbacks(),
    )

    assert sections["secret_lifecycle_items"] == [
        {
            "key": "None",
            "service": "None",
            "pattern": "None",
            "lifecycle": "",
            "owner": "",
            "owner_source": "",
            "suppression": "None",
            "suppressed": "0",
            "revocation": "{}",
            "prevention": "[]",
            "metadata": "{}",
            "updated": "",
            "remediation": "None",
            "remediation_status": "None",
            "source": "None",
            "repo": "None",
        }
    ]


def test_finding_sections_pick_representative_vulnerabilities_after_filtering() -> None:
    con = _connect()
    con.executescript(
        """
        CREATE TABLE vulnerability_findings (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            severity TEXT,
            vuln_type TEXT,
            title TEXT,
            target_url TEXT,
            parameter TEXT,
            evidence TEXT,
            cloud_provider TEXT,
            resource_id TEXT,
            found_at TEXT
        );
        INSERT INTO vulnerability_findings VALUES
            (1, 1001, 'LOW', 'INFO', '', 'https://blank.example', '',
             'blank', '', '', '2026-08-12T00:00:00'),
            (2, 1001, 'HIGH', 'EXPOSURE', 'Duplicate title', 'https://old.example',
             '', 'old', 'aws', 'bucket-old', '2026-08-12T01:00:00'),
            (3, 1001, 'CRITICAL', 'EXPOSURE', 'Unique title', 'https://unique.example',
             '', 'unique', 'aws', 'bucket-unique', '2026-08-12T02:00:00'),
            (4, 1001, 'HIGH', 'EXPOSURE', 'Duplicate title', 'https://new.example',
             '', 'new', 'aws', 'bucket-new', '2026-08-12T03:00:00'),
            (5, 1001, 'LOW', 'INFO', 'Unreportable top row',
             'https://ignore.example', '', 'ignore', '', '',
             '2026-08-12T04:00:00');
        """
    )

    sections = finding_sections(
        con,
        1001,
        limit=2,
        callbacks=_callbacks(
            vulnerability_reportable_titles={"Duplicate title", "Unique title"}
        ),
    )

    assert sections["vulnerability_findings"] == [
        {
            "id": "4",
            "title": "Duplicate title",
            "severity": "HIGH",
            "type": "EXPOSURE",
            "target": "https://new.example",
            "parameter": "",
            "provider": "aws",
            "resource": "bucket-new",
            "found": "2026-08-12T03:00:00",
        },
        {
            "id": "3",
            "title": "Unique title",
            "severity": "CRITICAL",
            "type": "EXPOSURE",
            "target": "https://unique.example",
            "parameter": "",
            "provider": "aws",
            "resource": "bucket-unique",
            "found": "2026-08-12T02:00:00",
        },
    ]


def test_representative_vulnerability_rows_fill_duplicates_after_unique_titles() -> None:
    con = _connect()
    con.executescript(
        """
        CREATE TABLE vulnerability_findings (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            title TEXT,
            target_url TEXT
        );
        INSERT INTO vulnerability_findings VALUES
            (1, 1001, 'Same', 'https://one.example'),
            (2, 1001, 'Same', 'https://two.example'),
            (3, 1001, '', 'https://blank.example');
        """
    )
    rows = _fetch_rows(
        con,
        """
        SELECT id, title, target_url
        FROM vulnerability_findings
        WHERE engagement_id=?
        ORDER BY id DESC
        """,
        (1001,),
    )

    selected = representative_vulnerability_rows(rows, 3)

    assert [row["id"] for row in selected] == [3, 2, 1]


def test_cloud_sections_query_assets_and_validation_results() -> None:
    con = _connect()
    con.executescript(
        """
        CREATE TABLE cloud_assets (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            asset_type TEXT,
            identifier TEXT,
            provider_identifier TEXT,
            source TEXT,
            metadata_json TEXT,
            discovered_at TEXT
        );
        CREATE TABLE cloud_validation_results (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            asset_type TEXT,
            identifier TEXT,
            provider_identifier TEXT,
            validation_status TEXT,
            validation_method TEXT,
            http_status INTEGER,
            evidence TEXT,
            notes TEXT,
            checked_at TEXT
        );
        INSERT INTO cloud_assets VALUES
            (1, 1001, 's3', 'bucket-a', 'arn:aws:s3:::bucket-a',
             'seed', '{}', '2026-08-12T01:00:00'),
            (2, 1001, 'gcs', 'bucket-b', '',
             'connector', '{}', '2026-08-12T03:00:00'),
            (3, 1002, 's3', 'other-bucket', '',
             'other', '{}', '2026-08-12T04:00:00');
        INSERT INTO cloud_validation_results VALUES
            (1, 1001, 'aws_s3', 'bucket-a', '', 'FAILED',
             's3_head', 403, '{}', '', '2026-08-12T01:30:00'),
            (2, 1001, 'aws_s3', 'bucket-a', 'provider-display-bucket-a', 'VALIDATED',
             's3_head', 200, '{}', '', '2026-08-12T02:00:00'),
            (3, 1002, 'aws_s3', 'other-bucket', 'provider-other', 'VALIDATED',
             's3_head', 200, '{}', '', '2026-08-12T04:00:00');
        """
    )

    sections = cloud_sections(
        con,
        1001,
        limit=10,
        callbacks=_callbacks(),
    )

    assert [row["asset"] for row in sections["cloud_assets"]] == [
        "bucket-b",
        "arn:aws:s3:::bucket-a",
    ]
    assert sections["cloud_assets"][0]["validation"] == "None"
    assert sections["cloud_assets"][1]["validation"] == "VALIDATED"
    assert sections["cloud_assets"][1]["checked"] == "2026-08-12T02:00:00"
    assert [row["asset"] for row in sections["cloud_validation_results"]] == [
        "provider-display-bucket-a",
        "bucket-a",
    ]


def test_cloud_sections_support_legacy_asset_columns_without_validation_table() -> None:
    con = _connect()
    con.executescript(
        """
        CREATE TABLE cloud_assets (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            asset_type TEXT,
            identifier TEXT
        );
        INSERT INTO cloud_assets VALUES
            (1, 1001, 'azure_blob_storage', 'legacy-container');
        """
    )

    sections = cloud_sections(
        con,
        1001,
        limit=10,
        callbacks=_callbacks(),
    )

    assert sections["cloud_assets"] == [
        {
            "asset": "legacy-container",
            "type": "azure_blob_storage",
            "validation": "None",
            "method": "None",
            "checked": "None",
            "source": "None",
        }
    ]
    assert sections["cloud_validation_results"] == []


def test_monitoring_configuration_sections_query_expected_groups_and_order() -> None:
    con = _connect()
    con.executescript(
        """
        CREATE TABLE monitoring_policies (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            name TEXT,
            enabled INTEGER,
            schedule_interval_minutes INTEGER,
            mode TEXT,
            last_snapshot_id INTEGER,
            last_run_at TEXT,
            next_run_at TEXT,
            updated_at TEXT
        );
        CREATE TABLE monitoring_alert_routes (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            name TEXT,
            enabled INTEGER,
            min_severity TEXT,
            alert_type TEXT,
            entity_prefix TEXT,
            channel TEXT,
            destination TEXT,
            owner TEXT,
            escalation TEXT,
            updated_at TEXT
        );
        CREATE TABLE monitoring_alert_suppressions (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            alert_type TEXT,
            entity_key TEXT,
            entity_prefix TEXT,
            severity TEXT,
            reason TEXT,
            created_by TEXT,
            expires_at TEXT,
            updated_at TEXT
        );
        INSERT INTO monitoring_policies VALUES
            (1, 1001, 'disabled', 0, 60, 'diff', 1, '', '2026-08-12T03:00:00', ''),
            (2, 1001, 'enabled-sooner', 1, 30, 'diff', 2, '', '2026-08-12T02:00:00', ''),
            (3, 1001, 'enabled-later', 1, 30, 'diff', 3, '', '2026-08-12T04:00:00', '');
        INSERT INTO monitoring_alert_routes VALUES
            (1, 1001, 'low', 1, 'LOW', '', '', '', '', '', '', ''),
            (2, 1001, 'critical', 1, 'CRITICAL', '', '', '', '', '', '', ''),
            (3, 1001, 'disabled-high', 0, 'HIGH', '', '', '', '', '', '', '');
        INSERT INTO monitoring_alert_suppressions VALUES
            (1, 1001, '', '', '', '', 'expired', '', '2026-08-10T00:00:00', ''),
            (2, 1001, '', '', '', '', 'active', '', '2026-08-13T00:00:00', '');
        """
    )

    sections = monitoring_configuration_sections(
        con,
        1001,
        limit=10,
        callbacks=_callbacks(),
    )

    assert [row["policy"] for row in sections["monitoring_policies"]] == [
        "enabled-sooner",
        "enabled-later",
        "disabled",
    ]
    assert [row["route"] for row in sections["monitoring_alert_routes"]] == [
        "critical",
        "low",
        "disabled-high",
    ]
    assert [row["reason"] for row in sections["monitoring_alert_suppressions"]] == [
        "active",
        "expired",
    ]


def test_monitoring_history_sections_query_expected_groups_and_order() -> None:
    con = _connect()
    con.executescript(
        """
        CREATE TABLE monitoring_snapshots (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            snapshot_kind TEXT,
            state_hash TEXT,
            summary_json TEXT,
            created_at TEXT
        );
        CREATE TABLE monitoring_trend_points (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            snapshot_id INTEGER,
            observed_at TEXT,
            asset_count INTEGER,
            finding_count INTEGER,
            critical_count INTEGER,
            high_count INTEGER,
            added_count INTEGER,
            removed_count INTEGER,
            changed_count INTEGER,
            alert_count INTEGER,
            open_alert_count INTEGER
        );
        CREATE TABLE monitoring_changes (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            snapshot_id INTEGER,
            entity_type TEXT,
            entity_key TEXT,
            change_type TEXT,
            severity TEXT,
            before_json TEXT,
            after_json TEXT,
            created_at TEXT
        );
        CREATE TABLE monitoring_alerts (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            snapshot_id INTEGER,
            change_id INTEGER,
            alert_type TEXT,
            severity TEXT,
            title TEXT,
            status TEXT,
            metadata_json TEXT,
            created_at TEXT,
            updated_at TEXT
        );
        INSERT INTO monitoring_snapshots VALUES
            (1, 1001, 'manual', 'hash-1', '{}', '2026-08-12T01:00:00'),
            (2, 1001, 'scheduled', 'hash-2', '{}', '2026-08-12T02:00:00');
        INSERT INTO monitoring_trend_points VALUES
            (1, 1001, 1, '2026-08-12T01:00:00', 5, 1, 0, 1, 1, 0, 0, 0, 0),
            (2, 1001, 2, '2026-08-12T02:00:00', 8, 2, 1, 1, 3, 0, 1, 2, 1);
        INSERT INTO monitoring_changes VALUES
            (1, 1001, 1, 'host', 'old.example', 'removed', 'LOW', '{}', '{}', ''),
            (2, 1001, 2, 'host', 'new.example', 'added', 'HIGH', '{}', '{}', '');
        INSERT INTO monitoring_alerts VALUES
            (1, 1001, 2, 2, 'asset_added', 'LOW', 'Low alert', 'resolved', '{}', '', ''),
            (2, 1001, 2, 2, 'asset_added', 'HIGH', 'High open', 'open', '{}', '', ''),
            (3, 1001, 2, 2, 'asset_added', 'CRITICAL', 'Critical ack', 'acknowledged', '{}', '', '');
        """
    )

    sections = monitoring_history_sections(
        con,
        1001,
        limit=10,
        callbacks=_callbacks(),
    )

    assert [row["snapshot"] for row in sections["monitoring_snapshots"]] == ["2", "1"]
    assert [row["snapshot"] for row in sections["monitoring_trend_points"]] == ["2", "1"]
    assert [row["entity"] for row in sections["monitoring_changes"]] == [
        "new.example",
        "old.example",
    ]
    assert [row["title"] for row in sections["monitoring_alerts"]] == [
        "High open",
        "Critical ack",
        "Low alert",
    ]


def test_remediation_workflow_sections_query_expected_order_and_review_queue() -> None:
    con = _connect()
    con.executescript(
        """
        CREATE TABLE remediation_items (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            finding_table TEXT,
            finding_ref TEXT,
            title TEXT,
            severity TEXT,
            owner TEXT,
            sla_due_at TEXT,
            risk_acceptance_expires_at TEXT,
            status TEXT,
            retest_status TEXT,
            ticket_ref TEXT,
            ticket_url TEXT,
            updated_at TEXT
        );
        INSERT INTO remediation_items VALUES
            (1, 1001, 'findings', '1', 'Medium assigned', 'MEDIUM', 'appsec',
             '2026-08-20', NULL, 'assigned', 'pending', '', '', ''),
            (2, 1001, 'findings', '2', 'Critical open later', 'CRITICAL', 'appsec',
             '2026-08-19', NULL, 'open', 'pending', '', '', ''),
            (3, 1001, 'findings', '3', 'Critical open sooner', 'CRITICAL', 'appsec',
             '2026-08-18', NULL, 'open', 'pending', '', '', ''),
            (4, 1002, 'findings', '4', 'Other', 'CRITICAL', 'appsec',
             '2026-08-01', NULL, 'open', 'pending', '', '', '');
        """
    )

    sections = remediation_workflow_sections(
        con,
        1001,
        limit=10,
        callbacks=_callbacks(
            review_queue_items=[
                {"title": "Needs owner", "review_priority": 90},
                {"title": "Needs retest", "review_priority": 80},
            ]
        ),
    )

    assert [row["finding"] for row in sections["remediation_items"]] == [
        "findings:3",
        "findings:2",
        "findings:1",
    ]
    assert sections["remediation_review_queue"] == [
        {"title": "Needs owner", "priority": "90"},
        {"title": "Needs retest", "priority": "80"},
    ]


def test_remediation_workflow_sections_support_legacy_missing_risk_expiry() -> None:
    con = _connect()
    con.executescript(
        """
        CREATE TABLE remediation_items (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            finding_table TEXT,
            finding_ref TEXT,
            title TEXT,
            severity TEXT,
            owner TEXT,
            sla_due_at TEXT,
            status TEXT,
            retest_status TEXT,
            ticket_ref TEXT,
            ticket_url TEXT,
            updated_at TEXT
        );
        INSERT INTO remediation_items VALUES
            (1, 1001, 'findings', '1', 'Legacy row', 'HIGH', 'appsec',
             '2026-08-20', 'open', 'pending', '', '', '');
        """
    )

    sections = remediation_workflow_sections(
        con,
        1001,
        limit=10,
        callbacks=_callbacks(review_queue_items=[{"title": "Should not surface"}]),
    )

    assert sections["remediation_items"] == [
        {
            "finding": "findings:1",
            "severity": "HIGH",
            "status": "open",
            "sla": "2026-08-20",
            "risk_expiry": "None",
        }
    ]
    assert sections["remediation_review_queue"] == []


def test_asset_graph_sections_query_expected_groups_and_order() -> None:
    con = _connect()
    con.executescript(
        """
        CREATE TABLE asset_entities (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            entity_key TEXT,
            entity_type TEXT,
            label TEXT,
            source_table TEXT,
            source_id TEXT,
            confidence REAL,
            metadata_json TEXT,
            updated_at TEXT
        );
        CREATE TABLE asset_relationships (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            relationship_type TEXT,
            source_entity_id INTEGER,
            target_entity_id INTEGER,
            confidence REAL,
            evidence_json TEXT,
            updated_at TEXT
        );
        CREATE TABLE asset_ownership_claims (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            entity_id INTEGER,
            owner_kind TEXT,
            owner_ref TEXT,
            owner_display TEXT,
            claim_type TEXT,
            confidence REAL,
            source TEXT,
            status TEXT,
            evidence_json TEXT,
            updated_at TEXT
        );
        INSERT INTO asset_entities VALUES
            (1, 1001, 'host:a', 'host', 'Host A', 'hosts', '1', 0.95, '{}', '2026-08-12T01:00:00'),
            (2, 1001, 'finding:a', 'finding', 'Finding A', 'findings', '1', 0.70, '{}', '2026-08-12T02:00:00'),
            (3, 1001, 'cloud:a', 'cloud', 'Cloud A', 'cloud', '1', 0.90, '{}', '2026-08-12T03:00:00'),
            (4, 1001, 'host:b', 'host', 'Host B', 'hosts', '2', 0.99, '{}', '2026-08-12T04:00:00'),
            (5, 1002, 'host:other', 'host', 'Other', 'hosts', '3', 1.0, '{}', '');
        INSERT INTO asset_relationships VALUES
            (1, 1001, 'references_cloud', 1, 3, 0.90, '{}', '2026-08-12T01:00:00'),
            (2, 1001, 'has_finding', 1, 2, 0.60, '{}', '2026-08-12T02:00:00'),
            (3, 1001, 'owned_by', 4, 3, 0.99, '{}', '2026-08-12T03:00:00');
        INSERT INTO asset_ownership_claims VALUES
            (1, 1001, 1, 'team', 'team-a', 'Team A', 'dns', 0.80, 'dns', 'accepted', '{}', '2026-08-12T01:00:00'),
            (2, 1001, 3, 'team', 'team-b', 'Team B', 'cloud', 0.60, 'cloud', 'active', '{}', '2026-08-12T02:00:00'),
            (3, 1001, 4, 'team', 'team-c', 'Team C', 'manual', 0.99, 'manual', 'active', '{}', '2026-08-12T03:00:00');
        """
    )

    sections = asset_graph_sections(
        con,
        1001,
        limit=10,
        callbacks=_callbacks(
            ownership_conflicts=[{"entity_key": "cloud:a", "owner_count": 2}],
            asset_graph={
                "attack_paths": [{"path_id": "p1"}],
                "choke_points": [{"entity_key": "cloud:a"}],
                "minimal_fix_set_candidates": [{"entity_key": "host:b"}],
            },
        ),
    )

    assert [row["key"] for row in sections["asset_entities"]] == [
        "finding:a",
        "cloud:a",
        "host:b",
        "host:a",
    ]
    assert [row["type"] for row in sections["asset_relationships"]] == [
        "has_finding",
        "owned_by",
        "references_cloud",
    ]
    assert [row["owner"] for row in sections["asset_ownership_claims"]] == [
        "Team C",
        "Team B",
        "Team A",
    ]
    assert sections["asset_ownership_conflicts"] == [
        {"asset": "cloud:a", "owners": "2"}
    ]
    assert sections["asset_graph_attack_paths"] == [{"path": "p1"}]
    assert sections["asset_graph_choke_points"] == [{"entity": "cloud:a"}]
    assert sections["asset_graph_fix_candidates"] == [{"entity": "host:b"}]


def test_active_validation_sections_query_expected_groups_and_order() -> None:
    con = _connect()
    con.executescript(
        """
        CREATE TABLE active_validation_jobs (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            target_ref TEXT,
            target_kind TEXT,
            method TEXT,
            mode TEXT,
            status TEXT,
            approved INTEGER,
            roe_id TEXT,
            scope_manifest_hash TEXT,
            safe_profile TEXT,
            metadata_json TEXT,
            updated_at TEXT
        );
        CREATE TABLE active_validation_runs (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            job_id INTEGER,
            status TEXT,
            result TEXT,
            operator TEXT,
            evidence_json TEXT,
            error TEXT,
            completed_at TEXT
        );
        INSERT INTO active_validation_jobs VALUES
            (1, 1001, 'host:failed', 'host', 'fix_verification', 'lab',
             'failed', 1, 'ROE-1', 'scope-1', 'standard', '{}', '2026-08-12T01:00:00'),
            (2, 1001, 'host:queued-old', 'host', 'fix_verification', 'lab',
             'queued', 1, 'ROE-1', 'scope-1', 'standard', '{}', '2026-08-12T02:00:00'),
            (3, 1001, 'host:approved', 'host', 'fix_verification', 'lab',
             'approved', 1, 'ROE-1', 'scope-1', 'standard', '{}', '2026-08-12T03:00:00'),
            (4, 1001, 'host:queued-new', 'host', 'fix_verification', 'lab',
             'queued', 1, 'ROE-1', 'scope-1', 'standard', '{}', '2026-08-12T04:00:00'),
            (5, 1002, 'host:other', 'host', 'fix_verification', 'lab',
             'approved', 1, 'ROE-1', 'scope-1', 'standard', '{}', '2026-08-12T05:00:00');
        INSERT INTO active_validation_runs VALUES
            (1, 1001, 1, 'failed', 'blocked', 'alice', '{}', '', ''),
            (2, 1001, 3, 'passed', 'verified', 'alice', '{}', '', ''),
            (3, 1002, 5, 'passed', 'other', 'alice', '{}', '', '');
        """
    )

    sections = active_validation_sections(
        con,
        1001,
        limit=10,
        callbacks=_callbacks(
            active_validation_coverage=[{"coverage": "MITRE T1190"}],
        ),
    )

    assert sections["active_validation_coverage"] == [{"coverage": "MITRE T1190"}]
    assert [row["target"] for row in sections["active_validation_jobs"]] == [
        "host:approved",
        "host:queued-new",
        "host:queued-old",
        "host:failed",
    ]
    assert [row["job"] for row in sections["active_validation_runs"]] == ["3", "1"]


def test_audit_sections_query_recent_audit_and_scope_denials() -> None:
    con = _connect()
    con.executescript(
        """
        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            logged_at TEXT,
            phase TEXT,
            module TEXT,
            action TEXT,
            target TEXT,
            result TEXT
        );
        INSERT INTO audit_log VALUES
            (1, 1001, '2026-08-12T01:00:00', 'phase', 'collector',
             'normal_old', 'target-old', 'old result'),
            (2, 1001, '2026-08-12T02:00:00', 'phase', 'scheduled_task',
             'scheduled_task_scope_denied', 'target-denied', 'denied result'),
            (3, 1001, '2026-08-12T03:00:00', 'phase', 'collector',
             'normal_new', 'target-new', 'new result'),
            (4, 1002, '2026-08-12T04:00:00', 'phase', 'collector',
             'scheduled_task_scope_denied', 'target-other', 'other result'),
            (5, 1001, '2026-08-12T05:00:00', 'phase', 'recursive',
             'recursive_seed_scope_denied', 'target-recursive', 'recursive result');
        """
    )

    sections = audit_sections(
        con,
        1001,
        audit_limit=3,
        scope_denial_limit=10,
        scope_denial_actions=(
            "scheduled_task_scope_denied",
            "recursive_seed_scope_denied",
        ),
        callbacks=_callbacks(),
    )

    assert [row["action"] for row in sections["audit_log"]] == [
        "recursive_seed_scope_denied",
        "normal_new",
        "scheduled_task_scope_denied",
    ]
    assert [row["action"] for row in sections["scope_denials"]] == [
        "recursive_seed_scope_denied",
        "scheduled_task_scope_denied",
    ]
    assert {row["target"] for row in sections["scope_denials"]} == {
        "target-denied",
        "target-recursive",
    }


def test_retention_sections_query_expected_groups_and_order() -> None:
    con = _connect()
    con.executescript(
        """
        CREATE TABLE retention_policies (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            name TEXT,
            enabled INTEGER,
            audit_review_days INTEGER,
            monitoring_days INTEGER,
            remediation_event_days INTEGER,
            retention_run_days INTEGER,
            legal_hold_override INTEGER,
            metadata_json TEXT,
            updated_at TEXT
        );
        CREATE TABLE retention_runs (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            policy_name TEXT,
            mode TEXT,
            status TEXT,
            operator TEXT,
            summary_json TEXT,
            created_at TEXT
        );
        CREATE TABLE retention_run_items (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER,
            retention_run_id INTEGER,
            category TEXT,
            table_name TEXT,
            retention_days INTEGER,
            cutoff_at TEXT,
            eligible_count INTEGER,
            deleted_count INTEGER,
            skipped_count INTEGER,
            reason TEXT,
            created_at TEXT
        );
        INSERT INTO retention_policies VALUES
            (1, 1001, 'b-disabled', 0, 30, 30, 90, 120, 0, '{}', '2026-08-11'),
            (2, 1001, 'a-enabled', 1, 45, 30, 90, 120, 0, '{}', '2026-08-12');
        INSERT INTO retention_runs VALUES
            (1, 1001, 'a-enabled', 'apply', 'complete', 'system', '{}', '2026-08-11'),
            (2, 1001, 'a-enabled', 'dry-run', 'complete', 'system', '{}', '2026-08-12');
        INSERT INTO retention_run_items VALUES
            (1, 1001, 2, 'monitoring', 'monitoring_alerts', 30, '', 5, 0, 5, '', ''),
            (2, 1001, 2, 'audit', 'audit_log', 90, '', 10, 0, 10, '', ''),
            (3, 1001, 1, 'old', 'old_table', 90, '', 99, 0, 99, '', '');
        """
    )

    sections = retention_sections(
        con,
        1001,
        limit=10,
        callbacks=_callbacks(),
    )

    assert [row["policy"] for row in sections["retention_policies"]] == [
        "a-enabled",
        "b-disabled",
    ]
    assert [row["run"] for row in sections["retention_runs"]] == ["2", "1"]
    assert [row["table"] for row in sections["retention_run_items"]] == [
        "audit_log",
        "monitoring_alerts",
        "old_table",
    ]


def test_missing_tables_return_empty_sections() -> None:
    con = _connect()

    assert distributed_task_section_rows(con, 1001, limit=10, callbacks=_callbacks()) == []
    assert seed_sections(
        con,
        1001,
        limit=10,
        seed_run_limit=10,
        callbacks=_callbacks(),
    ) == {
        "engagement_seeds": [],
        "seed_relations": [],
        "seed_runs": [],
    }
    assert inventory_sections(con, 1001, limit=10, callbacks=_callbacks()) == {
        "hosts": [],
        "emails": [],
    }
    assert engagement_run_section_rows(
        con,
        1001,
        db_path=None,
        limit=10,
        callbacks=_callbacks(),
    ) == []
    assert email_intelligence_section_rows(con, 1001, limit=10, callbacks=_callbacks()) == []
    assert account_existence_section_rows(con, 1001, limit=10, callbacks=_callbacks()) == []
    assert service_section_rows(con, 1001, limit=10, callbacks=_callbacks()) == []
    assert crawl_result_section_rows(con, 1001, limit=10, callbacks=_callbacks()) == []
    assert social_profile_section_rows(con, 1001, limit=10, callbacks=_callbacks()) == []
    assert port_scan_result_section_rows(con, 1001, limit=10, callbacks=_callbacks()) == []
    assert passive_vuln_section_rows(con, 1001, limit=10, callbacks=_callbacks()) == []
    assert auth_test_result_section_rows(con, 1001, limit=10, callbacks=_callbacks()) == []
    assert artifact_queue_section_rows(con, 1001, limit=10, callbacks=_callbacks()) == []
    assert finding_sections(con, 1001, limit=10, callbacks=_callbacks()) == {
        "key_scanner_findings": [],
        "secret_lifecycle_items": [],
        "vulnerability_findings": [],
    }
    assert monitoring_configuration_sections(
        con,
        1001,
        limit=10,
        callbacks=_callbacks(),
    ) == {
        "monitoring_policies": [],
        "monitoring_alert_routes": [],
        "monitoring_alert_suppressions": [],
    }
    assert monitoring_history_sections(con, 1001, limit=10, callbacks=_callbacks()) == {
        "monitoring_snapshots": [],
        "monitoring_trend_points": [],
        "monitoring_changes": [],
        "monitoring_alerts": [],
    }
    assert remediation_workflow_sections(con, 1001, limit=10, callbacks=_callbacks()) == {
        "remediation_items": [],
        "remediation_review_queue": [],
    }
    assert cloud_sections(con, 1001, limit=10, callbacks=_callbacks()) == {
        "cloud_assets": [],
        "cloud_validation_results": [],
    }
    assert asset_graph_sections(con, 1001, limit=10, callbacks=_callbacks()) == {
        "asset_entities": [],
        "asset_relationships": [],
        "asset_ownership_claims": [],
        "asset_ownership_conflicts": [],
        "asset_graph_attack_paths": [],
        "asset_graph_choke_points": [],
        "asset_graph_fix_candidates": [],
    }
    assert active_validation_sections(con, 1001, limit=10, callbacks=_callbacks()) == {
        "active_validation_coverage": [],
        "active_validation_jobs": [],
        "active_validation_runs": [],
    }
    assert audit_sections(
        con,
        1001,
        audit_limit=10,
        scope_denial_limit=10,
        scope_denial_actions=("scheduled_task_scope_denied",),
        callbacks=_callbacks(),
    ) == {
        "audit_log": [],
        "scope_denials": [],
    }
    assert retention_sections(con, 1001, limit=10, callbacks=_callbacks()) == {
        "retention_policies": [],
        "retention_runs": [],
        "retention_run_items": [],
    }
