//! Integration tests for `forge-storage::schema` — proves the full v48 DDL
//! applies correctly, is idempotent, and that FK enforcement actually
//! rejects orphan rows once `direct_connect`'s PRAGMA block is active.

use forge_storage::direct_connect::direct_connect_memory;
use forge_storage::schema::{SCHEMA_VERSION, apply_schema, statement_count, table_names};

// ─── apply_schema ─────────────────────────────────────────────────────────────

#[test]
fn apply_schema_succeeds_on_fresh_memory_db() {
    let conn = direct_connect_memory().unwrap();
    apply_schema(&conn).unwrap();
}

#[test]
fn apply_schema_is_idempotent() {
    let conn = direct_connect_memory().unwrap();
    apply_schema(&conn).unwrap();
    // Re-running must not error (all statements are IF NOT EXISTS).
    apply_schema(&conn).unwrap();
}

#[test]
fn apply_schema_creates_version_table() {
    let conn = direct_connect_memory().unwrap();
    apply_schema(&conn).unwrap();
    let exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='_schema_version'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(exists, 1);
}

#[test]
fn schema_version_constant_matches_python_source() {
    // Python's SCHEMA_VERSION = 48 (forge/db/schema.py). This constant must
    // be updated in lockstep if the Python schema version ever changes.
    assert_eq!(SCHEMA_VERSION, 48);
}

// ─── table inventory ──────────────────────────────────────────────────────────

/// Every table name expected from the current (v48) Python schema, in the
/// same order they're declared in `forge/db/schema.py`. Used to prove the
/// Rust port has 1:1 table-name parity with the source, not just "some
/// tables that compile".
const EXPECTED_TABLES: &[&str] = &[
    "engagements",
    "workspaces",
    "workspace_memberships",
    "engagement_seeds",
    "seed_runs",
    "engagement_runs",
    "run_audit_manifests",
    "audit_reviews",
    "retention_policies",
    "retention_runs",
    "retention_run_items",
    "seed_relations",
    "asset_entities",
    "asset_relationships",
    "asset_ownership_claims",
    "active_validation_jobs",
    "active_validation_runs",
    "artifact_queue",
    "hosts",
    "services",
    "credentials",
    "query_audit",
    "audit_log",
    "task_progress",
    "payloads",
    "agents",
    "exfiltrated_data",
    "persistence",
    "lateral_movement",
    "llm_feedback",
    "key_scanner_findings",
    "secret_lifecycle_items",
    "secret_suppressions",
    "connector_secrets",
    "emails",
    "email_intelligence",
    "dehashed_sync_state",
    "scavenger_findings",
    "vulnerability_findings",
    "remediation_items",
    "remediation_ticket_events",
    "monitoring_policies",
    "monitoring_snapshots",
    "monitoring_changes",
    "monitoring_alerts",
    "monitoring_trend_points",
    "monitoring_alert_deliveries",
    "monitoring_alert_routes",
    "monitoring_alert_suppressions",
    "cloud_assets",
    "cloud_validation_results",
    "validation_claims",
    "attack_graph_snapshots",
    "crawl_results",
    "port_scan_results",
    "passive_vulns",
    "auth_test_results",
    "distributed_tasks",
    "worker_heartbeats",
    "queue_metrics",
    "command_center_actions",
    "command_center_timeline",
    "sentry_state",
    "approval_queue",
];

#[test]
fn table_names_matches_expected_inventory_exactly() {
    let parsed = table_names();
    assert_eq!(
        parsed, EXPECTED_TABLES,
        "table_names() must match the exact Python schema.py table list, in order"
    );
}

#[test]
fn table_count_is_sixty_four() {
    // Locks the count so an accidental deletion during future edits is
    // caught immediately, independent of the exact-list comparison above.
    assert_eq!(EXPECTED_TABLES.len(), 64);
    assert_eq!(table_names().len(), 64);
}

#[test]
fn statement_count_is_stable_and_nonzero() {
    // Sanity: tables + indexes + the validation_claims CHECK-only statement.
    // This is a regression guard, not a magic-number test — any change to
    // the statement count should be intentional and reviewed.
    let count = statement_count();
    assert!(
        count > EXPECTED_TABLES.len(),
        "must include indexes beyond just tables"
    );
    assert_eq!(count, 126);
}

#[test]
fn apply_schema_creates_every_expected_table_in_sqlite_master() {
    let conn = direct_connect_memory().unwrap();
    apply_schema(&conn).unwrap();
    for table in EXPECTED_TABLES {
        let exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                [table],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(exists, 1, "table '{table}' was not created by apply_schema");
    }
}

// ─── FK enforcement ───────────────────────────────────────────────────────────

#[test]
fn foreign_key_enforcement_rejects_orphan_host() {
    let conn = direct_connect_memory().unwrap();
    apply_schema(&conn).unwrap();
    // No engagement with id=999 exists; inserting a host referencing it
    // must fail because direct_connect enabled PRAGMA foreign_keys=ON.
    let result = conn.execute(
        "INSERT INTO hosts (engagement_id, ip) VALUES (999, '10.0.0.1')",
        [],
    );
    assert!(
        result.is_err(),
        "FK violation must be rejected when foreign_keys=ON"
    );
}

#[test]
fn foreign_key_enforcement_accepts_valid_reference() {
    let conn = direct_connect_memory().unwrap();
    apply_schema(&conn).unwrap();
    conn.execute(
        "INSERT INTO engagements (name, operator) VALUES ('test-engagement', 'operator1')",
        [],
    )
    .unwrap();
    let engagement_id: i64 = conn
        .query_row("SELECT last_insert_rowid()", [], |row| row.get(0))
        .unwrap();
    let result = conn.execute(
        "INSERT INTO hosts (engagement_id, ip) VALUES (?1, '10.0.0.1')",
        [engagement_id],
    );
    assert!(result.is_ok(), "valid FK reference must be accepted");
}

// ─── CHECK constraints ─────────────────────────────────────────────────────────

#[test]
fn engagement_status_check_rejects_invalid_value() {
    let conn = direct_connect_memory().unwrap();
    apply_schema(&conn).unwrap();
    let result = conn.execute(
        "INSERT INTO engagements (name, operator, status) VALUES ('t', 'op', 'BOGUS_STATUS')",
        [],
    );
    assert!(
        result.is_err(),
        "CHECK constraint must reject an unlisted status"
    );
}

#[test]
fn engagement_status_check_accepts_valid_values() {
    let conn = direct_connect_memory().unwrap();
    apply_schema(&conn).unwrap();
    for status in ["PREP", "ACTIVE", "COMPLETE", "ARCHIVED"] {
        let name = format!("engagement-{status}");
        let result = conn.execute(
            "INSERT INTO engagements (name, operator, status) VALUES (?1, 'op', ?2)",
            [&name, status],
        );
        assert!(result.is_ok(), "status '{status}' must be accepted");
    }
}

#[test]
fn engagement_name_uniqueness_is_enforced() {
    let conn = direct_connect_memory().unwrap();
    apply_schema(&conn).unwrap();
    conn.execute(
        "INSERT INTO engagements (name, operator) VALUES ('dup-name', 'op')",
        [],
    )
    .unwrap();
    let result = conn.execute(
        "INSERT INTO engagements (name, operator) VALUES ('dup-name', 'op2')",
        [],
    );
    assert!(
        result.is_err(),
        "UNIQUE constraint on engagements.name must be enforced"
    );
}

// ─── File-backed DB (not just :memory:) ───────────────────────────────────────

#[test]
fn apply_schema_works_on_file_backed_db() {
    use forge_storage::direct_connect::direct_connect;
    let dir = std::env::temp_dir().join(format!(
        "forge-storage-schema-apply-file-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db_path = dir.join("engagement.db");
    {
        let conn = direct_connect(&db_path).unwrap();
        apply_schema(&conn).unwrap();
        // Prove the shape stuck: insert a row through the file-backed handle.
        conn.execute(
            "INSERT INTO engagements (name, operator) VALUES ('on-disk', 'op')",
            [],
        )
        .unwrap();
    }
    // Reopen the same file and prove the schema persists across connections.
    {
        let conn = direct_connect(&db_path).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM engagements", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }
    std::fs::remove_dir_all(&dir).ok();
}

// ─── Index inventory ──────────────────────────────────────────────────────────

#[test]
fn apply_schema_creates_sixty_two_indexes_matching_schema_source() {
    // 60 CREATE INDEX IF NOT EXISTS + 2 CREATE UNIQUE INDEX IF NOT EXISTS =
    // 62 user-defined indexes (sqlite_autoindex_* entries are excluded via
    // the WHERE clause).
    let conn = direct_connect_memory().unwrap();
    apply_schema(&conn).unwrap();
    let index_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE type='index' AND name NOT LIKE 'sqlite_autoindex_%'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        index_count, 62,
        "schema must create exactly 62 named indexes (60 regular + 2 unique)"
    );
}

// ─── Stronger idempotency ─────────────────────────────────────────────────────

#[test]
fn apply_schema_three_consecutive_calls_remain_idempotent() {
    // Guards against a subtle regression where a non-`IF NOT EXISTS` DDL
    // statement would succeed on the second call (because the first apply
    // created the object) but fail on the third if transactional state
    // leaked. All statements must be truly idempotent.
    let conn = direct_connect_memory().unwrap();
    apply_schema(&conn).unwrap();
    apply_schema(&conn).unwrap();
    apply_schema(&conn).unwrap();
}

// ─── _schema_version table semantics ──────────────────────────────────────────

#[test]
fn schema_version_table_starts_empty_after_apply() {
    // apply_schema creates the _schema_version table but does NOT insert a
    // row — version bookkeeping is the migrations layer's job (deferred).
    // This test locks the current contract so a future "helpful" change
    // that silently writes a row is caught.
    let conn = direct_connect_memory().unwrap();
    apply_schema(&conn).unwrap();
    let row_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM _schema_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(row_count, 0);
}

// ─── engagement_seeds: additional constraint coverage ─────────────────────────

#[test]
fn engagement_seeds_seed_type_check_rejects_invalid_value() {
    let conn = direct_connect_memory().unwrap();
    apply_schema(&conn).unwrap();
    conn.execute(
        "INSERT INTO engagements (name, operator) VALUES ('e', 'op')",
        [],
    )
    .unwrap();
    let engagement_id: i64 = conn
        .query_row("SELECT last_insert_rowid()", [], |row| row.get(0))
        .unwrap();
    let result = conn.execute(
        "INSERT INTO engagement_seeds (engagement_id, seed_value, seed_type)
         VALUES (?1, 'bogus.value', 'NOT_A_REAL_TYPE')",
        [engagement_id],
    );
    assert!(
        result.is_err(),
        "CHECK on engagement_seeds.seed_type must reject unlisted values"
    );
}

#[test]
fn engagement_seeds_source_check_rejects_invalid_value() {
    let conn = direct_connect_memory().unwrap();
    apply_schema(&conn).unwrap();
    conn.execute(
        "INSERT INTO engagements (name, operator) VALUES ('e', 'op')",
        [],
    )
    .unwrap();
    let engagement_id: i64 = conn
        .query_row("SELECT last_insert_rowid()", [], |row| row.get(0))
        .unwrap();
    let result = conn.execute(
        "INSERT INTO engagement_seeds (engagement_id, seed_value, seed_type, source)
         VALUES (?1, 'target.example', 'domain', 'rogue_source')",
        [engagement_id],
    );
    assert!(
        result.is_err(),
        "CHECK on engagement_seeds.source must reject unlisted values"
    );
}

#[test]
fn engagement_seeds_composite_unique_rejects_duplicate() {
    // UNIQUE (engagement_id, seed_type, seed_value) — same (type, value)
    // must be allowed under different engagements but rejected within one.
    let conn = direct_connect_memory().unwrap();
    apply_schema(&conn).unwrap();
    conn.execute(
        "INSERT INTO engagements (name, operator) VALUES ('e1', 'op')",
        [],
    )
    .unwrap();
    let engagement_id: i64 = conn
        .query_row("SELECT last_insert_rowid()", [], |row| row.get(0))
        .unwrap();

    conn.execute(
        "INSERT INTO engagement_seeds (engagement_id, seed_value, seed_type)
         VALUES (?1, 'target.example', 'domain')",
        [engagement_id],
    )
    .unwrap();

    let duplicate = conn.execute(
        "INSERT INTO engagement_seeds (engagement_id, seed_value, seed_type)
         VALUES (?1, 'target.example', 'domain')",
        [engagement_id],
    );
    assert!(
        duplicate.is_err(),
        "composite UNIQUE must reject identical (engagement_id, seed_type, seed_value)"
    );

    // Different engagement with same (type, value) must be allowed.
    conn.execute(
        "INSERT INTO engagements (name, operator) VALUES ('e2', 'op')",
        [],
    )
    .unwrap();
    let other_engagement_id: i64 = conn
        .query_row("SELECT last_insert_rowid()", [], |row| row.get(0))
        .unwrap();
    let cross_engagement = conn.execute(
        "INSERT INTO engagement_seeds (engagement_id, seed_value, seed_type)
         VALUES (?1, 'target.example', 'domain')",
        [other_engagement_id],
    );
    assert!(
        cross_engagement.is_ok(),
        "same (seed_type, seed_value) under a different engagement_id must be allowed"
    );
}

#[test]
fn engagement_seeds_parent_seed_id_fk_rejects_orphan_parent() {
    // engagement_seeds.parent_seed_id is a self-referential FK; a non-NULL
    // value pointing at a non-existent row must be rejected when
    // foreign_keys=ON (direct_connect default).
    let conn = direct_connect_memory().unwrap();
    apply_schema(&conn).unwrap();
    conn.execute(
        "INSERT INTO engagements (name, operator) VALUES ('e', 'op')",
        [],
    )
    .unwrap();
    let engagement_id: i64 = conn
        .query_row("SELECT last_insert_rowid()", [], |row| row.get(0))
        .unwrap();

    let result = conn.execute(
        "INSERT INTO engagement_seeds
             (engagement_id, seed_value, seed_type, parent_seed_id)
         VALUES (?1, 'child.example', 'domain', 999999)",
        [engagement_id],
    );
    assert!(
        result.is_err(),
        "self-referential FK must reject parent_seed_id pointing to a missing row"
    );
}

#[test]
fn engagement_seeds_parent_seed_id_fk_accepts_valid_parent() {
    let conn = direct_connect_memory().unwrap();
    apply_schema(&conn).unwrap();
    conn.execute(
        "INSERT INTO engagements (name, operator) VALUES ('e', 'op')",
        [],
    )
    .unwrap();
    let engagement_id: i64 = conn
        .query_row("SELECT last_insert_rowid()", [], |row| row.get(0))
        .unwrap();

    conn.execute(
        "INSERT INTO engagement_seeds (engagement_id, seed_value, seed_type)
         VALUES (?1, 'parent.example', 'domain')",
        [engagement_id],
    )
    .unwrap();
    let parent_id: i64 = conn
        .query_row("SELECT last_insert_rowid()", [], |row| row.get(0))
        .unwrap();

    let result = conn.execute(
        "INSERT INTO engagement_seeds
             (engagement_id, seed_value, seed_type, parent_seed_id)
         VALUES (?1, 'child.example', 'subdomain', ?2)",
        [engagement_id, parent_id],
    );
    assert!(
        result.is_ok(),
        "valid self-FK parent reference must be accepted"
    );
}

// ─── asset_entities: confidence range CHECK ───────────────────────────────────

#[test]
fn asset_entities_confidence_check_rejects_above_one() {
    let conn = direct_connect_memory().unwrap();
    apply_schema(&conn).unwrap();
    conn.execute(
        "INSERT INTO engagements (name, operator) VALUES ('e', 'op')",
        [],
    )
    .unwrap();
    let engagement_id: i64 = conn
        .query_row("SELECT last_insert_rowid()", [], |row| row.get(0))
        .unwrap();

    let result = conn.execute(
        "INSERT INTO asset_entities (engagement_id, entity_key, entity_type, label, confidence)
         VALUES (?1, 'k', 'asset', 'lbl', 1.5)",
        [engagement_id],
    );
    assert!(
        result.is_err(),
        "CHECK (confidence <= 1.0) must reject out-of-range confidence"
    );
}

#[test]
fn asset_entities_confidence_check_rejects_below_zero() {
    let conn = direct_connect_memory().unwrap();
    apply_schema(&conn).unwrap();
    conn.execute(
        "INSERT INTO engagements (name, operator) VALUES ('e', 'op')",
        [],
    )
    .unwrap();
    let engagement_id: i64 = conn
        .query_row("SELECT last_insert_rowid()", [], |row| row.get(0))
        .unwrap();

    let result = conn.execute(
        "INSERT INTO asset_entities (engagement_id, entity_key, entity_type, label, confidence)
         VALUES (?1, 'k', 'asset', 'lbl', -0.1)",
        [engagement_id],
    );
    assert!(
        result.is_err(),
        "CHECK (confidence >= 0.0) must reject negative confidence"
    );
}

#[test]
fn asset_entities_entity_type_check_rejects_invalid() {
    let conn = direct_connect_memory().unwrap();
    apply_schema(&conn).unwrap();
    conn.execute(
        "INSERT INTO engagements (name, operator) VALUES ('e', 'op')",
        [],
    )
    .unwrap();
    let engagement_id: i64 = conn
        .query_row("SELECT last_insert_rowid()", [], |row| row.get(0))
        .unwrap();
    let result = conn.execute(
        "INSERT INTO asset_entities (engagement_id, entity_key, entity_type, label)
         VALUES (?1, 'k', 'TOTALLY_INVALID_TYPE', 'lbl')",
        [engagement_id],
    );
    assert!(
        result.is_err(),
        "CHECK on asset_entities.entity_type must reject unlisted values"
    );
}

// ─── Multiple engagements cohabit the same DB ─────────────────────────────────

#[test]
fn multiple_engagements_can_coexist_in_one_db() {
    let conn = direct_connect_memory().unwrap();
    apply_schema(&conn).unwrap();
    for i in 0..5 {
        conn.execute(
            "INSERT INTO engagements (name, operator) VALUES (?1, 'op')",
            [format!("engagement-{i}")],
        )
        .unwrap();
    }
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM engagements", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 5);
}
