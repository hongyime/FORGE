from __future__ import annotations

import sqlite3
from pathlib import Path

from forge.db.migrations import TARGET_VERSION, run_migrations
from forge.db.schema import apply_schema
from forge.db.validation import validate_canonical_schema


def test_multi_seed_tables_are_canonical_on_fresh_db(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    con = sqlite3.connect(db_path)
    try:
        apply_schema(con)
        run_migrations(con)
        validate_canonical_schema(con)

        tables = {
            row[0]
            for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
        assert {
            "workspaces",
            "workspace_memberships",
            "engagement_seeds",
            "seed_runs",
            "engagement_runs",
            "run_audit_manifests",
            "seed_relations",
            "artifact_queue",
            "validation_claims",
            "remediation_items",
            "monitoring_policies",
            "monitoring_snapshots",
            "monitoring_changes",
            "monitoring_alerts",
            "monitoring_trend_points",
            "monitoring_alert_deliveries",
            "monitoring_alert_routes",
            "monitoring_alert_suppressions",
            "remediation_ticket_events",
            "asset_entities",
            "asset_relationships",
            "asset_ownership_claims",
            "active_validation_jobs",
            "active_validation_runs",
            "secret_lifecycle_items",
            "secret_suppressions",
            "retention_policies",
            "retention_runs",
            "retention_run_items",
        } <= tables

        version = con.execute("SELECT MAX(version) FROM _schema_version").fetchone()[0]
        assert int(version) == TARGET_VERSION
        cloud_asset_columns = {
            str(row[1]) for row in con.execute("PRAGMA table_info(cloud_assets)").fetchall()
        }
        validation_columns = {
            str(row[1])
            for row in con.execute("PRAGMA table_info(cloud_validation_results)").fetchall()
        }
        engagement_columns = {
            str(row[1])
            for row in con.execute("PRAGMA table_info(engagements)").fetchall()
        }
        remediation_columns = {
            str(row[1])
            for row in con.execute("PRAGMA table_info(remediation_items)").fetchall()
        }
        remediation_ticket_columns = {
            str(row[1])
            for row in con.execute("PRAGMA table_info(remediation_ticket_events)").fetchall()
        }
        monitoring_policy_columns = {
            str(row[1])
            for row in con.execute("PRAGMA table_info(monitoring_policies)").fetchall()
        }
        monitoring_snapshot_columns = {
            str(row[1])
            for row in con.execute("PRAGMA table_info(monitoring_snapshots)").fetchall()
        }
        monitoring_trend_columns = {
            str(row[1])
            for row in con.execute("PRAGMA table_info(monitoring_trend_points)").fetchall()
        }
        monitoring_delivery_columns = {
            str(row[1])
            for row in con.execute("PRAGMA table_info(monitoring_alert_deliveries)").fetchall()
        }
        monitoring_route_columns = {
            str(row[1])
            for row in con.execute("PRAGMA table_info(monitoring_alert_routes)").fetchall()
        }
        monitoring_suppression_columns = {
            str(row[1])
            for row in con.execute("PRAGMA table_info(monitoring_alert_suppressions)").fetchall()
        }
        asset_entity_columns = {
            str(row[1])
            for row in con.execute("PRAGMA table_info(asset_entities)").fetchall()
        }
        asset_relationship_columns = {
            str(row[1])
            for row in con.execute("PRAGMA table_info(asset_relationships)").fetchall()
        }
        asset_ownership_columns = {
            str(row[1])
            for row in con.execute("PRAGMA table_info(asset_ownership_claims)").fetchall()
        }
        active_validation_job_columns = {
            str(row[1])
            for row in con.execute("PRAGMA table_info(active_validation_jobs)").fetchall()
        }
        active_validation_run_columns = {
            str(row[1])
            for row in con.execute("PRAGMA table_info(active_validation_runs)").fetchall()
        }
        secret_lifecycle_columns = {
            str(row[1])
            for row in con.execute("PRAGMA table_info(secret_lifecycle_items)").fetchall()
        }
        secret_suppression_columns = {
            str(row[1])
            for row in con.execute("PRAGMA table_info(secret_suppressions)").fetchall()
        }
        retention_policy_columns = {
            str(row[1])
            for row in con.execute("PRAGMA table_info(retention_policies)").fetchall()
        }
        retention_run_columns = {
            str(row[1])
            for row in con.execute("PRAGMA table_info(retention_runs)").fetchall()
        }
        retention_run_item_columns = {
            str(row[1])
            for row in con.execute("PRAGMA table_info(retention_run_items)").fetchall()
        }
        assert "provider_identifier" in cloud_asset_columns
        assert "provider_identifier" in validation_columns
        assert "workspace_id" in engagement_columns
        assert {
            "owner",
            "sla_due_at",
            "risk_acceptance_reason",
            "risk_acceptance_expires_at",
            "retest_status",
            "ticket_system",
            "ticket_ref",
            "ticket_url",
        } <= remediation_columns
        assert {
            "remediation_item_id",
            "connector",
            "destination",
            "action",
            "status",
            "item_updated_at",
            "attempt_count",
            "delivered_at",
        } <= remediation_ticket_columns
        assert {
            "schedule_interval_minutes",
            "mode",
            "last_snapshot_id",
            "next_run_at",
        } <= monitoring_policy_columns
        assert {"state_hash", "state_json", "summary_json"} <= monitoring_snapshot_columns
        assert {
            "snapshot_id",
            "observed_at",
            "asset_count",
            "finding_count",
            "added_count",
            "alert_count",
            "open_alert_count",
        } <= monitoring_trend_columns
        assert {
            "alert_id",
            "channel",
            "destination",
            "status",
            "attempt_count",
            "delivered_at",
        } <= monitoring_delivery_columns
        assert {
            "name",
            "enabled",
            "min_severity",
            "alert_type",
            "entity_prefix",
            "channel",
            "destination",
            "owner",
            "escalation",
        } <= monitoring_route_columns
        assert {
            "alert_type",
            "entity_key",
            "entity_prefix",
            "severity",
            "reason",
            "created_by",
            "expires_at",
        } <= monitoring_suppression_columns
        assert {
            "entity_key",
            "entity_type",
            "label",
            "source_table",
            "source_id",
            "confidence",
            "metadata_json",
            "last_seen_at",
        } <= asset_entity_columns
        assert {
            "cve_id",
            "cvss_version",
            "cvss_vector",
            "cwe_ids",
            "cpe_matches",
            "epss_score",
            "epss_percentile",
            "cisa_kev",
            "cisa_kev_due_date",
            "attack_techniques",
            "stix_external_refs_json",
            "standards_json",
        } <= {
            str(row[1])
            for row in con.execute("PRAGMA table_info(vulnerability_findings)").fetchall()
        }
        assert {
            "source_entity_id",
            "target_entity_id",
            "relationship_type",
            "confidence",
            "source_table",
            "source_id",
            "evidence_json",
        } <= asset_relationship_columns
        assert {
            "entity_id",
            "owner_kind",
            "owner_ref",
            "owner_display",
            "claim_type",
            "confidence",
            "source",
            "status",
            "evidence_json",
        } <= asset_ownership_columns
        assert {
            "target_ref",
            "target_kind",
            "method",
            "mode",
            "status",
            "approved",
            "roe_id",
            "scope_manifest_ref",
            "scope_manifest_hash",
            "safe_profile",
            "max_steps",
            "requested_by",
            "approved_by",
            "approval_note",
            "metadata_json",
        } <= active_validation_job_columns
        assert {
            "job_id",
            "status",
            "result",
            "operator",
            "evidence_json",
            "error",
            "started_at",
            "completed_at",
        } <= active_validation_run_columns
        assert {
            "key_finding_id",
            "lifecycle_status",
            "owner",
            "owner_source",
            "revocation_guidance_json",
            "prevention_guidance_json",
            "suppression_id",
            "suppressed",
        } <= secret_lifecycle_columns
        assert {
            "key_finding_id",
            "service",
            "pattern_name",
            "source_url",
            "reason",
            "status",
            "expires_at",
            "created_by",
            "evidence_json",
        } <= secret_suppression_columns
        assert {
            "audit_review_days",
            "monitoring_days",
            "remediation_event_days",
            "retention_run_days",
            "legal_hold_override",
        } <= retention_policy_columns
        assert {
            "policy_id",
            "policy_name",
            "mode",
            "status",
            "operator",
            "summary_json",
        } <= retention_run_columns
        assert {
            "retention_run_id",
            "category",
            "table_name",
            "eligible_count",
            "deleted_count",
            "skipped_count",
            "reason",
        } <= retention_run_item_columns
        default_workspace = con.execute(
            "SELECT name FROM workspaces WHERE workspace_id='default'"
        ).fetchone()
        assert default_workspace == ("Default Workspace",)
    finally:
        con.close()


def test_cloud_provider_migration_expands_existing_constraints(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    con = sqlite3.connect(db_path)
    try:
        con.executescript(
            """
            CREATE TABLE engagements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                scope_json TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL DEFAULT 'ACTIVE',
                operator TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE cloud_assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL REFERENCES engagements(id),
                asset_type TEXT NOT NULL,
                identifier TEXT NOT NULL,
                source TEXT NOT NULL,
                discovered_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                cloud_provider TEXT CHECK (cloud_provider IN ('aws','azure','gcp','firebase','supabase')),
                resource_type TEXT,
                region TEXT,
                account_id TEXT,
                subscription_id TEXT,
                resource_group TEXT,
                tags_json TEXT DEFAULT '{}',
                compliance_frameworks TEXT DEFAULT '[]',
                last_assessed TIMESTAMP,
                UNIQUE (engagement_id, asset_type, identifier)
            );

            CREATE TABLE vulnerability_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL REFERENCES engagements(id),
                vuln_type TEXT NOT NULL,
                target_url TEXT NOT NULL,
                parameter TEXT,
                severity TEXT NOT NULL CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
                title TEXT NOT NULL,
                description TEXT,
                evidence TEXT,
                cvss_score REAL,
                found_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                cloud_provider TEXT CHECK (cloud_provider IN ('aws','azure','gcp','firebase','supabase')),
                resource_id TEXT,
                compliance_control TEXT,
                remediation_cli TEXT,
                UNIQUE (engagement_id, vuln_type, target_url, parameter)
            );

            CREATE INDEX idx_vuln_findings_engagement
                ON vulnerability_findings (engagement_id, severity, vuln_type);

            CREATE TABLE _schema_version (
                version INTEGER NOT NULL,
                applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        con.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (1001, 'Acme Example', '[]', 'ACTIVE', 'delta-one')
            """
        )
        con.execute(
            """
            INSERT INTO cloud_assets
                (engagement_id, asset_type, identifier, source, cloud_provider)
            VALUES
                (1001, 'aws_s3', 'acme-public-assets', 'artifact_s3_uri', 'aws')
            """
        )
        con.execute(
            """
            INSERT INTO vulnerability_findings
                (engagement_id, vuln_type, target_url, parameter, severity, title, cloud_provider, resource_id)
            VALUES
                (1001, 'DETERMINISTIC_CLOUD_EXPOSURE', 'aws_s3://acme-public-assets', 'aws_s3', 'LOW', 'Existing S3 finding', 'aws', 'acme-public-assets')
            """
        )
        con.execute("INSERT INTO _schema_version (version) VALUES (16)")
        con.commit()

        run_migrations(con)

        con.execute(
            """
            INSERT INTO cloud_assets
                (engagement_id, asset_type, identifier, source, cloud_provider)
            VALUES
                (1001, 'do_spaces', 'nyc3/acme-space-public', 'artifact_url_extract', 'digitalocean')
            """
        )
        con.execute(
            """
            INSERT INTO vulnerability_findings
                (engagement_id, vuln_type, target_url, parameter, severity, title, cloud_provider, resource_id)
            VALUES
                (1001, 'DETERMINISTIC_CLOUD_EXPOSURE', 'do_spaces://nyc3/acme-space-public', 'do_spaces', 'LOW', 'DigitalOcean Spaces finding', 'digitalocean', 'nyc3/acme-space-public')
            """
        )
        con.commit()

        version = con.execute("SELECT MAX(version) FROM _schema_version").fetchone()[0]
        assert int(version) == TARGET_VERSION

        counts = con.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM cloud_assets WHERE cloud_provider='digitalocean'),
                (SELECT COUNT(*) FROM vulnerability_findings WHERE cloud_provider='digitalocean'),
                (SELECT COUNT(*) FROM cloud_assets WHERE provider_identifier='acme-public-assets')
            """
        ).fetchone()
        assert counts == (1, 1, 1)
    finally:
        con.close()


def test_cloud_validation_migration_preserves_provider_identifier(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    con = sqlite3.connect(db_path)
    try:
        con.executescript(
            """
            CREATE TABLE cloud_assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                asset_type TEXT NOT NULL,
                identifier TEXT NOT NULL,
                source TEXT NOT NULL,
                discovered_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (engagement_id, asset_type, identifier)
            );
            CREATE TABLE cloud_validation_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                asset_type TEXT NOT NULL,
                identifier TEXT NOT NULL,
                validation_status TEXT NOT NULL,
                validation_method TEXT,
                http_status INTEGER,
                evidence TEXT,
                notes TEXT,
                checked_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (engagement_id, asset_type, identifier)
            );
            CREATE TABLE _schema_version (
                version INTEGER NOT NULL,
                applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            INSERT INTO cloud_assets (engagement_id, asset_type, identifier, source)
            VALUES (1001, 'aws_cognito_user_pool', 'us-east-1_abcd12345', 'legacy');
            INSERT INTO cloud_validation_results
                (engagement_id, asset_type, identifier, validation_status, validation_method)
            VALUES
                (1001, 'aws_cognito_user_pool', 'us-east-1_abcd12345', 'UNSUPPORTED', 'legacy');
            INSERT INTO _schema_version (version) VALUES (18);
            """
        )
        con.commit()

        run_migrations(con)

        row = con.execute(
            """
            SELECT ca.provider_identifier, cvr.provider_identifier
            FROM cloud_assets ca
            JOIN cloud_validation_results cvr
              ON cvr.engagement_id=ca.engagement_id
             AND cvr.asset_type=ca.asset_type
             AND cvr.identifier=ca.identifier
            """
        ).fetchone()
        assert row == ("us-east-1_abcd12345", "us-east-1_abcd12345")
        version = con.execute("SELECT MAX(version) FROM _schema_version").fetchone()[0]
        assert int(version) == TARGET_VERSION
    finally:
        con.close()


def test_engagement_metadata_migration_adds_metadata_json_column(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    con = sqlite3.connect(db_path)
    try:
        con.executescript(
            """
            CREATE TABLE engagements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                scope_json TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL DEFAULT 'ACTIVE',
                operator TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (1, 'Legacy Example', '["legacy.example"]', 'ACTIVE', 'delta-one');
            """
        )

        run_migrations(con)
        validate_canonical_schema(con)

        engagement_columns = {
            str(row[1]) for row in con.execute("PRAGMA table_info(engagements)").fetchall()
        }
        assert "metadata_json" in engagement_columns
        row = con.execute("SELECT metadata_json FROM engagements WHERE id=1").fetchone()
        assert row is not None
        assert str(row[0]) == "{}"
    finally:
        con.close()


def test_distributed_task_attempt_backfill_counts_running_claims(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    con = sqlite3.connect(db_path)
    try:
        con.executescript(
            """
            CREATE TABLE distributed_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                task_key TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'queued',
                priority INTEGER NOT NULL DEFAULT 100,
                payload TEXT,
                worker_id TEXT,
                error TEXT,
                attempt_count INTEGER NOT NULL DEFAULT 0,
                max_attempts INTEGER NOT NULL DEFAULT 3,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (engagement_id, task_key)
            );
            CREATE TABLE _schema_version (
                version INTEGER NOT NULL,
                applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            INSERT INTO distributed_tasks (engagement_id, task_key, status, worker_id)
            VALUES (1001, 'validate:key:running', 'running', 'worker-a');
            INSERT INTO distributed_tasks (engagement_id, task_key, status)
            VALUES (1001, 'validate:key:queued', 'queued');
            INSERT INTO _schema_version (version) VALUES (23);
            """
        )
        con.commit()

        run_migrations(con)

        rows = dict(
            con.execute(
                """
                SELECT task_key, attempt_count
                FROM distributed_tasks
                ORDER BY task_key
                """
            ).fetchall()
        )
        version = con.execute("SELECT MAX(version) FROM _schema_version").fetchone()[0]
        assert int(version) == TARGET_VERSION
        assert rows == {
            "validate:key:queued": 0,
            "validate:key:running": 1,
        }
    finally:
        con.close()


def test_workspace_rbac_migration_backfills_default_workspace(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    con = sqlite3.connect(db_path)
    try:
        con.executescript(
            """
            CREATE TABLE engagements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                scope_json TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL DEFAULT 'ACTIVE',
                operator TEXT NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE _schema_version (
                version INTEGER NOT NULL,
                applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (1001, 'Legacy Example', '["legacy.example"]', 'ACTIVE', 'delta-one');
            INSERT INTO _schema_version (version) VALUES (26);
            """
        )
        con.commit()

        run_migrations(con)
        run_migrations(con)

        version = con.execute("SELECT MAX(version) FROM _schema_version").fetchone()[0]
        engagement_columns = {
            str(row[1])
            for row in con.execute("PRAGMA table_info(engagements)").fetchall()
        }
        workspace = con.execute(
            "SELECT workspace_id, name FROM workspaces WHERE workspace_id='default'"
        ).fetchone()
        engagement_workspace = con.execute(
            "SELECT workspace_id FROM engagements WHERE id=1001"
        ).fetchone()
        membership = con.execute(
            """
            SELECT role, permissions_json
            FROM workspace_memberships
            WHERE workspace_id='default' AND subject='delta-one'
            """
        ).fetchone()
        membership_count = con.execute(
            "SELECT COUNT(*) FROM workspace_memberships"
        ).fetchone()[0]

        assert int(version) == TARGET_VERSION
        assert "workspace_id" in engagement_columns
        assert workspace == ("default", "Default Workspace")
        assert engagement_workspace == ("default",)
        assert membership == ("owner", '["*"]')
        assert int(membership_count) == 1
    finally:
        con.close()


def test_apply_schema_defers_workspace_index_until_migration_backfills_column(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    con = sqlite3.connect(db_path)
    try:
        con.executescript(
            """
            CREATE TABLE engagements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                scope_json TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL DEFAULT 'ACTIVE',
                operator TEXT NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE _schema_version (
                version INTEGER NOT NULL,
                applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (1001, 'Legacy Example', '["legacy.example"]', 'ACTIVE', 'delta-one');
            INSERT INTO _schema_version (version) VALUES (26);
            """
        )
        con.commit()

        apply_schema(con)
        run_migrations(con)

        version = con.execute("SELECT MAX(version) FROM _schema_version").fetchone()[0]
        engagement_workspace = con.execute(
            "SELECT workspace_id FROM engagements WHERE id=1001"
        ).fetchone()
        indexes = {
            str(row[1])
            for row in con.execute("PRAGMA index_list(engagements)").fetchall()
        }
    finally:
        con.close()

    assert int(version) == TARGET_VERSION
    assert engagement_workspace == ("default",)
    assert "idx_engagements_workspace" in indexes


def test_vulnerability_standards_migration_adds_ctem_metadata_columns(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    con = sqlite3.connect(db_path)
    try:
        con.executescript(
            """
            CREATE TABLE _schema_version (
                version INTEGER NOT NULL,
                applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            INSERT INTO _schema_version (version) VALUES (40);

            CREATE TABLE engagements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                workspace_id TEXT NOT NULL DEFAULT 'default',
                scope_json TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL DEFAULT 'ACTIVE',
                operator TEXT NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (1001, 'Legacy Example', '["legacy.example"]', 'ACTIVE', 'delta-one');

            CREATE TABLE vulnerability_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL REFERENCES engagements(id),
                vuln_type TEXT NOT NULL,
                target_url TEXT NOT NULL,
                parameter TEXT,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                evidence TEXT,
                cvss_score REAL,
                found_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (engagement_id, vuln_type, target_url, parameter)
            );
            INSERT INTO vulnerability_findings
                (engagement_id, vuln_type, target_url, severity, title, evidence)
            VALUES
                (1001, 'cve_exposure', 'https://legacy.example', 'HIGH',
                 'Legacy CVE finding', 'CVE-2026-0001 CWE-200 T1530');
            """
        )
        con.commit()

        run_migrations(con)

        version = con.execute("SELECT MAX(version) FROM _schema_version").fetchone()[0]
        columns = {
            str(row[1])
            for row in con.execute("PRAGMA table_info(vulnerability_findings)").fetchall()
        }
        con.execute(
            """
            UPDATE vulnerability_findings
            SET cve_id='CVE-2026-0001',
                cvss_version='3.1',
                cwe_ids='["CWE-200"]',
                cpe_matches='["cpe:2.3:a:acme:app:1.0:*:*:*:*:*:*:*"]',
                epss_score=0.42,
                epss_percentile=0.88,
                cisa_kev=1,
                cisa_kev_due_date='2026-09-30',
                attack_techniques='["T1530"]',
                stix_external_refs_json='[{"source_name":"cve","external_id":"CVE-2026-0001"}]',
                standards_json='{"source":"fixture"}'
            WHERE engagement_id=1001
            """
        )
        row = con.execute(
            """
            SELECT cve_id, cvss_version, cisa_kev, cisa_kev_due_date, standards_json
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()
    finally:
        con.close()

    assert int(version) == TARGET_VERSION
    assert {
        "cve_id",
        "cvss_version",
        "cvss_vector",
        "cwe_ids",
        "cpe_matches",
        "epss_score",
        "epss_percentile",
        "cisa_kev",
        "cisa_kev_due_date",
        "attack_techniques",
        "stix_external_refs_json",
        "standards_json",
    } <= columns
    assert row == (
        "CVE-2026-0001",
        "3.1",
        1,
        "2026-09-30",
        '{"source":"fixture"}',
    )


def test_secret_lifecycle_migration_adds_suppression_workflow_tables(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    con = sqlite3.connect(db_path)
    try:
        con.executescript(
            """
            CREATE TABLE _schema_version (
                version INTEGER NOT NULL,
                applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            INSERT INTO _schema_version (version) VALUES (41);

            CREATE TABLE engagements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                workspace_id TEXT NOT NULL DEFAULT 'default',
                scope_json TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL DEFAULT 'ACTIVE',
                operator TEXT NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (1001, 'Legacy Example', '["legacy.example"]', 'ACTIVE', 'delta-one');

            CREATE TABLE key_scanner_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL REFERENCES engagements(id),
                domain TEXT NOT NULL,
                service TEXT NOT NULL,
                pattern_name TEXT NOT NULL,
                source_backend TEXT NOT NULL DEFAULT 'github',
                source_url TEXT NOT NULL,
                repo_name TEXT,
                key_redacted TEXT NOT NULL,
                key_enc TEXT,
                validation_state TEXT NOT NULL DEFAULT 'UNCONFIRMED',
                validation_detail TEXT,
                found_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                validated_at TIMESTAMP,
                UNIQUE (engagement_id, source_url, pattern_name)
            );
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_url, key_redacted)
            VALUES
                (30, 1001, 'legacy.example', 'github', 'GitHub PAT',
                 'https://github.com/acme/app/blob/main/.env', 'ghp_...TEST');
            """
        )
        con.commit()

        run_migrations(con)

        version = con.execute("SELECT MAX(version) FROM _schema_version").fetchone()[0]
        lifecycle_columns = {
            str(row[1])
            for row in con.execute("PRAGMA table_info(secret_lifecycle_items)").fetchall()
        }
        suppression_columns = {
            str(row[1])
            for row in con.execute("PRAGMA table_info(secret_suppressions)").fetchall()
        }
        con.execute(
            """
            INSERT INTO secret_suppressions
                (engagement_id, key_finding_id, service, pattern_name,
                 source_url, reason, created_by)
            VALUES
                (1001, 30, 'github', 'GitHub PAT',
                 'https://github.com/acme/app/blob/main/.env',
                 'fixture token', 'delta-one')
            """
        )
        con.execute(
            """
            INSERT INTO secret_lifecycle_items
                (engagement_id, key_finding_id, lifecycle_status, owner,
                 owner_source, revocation_guidance_json, prevention_guidance_json,
                 suppression_id, suppressed)
            VALUES
                (1001, 30, 'suppressed', 'appsec@example.com',
                 'validation_claims', '{"service":"github"}',
                 '[{"tool":"gitleaks"}]', 1, 1)
            """
        )
        row = con.execute(
            """
            SELECT lifecycle_status, owner, suppressed
            FROM secret_lifecycle_items
            WHERE engagement_id=1001 AND key_finding_id=30
            """
        ).fetchone()
    finally:
        con.close()

    assert int(version) == TARGET_VERSION
    assert {
        "key_finding_id",
        "lifecycle_status",
        "owner",
        "owner_source",
        "revocation_guidance_json",
        "prevention_guidance_json",
        "suppression_id",
        "suppressed",
    } <= lifecycle_columns
    assert {"reason", "status", "expires_at", "created_by", "evidence_json"} <= suppression_columns
    assert row == ("suppressed", "appsec@example.com", 1)


def test_remediation_workflow_migration_adds_owner_sla_ticket_state(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    con = sqlite3.connect(db_path)
    try:
        con.executescript(
            """
            CREATE TABLE engagements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                scope_json TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL DEFAULT 'ACTIVE',
                operator TEXT NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                workspace_id TEXT NOT NULL DEFAULT 'default',
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE _schema_version (
                version INTEGER NOT NULL,
                applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            INSERT INTO engagements (id, name, scope_json, status, operator, workspace_id)
            VALUES (1001, 'Legacy Example', '["legacy.example"]', 'ACTIVE', 'delta-one', 'default');
            INSERT INTO _schema_version (version) VALUES (27);
            """
        )
        con.commit()

        run_migrations(con)
        run_migrations(con)

        version = con.execute("SELECT MAX(version) FROM _schema_version").fetchone()[0]
        columns = {
            str(row[1])
            for row in con.execute("PRAGMA table_info(remediation_items)").fetchall()
        }
        con.execute(
            """
            INSERT INTO remediation_items
                (engagement_id, finding_table, finding_ref, title, severity,
                 owner, sla_due_at, ticket_system, ticket_ref, retest_status)
            VALUES
                (1001, 'manual', 'manual-risk-1', 'Manual risk', 'HIGH',
                 'appsec', '2026-08-20', 'github', 'SEC-1001', 'pending')
            """
        )
        con.execute(
            """
            INSERT INTO remediation_items
                (engagement_id, finding_table, finding_ref, title, severity)
            VALUES
                (1001, 'monitoring_alerts', '42', 'Added exposed service', 'HIGH')
            """
        )
        con.execute(
            """
            INSERT INTO remediation_ticket_events
                (engagement_id, remediation_item_id, connector, destination,
                 action, status, item_updated_at)
            VALUES
                (1001, 1, 'github_issues', 'https://api.github.com/repos/acme/security',
                 'update', 'delivered', '2026-07-09T10:00:00Z')
            """
        )
        con.execute(
            """
            INSERT INTO remediation_ticket_events
                (engagement_id, remediation_item_id, connector, destination,
                 action, status, item_updated_at)
            VALUES
                (1001, 2, 'jira', 'https://acme.atlassian.net/rest/api/3/issue/SEC',
                 'create', 'delivered', '2026-07-09T10:00:00Z')
            """
        )
        con.execute(
            """
            INSERT INTO remediation_ticket_events
                (engagement_id, remediation_item_id, connector, destination,
                 action, status, item_updated_at)
            VALUES
                (1001, 2, 'servicenow', 'https://acme.service-now.com/api/now/table/incident',
                 'create', 'delivered', '2026-07-09T10:00:00Z')
            """
        )
        row = con.execute(
            """
            SELECT owner, sla_due_at, ticket_system, ticket_ref, retest_status
            FROM remediation_items
            WHERE engagement_id=1001
              AND finding_table='manual'
            """
        ).fetchone()
        monitoring_row = con.execute(
            """
            SELECT finding_table, finding_ref, title
            FROM remediation_items
            WHERE engagement_id=1001
              AND finding_table='monitoring_alerts'
            """
        ).fetchone()
        event_rows = con.execute(
            """
            SELECT connector, destination, action, status
            FROM remediation_ticket_events
            WHERE engagement_id=1001
            ORDER BY connector
            """
        ).fetchall()

        assert int(version) == TARGET_VERSION
        assert {
            "risk_acceptance_reason",
            "risk_accepted_by",
            "risk_acceptance_expires_at",
            "retest_requested_at",
            "ticket_url",
        } <= columns
        assert row == ("appsec", "2026-08-20", "github", "SEC-1001", "pending")
        assert monitoring_row == ("monitoring_alerts", "42", "Added exposed service")
        assert [tuple(row) for row in event_rows] == [
            (
                "github_issues",
                "https://api.github.com/repos/acme/security",
                "update",
                "delivered",
            ),
            (
                "jira",
                "https://acme.atlassian.net/rest/api/3/issue/SEC",
                "create",
                "delivered",
            ),
            (
                "servicenow",
                "https://acme.service-now.com/api/now/table/incident",
                "create",
                "delivered",
            ),
        ]
    finally:
        con.close()


def test_soar_remediation_connector_migration_preserves_events_and_widens_check(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    con = sqlite3.connect(db_path)
    try:
        con.executescript(
            """
            CREATE TABLE engagements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                scope_json TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL DEFAULT 'ACTIVE',
                operator TEXT NOT NULL
            );
            CREATE TABLE remediation_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL REFERENCES engagements(id),
                finding_table TEXT NOT NULL DEFAULT 'manual',
                finding_ref TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'INFO',
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE remediation_ticket_events (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id       INTEGER NOT NULL REFERENCES engagements(id),
                remediation_item_id INTEGER NOT NULL REFERENCES remediation_items(id),
                connector           TEXT    NOT NULL CHECK (connector IN ('jsonl','stdout','webhook','github_issues','jira','servicenow')),
                destination         TEXT    NOT NULL,
                action              TEXT    NOT NULL CHECK (action IN ('create','update')),
                status              TEXT    NOT NULL CHECK (status IN ('delivered','failed')),
                item_updated_at     TEXT    NOT NULL DEFAULT '',
                attempt_count       INTEGER NOT NULL DEFAULT 1,
                last_error          TEXT,
                delivered_at        TEXT,
                metadata_json       TEXT    NOT NULL DEFAULT '{}',
                created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (remediation_item_id, connector, destination, item_updated_at)
            );
            CREATE INDEX idx_remediation_ticket_events_engagement
                ON remediation_ticket_events (engagement_id, status, connector, updated_at DESC);
            CREATE TABLE _schema_version (
                version INTEGER NOT NULL,
                applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (1001, 'Legacy Example', '["legacy.example"]', 'ACTIVE', 'delta-one');
            INSERT INTO remediation_items
                (id, engagement_id, finding_table, finding_ref, title, severity, updated_at)
            VALUES
                (10, 1001, 'manual', 'manual-1', 'Legacy risk', 'HIGH',
                 '2026-07-09T10:00:00Z');
            INSERT INTO remediation_ticket_events
                (engagement_id, remediation_item_id, connector, destination,
                 action, status, item_updated_at, metadata_json)
            VALUES
                (1001, 10, 'servicenow',
                 'https://acme.service-now.com/api/now/table/incident',
                 'update', 'delivered', '2026-07-09T10:00:00Z',
                 '{"operator":"legacy"}');
            INSERT INTO _schema_version (version) VALUES (44);
            """
        )
        con.commit()

        run_migrations(con)
        run_migrations(con)

        version = con.execute("SELECT MAX(version) FROM _schema_version").fetchone()[0]
        old_event = con.execute(
            """
            SELECT connector, destination, action, status, metadata_json
            FROM remediation_ticket_events
            WHERE id=1
            """
        ).fetchone()
        con.execute(
            """
            INSERT INTO remediation_ticket_events
                (engagement_id, remediation_item_id, connector, destination,
                 action, status, item_updated_at)
            VALUES
                (1001, 10, 'tines', 'https://tenant.tines.com/redacted-webhook-path-a',
                 'update', 'delivered', '2026-07-09T10:00:00Z'),
                (1001, 10, 'splunk_hec', 'https://splunk.example/services/collector/event',
                 'update', 'delivered', '2026-07-09T10:01:00Z'),
                (1001, 10, 'torq', 'https://hooks.torq.io/redacted-webhook-path-b',
                 'update', 'delivered', '2026-07-09T10:02:00Z')
            """
        )
        connectors = [
            str(row[0])
            for row in con.execute(
                """
                SELECT connector
                FROM remediation_ticket_events
                WHERE engagement_id=1001
                ORDER BY connector
                """
            ).fetchall()
        ]
        remediation_columns = {
            str(row[1])
            for row in con.execute("PRAGMA table_info(remediation_items)").fetchall()
        }

        assert int(version) == TARGET_VERSION
        assert "risk_acceptance_expires_at" in remediation_columns
        assert tuple(old_event) == (
            "servicenow",
            "https://acme.service-now.com/api/now/table/incident",
            "update",
            "delivered",
            '{"operator":"legacy"}',
        )
        assert connectors == ["servicenow", "splunk_hec", "tines", "torq"]
    finally:
        con.close()


def test_current_version_remediation_risk_expiry_drift_is_repaired(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    con = sqlite3.connect(db_path)
    try:
        con.executescript(
            """
            CREATE TABLE engagements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                scope_json TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL DEFAULT 'ACTIVE',
                operator TEXT NOT NULL
            );
            CREATE TABLE remediation_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL REFERENCES engagements(id),
                finding_table TEXT NOT NULL DEFAULT 'manual',
                finding_ref TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'INFO',
                owner TEXT,
                sla_due_at TEXT,
                status TEXT NOT NULL DEFAULT 'risk_accepted',
                risk_acceptance_reason TEXT,
                risk_accepted_by TEXT,
                risk_accepted_at TIMESTAMP,
                retest_status TEXT NOT NULL DEFAULT 'not_requested',
                retest_requested_at TIMESTAMP,
                retested_at TIMESTAMP,
                ticket_system TEXT,
                ticket_ref TEXT,
                ticket_url TEXT,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE _schema_version (
                version INTEGER NOT NULL,
                applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (1001, 'Legacy Current', '["legacy.example"]', 'ACTIVE', 'delta-one');
            INSERT INTO remediation_items
                (id, engagement_id, finding_table, finding_ref, title, severity,
                 owner, sla_due_at, status, risk_acceptance_reason,
                 risk_accepted_by, risk_accepted_at, retest_status,
                 metadata_json, created_at, updated_at)
            VALUES
                (10, 1001, 'manual', 'manual-1', 'Legacy accepted risk', 'HIGH',
                 'appsec', '2026-08-31T00:00:00Z', 'risk_accepted',
                 'legacy acceptance', 'delta-one', '2026-07-09T09:00:00Z',
                 'not_requested', '{}', '2026-07-09T09:00:00Z',
                 '2026-07-09T10:00:00Z');
            INSERT INTO _schema_version (version) VALUES (%d);
            """
            % TARGET_VERSION
        )
        con.commit()

        apply_schema(con)
        run_migrations(con)

        version = con.execute("SELECT MAX(version) FROM _schema_version").fetchone()[0]
        remediation_columns = {
            str(row[1])
            for row in con.execute("PRAGMA table_info(remediation_items)").fetchall()
        }
        remediation_indexes = {
            str(row[1])
            for row in con.execute("PRAGMA index_list(remediation_items)").fetchall()
        }
        legacy_row = con.execute(
            """
            SELECT risk_acceptance_reason, risk_acceptance_expires_at
            FROM remediation_items
            WHERE id=10
            """
        ).fetchone()

        assert int(version) == TARGET_VERSION
        assert "risk_acceptance_expires_at" in remediation_columns
        assert "idx_remediation_items_risk_expiry" in remediation_indexes
        assert tuple(legacy_row) == ("legacy acceptance", None)
    finally:
        con.close()


def test_continuous_monitoring_migration_adds_snapshot_diff_alert_state(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    con = sqlite3.connect(db_path)
    try:
        con.executescript(
            """
            CREATE TABLE engagements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                scope_json TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL DEFAULT 'ACTIVE',
                operator TEXT NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                workspace_id TEXT NOT NULL DEFAULT 'default',
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE _schema_version (
                version INTEGER NOT NULL,
                applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            INSERT INTO engagements (id, name, scope_json, status, operator, workspace_id)
            VALUES (1001, 'Legacy Example', '["legacy.example"]', 'ACTIVE', 'delta-one', 'default');
            INSERT INTO _schema_version (version) VALUES (28);
            """
        )
        con.commit()

        run_migrations(con)
        run_migrations(con)

        version = con.execute("SELECT MAX(version) FROM _schema_version").fetchone()[0]
        con.execute(
            """
            INSERT INTO monitoring_policies
                (engagement_id, name, schedule_interval_minutes, mode)
            VALUES (1001, 'Daily passive', 1440, 'passive')
            """
        )
        policy_id = int(con.execute("SELECT id FROM monitoring_policies").fetchone()[0])
        con.execute(
            """
            INSERT INTO monitoring_snapshots
                (engagement_id, policy_id, snapshot_kind, state_hash, state_json, summary_json)
            VALUES
                (1001, ?, 'manual', 'sha256:test', '{"assets":{},"findings":{}}',
                 '{"asset_count":0,"finding_count":0}')
            """,
            (policy_id,),
        )
        snapshot_id = int(con.execute("SELECT id FROM monitoring_snapshots").fetchone()[0])
        con.execute(
            """
            INSERT INTO monitoring_changes
                (engagement_id, snapshot_id, entity_type, entity_key, change_type, severity)
            VALUES (1001, ?, 'asset', 'host:legacy.example', 'added', 'INFO')
            """,
            (snapshot_id,),
        )
        change_id = int(con.execute("SELECT id FROM monitoring_changes").fetchone()[0])
        con.execute(
            """
            INSERT INTO monitoring_alerts
                (engagement_id, policy_id, snapshot_id, change_id, alert_type, severity, title)
            VALUES (1001, ?, ?, ?, 'asset_added', 'INFO', 'Added asset: legacy.example')
            """,
            (policy_id, snapshot_id, change_id),
        )
        row = con.execute(
            """
            SELECT p.schedule_interval_minutes, s.state_hash, c.change_type, a.status
            FROM monitoring_policies p
            JOIN monitoring_snapshots s ON s.policy_id=p.id
            JOIN monitoring_changes c ON c.snapshot_id=s.id
            JOIN monitoring_alerts a ON a.change_id=c.id
            """
        ).fetchone()

        assert int(version) == TARGET_VERSION
        assert row == (1440, "sha256:test", "added", "open")
    finally:
        con.close()


def test_monitoring_trend_migration_backfills_existing_snapshots(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    con = sqlite3.connect(db_path)
    try:
        con.executescript(
            """
            CREATE TABLE engagements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                scope_json TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL DEFAULT 'ACTIVE',
                operator TEXT NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                workspace_id TEXT NOT NULL DEFAULT 'default',
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE _schema_version (
                version INTEGER NOT NULL,
                applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE monitoring_policies (
                id                         INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id              INTEGER NOT NULL REFERENCES engagements(id),
                name                       TEXT    NOT NULL,
                enabled                    INTEGER NOT NULL DEFAULT 1,
                schedule_interval_minutes  INTEGER NOT NULL DEFAULT 1440,
                mode                       TEXT    NOT NULL DEFAULT 'passive',
                last_snapshot_id           INTEGER,
                last_run_at                TEXT,
                next_run_at                TEXT,
                metadata_json              TEXT    NOT NULL DEFAULT '{}',
                created_at                 TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at                 TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (engagement_id, name)
            );
            CREATE TABLE monitoring_snapshots (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id   INTEGER NOT NULL REFERENCES engagements(id),
                policy_id       INTEGER REFERENCES monitoring_policies(id),
                snapshot_kind   TEXT    NOT NULL DEFAULT 'manual',
                state_hash      TEXT    NOT NULL,
                state_json      TEXT    NOT NULL,
                summary_json    TEXT    NOT NULL,
                created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE monitoring_changes (
                id                    INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id         INTEGER NOT NULL REFERENCES engagements(id),
                baseline_snapshot_id  INTEGER,
                snapshot_id           INTEGER NOT NULL REFERENCES monitoring_snapshots(id),
                entity_type           TEXT    NOT NULL,
                entity_key            TEXT    NOT NULL,
                change_type           TEXT    NOT NULL,
                severity              TEXT    NOT NULL DEFAULT 'INFO',
                before_json           TEXT,
                after_json            TEXT,
                created_at            TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (snapshot_id, entity_type, entity_key, change_type)
            );
            CREATE TABLE monitoring_alerts (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id   INTEGER NOT NULL REFERENCES engagements(id),
                policy_id       INTEGER REFERENCES monitoring_policies(id),
                snapshot_id     INTEGER NOT NULL REFERENCES monitoring_snapshots(id),
                change_id       INTEGER REFERENCES monitoring_changes(id),
                alert_type      TEXT    NOT NULL,
                severity        TEXT    NOT NULL DEFAULT 'INFO',
                title           TEXT    NOT NULL,
                status          TEXT    NOT NULL DEFAULT 'open',
                metadata_json   TEXT    NOT NULL DEFAULT '{}',
                created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            INSERT INTO engagements (id, name, scope_json, status, operator, workspace_id)
            VALUES (1001, 'Legacy Example', '["legacy.example"]', 'ACTIVE', 'delta-one', 'default');
            INSERT INTO _schema_version (version) VALUES (29);
            INSERT INTO monitoring_policies
                (id, engagement_id, name, schedule_interval_minutes, mode)
            VALUES (7, 1001, 'Hourly passive', 60, 'passive');
            INSERT INTO monitoring_snapshots
                (id, engagement_id, policy_id, snapshot_kind, state_hash, state_json, summary_json, created_at)
            VALUES
                (11, 1001, 7, 'scheduled', 'sha256:test', '{"assets":{},"findings":{}}',
                 '{"asset_count":3,"finding_count":2,"severity_summary":{"CRITICAL":1,"HIGH":1,"MEDIUM":0,"LOW":0,"INFO":0}}',
                 '2026-07-09T10:00:00Z');
            INSERT INTO monitoring_changes
                (engagement_id, snapshot_id, entity_type, entity_key, change_type, severity)
            VALUES
                (1001, 11, 'asset', 'host:vpn.legacy.example', 'added', 'INFO'),
                (1001, 11, 'finding', 'finding:vpn', 'changed', 'CRITICAL');
            INSERT INTO monitoring_alerts
                (engagement_id, policy_id, snapshot_id, change_id, alert_type, severity, title, status)
            VALUES
                (1001, 7, 11, 1, 'asset_added', 'INFO', 'Added asset', 'resolved'),
                (1001, 7, 11, 2, 'finding_changed', 'CRITICAL', 'Changed finding', 'open');
            """
        )
        con.commit()

        run_migrations(con)
        run_migrations(con)

        version = con.execute("SELECT MAX(version) FROM _schema_version").fetchone()[0]
        row = con.execute(
            """
            SELECT snapshot_id,
                   asset_count,
                   finding_count,
                   critical_count,
                   high_count,
                   added_count,
                   changed_count,
                   alert_count,
                   open_alert_count,
                   observed_at
            FROM monitoring_trend_points
            WHERE engagement_id=1001
            """
        ).fetchone()

        assert int(version) == TARGET_VERSION
        assert row == (11, 3, 2, 1, 1, 1, 1, 2, 1, "2026-07-09T10:00:00Z")
    finally:
        con.close()


def test_monitoring_alert_delivery_migration_adds_idempotency_records(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    con = sqlite3.connect(db_path)
    try:
        con.executescript(
            """
            CREATE TABLE engagements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                scope_json TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL DEFAULT 'ACTIVE',
                operator TEXT NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                workspace_id TEXT NOT NULL DEFAULT 'default',
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE _schema_version (
                version INTEGER NOT NULL,
                applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE monitoring_alerts (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id   INTEGER NOT NULL REFERENCES engagements(id),
                policy_id       INTEGER,
                snapshot_id     INTEGER NOT NULL,
                change_id       INTEGER,
                alert_type      TEXT    NOT NULL,
                severity        TEXT    NOT NULL DEFAULT 'INFO',
                title           TEXT    NOT NULL,
                status          TEXT    NOT NULL DEFAULT 'open',
                metadata_json   TEXT    NOT NULL DEFAULT '{}',
                created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            INSERT INTO engagements (id, name, scope_json, status, operator, workspace_id)
            VALUES (1001, 'Legacy Example', '["legacy.example"]', 'ACTIVE', 'delta-one', 'default');
            INSERT INTO _schema_version (version) VALUES (30);
            INSERT INTO monitoring_alerts
                (id, engagement_id, snapshot_id, alert_type, severity, title)
            VALUES (42, 1001, 11, 'asset_added', 'INFO', 'Added asset');
            """
        )
        con.commit()

        run_migrations(con)
        run_migrations(con)

        version = con.execute("SELECT MAX(version) FROM _schema_version").fetchone()[0]
        con.execute(
            """
            INSERT INTO monitoring_alert_deliveries
                (engagement_id, alert_id, channel, destination, status, attempt_count, delivered_at)
            VALUES
                (1001, 42, 'jsonl', 'alerts.jsonl', 'delivered', 1, '2026-07-09T10:01:00Z')
            """
        )
        row = con.execute(
            """
            SELECT channel, destination, status, attempt_count, delivered_at
            FROM monitoring_alert_deliveries
            WHERE alert_id=42
            """
        ).fetchone()

        assert int(version) == TARGET_VERSION
        assert row == ("jsonl", "alerts.jsonl", "delivered", 1, "2026-07-09T10:01:00Z")
    finally:
        con.close()


def test_monitoring_alert_routing_migration_adds_routes_and_suppressions(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    con = sqlite3.connect(db_path)
    try:
        con.executescript(
            """
            CREATE TABLE engagements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                scope_json TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL DEFAULT 'ACTIVE',
                operator TEXT NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                workspace_id TEXT NOT NULL DEFAULT 'default',
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE _schema_version (
                version INTEGER NOT NULL,
                applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            INSERT INTO engagements (id, name, scope_json, status, operator, workspace_id)
            VALUES (1001, 'Legacy Example', '["legacy.example"]', 'ACTIVE', 'delta-one', 'default');
            INSERT INTO _schema_version (version) VALUES (31);
            """
        )
        con.commit()

        run_migrations(con)
        run_migrations(con)

        version = con.execute("SELECT MAX(version) FROM _schema_version").fetchone()[0]
        con.execute(
            """
            INSERT INTO monitoring_alert_routes
                (engagement_id, name, min_severity, channel, destination, owner, escalation)
            VALUES
                (1001, 'critical-local', 'HIGH', 'jsonl', 'alerts.jsonl', 'appsec', 'pager')
            """
        )
        con.execute(
            """
            INSERT INTO monitoring_alert_suppressions
                (engagement_id, alert_type, entity_prefix, reason, created_by, expires_at)
            VALUES
                (1001, 'asset_added', 'host:lab.', 'lab asset', 'delta-one', '2026-07-10T00:00:00Z')
            """
        )
        route = con.execute(
            """
            SELECT min_severity, channel, owner, escalation
            FROM monitoring_alert_routes
            WHERE engagement_id=1001
            """
        ).fetchone()
        suppression = con.execute(
            """
            SELECT alert_type, entity_prefix, reason, created_by
            FROM monitoring_alert_suppressions
            WHERE engagement_id=1001
            """
        ).fetchone()

        assert int(version) == TARGET_VERSION
        assert route == ("HIGH", "jsonl", "appsec", "pager")
        assert suppression == ("asset_added", "host:lab.", "lab asset", "delta-one")
    finally:
        con.close()
