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
            for row in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert {
            "engagement_seeds",
            "seed_runs",
            "engagement_runs",
            "run_audit_manifests",
            "seed_relations",
            "artifact_queue",
            "validation_claims",
        } <= tables

        version = con.execute("SELECT MAX(version) FROM _schema_version").fetchone()[0]
        assert int(version) == TARGET_VERSION
        cloud_asset_columns = {
            str(row[1])
            for row in con.execute("PRAGMA table_info(cloud_assets)").fetchall()
        }
        validation_columns = {
            str(row[1])
            for row in con.execute("PRAGMA table_info(cloud_validation_results)").fetchall()
        }
        assert "provider_identifier" in cloud_asset_columns
        assert "provider_identifier" in validation_columns
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
            str(row[1])
            for row in con.execute("PRAGMA table_info(engagements)").fetchall()
        }
        assert "metadata_json" in engagement_columns
        row = con.execute(
            "SELECT metadata_json FROM engagements WHERE id=1"
        ).fetchone()
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
