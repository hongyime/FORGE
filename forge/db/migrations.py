"""
forge/db/migrations.py — Version-gated engagement DB migration runner.

Migrations are applied in version order on every DB open (via session.py).
Each migration function receives the connection and must be idempotent —
calling it twice on a schema that already has the changes is a no-op.

Migration index
───────────────
  0001  initial schema (v7.0)
  0002  credentials.validated columns
  0003  query_audit
  0004  Phase 5 tables: payloads, agents, exfiltrated_data, persistence, lateral_movement
  0005  credentials hash columns: hash_type, hash_plaintext, hash_crack_source
  0006  credentials enrichment_data column
  0007  v7.2 tables: vulnerability_findings, cloud_assets, key_scanner_findings
  0019  provider_identifier exact cloud/provider identifier columns

Design constraints:
  - All ALTER TABLE statements use `IF NOT EXISTS` workaround (SQLite
    does not support IF NOT EXISTS on ALTER TABLE; we catch OperationalError).
  - Migration functions must be pure SQLite — no Python data transforms.
  - The _schema_version table stores the highest applied version, not a
    per-migration log, to keep the query simple.
"""

from __future__ import annotations

import logging
import sqlite3
from typing import Callable

_LOG = logging.getLogger(__name__)

# Type alias for migration callables.
Migration = Callable[[sqlite3.Connection], None]


# ---------------------------------------------------------------------------
# Migration implementations
# ---------------------------------------------------------------------------


def _m0001_initial_schema(conn: sqlite3.Connection) -> None:
    """Initial engagement schema — engagements, hosts, services."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS engagements (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            name         TEXT    NOT NULL UNIQUE,
            scope_json   TEXT    NOT NULL DEFAULT '[]',
            status       TEXT    NOT NULL DEFAULT 'PREP'
                                 CHECK (status IN ('PREP','ACTIVE','COMPLETE','ARCHIVED')),
            operator     TEXT    NOT NULL,
            created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS hosts (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL REFERENCES engagements(id),
            ip            TEXT    NOT NULL,
            hostname      TEXT,
            os_family     TEXT,
            host_context  TEXT    DEFAULT '{}',
            in_scope      INTEGER NOT NULL DEFAULT 1,
            discovered_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (engagement_id, ip)
        );

        CREATE INDEX IF NOT EXISTS idx_hosts_engagement
            ON hosts (engagement_id, in_scope);

        CREATE TABLE IF NOT EXISTS services (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id       INTEGER NOT NULL REFERENCES hosts(id),
            port          INTEGER NOT NULL,
            protocol      TEXT    NOT NULL DEFAULT 'tcp',
            service_name  TEXT,
            banner        TEXT,
            version       TEXT,
            discovered_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (host_id, port, protocol)
        );

        CREATE TABLE IF NOT EXISTS task_progress (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL REFERENCES engagements(id),
            task_key      TEXT    NOT NULL,
            status        TEXT    NOT NULL DEFAULT 'pending'
                                  CHECK (status IN ('pending','running','complete','failed')),
            checkpoint    TEXT,
            started_at    TIMESTAMP,
            completed_at  TIMESTAMP,
            UNIQUE (engagement_id, task_key)
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER REFERENCES engagements(id),
            phase         TEXT,
            module        TEXT,
            action        TEXT    NOT NULL,
            target        TEXT,
            result        TEXT,
            operator      TEXT,
            logged_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS credentials (
            id                     INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id          INTEGER NOT NULL REFERENCES engagements(id),
            email                  TEXT    NOT NULL,
            password_hash          TEXT,
            password_plaintext_enc TEXT,
            breach_name            TEXT,
            breach_date            TIMESTAMP,
            source                 TEXT,
            confidence             TEXT,
            discovered_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_creds_engagement ON credentials (engagement_id);
        CREATE INDEX IF NOT EXISTS idx_creds_email      ON credentials (email);
    """)
    try:
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_engagement ON audit_log (engagement_id, phase)")
    except sqlite3.OperationalError:
        pass
    conn.commit()


def _m0002_credentials_validated(conn: sqlite3.Connection) -> None:
    """Add validation columns to credentials (PRD §4.1)."""
    _safe_alter(
        conn, "ALTER TABLE credentials ADD COLUMN validated         INTEGER NOT NULL DEFAULT 0"
    )
    _safe_alter(conn, "ALTER TABLE credentials ADD COLUMN validated_service TEXT")
    _safe_alter(conn, "ALTER TABLE credentials ADD COLUMN validated_host    TEXT")
    _safe_alter(conn, "ALTER TABLE credentials ADD COLUMN validated_at      TIMESTAMP")
    _safe_alter(conn, "ALTER TABLE credentials ADD COLUMN validation_error  TEXT")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_creds_validated ON credentials (validated)")
    conn.commit()


def _m0003_query_audit(conn: sqlite3.Connection) -> None:
    """Add breach query audit log (obfuscated as query_audit per §12.6)."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS query_audit (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL REFERENCES engagements(id),
            source        TEXT    NOT NULL,
            email_queried TEXT    NOT NULL,
            queried_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            matched       INTEGER NOT NULL DEFAULT 0,
            records_found INTEGER NOT NULL DEFAULT 0,
            operator      TEXT    NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_query_audit_engagement
            ON query_audit (engagement_id);

        CREATE INDEX IF NOT EXISTS idx_query_audit_email
            ON query_audit (email_queried);
    """)


def _m0004_phase5_tables(conn: sqlite3.Connection) -> None:
    """Add Phase 5 tables: payloads, agents, exfiltrated_data, persistence, lateral_movement."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS payloads (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id     INTEGER NOT NULL REFERENCES engagements(id),
            payload_type      TEXT    NOT NULL,
            target_os         TEXT    NOT NULL,
            technique         TEXT,
            obfuscation_chain TEXT,
            delivery_url      TEXT,
            content_hash      TEXT,
            generated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            lots_host         TEXT,
            metadata_stripped INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS agents (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id   INTEGER NOT NULL REFERENCES engagements(id),
            host_id         INTEGER REFERENCES hosts(id),
            beacon_interval INTEGER NOT NULL DEFAULT 30,
            jitter_pct      INTEGER NOT NULL DEFAULT 15,
            c2_urls         TEXT    NOT NULL DEFAULT '[]',
            channel         TEXT    NOT NULL DEFAULT 'http',
            sleep_mask      INTEGER NOT NULL DEFAULT 1,
            checkin_at      TIMESTAMP,
            created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS exfiltrated_data (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id     INTEGER NOT NULL REFERENCES engagements(id),
            host_id           INTEGER REFERENCES hosts(id),
            source_path       TEXT    NOT NULL,
            staging_path      TEXT,
            file_hash         TEXT,
            bytes_transferred INTEGER,
            chunks_total      INTEGER,
            chunks_sent       INTEGER NOT NULL DEFAULT 0,
            exfil_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS persistence (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id        INTEGER NOT NULL REFERENCES engagements(id),
            host_id              INTEGER REFERENCES hosts(id),
            technique            TEXT    NOT NULL,
            target_os            TEXT    NOT NULL,
            install_cmd          TEXT    NOT NULL,
            cleanup_cmd          TEXT,
            lolbins_used         TEXT,
            obfuscation_applied  INTEGER NOT NULL DEFAULT 0,
            installed            INTEGER NOT NULL DEFAULT 0,
            verified             INTEGER NOT NULL DEFAULT 0,
            created_at           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS lateral_movement (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id       INTEGER NOT NULL REFERENCES engagements(id),
            source_host_id      INTEGER REFERENCES hosts(id),
            target_host_id      INTEGER NOT NULL REFERENCES hosts(id),
            technique           TEXT    NOT NULL,
            credential_id       INTEGER REFERENCES credentials(id),
            command             TEXT    NOT NULL,
            success             INTEGER,
            output              TEXT,
            scope_verified      INTEGER NOT NULL DEFAULT 0,
            operator_confirmed  INTEGER NOT NULL DEFAULT 0,
            executed_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS llm_feedback (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER REFERENCES engagements(id),
            model         TEXT    NOT NULL DEFAULT 'qwen2.5-1.5b',
            prompt_hash   TEXT,
            response_hash TEXT,
            quality_score REAL,
            validator_ok  INTEGER NOT NULL DEFAULT 0,
            generated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
    """)


def _m0005_credentials_hash_cols(conn: sqlite3.Connection) -> None:
    """Add hash-cracking columns to credentials (Module 4-C, PRD §4.1)."""
    _safe_alter(conn, "ALTER TABLE credentials ADD COLUMN hash_type         TEXT")
    _safe_alter(conn, "ALTER TABLE credentials ADD COLUMN hash_plaintext    TEXT")
    _safe_alter(conn, "ALTER TABLE credentials ADD COLUMN hash_crack_source TEXT")
    conn.commit()


def _m0006_credentials_enrichment(conn: sqlite3.Connection) -> None:
    """Add enrichment_data column to credentials (Module 2-C/2-D JSON intel)."""
    _safe_alter(conn, "ALTER TABLE credentials ADD COLUMN enrichment_data TEXT DEFAULT '{}'")
    conn.commit()


def _m0007_v72_tables(conn: sqlite3.Connection) -> None:
    """Add v7.2 tables: vulnerability_findings, cloud_assets, key_scanner_findings.

    key_scanner_findings schema aligned with secret_finder.py DDL and forge_spec.md §E:
      - validation_state uses REVOKED/UNCONFIRMED (not the old INVALID/UNVALIDATED).
      - Full column set: domain, service, pattern_name, source_backend, source_url,
        repo_name, key_redacted, key_enc, validation_detail.
      - UNIQUE constraint on (engagement_id, source_url, pattern_name).
    """
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS key_scanner_findings (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id    INTEGER NOT NULL REFERENCES engagements(id),
            domain           TEXT    NOT NULL,
            service          TEXT    NOT NULL,
            pattern_name     TEXT    NOT NULL,
            source_backend   TEXT    NOT NULL DEFAULT 'github',
            source_url       TEXT    NOT NULL,
            repo_name        TEXT,
            key_redacted     TEXT    NOT NULL,
            key_enc          TEXT,
            validation_state TEXT    NOT NULL DEFAULT 'UNCONFIRMED'
                             CHECK (validation_state IN ('ACTIVE','REVOKED','UNCONFIRMED','ERROR')),
            validation_detail TEXT,
            found_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            validated_at     TIMESTAMP,
            UNIQUE (engagement_id, source_url, pattern_name)
        );

        CREATE INDEX IF NOT EXISTS idx_key_findings_engagement
            ON key_scanner_findings (engagement_id, validation_state);

        CREATE INDEX IF NOT EXISTS idx_key_findings_service
            ON key_scanner_findings (service, validation_state);

        CREATE TABLE IF NOT EXISTS vulnerability_findings (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id   INTEGER NOT NULL REFERENCES engagements(id),
            vuln_type       TEXT    NOT NULL,
            target_url      TEXT    NOT NULL,
            parameter       TEXT,
            severity        TEXT    NOT NULL
                            CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
            title           TEXT    NOT NULL,
            description     TEXT,
            evidence        TEXT,
            cvss_score      REAL,
            found_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (engagement_id, vuln_type, target_url, parameter)
        );

        CREATE INDEX IF NOT EXISTS idx_vuln_findings_engagement
            ON vulnerability_findings (engagement_id, severity, vuln_type);

        CREATE TABLE IF NOT EXISTS cloud_assets (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id   INTEGER NOT NULL REFERENCES engagements(id),
            asset_type      TEXT    NOT NULL,
            identifier      TEXT    NOT NULL,
            provider_identifier TEXT,
            source          TEXT    NOT NULL,
            discovered_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (engagement_id, asset_type, identifier)
        );
    """)


def _m0008_phase2_support_tables(conn: sqlite3.Connection) -> None:
    """Add Phase 2 support tables: emails, email_intelligence, dehashed_sync_state,
    scavenger_findings.

    These tables are referenced by Modules 2-A, 2-C, 2-D, 2-E, and 2-I but were
    absent from migrations 0001–0007. All tables use IF NOT EXISTS for idempotency.
    """
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS emails (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL REFERENCES engagements(id),
            email         TEXT    NOT NULL,
            domain        TEXT,
            source        TEXT,
            first_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (engagement_id, email)
        );

        CREATE INDEX IF NOT EXISTS idx_emails_engagement
            ON emails (engagement_id, domain);

        CREATE TABLE IF NOT EXISTS email_intelligence (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id   INTEGER NOT NULL REFERENCES engagements(id),
            email           TEXT    NOT NULL,
            source          TEXT    NOT NULL,
            breach_count    INTEGER NOT NULL DEFAULT 0,
            breach_names    TEXT    DEFAULT '[]',
            paste_count     INTEGER NOT NULL DEFAULT 0,
            enrichment_data TEXT    DEFAULT '{}',
            last_synced     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (engagement_id, email, source)
        );

        CREATE TABLE IF NOT EXISTS dehashed_sync_state (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL REFERENCES engagements(id),
            query_type    TEXT    NOT NULL,
            query_value   TEXT    NOT NULL,
            last_synced   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            total_count   INTEGER,
            UNIQUE (engagement_id, query_type, query_value)
        );

        CREATE TABLE IF NOT EXISTS scavenger_findings (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id     INTEGER NOT NULL REFERENCES engagements(id),
            url               TEXT    NOT NULL,
            pattern_name      TEXT    NOT NULL,
            matched_value_enc TEXT    NOT NULL,
            context           TEXT,
            backend           TEXT    NOT NULL DEFAULT 'github',
            discovered_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (engagement_id, url, pattern_name)
        );

        CREATE INDEX IF NOT EXISTS idx_scavenger_engagement
            ON scavenger_findings (engagement_id);
    """)


def _m0009_attack_graph_snapshots(conn: sqlite3.Connection) -> None:
    """Add attack_graph_snapshots table for Module 4-H (Attack Path Visualizer).

    graph_json stores AttackGraph.model_dump_json(). The _assert_no_sensitive_data()
    guard in AttackGraphBuilder._write_snapshot() prevents any credential material
    from being written here.
    """
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS attack_graph_snapshots (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id        INTEGER NOT NULL REFERENCES engagements(id),
            snapshot_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            node_count           INTEGER NOT NULL,
            edge_count           INTEGER NOT NULL,
            critical_path_weight REAL    NOT NULL DEFAULT 0.0,
            min_severity         TEXT    NOT NULL DEFAULT 'LOW'
                                 CHECK (min_severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
            pruned               INTEGER NOT NULL DEFAULT 0,
            graph_json           TEXT    NOT NULL,
            mermaid_output       TEXT,
            dot_output           TEXT,
            UNIQUE (engagement_id, snapshot_at)
        );

        CREATE INDEX IF NOT EXISTS idx_attack_graph_engagement
            ON attack_graph_snapshots (engagement_id, snapshot_at DESC);
    """)


def _m0010_security_integration_tables(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS crawl_results (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id   INTEGER NOT NULL REFERENCES engagements(id),
            url             TEXT    NOT NULL,
            final_url       TEXT,
            title           TEXT,
            screenshot_path TEXT,
            tech_stack_json TEXT,
            discovered_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS port_scan_results (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL REFERENCES engagements(id),
            host          TEXT    NOT NULL,
            port          INTEGER NOT NULL,
            proto         TEXT,
            service       TEXT,
            version       TEXT,
            confidence    REAL,
            scanner       TEXT,
            cdn_detected  INTEGER NOT NULL DEFAULT 0,
            waf_detected  INTEGER NOT NULL DEFAULT 0,
            scanned_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS passive_vulns (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id  INTEGER NOT NULL REFERENCES engagements(id),
            vuln_id        TEXT    NOT NULL,
            plugin         TEXT,
            url            TEXT,
            payload        TEXT,
            param          TEXT,
            severity       TEXT,
            request_b64    TEXT,
            response_b64   TEXT,
            verified       INTEGER NOT NULL DEFAULT 0,
            false_positive INTEGER NOT NULL DEFAULT 0,
            reported       INTEGER NOT NULL DEFAULT 0,
            discovered_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (engagement_id, vuln_id)
        );

        CREATE TABLE IF NOT EXISTS auth_test_results (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL REFERENCES engagements(id),
            target_url    TEXT    NOT NULL,
            form_data     TEXT,
            attack_type   TEXT,
            success       INTEGER NOT NULL DEFAULT 0,
            response_data TEXT,
            tested_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS distributed_tasks (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL REFERENCES engagements(id),
            task_key      TEXT    NOT NULL,
            status        TEXT    NOT NULL DEFAULT 'queued',
            priority      INTEGER NOT NULL DEFAULT 100,
            payload       TEXT,
            worker_id     TEXT,
            error         TEXT,
            created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (engagement_id, task_key)
        );

        CREATE INDEX IF NOT EXISTS idx_distributed_tasks_status
            ON distributed_tasks (engagement_id, status, priority);
    """)


def _m0011_worker_metrics_tables(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS worker_heartbeats (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id   INTEGER NOT NULL REFERENCES engagements(id),
            worker_id       TEXT    NOT NULL,
            status          TEXT    NOT NULL DEFAULT 'idle',
            last_task_key   TEXT,
            last_error      TEXT,
            tasks_completed INTEGER NOT NULL DEFAULT 0,
            tasks_failed    INTEGER NOT NULL DEFAULT 0,
            heartbeat_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (engagement_id, worker_id)
        );

        CREATE INDEX IF NOT EXISTS idx_worker_heartbeats_engagement
            ON worker_heartbeats (engagement_id, heartbeat_at DESC);

        CREATE TABLE IF NOT EXISTS queue_metrics (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL REFERENCES engagements(id),
            queued_count  INTEGER NOT NULL DEFAULT 0,
            running_count INTEGER NOT NULL DEFAULT 0,
            done_count    INTEGER NOT NULL DEFAULT 0,
            failed_count  INTEGER NOT NULL DEFAULT 0,
            sampled_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_queue_metrics_engagement
            ON queue_metrics (engagement_id, sampled_at DESC);
    """)


def _m0012_enhanced_llm_feedback(conn: sqlite3.Connection) -> None:
    """Enhanced LLM feedback schema for improved validation and self-correction."""
    # Add enhanced telemetry fields to llm_feedback table
    _safe_alter(conn, "ALTER TABLE llm_feedback ADD COLUMN correction_loops INTEGER DEFAULT 0")
    _safe_alter(conn, "ALTER TABLE llm_feedback ADD COLUMN feedback_text TEXT")
    _safe_alter(conn, "ALTER TABLE llm_feedback ADD COLUMN narrative_coherence_score REAL")
    _safe_alter(conn, "ALTER TABLE llm_feedback ADD COLUMN opsec_violation_count INTEGER DEFAULT 0")
    _safe_alter(conn, "ALTER TABLE llm_feedback ADD COLUMN hallucination_score REAL")
    _safe_alter(conn, "ALTER TABLE llm_feedback ADD COLUMN factual_accuracy_score REAL")
    _safe_alter(conn, "ALTER TABLE llm_feedback ADD COLUMN engagement_context_relevance REAL")
    _safe_alter(conn, "ALTER TABLE llm_feedback ADD COLUMN final_approval BOOLEAN DEFAULT FALSE")
    _safe_alter(conn, "ALTER TABLE llm_feedback ADD COLUMN validation_timestamp TIMESTAMP")
    
    # Create new validation rules table
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS llm_validation_rules (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_name         TEXT    NOT NULL UNIQUE,
            rule_type         TEXT    NOT NULL CHECK (rule_type IN ('opsec','factual','coherence','relevance')),
            severity          TEXT    NOT NULL DEFAULT 'medium' CHECK (severity IN ('low','medium','high','critical')),
            pattern           TEXT    NOT NULL,
            description       TEXT,
            remediation_hint  TEXT,
            enabled           INTEGER NOT NULL DEFAULT 1,
            created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_validation_rules_type ON llm_validation_rules (rule_type, enabled);
        CREATE INDEX IF NOT EXISTS idx_validation_rules_severity ON llm_validation_rules (severity, enabled);
    """)
    
    # Insert default validation rules
    default_rules = [
        ("hardcoded_ip", "opsec", "critical", r"\\b(?:[0-9]{{1,3}}\\.){{3}}[0-9]{{1,3}}\\b", 
         "Hardcoded IP addresses in reports", "Replace with [REDACTED] or similar"),
        ("credential_exposure", "opsec", "critical", r"(?i)(password|token|key|secret)\\s*[:=]\\s*\\S+",
         "Credential plaintext exposure", "Reference credentials by type only, never reveal values"),
        ("tool_disclosure", "opsec", "high", r"(?i)(nmap|metasploit|burp|sqlmap|forge)",
         "Security tool names in reports", "Use generic terms like 'automated scanner'"),
        ("methodology_disclosure", "opsec", "medium", r"(?i)(exploit.*chain|lateral.*movement|persistence)",
         "Detailed methodology disclosure", "Keep methodology descriptions high-level"),
        ("cve_format", "factual", "high", r"CVE\\s*-\s*\\d{{4}}\\s*-\s*\\d+",
         "CVE format validation", "Ensure CVE references follow proper format"),
        ("severity_consistency", "factual", "medium", r"(?i)(critical|high|medium|low|info)",
         "Severity rating consistency", "Ensure severity ratings align with CVSS scores"),
    ]
    
    for rule_name, rule_type, severity, pattern, description, remediation in default_rules:
        conn.execute("""
            INSERT OR IGNORE INTO llm_validation_rules 
            (rule_name, rule_type, severity, pattern, description, remediation_hint)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (rule_name, rule_type, severity, pattern, description, remediation))
    
    conn.commit()


def _m0013_cloud_audit_enhancement(conn: sqlite3.Connection) -> None:
    """Enhanced cloud audit schema for AWS and Azure support."""
    # Add cloud provider specific columns to cloud_assets table
    _safe_alter(conn, "ALTER TABLE cloud_assets ADD COLUMN cloud_provider TEXT CHECK (cloud_provider IN ('aws','azure','gcp','firebase','supabase','digitalocean'))")
    _safe_alter(conn, "ALTER TABLE cloud_assets ADD COLUMN resource_type TEXT")
    _safe_alter(conn, "ALTER TABLE cloud_assets ADD COLUMN region TEXT")
    _safe_alter(conn, "ALTER TABLE cloud_assets ADD COLUMN account_id TEXT")
    _safe_alter(conn, "ALTER TABLE cloud_assets ADD COLUMN subscription_id TEXT")
    _safe_alter(conn, "ALTER TABLE cloud_assets ADD COLUMN resource_group TEXT")
    _safe_alter(conn, "ALTER TABLE cloud_assets ADD COLUMN tags_json TEXT DEFAULT '{}'")
    _safe_alter(conn, "ALTER TABLE cloud_assets ADD COLUMN compliance_frameworks TEXT DEFAULT '[]'")
    _safe_alter(conn, "ALTER TABLE cloud_assets ADD COLUMN last_assessed TIMESTAMP")
    
    # Add cloud-specific vulnerability finding metadata
    _safe_alter(conn, "ALTER TABLE vulnerability_findings ADD COLUMN cloud_provider TEXT CHECK (cloud_provider IN ('aws','azure','gcp','firebase','supabase','digitalocean'))")
    _safe_alter(conn, "ALTER TABLE vulnerability_findings ADD COLUMN resource_id TEXT")
    _safe_alter(conn, "ALTER TABLE vulnerability_findings ADD COLUMN compliance_control TEXT")
    _safe_alter(conn, "ALTER TABLE vulnerability_findings ADD COLUMN remediation_cli TEXT")
    
    # Create cloud audit metadata table
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS cloud_audit_metadata (
            id                    INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id         INTEGER NOT NULL REFERENCES engagements(id),
            cloud_provider        TEXT    NOT NULL CHECK (cloud_provider IN ('aws','azure','gcp')),
            audit_type            TEXT    NOT NULL,
            audit_scope           TEXT    NOT NULL,
            credentials_used      TEXT,
            audit_start_time      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            audit_end_time        TIMESTAMP,
            resources_scanned     INTEGER DEFAULT 0,
            findings_count        INTEGER DEFAULT 0,
            error_count           INTEGER DEFAULT 0,
            status                TEXT    NOT NULL DEFAULT 'running' CHECK (status IN ('running','completed','failed','cancelled')),
            metadata_json         TEXT    DEFAULT '{}',
            UNIQUE (engagement_id, cloud_provider, audit_type, audit_start_time)
        );

        CREATE INDEX IF NOT EXISTS idx_cloud_audit_engagement ON cloud_audit_metadata (engagement_id, cloud_provider, status);
        CREATE INDEX IF NOT EXISTS idx_cloud_audit_status ON cloud_audit_metadata (status, audit_end_time);
    """)
    
    conn.commit()


def _m0014_command_center_tables(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS command_center_actions (
            action_id           TEXT PRIMARY KEY,
            engagement_id       INTEGER NOT NULL REFERENCES engagements(id),
            target_type         TEXT    NOT NULL CHECK (target_type IN ('host','service','url','credential')),
            target_ref          TEXT    NOT NULL,
            action_type         TEXT    NOT NULL CHECK (
                                action_type IN (
                                    'scan_ports',
                                    'crawl',
                                    'content_discovery',
                                    'vuln_scan',
                                    'credential_test',
                                    'exploit_attempt',
                                    'brute_force_policy_check',
                                    'share_enumeration'
                                )
                            ),
            confidence_score    INTEGER NOT NULL CHECK (confidence_score >= 0 AND confidence_score <= 100),
            risk_level          TEXT    NOT NULL CHECK (risk_level IN ('low','medium','high','critical')),
            requires_approval   INTEGER NOT NULL DEFAULT 0,
            status              TEXT    NOT NULL CHECK (status IN ('suggested','queued','running','succeeded','failed','cancelled','rolled_back')),
            created_at          TEXT    NOT NULL,
            updated_at          TEXT    NOT NULL,
            reasoning           TEXT    NOT NULL,
            opsec_warnings_json TEXT    NOT NULL DEFAULT '[]',
            params_json         TEXT    NOT NULL DEFAULT '{}',
            execution_mode      TEXT    NOT NULL DEFAULT 'manual' CHECK (execution_mode IN ('manual','autonomous')),
            policy_outcome      TEXT    NOT NULL DEFAULT 'suggest' CHECK (policy_outcome IN ('auto_execute','queue','suggest','hidden','blocked')),
            policy_reason       TEXT    NOT NULL DEFAULT ''
        );

        CREATE INDEX IF NOT EXISTS idx_command_center_actions_target
            ON command_center_actions (engagement_id, target_ref, status, confidence_score DESC);

        CREATE INDEX IF NOT EXISTS idx_command_center_actions_status
            ON command_center_actions (engagement_id, status, execution_mode);

        CREATE TABLE IF NOT EXISTS command_center_timeline (
            event_id     TEXT PRIMARY KEY,
            engagement_id INTEGER NOT NULL REFERENCES engagements(id),
            event_type   TEXT    NOT NULL,
            severity     TEXT    NOT NULL DEFAULT 'info' CHECK (severity IN ('info','warning','critical')),
            acknowledged INTEGER NOT NULL DEFAULT 0,
            timestamp    TEXT    NOT NULL,
            expires_at   TEXT,
            payload_json TEXT    NOT NULL DEFAULT '{}'
        );

        CREATE INDEX IF NOT EXISTS idx_command_center_timeline
            ON command_center_timeline (engagement_id, timestamp DESC, severity);

        CREATE TABLE IF NOT EXISTS sentry_state (
            engagement_id                  INTEGER PRIMARY KEY REFERENCES engagements(id),
            enabled                        INTEGER NOT NULL DEFAULT 0,
            emergency_stop                 INTEGER NOT NULL DEFAULT 0,
            auto_execute_threshold         INTEGER NOT NULL DEFAULT 95,
            max_concurrent_auto            INTEGER NOT NULL DEFAULT 3,
            require_operator_approval      INTEGER NOT NULL DEFAULT 0,
            pause_on_new_critical_finding  INTEGER NOT NULL DEFAULT 1,
            paused_reason                  TEXT,
            whitelisted_action_types_json  TEXT    NOT NULL DEFAULT '["credential_test"]',
            action_overrides_json          TEXT    NOT NULL DEFAULT '{}',
            engagement_overrides_json      TEXT    NOT NULL DEFAULT '{}',
            updated_at                     TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()


def _m0015_multi_seed_orchestration(conn: sqlite3.Connection) -> None:
    """Add multi-seed orchestration and artifact-queue tables."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS engagement_seeds (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id  INTEGER NOT NULL REFERENCES engagements(id),
            seed_value     TEXT    NOT NULL,
            seed_type      TEXT    NOT NULL
                           CHECK (seed_type IN (
                               'domain','email','phone','username','ipv4','ipv6',
                               'name','company','url','apk_url','subdomain','other'
                           )),
            source         TEXT    NOT NULL DEFAULT 'operator'
                           CHECK (source IN ('operator','scope','discovered','artifact','cross_reference')),
            status         TEXT    NOT NULL DEFAULT 'pending'
                           CHECK (status IN ('pending','running','completed','failed','ignored')),
            depth          INTEGER NOT NULL DEFAULT 0,
            confidence     REAL    NOT NULL DEFAULT 1.0,
            parent_seed_id INTEGER REFERENCES engagement_seeds(id),
            metadata_json  TEXT    NOT NULL DEFAULT '{}',
            discovered_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (engagement_id, seed_type, seed_value)
        );

        CREATE INDEX IF NOT EXISTS idx_engagement_seeds_engagement
            ON engagement_seeds (engagement_id, status, depth);

        CREATE TABLE IF NOT EXISTS seed_runs (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL REFERENCES engagements(id),
            seed_id       INTEGER NOT NULL REFERENCES engagement_seeds(id),
            loop_name     TEXT    NOT NULL,
            status        TEXT    NOT NULL DEFAULT 'queued'
                          CHECK (status IN ('queued','running','completed','failed','skipped')),
            input_count   INTEGER NOT NULL DEFAULT 0,
            output_count  INTEGER NOT NULL DEFAULT 0,
            error         TEXT,
            metadata_json TEXT    NOT NULL DEFAULT '{}',
            started_at    TIMESTAMP,
            completed_at  TIMESTAMP,
            UNIQUE (engagement_id, seed_id, loop_name, started_at)
        );

        CREATE INDEX IF NOT EXISTS idx_seed_runs_engagement
            ON seed_runs (engagement_id, status, started_at);

        CREATE TABLE IF NOT EXISTS engagement_runs (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id     INTEGER NOT NULL REFERENCES engagements(id),
            run_kind          TEXT    NOT NULL DEFAULT 'kill_chain'
                              CHECK (run_kind IN ('kill_chain','reporting','dashboard','other')),
            status            TEXT    NOT NULL DEFAULT 'running'
                              CHECK (status IN ('running','completed','failed','cancelled')),
            seed_value        TEXT,
            seed_type         TEXT,
            seed_count        INTEGER NOT NULL DEFAULT 0,
            max_iterations    INTEGER NOT NULL DEFAULT 0,
            current_iteration INTEGER NOT NULL DEFAULT 0,
            resume_enabled    INTEGER NOT NULL DEFAULT 0,
            dry_run           INTEGER NOT NULL DEFAULT 0,
            attack_mode       INTEGER NOT NULL DEFAULT 0,
            error             TEXT,
            metadata_json     TEXT    NOT NULL DEFAULT '{}',
            started_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            completed_at      TIMESTAMP,
            updated_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_engagement_runs_engagement
            ON engagement_runs (engagement_id, status, started_at DESC);

        CREATE TABLE IF NOT EXISTS seed_relations (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id  INTEGER NOT NULL REFERENCES engagements(id),
            source_seed_id INTEGER NOT NULL REFERENCES engagement_seeds(id),
            target_seed_id INTEGER NOT NULL REFERENCES engagement_seeds(id),
            relation_type  TEXT    NOT NULL
                           CHECK (relation_type IN ('derived_from','corroborates','conflicts_with','same_entity','related_asset')),
            confidence     REAL    NOT NULL DEFAULT 0.5,
            evidence_json  TEXT    NOT NULL DEFAULT '{}',
            discovered_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (engagement_id, source_seed_id, target_seed_id, relation_type)
        );

        CREATE INDEX IF NOT EXISTS idx_seed_relations_engagement
            ON seed_relations (engagement_id, relation_type, confidence DESC);

        CREATE TABLE IF NOT EXISTS artifact_queue (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id   INTEGER NOT NULL REFERENCES engagements(id),
            source_url      TEXT    NOT NULL,
            local_path      TEXT,
            artifact_type   TEXT    NOT NULL
                            CHECK (artifact_type IN ('apk','ipa','document','archive','config','binary','other')),
            discovered_from TEXT,
            status          TEXT    NOT NULL DEFAULT 'queued'
                            CHECK (status IN ('queued','downloaded','parsed','failed','skipped')),
            sha256          TEXT,
            notes           TEXT,
            metadata_json   TEXT    NOT NULL DEFAULT '{}',
            queued_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (engagement_id, source_url)
        );

        CREATE INDEX IF NOT EXISTS idx_artifact_queue_engagement
            ON artifact_queue (engagement_id, status, artifact_type);
    """)
    conn.commit()


def _m0016_cloud_validation_results(conn: sqlite3.Connection) -> None:
    """Add deterministic cloud validation result storage."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS cloud_validation_results (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id     INTEGER NOT NULL REFERENCES engagements(id),
            asset_type        TEXT    NOT NULL,
            identifier        TEXT    NOT NULL,
            provider_identifier TEXT,
            validation_status TEXT    NOT NULL
                              CHECK (validation_status IN (
                                  'UNVALIDATED',
                                  'VALIDATED',
                                  'ACCESSIBLE_BUT_NO_DATA',
                                  'UNVERIFIED',
                                  'DEAD',
                                  'HONEYPOT_SUSPECTED',
                                  'UNSUPPORTED'
                              )),
            validation_method TEXT,
            http_status       INTEGER,
            evidence          TEXT,
            notes             TEXT,
            checked_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (engagement_id, asset_type, identifier)
        );

        CREATE INDEX IF NOT EXISTS idx_cloud_validation_engagement
            ON cloud_validation_results (engagement_id, validation_status, checked_at DESC);
    """)
    conn.commit()


def _m0017_cloud_provider_enum_expansion(conn: sqlite3.Connection) -> None:
    """Expand cloud-provider CHECK constraints to include DigitalOcean."""
    expected_clause = "cloud_provider IN ('aws','azure','gcp','firebase','supabase','digitalocean')"

    if not _table_sql_contains(conn, "cloud_assets", expected_clause):
        _rebuild_table(
            conn,
            "cloud_assets",
            """
            CREATE TABLE cloud_assets (
                id                    INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id         INTEGER NOT NULL REFERENCES engagements(id),
                asset_type            TEXT    NOT NULL,
                identifier            TEXT    NOT NULL,
                provider_identifier   TEXT,
                source                TEXT    NOT NULL,
                discovered_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                cloud_provider        TEXT    CHECK (cloud_provider IN ('aws','azure','gcp','firebase','supabase','digitalocean')),
                resource_type         TEXT,
                region                TEXT,
                account_id            TEXT,
                subscription_id       TEXT,
                resource_group        TEXT,
                tags_json             TEXT    DEFAULT '{}',
                compliance_frameworks TEXT    DEFAULT '[]',
                last_assessed         TIMESTAMP,
                UNIQUE (engagement_id, asset_type, identifier)
            )
            """,
        )

    if not _table_sql_contains(conn, "vulnerability_findings", expected_clause):
        _rebuild_table(
            conn,
            "vulnerability_findings",
            """
            CREATE TABLE vulnerability_findings (
                id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id      INTEGER NOT NULL REFERENCES engagements(id),
                vuln_type          TEXT    NOT NULL,
                target_url         TEXT    NOT NULL,
                parameter          TEXT,
                severity           TEXT    NOT NULL
                                   CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
                title              TEXT    NOT NULL,
                description        TEXT,
                evidence           TEXT,
                cvss_score         REAL,
                found_at           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                cloud_provider     TEXT    CHECK (cloud_provider IN ('aws','azure','gcp','firebase','supabase','digitalocean')),
                resource_id        TEXT,
                compliance_control TEXT,
                remediation_cli    TEXT,
                UNIQUE (engagement_id, vuln_type, target_url, parameter)
            )
            """,
            [
                """
                CREATE INDEX IF NOT EXISTS idx_vuln_findings_engagement
                    ON vulnerability_findings (engagement_id, severity, vuln_type)
                """.strip(),
            ],
        )

    conn.commit()


def _m0018_engagement_metadata(conn: sqlite3.Connection) -> None:
    """Add engagement-level metadata storage for tags and future UI facets."""
    _safe_alter(
        conn,
        "ALTER TABLE engagements ADD COLUMN metadata_json TEXT NOT NULL DEFAULT '{}'",
    )
    conn.commit()


def _m0019_cloud_provider_identifier(conn: sqlite3.Connection) -> None:
    """Preserve exact first-seen provider identifiers beside canonical keys."""
    if _table_sql_contains(conn, "cloud_assets", "cloud_assets"):
        _safe_alter(conn, "ALTER TABLE cloud_assets ADD COLUMN provider_identifier TEXT")
        conn.execute(
            """
            UPDATE cloud_assets
            SET provider_identifier = identifier
            WHERE provider_identifier IS NULL OR TRIM(provider_identifier) = ''
            """
        )
    if _table_sql_contains(conn, "cloud_validation_results", "cloud_validation_results"):
        _safe_alter(conn, "ALTER TABLE cloud_validation_results ADD COLUMN provider_identifier TEXT")
        conn.execute(
            """
            UPDATE cloud_validation_results
            SET provider_identifier = identifier
            WHERE provider_identifier IS NULL OR TRIM(provider_identifier) = ''
            """
        )
    conn.commit()


def _m0020_validation_claims(conn: sqlite3.Connection) -> None:
    """Add short-lived claims for concurrent validation sweeps."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS validation_claims (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL REFERENCES engagements(id),
            claim_type    TEXT    NOT NULL
                         CHECK (claim_type IN ('key','asset')),
            key_id        INTEGER,
            asset_type    TEXT,
            identifier    TEXT,
            owner         TEXT    NOT NULL,
            claimed_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at    TIMESTAMP NOT NULL,
            updated_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CHECK (
                (claim_type='key' AND key_id IS NOT NULL AND asset_type IS NULL AND identifier IS NULL)
                OR
                (claim_type='asset' AND key_id IS NULL AND asset_type IS NOT NULL AND identifier IS NOT NULL)
            )
        );

        CREATE UNIQUE INDEX IF NOT EXISTS idx_validation_claims_key
            ON validation_claims (engagement_id, claim_type, key_id)
            WHERE claim_type='key';

        CREATE UNIQUE INDEX IF NOT EXISTS idx_validation_claims_asset
            ON validation_claims (engagement_id, claim_type, asset_type, identifier)
            WHERE claim_type='asset';

        CREATE INDEX IF NOT EXISTS idx_validation_claims_expiry
            ON validation_claims (claim_type, expires_at);
    """)
    conn.commit()


# ---------------------------------------------------------------------------
# Migration registry — ordered by version number
# ---------------------------------------------------------------------------

_MIGRATIONS: list[tuple[int, str, Migration]] = [
    (1, "initial_schema", _m0001_initial_schema),
    (2, "credentials_validated", _m0002_credentials_validated),
    (3, "query_audit", _m0003_query_audit),
    (4, "phase5_tables", _m0004_phase5_tables),
    (5, "credentials_hash_cols", _m0005_credentials_hash_cols),
    (6, "credentials_enrichment", _m0006_credentials_enrichment),
    (7, "v72_tables", _m0007_v72_tables),
    (8, "phase2_support_tables", _m0008_phase2_support_tables),
    (9, "attack_graph_snapshots", _m0009_attack_graph_snapshots),
    (10, "security_integration_tables", _m0010_security_integration_tables),
    (11, "worker_metrics_tables", _m0011_worker_metrics_tables),
    (12, "enhanced_llm_feedback", _m0012_enhanced_llm_feedback),
    (13, "cloud_audit_enhancement", _m0013_cloud_audit_enhancement),
    (14, "command_center_tables", _m0014_command_center_tables),
    (15, "multi_seed_orchestration", _m0015_multi_seed_orchestration),
    (16, "cloud_validation_results", _m0016_cloud_validation_results),
    (17, "cloud_provider_enum_expansion", _m0017_cloud_provider_enum_expansion),
    (18, "engagement_metadata", _m0018_engagement_metadata),
    (19, "cloud_provider_identifier", _m0019_cloud_provider_identifier),
    (20, "validation_claims", _m0020_validation_claims),
]

TARGET_VERSION: int = max(v for v, _, _ in _MIGRATIONS)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def run_migrations(conn: sqlite3.Connection) -> None:
    """
    Apply all pending migrations to *conn* in version order.

    Called by :func:`forge.db.session.get_engagement_db` immediately after
    the schema version table is read. Safe to call repeatedly.

    :param conn: Open, writeable engagement DB connection (WAL mode assumed).
    """
    conn.execute("""
        CREATE TABLE IF NOT EXISTS _schema_version (
            version    INTEGER NOT NULL,
            applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()

    row = conn.execute("SELECT MAX(version) FROM _schema_version").fetchone()
    current_version: int = row[0] if row[0] is not None else 0

    if current_version == TARGET_VERSION:
        return  # Already up to date.

    pending = [(v, name, fn) for v, name, fn in _MIGRATIONS if v > current_version]

    for version, name, fn in pending:
        _LOG.info("Applying migration %04d (%s)...", version, name)
        try:
            fn(conn)
            conn.execute("INSERT INTO _schema_version (version) VALUES (?)", (version,))
            conn.commit()
            _LOG.info("Migration %04d applied.", version)
        except Exception as exc:
            conn.rollback()
            _LOG.error("Migration %04d (%s) failed: %s", version, name, exc)
            raise

    _LOG.info("DB schema up to date (v%d → v%d).", current_version, TARGET_VERSION)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _safe_alter(conn: sqlite3.Connection, sql: str) -> None:
    """
    Execute an ALTER TABLE statement, silently ignoring 'duplicate column'
    errors. SQLite does not support IF NOT EXISTS on ALTER TABLE.
    """
    try:
        conn.execute(sql)
    except sqlite3.OperationalError as exc:
        if "duplicate column" in str(exc).lower():
            return
        raise


def _table_sql_contains(conn: sqlite3.Connection, table_name: str, fragment: str) -> bool:
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    sql = str(row[0] or "") if row else ""
    return fragment.lower() in sql.lower()


def _quoted_identifier(name: str) -> str:
    return '"' + str(name).replace('"', '""') + '"'


def _rebuild_table(
    conn: sqlite3.Connection,
    table_name: str,
    create_table_sql: str,
    post_sql: list[str] | None = None,
) -> None:
    columns = [
        str(row[1])
        for row in conn.execute(f"PRAGMA table_info({_quoted_identifier(table_name)})").fetchall()
    ]
    if not columns:
        return

    temp_table = f"{table_name}__m0017_old"
    conn.execute(
        f"ALTER TABLE {_quoted_identifier(table_name)} RENAME TO {_quoted_identifier(temp_table)}"
    )
    conn.execute(create_table_sql)

    new_columns = [
        str(row[1])
        for row in conn.execute(f"PRAGMA table_info({_quoted_identifier(table_name)})").fetchall()
    ]
    copy_columns = [column for column in columns if column in new_columns]
    if copy_columns:
        quoted_columns = ", ".join(_quoted_identifier(column) for column in copy_columns)
        conn.execute(
            f"""
            INSERT INTO {_quoted_identifier(table_name)} ({quoted_columns})
            SELECT {quoted_columns}
            FROM {_quoted_identifier(temp_table)}
            """
        )

    conn.execute(f"DROP TABLE {_quoted_identifier(temp_table)}")
    for sql in post_sql or []:
        conn.execute(sql)
