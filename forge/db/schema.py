"""
forge/db/schema.py — Engagement state store DDL.

All CREATE TABLE and FTS5 virtual table statements for the FORGE engagement
database. Tables are created idempotently (IF NOT EXISTS); ordering matters
due to REFERENCES constraints.

Schema version: 7 (v7.2)
Authoritative source: PRD v7.2 §4.1–§4.5

Design notes:
  - WAL mode is enabled by session.py at connection time; not here.
  - FTS5 content tables shadow their base tables for zero-copy search.
  - All plaintext passwords are stored age-encrypted in *_enc columns.
  - Boolean fields use INTEGER 0/1 (SQLite has no native BOOLEAN).
  - REFERENCES constraints are declared but FK enforcement requires
    `PRAGMA foreign_keys = ON`, set by session.py.
"""

from __future__ import annotations

import sqlite3

# ---------------------------------------------------------------------------
# Ordered DDL — DO NOT reorder without updating migrations.py
# ---------------------------------------------------------------------------

_SCHEMA_STATEMENTS: tuple[str, ...] = (
    # ------------------------------------------------------------------
    # Core engagement record
    # ------------------------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS engagements (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        name         TEXT    NOT NULL UNIQUE,
        scope_json   TEXT    NOT NULL DEFAULT '[]',
        status       TEXT    NOT NULL DEFAULT 'PREP'
                             CHECK (status IN ('PREP','ACTIVE','COMPLETE','ARCHIVED')),
        operator     TEXT    NOT NULL,
        metadata_json TEXT   NOT NULL DEFAULT '{}',
        created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    # ------------------------------------------------------------------
    # First-class engagement seeds / orchestration state
    # ------------------------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS engagement_seeds (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id INTEGER NOT NULL REFERENCES engagements(id),
        seed_value    TEXT    NOT NULL,
        seed_type     TEXT    NOT NULL
                      CHECK (seed_type IN (
                          'domain','email','phone','username','ipv4','ipv6',
                          'name','company','url','apk_url','subdomain','other'
                      )),
        source        TEXT    NOT NULL DEFAULT 'operator'
                      CHECK (source IN ('operator','scope','discovered','artifact','cross_reference')),
        status        TEXT    NOT NULL DEFAULT 'pending'
                      CHECK (status IN ('pending','running','completed','failed','ignored')),
        depth         INTEGER NOT NULL DEFAULT 0,
        confidence    REAL    NOT NULL DEFAULT 1.0,
        parent_seed_id INTEGER REFERENCES engagement_seeds(id),
        metadata_json TEXT    NOT NULL DEFAULT '{}',
        discovered_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (engagement_id, seed_type, seed_value)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_engagement_seeds_engagement
        ON engagement_seeds (engagement_id, status, depth)
    """,
    """
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
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_seed_runs_engagement
        ON seed_runs (engagement_id, status, started_at)
    """,
    """
    CREATE TABLE IF NOT EXISTS engagement_runs (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id    INTEGER NOT NULL REFERENCES engagements(id),
        run_kind         TEXT    NOT NULL DEFAULT 'kill_chain'
                         CHECK (run_kind IN ('kill_chain','reporting','dashboard','other')),
        status           TEXT    NOT NULL DEFAULT 'running'
                         CHECK (status IN ('running','completed','failed','cancelled')),
        seed_value       TEXT,
        seed_type        TEXT,
        seed_count       INTEGER NOT NULL DEFAULT 0,
        max_iterations   INTEGER NOT NULL DEFAULT 0,
        current_iteration INTEGER NOT NULL DEFAULT 0,
        resume_enabled   INTEGER NOT NULL DEFAULT 0,
        dry_run          INTEGER NOT NULL DEFAULT 0,
        attack_mode      INTEGER NOT NULL DEFAULT 0,
        error            TEXT,
        metadata_json    TEXT    NOT NULL DEFAULT '{}',
        started_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        completed_at     TIMESTAMP,
        updated_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_engagement_runs_engagement
        ON engagement_runs (engagement_id, status, started_at DESC)
    """,
    """
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
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_seed_relations_engagement
        ON seed_relations (engagement_id, relation_type, confidence DESC)
    """,
    """
    CREATE TABLE IF NOT EXISTS artifact_queue (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id  INTEGER NOT NULL REFERENCES engagements(id),
        source_url     TEXT    NOT NULL,
        local_path     TEXT,
        artifact_type  TEXT    NOT NULL
                       CHECK (artifact_type IN ('apk','ipa','document','archive','config','binary','other')),
        discovered_from TEXT,
        status         TEXT    NOT NULL DEFAULT 'queued'
                       CHECK (status IN ('queued','downloaded','parsed','failed','skipped')),
        sha256         TEXT,
        notes          TEXT,
        metadata_json  TEXT    NOT NULL DEFAULT '{}',
        queued_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (engagement_id, source_url)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_artifact_queue_engagement
        ON artifact_queue (engagement_id, status, artifact_type)
    """,
    # ------------------------------------------------------------------
    # Discovered hosts
    # ------------------------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS hosts (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id INTEGER NOT NULL REFERENCES engagements(id),
        ip            TEXT    NOT NULL,
        hostname      TEXT,
        os_family     TEXT    CHECK (os_family IN ('windows','linux','macos','unknown')),
        host_context  TEXT    DEFAULT '{}',   -- JSON blob; populated by Phase 1 enrichment
        in_scope      INTEGER NOT NULL DEFAULT 1,
        discovered_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (engagement_id, ip)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_hosts_engagement
        ON hosts (engagement_id, in_scope)
    """,
    # ------------------------------------------------------------------
    # Services on discovered hosts
    # ------------------------------------------------------------------
    """
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
    )
    """,
    # ------------------------------------------------------------------
    # Credentials (extended — PRD §4.1)
    # ------------------------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS credentials (
        id                     INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id          INTEGER NOT NULL REFERENCES engagements(id),
        email                  TEXT    NOT NULL,
        password_hash          TEXT,
        password_plaintext_enc TEXT,            -- age-encrypted; NEVER plaintext at rest
        hash_type              TEXT,            -- 'ntlm' | 'bcrypt' | 'sha1' | ...
        hash_plaintext         TEXT,            -- in-memory only; NULL in DB
        hash_crack_source      TEXT,            -- 'hashcat_offline' | 'hashbuster_online'
        breach_name            TEXT,
        breach_date            TIMESTAMP,
        source                 TEXT,
        confidence             TEXT    CHECK (confidence IN ('confirmed','likely','possible')),
        discovered_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        validated              INTEGER NOT NULL DEFAULT 0,
        validated_service      TEXT,
        validated_host         TEXT,
        validated_at           TIMESTAMP,
        validation_error       TEXT,
        enrichment_data        TEXT DEFAULT '{}'  -- JSON; additional intel from DeHashed etc.
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_creds_engagement ON credentials (engagement_id)
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_creds_validated  ON credentials (validated)
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_creds_email      ON credentials (email)
    """,
    # ------------------------------------------------------------------
    # Breach query audit log (Modules 2-A, 2-C, 2-D)
    # Physical table name is query_audit.
    # ------------------------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS query_audit (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id INTEGER NOT NULL REFERENCES engagements(id),
        source        TEXT    NOT NULL,
        email_queried TEXT    NOT NULL,
        queried_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        matched       INTEGER NOT NULL DEFAULT 0,
        records_found INTEGER NOT NULL DEFAULT 0,
        operator      TEXT    NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_query_audit_engagement
        ON query_audit (engagement_id)
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_query_audit_email
        ON query_audit (email_queried)
    """,
    # ------------------------------------------------------------------
    # Audit log (all phases)
    # ------------------------------------------------------------------
    """
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
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_audit_engagement
        ON audit_log (engagement_id, phase)
    """,
    # ------------------------------------------------------------------
    # Task progress (resume semantics — PRD §1.4)
    # ------------------------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS task_progress (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id INTEGER NOT NULL REFERENCES engagements(id),
        task_key      TEXT    NOT NULL,    -- e.g. 'subdomain_enum:example.com'
        status        TEXT    NOT NULL DEFAULT 'pending'
                              CHECK (status IN ('pending','running','complete','failed')),
        checkpoint    TEXT,               -- JSON last-good state for resume
        started_at    TIMESTAMP,
        completed_at  TIMESTAMP,
        UNIQUE (engagement_id, task_key)
    )
    """,
    # ------------------------------------------------------------------
    # Payloads (Modules 5-F + 5-G)
    # ------------------------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS payloads (
        id                     INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id          INTEGER NOT NULL REFERENCES engagements(id),
        payload_type           TEXT    NOT NULL,  -- 'reverse_shell' | 'c2_beacon' | ...
        target_os              TEXT    NOT NULL
                               CHECK (target_os IN ('windows','linux','macos')),
        technique              TEXT,
        obfuscation_chain      TEXT,              -- JSON array of applied transforms
        delivery_url           TEXT,              -- LOTS / shortener URL
        content_hash           TEXT,              -- SHA256 of raw payload (pre-obfuscation)
        generated_at           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        lots_host              TEXT,
        metadata_stripped      INTEGER NOT NULL DEFAULT 1
    )
    """,
    # ------------------------------------------------------------------
    # C2 Agents (Module 5-G) — stored in obfuscated 'sessions' concept
    # ------------------------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS agents (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id  INTEGER NOT NULL REFERENCES engagements(id),
        host_id        INTEGER REFERENCES hosts(id),
        beacon_interval INTEGER NOT NULL DEFAULT 30,
        jitter_pct     INTEGER NOT NULL DEFAULT 15,
        c2_urls        TEXT    NOT NULL DEFAULT '[]',  -- JSON array; age-encrypted at write
        channel        TEXT    NOT NULL DEFAULT 'http'
                               CHECK (channel IN ('http','dns','smb','icmp')),
        sleep_mask     INTEGER NOT NULL DEFAULT 1,
        checkin_at     TIMESTAMP,
        created_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    # ------------------------------------------------------------------
    # Exfiltrated data manifest (Module 5-H)
    # ------------------------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS exfiltrated_data (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id     INTEGER NOT NULL REFERENCES engagements(id),
        host_id           INTEGER REFERENCES hosts(id),
        source_path       TEXT    NOT NULL,
        staging_path      TEXT,                  -- obfuscated local staging path
        file_hash         TEXT,
        bytes_transferred INTEGER,
        chunks_total      INTEGER,
        chunks_sent       INTEGER NOT NULL DEFAULT 0,
        exfil_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        artifact_family   TEXT,
        artifact_subtype  TEXT,
        source_platform   TEXT,
        collection_method TEXT,
        confidence        REAL,
        report_safe_summary TEXT
    )
    """,
    # ------------------------------------------------------------------
    # Persistence (Module 5-I)
    # ------------------------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS persistence (
        id                   INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id        INTEGER NOT NULL REFERENCES engagements(id),
        host_id              INTEGER REFERENCES hosts(id),
        technique            TEXT    NOT NULL,
        target_os            TEXT    NOT NULL
                             CHECK (target_os IN ('windows','linux','macos')),
        install_cmd          TEXT    NOT NULL,
        cleanup_cmd          TEXT,
        lolbins_used         TEXT,               -- JSON array of LOLBin names
        obfuscation_applied  INTEGER NOT NULL DEFAULT 0,
        installed            INTEGER NOT NULL DEFAULT 0,
        verified             INTEGER NOT NULL DEFAULT 0,
        created_at           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    # ------------------------------------------------------------------
    # Lateral movement (Module 5-J)
    # ------------------------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS lateral_movement (
        id                  INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id       INTEGER NOT NULL REFERENCES engagements(id),
        source_host_id      INTEGER REFERENCES hosts(id),
        target_host_id      INTEGER NOT NULL REFERENCES hosts(id),
        technique           TEXT    NOT NULL,
        credential_id       INTEGER REFERENCES credentials(id),
        command             TEXT    NOT NULL,
        success             INTEGER,             -- NULL = not yet executed
        output              TEXT,                -- truncated to 64 KB per §16 anti-pattern
        scope_verified      INTEGER NOT NULL DEFAULT 0,
        operator_confirmed  INTEGER NOT NULL DEFAULT 0,
        executed_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    # ------------------------------------------------------------------
    # LLM feedback (Phase 6)
    # ------------------------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS llm_feedback (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id INTEGER REFERENCES engagements(id),
        model         TEXT    NOT NULL DEFAULT 'qwen2.5-1.5b',
        prompt_hash   TEXT,
        response_hash TEXT,
        quality_score REAL,
        validator_ok  INTEGER NOT NULL DEFAULT 0,
        generated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    # ------------------------------------------------------------------
    # v7.2 schemas — Module 2-J (Key Scanner)
    # Schema aligned with secret_finder.py DDL and forge_spec.md §E.
    # validation_state uses REVOKED/UNCONFIRMED (not INVALID/UNVALIDATED).
    # UNIQUE constraint is on (engagement_id, source_url, pattern_name).
    # ------------------------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS key_scanner_findings (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id    INTEGER NOT NULL REFERENCES engagements(id),
        domain           TEXT    NOT NULL,
        service          TEXT    NOT NULL,
        pattern_name     TEXT    NOT NULL,
        source_backend   TEXT    NOT NULL DEFAULT 'github',
        source_url       TEXT    NOT NULL,
        repo_name        TEXT,
        key_redacted     TEXT    NOT NULL,        -- first4...last4 display value
        key_enc          TEXT,                    -- age-encrypted full key value
        validation_state TEXT    NOT NULL DEFAULT 'UNCONFIRMED'
                         CHECK (validation_state IN ('ACTIVE','REVOKED','UNCONFIRMED','ERROR')),
        validation_detail TEXT,
        found_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        validated_at     TIMESTAMP,
        UNIQUE (engagement_id, source_url, pattern_name)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_key_findings_engagement
        ON key_scanner_findings (engagement_id, validation_state)
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_key_findings_service
        ON key_scanner_findings (service, validation_state)
    """,
    # ------------------------------------------------------------------
    # Phase 2 support tables — emails, email_intelligence,
    # dehashed_sync_state, scavenger_findings
    # ------------------------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS emails (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id INTEGER NOT NULL REFERENCES engagements(id),
        email         TEXT    NOT NULL,
        domain        TEXT,
        source        TEXT,
        first_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (engagement_id, email)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_emails_engagement
        ON emails (engagement_id, domain)
    """,
    """
    CREATE TABLE IF NOT EXISTS email_intelligence (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id   INTEGER NOT NULL REFERENCES engagements(id),
        email           TEXT    NOT NULL,
        source          TEXT    NOT NULL,    -- 'xposedornot' | 'hibp' | 'dehashed'
        breach_count    INTEGER NOT NULL DEFAULT 0,
        breach_names    TEXT    DEFAULT '[]',
        paste_count     INTEGER NOT NULL DEFAULT 0,
        enrichment_data TEXT    DEFAULT '{}',
        last_synced     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (engagement_id, email, source)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS dehashed_sync_state (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id INTEGER NOT NULL REFERENCES engagements(id),
        query_type    TEXT    NOT NULL,
        query_value   TEXT    NOT NULL,
        last_synced   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        total_count   INTEGER,
        UNIQUE (engagement_id, query_type, query_value)
    )
    """,
    """
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
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_scavenger_engagement
        ON scavenger_findings (engagement_id)
    """,
    # ------------------------------------------------------------------
    # v7.2 schemas — Modules 4-D, 4-E, 4-G (Vulnerability Findings)
    # ------------------------------------------------------------------
    """
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
        evidence        TEXT,                    -- response snippet ≤ 512 chars
        cvss_score      REAL,
        found_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (engagement_id, vuln_type, target_url, parameter)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_vuln_findings_engagement
        ON vulnerability_findings (engagement_id, severity, vuln_type)
    """,
    # ------------------------------------------------------------------
    # v7.2 schemas — Modules 4-E, 4-F, 4-G (Cloud Assets)
    # ------------------------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS cloud_assets (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id   INTEGER NOT NULL REFERENCES engagements(id),
        asset_type      TEXT    NOT NULL,        -- 'firebase' | 'supabase' | 'aws_s3'
        identifier      TEXT    NOT NULL,        -- project ID, bucket name, etc.
        provider_identifier TEXT,                -- first-seen exact provider identifier
        source          TEXT    NOT NULL,        -- 'manual' | 'firebase_extract' | 'recon'
        discovered_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (engagement_id, asset_type, identifier)
    )
    """,
    """
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
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_cloud_validation_engagement
        ON cloud_validation_results (engagement_id, validation_status, checked_at DESC)
    """,
    # ------------------------------------------------------------------
    # v7.2 schemas — Module 4-H (Attack Path Visualizer)
    # graph_json stores AttackGraph.model_dump_json() — no credential material.
    # Sensitive-data guard: _assert_no_sensitive_data() checked before every write.
    # ------------------------------------------------------------------
    """
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
        graph_json           TEXT    NOT NULL,   -- no credential material; guard-checked
        mermaid_output       TEXT,               -- rendered Mermaid string (≤ 4000 chars)
        dot_output           TEXT,               -- rendered DOT string
        UNIQUE (engagement_id, snapshot_at)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_attack_graph_engagement
        ON attack_graph_snapshots (engagement_id, snapshot_at DESC)
    """,
    """
    CREATE TABLE IF NOT EXISTS crawl_results (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id   INTEGER NOT NULL REFERENCES engagements(id),
        url             TEXT    NOT NULL,
        final_url       TEXT,
        title           TEXT,
        screenshot_path TEXT,
        tech_stack_json TEXT,
        discovered_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
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
    )
    """,
    """
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
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS auth_test_results (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id INTEGER NOT NULL REFERENCES engagements(id),
        target_url    TEXT    NOT NULL,
        form_data     TEXT,
        attack_type   TEXT,
        success       INTEGER NOT NULL DEFAULT 0,
        response_data TEXT,
        tested_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
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
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_distributed_tasks_status
        ON distributed_tasks (engagement_id, status, priority)
    """,
    """
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
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_worker_heartbeats_engagement
        ON worker_heartbeats (engagement_id, heartbeat_at DESC)
    """,
    """
    CREATE TABLE IF NOT EXISTS queue_metrics (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id INTEGER NOT NULL REFERENCES engagements(id),
        queued_count  INTEGER NOT NULL DEFAULT 0,
        running_count INTEGER NOT NULL DEFAULT 0,
        done_count    INTEGER NOT NULL DEFAULT 0,
        failed_count  INTEGER NOT NULL DEFAULT 0,
        sampled_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_queue_metrics_engagement
        ON queue_metrics (engagement_id, sampled_at DESC)
    """,
    """
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
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_command_center_actions_target
        ON command_center_actions (engagement_id, target_ref, status, confidence_score DESC)
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_command_center_actions_status
        ON command_center_actions (engagement_id, status, execution_mode)
    """,
    """
    CREATE TABLE IF NOT EXISTS command_center_timeline (
        event_id      TEXT PRIMARY KEY,
        engagement_id INTEGER NOT NULL REFERENCES engagements(id),
        event_type    TEXT    NOT NULL,
        severity      TEXT    NOT NULL DEFAULT 'info' CHECK (severity IN ('info','warning','critical')),
        acknowledged  INTEGER NOT NULL DEFAULT 0,
        timestamp     TEXT    NOT NULL,
        expires_at    TEXT,
        payload_json  TEXT    NOT NULL DEFAULT '{}'
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_command_center_timeline
        ON command_center_timeline (engagement_id, timestamp DESC, severity)
    """,
    """
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
    )
    """,
    # ------------------------------------------------------------------
    # Phase 5 operator approval queue (RULE 8)
    # All destructive Phase 5 actions require operator approval.
    # ------------------------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS approval_queue (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id INTEGER NOT NULL REFERENCES engagements(id),
        action_name   TEXT    NOT NULL,
        description   TEXT,
        status        TEXT    NOT NULL DEFAULT 'pending'
                              CHECK (status IN ('pending','approved','rejected')),
        created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        decided_at    TIMESTAMP
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_approval_queue_engagement
        ON approval_queue(engagement_id, status)
    """,
)

# ---------------------------------------------------------------------------
# Schema version
# ---------------------------------------------------------------------------

SCHEMA_VERSION: int = 19

_VERSION_TABLE: str = """
    CREATE TABLE IF NOT EXISTS _schema_version (
        version   INTEGER NOT NULL,
        applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def apply_schema(conn: sqlite3.Connection) -> None:
    """
    Idempotently apply the full engagement schema to *conn*.

    This is called by :func:`forge.db.session.get_engagement_db` on first
    open and by migrations.py after each migration step.

    :param conn: An open, writeable SQLite connection.
    """
    conn.execute(_VERSION_TABLE)
    for stmt in _SCHEMA_STATEMENTS:
        conn.execute(stmt)
    conn.commit()
