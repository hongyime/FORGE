"""
forge/db/schema.py — Engagement state store DDL.

All CREATE TABLE and FTS5 virtual table statements for the FORGE engagement
database. Tables are created idempotently (IF NOT EXISTS); ordering matters
due to REFERENCES constraints.

Schema version: 48
Authoritative source: PRD v7.2 §4.1–§4.5

Design notes:
  - WAL mode is enabled by session.py at connection time; not here.
  - FTS5 content tables shadow their base tables for zero-copy search.
  - Plaintext passwords and connector secrets are stored encrypted in *_enc columns.
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
        workspace_id TEXT    NOT NULL DEFAULT 'default',
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
    # Workspace / RBAC foundation
    # ------------------------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS workspaces (
        workspace_id TEXT PRIMARY KEY,
        name         TEXT    NOT NULL,
        metadata_json TEXT   NOT NULL DEFAULT '{}',
        created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS workspace_memberships (
        workspace_id     TEXT    NOT NULL,
        subject          TEXT    NOT NULL,
        role             TEXT    NOT NULL DEFAULT 'operator',
        permissions_json TEXT    NOT NULL DEFAULT '[]',
        created_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (workspace_id, subject)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_workspace_memberships_subject
        ON workspace_memberships (subject, workspace_id)
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_engagements_workspace
        ON engagements (workspace_id, id)
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
                          'name','company','url','apk_url','subdomain',
                          'cloud_ref','other'
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
    CREATE TABLE IF NOT EXISTS run_audit_manifests (
        id                     INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id          INTEGER NOT NULL REFERENCES engagements(id),
        run_id                 INTEGER NOT NULL REFERENCES engagement_runs(id),
        manifest_hash          TEXT    NOT NULL UNIQUE,
        previous_manifest_hash TEXT,
        manifest_json          TEXT    NOT NULL,
        generated_at           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (engagement_id, run_id)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_run_audit_manifests_engagement
        ON run_audit_manifests (engagement_id, id DESC)
    """,
    """
    CREATE TABLE IF NOT EXISTS audit_reviews (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id    INTEGER NOT NULL REFERENCES engagements(id),
        run_id           INTEGER REFERENCES engagement_runs(id),
        manifest_hash    TEXT    NOT NULL DEFAULT '',
        review_status    TEXT    NOT NULL
                         CHECK (review_status IN (
                             'pending',
                             'approved',
                             'needs_changes',
                             'rejected',
                             'attested'
                         )),
        reviewer         TEXT    NOT NULL,
        comment          TEXT    NOT NULL DEFAULT '',
        attestation_json TEXT    NOT NULL DEFAULT '{}',
        legal_hold       INTEGER NOT NULL DEFAULT 0 CHECK (legal_hold IN (0, 1)),
        created_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_audit_reviews_engagement
        ON audit_reviews (engagement_id, created_at DESC, id DESC)
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_audit_reviews_run
        ON audit_reviews (engagement_id, run_id, id DESC)
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_audit_reviews_manifest
        ON audit_reviews (manifest_hash, id DESC)
    """,
    """
    CREATE TABLE IF NOT EXISTS retention_policies (
        id                       INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id            INTEGER NOT NULL REFERENCES engagements(id),
        name                     TEXT    NOT NULL DEFAULT 'default',
        enabled                  INTEGER NOT NULL DEFAULT 1
                                 CHECK (enabled IN (0, 1)),
        audit_review_days        INTEGER CHECK (audit_review_days IS NULL OR audit_review_days >= 1),
        monitoring_days          INTEGER CHECK (monitoring_days IS NULL OR monitoring_days >= 1),
        remediation_event_days   INTEGER CHECK (remediation_event_days IS NULL OR remediation_event_days >= 1),
        retention_run_days       INTEGER CHECK (retention_run_days IS NULL OR retention_run_days >= 1),
        legal_hold_override      INTEGER NOT NULL DEFAULT 0
                                 CHECK (legal_hold_override IN (0, 1)),
        metadata_json            TEXT    NOT NULL DEFAULT '{}',
        created_at               TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at               TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (engagement_id, name)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_retention_policies_engagement
        ON retention_policies (engagement_id, enabled, name)
    """,
    """
    CREATE TABLE IF NOT EXISTS retention_runs (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id  INTEGER NOT NULL REFERENCES engagements(id),
        policy_id      INTEGER REFERENCES retention_policies(id),
        policy_name    TEXT    NOT NULL DEFAULT 'default',
        mode           TEXT    NOT NULL CHECK (mode IN ('preview','apply')),
        status         TEXT    NOT NULL CHECK (status IN ('completed','blocked','skipped','failed')),
        operator       TEXT    NOT NULL DEFAULT '',
        summary_json   TEXT    NOT NULL DEFAULT '{}',
        created_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_retention_runs_engagement
        ON retention_runs (engagement_id, created_at DESC, id DESC)
    """,
    """
    CREATE TABLE IF NOT EXISTS retention_run_items (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        retention_run_id INTEGER NOT NULL REFERENCES retention_runs(id),
        engagement_id    INTEGER NOT NULL REFERENCES engagements(id),
        category         TEXT    NOT NULL,
        table_name       TEXT    NOT NULL DEFAULT '',
        retention_days   INTEGER,
        cutoff_at        TEXT    NOT NULL DEFAULT '',
        eligible_count   INTEGER NOT NULL DEFAULT 0,
        deleted_count    INTEGER NOT NULL DEFAULT 0,
        skipped_count    INTEGER NOT NULL DEFAULT 0,
        reason           TEXT    NOT NULL DEFAULT '',
        created_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_retention_run_items_run
        ON retention_run_items (retention_run_id, category)
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
    # ------------------------------------------------------------------
    # First-class Forge graph primitive / asset attribution
    # ------------------------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS asset_entities (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id  INTEGER NOT NULL REFERENCES engagements(id),
        entity_key     TEXT    NOT NULL,
        entity_type    TEXT    NOT NULL
                       CHECK (entity_type IN (
                           'asset',
                           'seed',
                           'host',
                           'service',
                           'identity',
                           'cloud',
                           'evidence',
                           'secret',
                           'finding',
                           'validation',
                           'remediation',
                           'ticket',
                           'owner',
                           'organization',
                           'other'
                       )),
        label          TEXT    NOT NULL,
        source_table   TEXT,
        source_id      INTEGER,
        confidence     REAL    NOT NULL DEFAULT 0.5
                       CHECK (confidence >= 0.0 AND confidence <= 1.0),
        metadata_json  TEXT    NOT NULL DEFAULT '{}',
        first_seen_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        last_seen_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        created_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (engagement_id, entity_key)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_asset_entities_engagement
        ON asset_entities (engagement_id, entity_type, updated_at DESC)
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_asset_entities_source
        ON asset_entities (engagement_id, source_table, source_id)
    """,
    """
    CREATE TABLE IF NOT EXISTS asset_relationships (
        id                  INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id       INTEGER NOT NULL REFERENCES engagements(id),
        source_entity_id    INTEGER NOT NULL REFERENCES asset_entities(id),
        target_entity_id    INTEGER NOT NULL REFERENCES asset_entities(id),
        relationship_type   TEXT    NOT NULL
                            CHECK (relationship_type IN (
                                'derived_from',
                                'corroborates',
                                'conflicts_with',
                                'same_entity',
                                'related_asset',
                                'runs_service',
                                'has_identity',
                                'references_cloud',
                                'supported_by',
                                'validated_by',
                                'has_finding',
                                'remediates',
                                'tracked_by',
                                'owned_by',
                                'routed_to',
                                'observed_in',
                                'other'
                            )),
        confidence          REAL    NOT NULL DEFAULT 0.5
                            CHECK (confidence >= 0.0 AND confidence <= 1.0),
        source_table        TEXT    NOT NULL DEFAULT 'system',
        source_id           INTEGER NOT NULL DEFAULT 0,
        evidence_json       TEXT    NOT NULL DEFAULT '{}',
        created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (
            engagement_id,
            source_entity_id,
            target_entity_id,
            relationship_type,
            source_table,
            source_id
        )
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_asset_relationships_engagement
        ON asset_relationships (engagement_id, relationship_type, updated_at DESC)
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_asset_relationships_source
        ON asset_relationships (engagement_id, source_entity_id, relationship_type)
    """,
    """
    CREATE TABLE IF NOT EXISTS asset_ownership_claims (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id  INTEGER NOT NULL REFERENCES engagements(id),
        entity_id      INTEGER NOT NULL REFERENCES asset_entities(id),
        owner_kind     TEXT    NOT NULL DEFAULT 'team'
                       CHECK (owner_kind IN (
                           'team',
                           'person',
                           'email',
                           'workspace',
                           'organization',
                           'third_party',
                           'cloud_account',
                           'service',
                           'unknown'
                       )),
        owner_ref      TEXT    NOT NULL,
        owner_display  TEXT    NOT NULL DEFAULT '',
        claim_type     TEXT    NOT NULL DEFAULT 'inferred'
                       CHECK (claim_type IN (
                           'explicit',
                           'inferred',
                           'route',
                           'scope',
                           'cloud_account',
                           'manual'
                       )),
        confidence     REAL    NOT NULL DEFAULT 0.5
                       CHECK (confidence >= 0.0 AND confidence <= 1.0),
        source         TEXT    NOT NULL DEFAULT 'system',
        status         TEXT    NOT NULL DEFAULT 'active'
                       CHECK (status IN ('active','needs_review','rejected','superseded')),
        evidence_json  TEXT    NOT NULL DEFAULT '{}',
        created_by     TEXT    NOT NULL DEFAULT '',
        created_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (engagement_id, entity_id, owner_kind, owner_ref, claim_type, source)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_asset_ownership_claims_entity
        ON asset_ownership_claims (engagement_id, entity_id, status, confidence DESC)
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_asset_ownership_claims_owner
        ON asset_ownership_claims (engagement_id, owner_kind, owner_ref, status)
    """,
    # ------------------------------------------------------------------
    # Separately gated active-validation lane
    # ------------------------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS active_validation_jobs (
        id                 INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id      INTEGER NOT NULL REFERENCES engagements(id),
        target_ref         TEXT    NOT NULL,
        target_kind        TEXT    NOT NULL DEFAULT 'asset'
                           CHECK (target_kind IN (
                               'asset',
                               'host',
                               'service',
                               'cloud',
                               'identity',
                               'finding',
                               'fixture',
                               'other'
                           )),
        method             TEXT    NOT NULL
                           CHECK (method IN (
                               'fixture_replay',
                               'control_simulation',
                               'http_reachability',
                               'http_security_headers',
                               'fix_verification'
                           )),
        mode               TEXT    NOT NULL DEFAULT 'dry_run'
                           CHECK (mode IN ('dry_run','lab','read_only_live')),
        status             TEXT    NOT NULL DEFAULT 'queued'
                           CHECK (status IN (
                               'queued',
                               'approved',
                               'running',
                               'completed',
                               'blocked',
                               'failed',
                               'cancelled'
                           )),
        approved           INTEGER NOT NULL DEFAULT 0 CHECK (approved IN (0,1)),
        roe_id             TEXT    NOT NULL DEFAULT '',
        scope_manifest_ref TEXT    NOT NULL DEFAULT '',
        scope_manifest_hash TEXT   NOT NULL DEFAULT '',
        safe_profile       TEXT    NOT NULL DEFAULT 'non_destructive',
        max_steps          INTEGER NOT NULL DEFAULT 1
                           CHECK (max_steps >= 1 AND max_steps <= 50),
        requested_by       TEXT    NOT NULL DEFAULT '',
        approved_by        TEXT    NOT NULL DEFAULT '',
        approval_note      TEXT    NOT NULL DEFAULT '',
        metadata_json      TEXT    NOT NULL DEFAULT '{}',
        created_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        approved_at        TIMESTAMP,
        updated_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_active_validation_jobs_engagement
        ON active_validation_jobs (engagement_id, status, mode, updated_at DESC)
    """,
    """
    CREATE TABLE IF NOT EXISTS active_validation_runs (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id INTEGER NOT NULL REFERENCES engagements(id),
        job_id        INTEGER NOT NULL REFERENCES active_validation_jobs(id),
        status        TEXT    NOT NULL
                      CHECK (status IN ('running','completed','blocked','failed')),
        result        TEXT    NOT NULL DEFAULT '',
        operator      TEXT    NOT NULL DEFAULT '',
        evidence_json TEXT    NOT NULL DEFAULT '{}',
        error         TEXT    NOT NULL DEFAULT '',
        started_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        completed_at  TIMESTAMP,
        created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_active_validation_runs_job
        ON active_validation_runs (engagement_id, job_id, created_at DESC)
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
        attempt_count  INTEGER NOT NULL DEFAULT 0,
        max_attempts   INTEGER NOT NULL DEFAULT 3,
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
    """
    CREATE TABLE IF NOT EXISTS secret_lifecycle_items (
        id                       INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id            INTEGER NOT NULL REFERENCES engagements(id),
        key_finding_id           INTEGER NOT NULL REFERENCES key_scanner_findings(id),
        lifecycle_status         TEXT    NOT NULL DEFAULT 'open'
                                 CHECK (lifecycle_status IN (
                                     'open',
                                     'owner_routed',
                                     'revocation_guided',
                                     'revoked',
                                     'suppressed',
                                     'risk_accepted'
                                 )),
        owner                    TEXT    NOT NULL DEFAULT '',
        owner_source             TEXT    NOT NULL DEFAULT '',
        revocation_guidance_json TEXT    NOT NULL DEFAULT '{}',
        prevention_guidance_json TEXT    NOT NULL DEFAULT '{}',
        suppression_id           INTEGER,
        suppressed               INTEGER NOT NULL DEFAULT 0 CHECK (suppressed IN (0, 1)),
        metadata_json            TEXT    NOT NULL DEFAULT '{}',
        created_at               TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at               TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (engagement_id, key_finding_id)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_secret_lifecycle_engagement
        ON secret_lifecycle_items (engagement_id, lifecycle_status, suppressed)
    """,
    """
    CREATE TABLE IF NOT EXISTS secret_suppressions (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id   INTEGER NOT NULL REFERENCES engagements(id),
        key_finding_id  INTEGER REFERENCES key_scanner_findings(id),
        service         TEXT    NOT NULL DEFAULT '',
        pattern_name    TEXT    NOT NULL DEFAULT '',
        source_url      TEXT    NOT NULL DEFAULT '',
        reason          TEXT    NOT NULL,
        status          TEXT    NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active','expired','revoked')),
        expires_at      TEXT,
        created_by      TEXT    NOT NULL DEFAULT '',
        evidence_json   TEXT    NOT NULL DEFAULT '{}',
        created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (engagement_id, key_finding_id, service, pattern_name, source_url, status)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_secret_suppressions_engagement
        ON secret_suppressions (engagement_id, status, expires_at)
    """,
    """
    CREATE TABLE IF NOT EXISTS connector_secrets (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id    INTEGER NOT NULL REFERENCES engagements(id),
        connector_id     TEXT    NOT NULL,
        secret_name      TEXT    NOT NULL,
        secret_value_enc TEXT    NOT NULL,
        secret_ref       TEXT    NOT NULL DEFAULT '',
        key_hint         TEXT    NOT NULL DEFAULT '',
        metadata_json    TEXT    NOT NULL DEFAULT '{}',
        created_by       TEXT    NOT NULL DEFAULT '',
        updated_by       TEXT    NOT NULL DEFAULT '',
        created_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (engagement_id, connector_id, secret_name)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_connector_secrets_engagement
        ON connector_secrets (engagement_id, connector_id, secret_name)
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
        cve_id          TEXT,
        cvss_score      REAL,
        cvss_version    TEXT    NOT NULL DEFAULT '',
        cvss_vector     TEXT    NOT NULL DEFAULT '',
        cwe_ids         TEXT    NOT NULL DEFAULT '[]',
        cpe_matches     TEXT    NOT NULL DEFAULT '[]',
        epss_score      REAL,
        epss_percentile REAL,
        cisa_kev        INTEGER NOT NULL DEFAULT 0 CHECK (cisa_kev IN (0, 1)),
        cisa_kev_due_date TEXT  NOT NULL DEFAULT '',
        attack_techniques TEXT  NOT NULL DEFAULT '[]',
        stix_external_refs_json TEXT NOT NULL DEFAULT '[]',
        standards_json  TEXT    NOT NULL DEFAULT '{}',
        found_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (engagement_id, vuln_type, target_url, parameter)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_vuln_findings_engagement
        ON vulnerability_findings (engagement_id, severity, vuln_type)
    """,
    """
    CREATE TABLE IF NOT EXISTS remediation_items (
        id                     INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id          INTEGER NOT NULL REFERENCES engagements(id),
        finding_table          TEXT    NOT NULL DEFAULT 'vulnerability_findings'
                                 CHECK (finding_table IN (
                                     'vulnerability_findings',
                                     'key_scanner_findings',
                                     'cloud_validation_results',
                                     'passive_vulns',
                                     'monitoring_alerts',
                                     'asset_graph',
                                     'manual'
                                 )),
        finding_id             INTEGER,
        finding_ref            TEXT    NOT NULL,
        title                  TEXT    NOT NULL,
        severity               TEXT    NOT NULL DEFAULT 'INFO'
                                 CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
        owner                  TEXT,
        sla_due_at             TEXT,
        status                 TEXT    NOT NULL DEFAULT 'open'
                                 CHECK (status IN (
                                     'open',
                                     'assigned',
                                     'in_progress',
                                     'risk_accepted',
                                     'retest_pending',
                                     'resolved',
                                     'false_positive'
                                 )),
        risk_acceptance_reason TEXT,
        risk_accepted_by       TEXT,
        risk_accepted_at       TIMESTAMP,
        risk_acceptance_expires_at TEXT,
        retest_status          TEXT    NOT NULL DEFAULT 'not_requested'
                                 CHECK (retest_status IN (
                                     'not_requested',
                                     'pending',
                                     'passed',
                                     'failed',
                                     'blocked'
                                 )),
        retest_requested_at    TIMESTAMP,
        retested_at            TIMESTAMP,
        ticket_system          TEXT,
        ticket_ref             TEXT,
        ticket_url             TEXT,
        metadata_json          TEXT    NOT NULL DEFAULT '{}',
        created_at             TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at             TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (engagement_id, finding_table, finding_ref)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_remediation_items_engagement
        ON remediation_items (engagement_id, status, severity)
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_remediation_items_owner
        ON remediation_items (engagement_id, owner, sla_due_at)
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_remediation_items_risk_expiry
        ON remediation_items (engagement_id, status, risk_acceptance_expires_at)
    """,
    """
    CREATE TABLE IF NOT EXISTS remediation_ticket_events (
        id                  INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id       INTEGER NOT NULL REFERENCES engagements(id),
        remediation_item_id INTEGER NOT NULL REFERENCES remediation_items(id),
        connector           TEXT    NOT NULL CHECK (connector IN ('jsonl','stdout','webhook','github_issues','jira','servicenow','tines','splunk_hec','torq')),
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
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_remediation_ticket_events_engagement
        ON remediation_ticket_events (engagement_id, status, connector, updated_at DESC)
    """,
    """
    CREATE TABLE IF NOT EXISTS monitoring_policies (
        id                         INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id              INTEGER NOT NULL REFERENCES engagements(id),
        name                       TEXT    NOT NULL,
        enabled                    INTEGER NOT NULL DEFAULT 1
                                   CHECK (enabled IN (0, 1)),
        schedule_interval_minutes  INTEGER NOT NULL DEFAULT 1440
                                   CHECK (schedule_interval_minutes >= 15),
        mode                       TEXT    NOT NULL DEFAULT 'passive'
                                   CHECK (mode IN ('passive','standard','active_validation')),
        last_snapshot_id           INTEGER REFERENCES monitoring_snapshots(id),
        last_run_at                TEXT,
        next_run_at                TEXT,
        metadata_json              TEXT    NOT NULL DEFAULT '{}',
        created_at                 TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at                 TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (engagement_id, name)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_monitoring_policies_engagement
        ON monitoring_policies (engagement_id, enabled, next_run_at)
    """,
    """
    CREATE TABLE IF NOT EXISTS monitoring_snapshots (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id   INTEGER NOT NULL REFERENCES engagements(id),
        policy_id       INTEGER REFERENCES monitoring_policies(id),
        snapshot_kind   TEXT    NOT NULL DEFAULT 'manual'
                        CHECK (snapshot_kind IN ('manual','scheduled','rerun')),
        state_hash      TEXT    NOT NULL,
        state_json      TEXT    NOT NULL,
        summary_json    TEXT    NOT NULL,
        created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_monitoring_snapshots_engagement
        ON monitoring_snapshots (engagement_id, created_at DESC, id DESC)
    """,
    """
    CREATE TABLE IF NOT EXISTS monitoring_changes (
        id                    INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id         INTEGER NOT NULL REFERENCES engagements(id),
        baseline_snapshot_id  INTEGER REFERENCES monitoring_snapshots(id),
        snapshot_id           INTEGER NOT NULL REFERENCES monitoring_snapshots(id),
        entity_type           TEXT    NOT NULL CHECK (entity_type IN ('asset','finding')),
        entity_key            TEXT    NOT NULL,
        change_type           TEXT    NOT NULL CHECK (change_type IN ('added','removed','changed')),
        severity              TEXT    NOT NULL DEFAULT 'INFO'
                              CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
        before_json           TEXT,
        after_json            TEXT,
        created_at            TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (snapshot_id, entity_type, entity_key, change_type)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_monitoring_changes_snapshot
        ON monitoring_changes (engagement_id, snapshot_id, change_type, severity)
    """,
    """
    CREATE TABLE IF NOT EXISTS monitoring_alerts (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id   INTEGER NOT NULL REFERENCES engagements(id),
        policy_id       INTEGER REFERENCES monitoring_policies(id),
        snapshot_id     INTEGER NOT NULL REFERENCES monitoring_snapshots(id),
        change_id       INTEGER REFERENCES monitoring_changes(id),
        alert_type      TEXT    NOT NULL,
        severity        TEXT    NOT NULL DEFAULT 'INFO'
                        CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
        title           TEXT    NOT NULL,
        status          TEXT    NOT NULL DEFAULT 'open'
                        CHECK (status IN ('open','acknowledged','resolved')),
        metadata_json   TEXT    NOT NULL DEFAULT '{}',
        created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_monitoring_alerts_engagement
        ON monitoring_alerts (engagement_id, status, severity, created_at DESC)
    """,
    """
    CREATE TABLE IF NOT EXISTS monitoring_trend_points (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id     INTEGER NOT NULL REFERENCES engagements(id),
        policy_id         INTEGER REFERENCES monitoring_policies(id),
        snapshot_id       INTEGER NOT NULL REFERENCES monitoring_snapshots(id),
        observed_at       TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
        asset_count       INTEGER NOT NULL DEFAULT 0,
        finding_count     INTEGER NOT NULL DEFAULT 0,
        critical_count    INTEGER NOT NULL DEFAULT 0,
        high_count        INTEGER NOT NULL DEFAULT 0,
        medium_count      INTEGER NOT NULL DEFAULT 0,
        low_count         INTEGER NOT NULL DEFAULT 0,
        info_count        INTEGER NOT NULL DEFAULT 0,
        added_count       INTEGER NOT NULL DEFAULT 0,
        removed_count     INTEGER NOT NULL DEFAULT 0,
        changed_count     INTEGER NOT NULL DEFAULT 0,
        alert_count       INTEGER NOT NULL DEFAULT 0,
        open_alert_count  INTEGER NOT NULL DEFAULT 0,
        summary_json      TEXT    NOT NULL DEFAULT '{}',
        created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (snapshot_id)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_monitoring_trend_points_engagement
        ON monitoring_trend_points (engagement_id, observed_at DESC, id DESC)
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_monitoring_trend_points_policy
        ON monitoring_trend_points (engagement_id, policy_id, observed_at DESC)
    """,
    """
    CREATE TABLE IF NOT EXISTS monitoring_alert_deliveries (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id  INTEGER NOT NULL REFERENCES engagements(id),
        alert_id       INTEGER NOT NULL REFERENCES monitoring_alerts(id),
        channel        TEXT    NOT NULL CHECK (channel IN ('jsonl','stdout','webhook')),
        destination    TEXT    NOT NULL DEFAULT '',
        status         TEXT    NOT NULL DEFAULT 'pending'
                       CHECK (status IN ('pending','delivered','failed','skipped')),
        attempt_count  INTEGER NOT NULL DEFAULT 0,
        last_error     TEXT,
        delivered_at   TEXT,
        metadata_json  TEXT    NOT NULL DEFAULT '{}',
        created_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (alert_id, channel, destination)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_monitoring_alert_deliveries_engagement
        ON monitoring_alert_deliveries (engagement_id, status, channel, updated_at DESC)
    """,
    """
    CREATE TABLE IF NOT EXISTS monitoring_alert_routes (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id  INTEGER NOT NULL REFERENCES engagements(id),
        name           TEXT    NOT NULL,
        enabled        INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
        min_severity   TEXT    NOT NULL DEFAULT 'INFO'
                       CHECK (min_severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
        alert_type     TEXT    NOT NULL DEFAULT '',
        entity_prefix  TEXT    NOT NULL DEFAULT '',
        channel        TEXT    NOT NULL CHECK (channel IN ('jsonl','stdout','webhook')),
        destination    TEXT    NOT NULL DEFAULT '',
        owner          TEXT    NOT NULL DEFAULT '',
        escalation     TEXT    NOT NULL DEFAULT '',
        metadata_json  TEXT    NOT NULL DEFAULT '{}',
        created_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (engagement_id, name)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_monitoring_alert_routes_engagement
        ON monitoring_alert_routes (engagement_id, enabled, min_severity, channel)
    """,
    """
    CREATE TABLE IF NOT EXISTS monitoring_alert_suppressions (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id  INTEGER NOT NULL REFERENCES engagements(id),
        alert_type     TEXT    NOT NULL DEFAULT '',
        entity_key     TEXT    NOT NULL DEFAULT '',
        entity_prefix  TEXT    NOT NULL DEFAULT '',
        severity       TEXT    NOT NULL DEFAULT ''
                       CHECK (severity IN ('','CRITICAL','HIGH','MEDIUM','LOW','INFO')),
        reason         TEXT    NOT NULL,
        created_by     TEXT    NOT NULL DEFAULT '',
        expires_at     TEXT,
        metadata_json  TEXT    NOT NULL DEFAULT '{}',
        created_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_monitoring_alert_suppressions_engagement
        ON monitoring_alert_suppressions (engagement_id, alert_type, severity, expires_at)
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
        metadata_json   TEXT    NOT NULL DEFAULT '{}',
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
    """
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
    )
    """,
    """
    CREATE UNIQUE INDEX IF NOT EXISTS idx_validation_claims_key
        ON validation_claims (engagement_id, claim_type, key_id)
        WHERE claim_type='key'
    """,
    """
    CREATE UNIQUE INDEX IF NOT EXISTS idx_validation_claims_asset
        ON validation_claims (engagement_id, claim_type, asset_type, identifier)
        WHERE claim_type='asset'
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_validation_claims_expiry
        ON validation_claims (claim_type, expires_at)
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
        attempt_count INTEGER NOT NULL DEFAULT 0,
        max_attempts  INTEGER NOT NULL DEFAULT 3,
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

SCHEMA_VERSION: int = 48

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
        try:
            conn.execute(stmt)
        except sqlite3.OperationalError as exc:
            if _defer_migration_owned_statement(stmt, exc):
                continue
            raise
    conn.commit()


def _defer_migration_owned_statement(stmt: str, exc: sqlite3.OperationalError) -> bool:
    """
    Let legacy DBs reach migrations when current-schema indexes reference
    columns added by a later ALTER TABLE migration.
    """
    if "no such column" not in str(exc).lower():
        return False
    normalized = " ".join(stmt.lower().split())
    migration_owned_indexes = (
        "idx_engagements_workspace",
        "idx_remediation_items_risk_expiry",
    )
    return any(
        normalized.startswith(f"create index if not exists {index_name} ")
        for index_name in migration_owned_indexes
    )
