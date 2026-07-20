"""
tests/phase6/test_report_synthesizer.py
Unit tests — Phase 6: forge/phase6/report_synthesizer.py + llm_validator.py

Coverage target: 100% (validator.py), 80% (report_synthesizer.py)

Test categories:
  1. Risk roll-up        — _derive_overall_risk() deterministic rule matrix
  2. ContextBuilder      — DB queries; no plaintext credentials loaded
  3. PromptAssembler     — credential leak guard; template fallback; overflow
  4. Validator V-01      — all mandatory sections present
  5. Validator V-02      — risk label in Executive Summary
  6. Validator V-03      — no unapproved RFC-1918 IPs
  7. Validator V-04      — no plaintext credential patterns
  8. Validator V-05      — minimum 50 words per mandatory section
  9. Validator V-06      — Executive Summary ≤ 500 words
 10. Validator V-07      — no paste URLs
 11. Validator V-08      — no shellcode / msfvenom patterns
 12. Validator V-09      — evidence strings ≤ 512 chars
 13. Validator V-10      — Exec Summary references monitoring when Section 8 present
 14. Strict mode         — WARNINGs promoted to ERRORs in --strict
 15. ValidationResult    — passed / summary() contract
 16. ReportSynthesizer   — dry_run skips LLM; ModelNotFoundError on missing GGUF
 17. ReportSynthesizer   — operator cancel raises RuntimeError; no file written
 18. ReportSynthesizer   — report file written; content includes mandatory sections
"""
from __future__ import annotations

import json
import re
import sqlite3
import textwrap
from pathlib import Path
from unittest import mock

import pytest

from forge.core.errors import ProviderUnavailableError
from forge.phase6.report_synthesizer import (
    ContextBuilder,
    ExploitContext,
    ModelNotFoundError,
    OngoingIntelligenceContext,
    PostExploitContext,
    PromptOverflowError,
    PromptAssembler,
    OsintContext,
    ReconContext,
    ReportContext,
    ReportSynthesizer,
    _derive_overall_risk,
    MANDATORY_SECTIONS,
    synthesise,
)
from forge.phase6.llm_validator import (
    ValidationResult,
    validate_report,
)


# ── Fixtures ───────────────────────────────────────────────────────────────────

ENGAGEMENT_ID = 1


@pytest.fixture()
def tmp_eng_db(tmp_path: Path) -> Path:
    """Minimal engagement DB for ContextBuilder tests."""
    db = tmp_path / "eng.db"
    con = sqlite3.connect(db)
    con.executescript(f"""
        CREATE TABLE engagements (
            id INTEGER PRIMARY KEY, name TEXT, status TEXT, operator TEXT,
            start_date TEXT, end_date TEXT
        );
        INSERT INTO engagements VALUES
            ({ENGAGEMENT_ID}, 'ACME Corp Assessment', 'ACTIVE', 'analyst_01',
             '2025-01-06', '2025-01-17');

        CREATE TABLE engagement_scope (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER, scope_entry TEXT
        );
        INSERT INTO engagement_scope (engagement_id, scope_entry)
            VALUES ({ENGAGEMENT_ID}, '10.0.0.0/24');

        CREATE TABLE hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER, hostname TEXT, ip_address TEXT, os_guess TEXT
        );
        INSERT INTO hosts (engagement_id, hostname, ip_address, os_guess)
            VALUES ({ENGAGEMENT_ID}, 'dc01.acme.local', '10.0.0.10', 'Windows Server 2019');

        CREATE TABLE subdomains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER, fqdn TEXT
        );
        INSERT INTO subdomains (engagement_id, fqdn)
            VALUES ({ENGAGEMENT_ID}, 'mail.acme.local');

        CREATE TABLE open_ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER, ip_address TEXT, port INTEGER, service TEXT
        );
        INSERT INTO open_ports (engagement_id, ip_address, port, service)
            VALUES ({ENGAGEMENT_ID}, '10.0.0.10', 443, 'https');

        CREATE TABLE emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER, email TEXT
        );
        INSERT INTO emails (engagement_id, email)
            VALUES ({ENGAGEMENT_ID}, 'admin@acme.local');

        CREATE TABLE email_intelligence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER,
            email TEXT,
            source TEXT,
            breach_count INTEGER,
            breach_names TEXT,
            paste_count INTEGER,
            enrichment_data TEXT,
            last_synced TEXT
        );
        INSERT INTO email_intelligence
            (engagement_id, email, source, breach_count, breach_names, paste_count, enrichment_data, last_synced)
        VALUES
            ({ENGAGEMENT_ID}, 'admin@acme.local', 'xposedornot', 2, '["Dropbox","LinkedIn"]', 0, '{{"breaches":["Dropbox","LinkedIn"]}}', '2025-01-07T11:00:00'),
            ({ENGAGEMENT_ID}, 'admin@acme.local', 'emailrep', 1, '["linkedin","github"]', 0, '{{"reputation":"low","suspicious":true,"details":{{"blacklisted":true,"profiles":["linkedin","github"]}}}}', '2025-01-07T11:05:00');

        CREATE TABLE account_existence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER,
            email TEXT,
            service TEXT,
            exists_flag INTEGER,
            rate_limited INTEGER,
            source_tool TEXT,
            queried_at TEXT
        );
        INSERT INTO account_existence
            (engagement_id, email, service, exists_flag, rate_limited, source_tool, queried_at)
        VALUES
            ({ENGAGEMENT_ID}, 'admin@acme.local', 'github.com', 1, 0, 'holehe', '2025-01-07T11:10:00'),
            ({ENGAGEMENT_ID}, 'admin@acme.local', 'twitter.com', 0, 1, 'holehe', '2025-01-07T11:10:00'),
            ({ENGAGEMENT_ID}, 'admin@acme.local', 'linkedin.com', 1, 0, 'holehe', '2025-01-07T11:10:00');

        CREATE TABLE engagement_seeds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER,
            seed_value TEXT,
            seed_type TEXT,
            source TEXT,
            status TEXT,
            depth INTEGER,
            confidence REAL,
            parent_seed_id INTEGER,
            metadata_json TEXT,
            discovered_at TEXT,
            updated_at TEXT
        );

        CREATE TABLE seed_relations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER,
            source_seed_id INTEGER,
            target_seed_id INTEGER,
            relation_type TEXT,
            confidence REAL,
            evidence_json TEXT
        );

        CREATE TABLE credential_hashes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER, hash TEXT, source TEXT
        );
        INSERT INTO credential_hashes (engagement_id, hash, source)
            VALUES ({ENGAGEMENT_ID}, 'aabbcc', 'dehashed');

        CREATE TABLE key_scanner_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER, validation_state TEXT
        );
        INSERT INTO key_scanner_findings (engagement_id, validation_state)
            VALUES ({ENGAGEMENT_ID}, 'ACTIVE');

        CREATE TABLE vulnerability_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER, cve_id TEXT, title TEXT, severity TEXT, evidence TEXT
        );
        INSERT INTO vulnerability_findings (engagement_id, cve_id, title, severity, evidence)
            VALUES ({ENGAGEMENT_ID}, 'CVE-2024-1234', 'SMBv1 Remote Code Execution',
                    'CRITICAL', 'Connection established to IPC$');

        CREATE TABLE payloads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER, shell_type TEXT
        );
        INSERT INTO payloads (engagement_id, shell_type) VALUES ({ENGAGEMENT_ID}, 'powershell');

        CREATE TABLE persistence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER, technique TEXT
        );
        INSERT INTO persistence (engagement_id, technique) VALUES ({ENGAGEMENT_ID}, 'com_hijack');

        CREATE TABLE lateral_movement (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER, target TEXT, technique TEXT, success INTEGER
        );
        INSERT INTO lateral_movement (engagement_id, target, technique, success)
            VALUES ({ENGAGEMENT_ID}, '10.0.0.20', 'smb', 1);

        CREATE TABLE exfiltrated_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER, sha256 TEXT, size_bytes INTEGER,
            artifact_family   TEXT,
            artifact_subtype  TEXT,
            source_platform   TEXT,
            collection_method TEXT,
            confidence        REAL,
            report_safe_summary TEXT
        );
        INSERT INTO exfiltrated_data (engagement_id, sha256, size_bytes, artifact_family) VALUES ({ENGAGEMENT_ID}, 'aabbccdd', 1024, 'ssh_key');
    """)
    con.commit()
    con.close()
    return db


def _insert_artifact_seed_relation_fixture(db: Path) -> None:
    con = sqlite3.connect(db)
    try:
        con.executemany(
            """
            INSERT INTO engagement_seeds
                (engagement_id, seed_value, seed_type, source, status, depth, confidence, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    ENGAGEMENT_ID,
                    "https://id.acme.local/.well-known/webfinger?resource=acct:press@acme.local",
                    "url",
                    "scope",
                    "completed",
                    0,
                    0.9,
                    "{}",
                ),
                (
                    ENGAGEMENT_ID,
                    "press@acme.local",
                    "email",
                    "artifact",
                    "pending",
                    1,
                    0.74,
                    "{}",
                ),
                (
                    ENGAGEMENT_ID,
                    "https://id.acme.local/.well-known/did.json",
                    "url",
                    "artifact",
                    "completed",
                    1,
                    0.73,
                    "{}",
                ),
                (
                    ENGAGEMENT_ID,
                    "did-owner@acme.local",
                    "email",
                    "artifact",
                    "pending",
                    2,
                    0.73,
                    "{}",
                ),
            ],
        )
        con.executemany(
            """
            INSERT INTO seed_relations
                (engagement_id, source_seed_id, target_seed_id, relation_type, confidence, evidence_json)
            VALUES (?, ?, ?, 'derived_from', ?, ?)
            """,
            [
                (
                    ENGAGEMENT_ID,
                    1,
                    2,
                    0.74,
                    '{"rule":"artifact_seed_provenance","extract_rule":"artifact_text_extract","source_url":"https://id.acme.local/.well-known/webfinger?resource=acct:press@acme.local","source_file":"https://id.acme.local/.well-known/webfinger","format":"webfinger","payload_count":3,"archive_sources":["wayback","commoncrawl"],"provider_sources":["wayback","commoncrawl"],"root_domain":"acme.local","key_enc":"super-secret"}',
                ),
                (
                    ENGAGEMENT_ID,
                    3,
                    4,
                    0.73,
                    '{"rule":"artifact_seed_provenance","extract_rule":"artifact_text_extract","source_url":"https://id.acme.local/.well-known/did.json","source_file":"https://id.acme.local/.well-known/did.json","format":"did.json","payload_count":2,"provider_sources":["direct"],"root_domain":"acme.local","token":"never-render-this"}',
                ),
            ],
        )
        con.commit()
    finally:
        con.close()


@pytest.fixture()
def full_report_text() -> str:
    """A valid report that passes all validator rules."""
    sections = {s: s for s in MANDATORY_SECTIONS}
    body_paragraph = " ".join(["This is a substantive sentence."] * 15)
    lines = []
    for section in MANDATORY_SECTIONS:
        lines.append(section)
        lines.append("")
        lines.append(body_paragraph)
        lines.append("")
    text = "\n".join(lines)
    # Insert risk label into Exec Summary
    text = text.replace(
        "## 1. Executive Summary\n",
        "## 1. Executive Summary\nThe overall risk is assessed as HIGH. " + body_paragraph + "\n",
        1,
    )
    return text


@pytest.fixture()
def patch_confirm_approve(monkeypatch):
    # The confirm path in _write_report is now guarded by both assume_yes
    # and stdin.isatty(). Under pytest stdin is not a TTY, so we force it
    # True here to make the questionary path reachable for tests.
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    m = mock.MagicMock()
    m.ask.return_value = True
    monkeypatch.setattr("questionary.confirm", lambda *a, **kw: m)


@pytest.fixture()
def patch_confirm_deny(monkeypatch):
    # See patch_confirm_approve — same reason.
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    m = mock.MagicMock()
    m.ask.return_value = False
    monkeypatch.setattr("questionary.confirm", lambda *a, **kw: m)


# ── 1. Risk roll-up ───────────────────────────────────────────────────────────

def test_risk_critical_if_any_critical():
    exploits = ExploitContext(cve_count=1, critical_count=1, high_count=0, medium_count=0)
    assert _derive_overall_risk(exploits) == "CRITICAL"


def test_risk_high_if_any_high_no_critical():
    exploits = ExploitContext(cve_count=1, critical_count=0, high_count=1, medium_count=0)
    assert _derive_overall_risk(exploits) == "HIGH"


def test_risk_high_if_three_or_more_mediums():
    exploits = ExploitContext(cve_count=3, critical_count=0, high_count=0, medium_count=3)
    assert _derive_overall_risk(exploits) == "HIGH"


def test_risk_medium_if_fewer_than_three_mediums():
    exploits = ExploitContext(cve_count=2, critical_count=0, high_count=0, medium_count=2)
    assert _derive_overall_risk(exploits) == "MEDIUM"


def test_risk_low_if_only_cves_no_severity():
    exploits = ExploitContext(cve_count=1, critical_count=0, high_count=0, medium_count=0)
    assert _derive_overall_risk(exploits) == "LOW"


def test_risk_informational_if_no_findings():
    exploits = ExploitContext()
    assert _derive_overall_risk(exploits) == "INFORMATIONAL"


def test_critical_overrides_high():
    exploits = ExploitContext(cve_count=5, critical_count=1, high_count=4, medium_count=3)
    assert _derive_overall_risk(exploits) == "CRITICAL"


# ── 2. ContextBuilder ─────────────────────────────────────────────────────────

def test_context_builder_loads_engagement(tmp_eng_db):
    ctx = ContextBuilder(tmp_eng_db, ENGAGEMENT_ID).build()
    assert ctx.engagement_name == "ACME Corp Assessment"
    assert ctx.operator == "analyst_01"


def test_context_builder_loads_scope(tmp_eng_db):
    ctx = ContextBuilder(tmp_eng_db, ENGAGEMENT_ID).build()
    assert "10.0.0.0/24" in ctx.scope


def test_context_builder_loads_recon(tmp_eng_db):
    ctx = ContextBuilder(tmp_eng_db, ENGAGEMENT_ID).build()
    assert len(ctx.recon.hosts) == 1
    assert ctx.recon.hosts[0]["hostname"] == "dc01.acme.local"
    assert len(ctx.recon.subdomains) == 1
    assert len(ctx.recon.open_ports) == 1


def test_context_builder_loads_osint_counts(tmp_eng_db):
    ctx = ContextBuilder(tmp_eng_db, ENGAGEMENT_ID).build()
    assert ctx.osint.emails_found == 1
    assert ctx.osint.credential_hashes == 1
    assert "dehashed" in ctx.osint.breach_sources
    assert "xposedornot" in ctx.osint.breach_sources
    assert "emailrep" not in ctx.osint.breach_sources
    assert ctx.osint.email_intelligence_records == 2
    assert {"emailrep", "xposedornot", "holehe"} <= set(ctx.osint.intelligence_sources)
    assert ctx.osint.account_existence_records == 3
    assert ctx.osint.registered_account_count == 2
    assert ctx.osint.registered_account_services == ["github.com", "linkedin.com"]
    assert ctx.osint.account_existence_rate_limited == 1
    assert ctx.osint.breached_email_count == 1
    assert ctx.osint.reputation_alert_count == 1
    assert ctx.osint.paste_alert_count == 0
    assert ctx.osint.key_findings_count == 0


def test_context_builder_counts_only_reportable_key_findings(tmp_eng_db):
    con = sqlite3.connect(tmp_eng_db)
    try:
        con.execute("ALTER TABLE key_scanner_findings ADD COLUMN service TEXT")
        con.execute("ALTER TABLE key_scanner_findings ADD COLUMN domain TEXT")
        con.execute("ALTER TABLE key_scanner_findings ADD COLUMN validation_detail TEXT")
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (engagement_id, validation_state, service, domain, validation_detail)
            VALUES
                (?, 'ACTIVE', 'github', '',
                 'VALIDATED:github_user_api:github user ok: user_id=928374 login=acmebot user_profile_present=true profile_url_matches_login=true')
            """,
            (ENGAGEMENT_ID,),
        )
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (engagement_id, validation_state, service, domain, validation_detail)
            VALUES
                (?, 'ACTIVE', 'github', '',
                 'VALIDATED:github_user_api:github user ok: user_id=111111 login=admin user_profile_present=true')
            """,
            (ENGAGEMENT_ID,),
        )
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (engagement_id, validation_state, service, domain, validation_detail)
            VALUES
                (?, 'ACTIVE', 'firebase', '',
                 'VALIDATED:firebase_database_shallow_read')
            """,
            (ENGAGEMENT_ID,),
        )
        con.commit()
    finally:
        con.close()

    ctx = ContextBuilder(tmp_eng_db, ENGAGEMENT_ID).build()

    assert ctx.osint.key_findings_count == 1


def test_context_builder_unions_seed_only_hosts_and_emails(tmp_eng_db):
    con = sqlite3.connect(tmp_eng_db)
    try:
        con.executemany(
            """
            INSERT INTO engagement_seeds
                (engagement_id, seed_value, seed_type, source, status, depth, confidence, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    ENGAGEMENT_ID,
                    "vpn.acme.local",
                    "subdomain",
                    "cross_reference",
                    "pending",
                    2,
                    0.76,
                    "{}",
                ),
                (
                    ENGAGEMENT_ID,
                    "press@acme.local",
                    "email",
                    "cross_reference",
                    "pending",
                    2,
                    0.79,
                    "{}",
                ),
            ],
        )
        con.commit()
    finally:
        con.close()

    ctx = ContextBuilder(tmp_eng_db, ENGAGEMENT_ID).build()
    assert len(ctx.recon.hosts) == 2
    assert "vpn.acme.local" in [str(item["hostname"]) for item in ctx.recon.hosts]
    assert "vpn.acme.local" in ctx.recon.subdomains
    assert ctx.osint.emails_found == 2


def test_context_builder_loads_scrubbed_artifact_seed_relation_provenance(tmp_eng_db):
    _insert_artifact_seed_relation_fixture(tmp_eng_db)

    ctx = ContextBuilder(tmp_eng_db, ENGAGEMENT_ID).build()

    assert ctx.seed_summary.relation_count == 2
    relation = ctx.seed_summary.relations[0]
    assert relation["relation_type"] == "derived_from"
    assert relation["source_value"] == "https://id.acme.local/.well-known/webfinger"
    assert relation["target_value"] == "press@acme.local"
    assert relation["evidence_metadata"]["rule"] == "artifact_seed_provenance"
    assert relation["evidence_metadata"]["extract_rule"] == "artifact_text_extract"
    assert relation["evidence_metadata"]["format"] == "webfinger"
    assert relation["evidence_metadata"]["payload_count"] == 3
    assert "key_enc" not in relation["evidence_metadata"]
    did_relation = next(
        item
        for item in ctx.seed_summary.relations
        if item["evidence_metadata"].get("format") == "did.json"
    )
    assert did_relation["source_value"] == "https://id.acme.local/.well-known/did.json"
    assert did_relation["target_value"] == "did-owner@acme.local"
    assert did_relation["evidence_metadata"]["provider_sources"] == ["direct"]
    assert "token" not in did_relation["evidence_metadata"]
    assert "super-secret" not in json.dumps(ctx.seed_summary.relations, sort_keys=True)
    assert "never-render-this" not in json.dumps(ctx.seed_summary.relations, sort_keys=True)


def test_context_builder_filters_non_validated_managed_cloud_seeds_from_summary(
    tmp_eng_db,
):
    con = sqlite3.connect(tmp_eng_db)
    try:
        con.execute(
            """
            CREATE TABLE cloud_validation_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER,
                asset_type TEXT,
                identifier TEXT,
                validation_status TEXT
            )
            """
        )
        con.executemany(
            """
            INSERT INTO cloud_validation_results
                (engagement_id, asset_type, identifier, validation_status)
            VALUES (?, ?, ?, ?)
            """,
            [
                (ENGAGEMENT_ID, "gcs", "validated-gcs", "VALIDATED"),
                (ENGAGEMENT_ID, "gcs", "decoy-gcs", "HONEYPOT_SUSPECTED"),
                (ENGAGEMENT_ID, "azure_blob", "validblob/public", "VALIDATED"),
                (ENGAGEMENT_ID, "azure_blob", "decoyblob/public", "HONEYPOT_SUSPECTED"),
                (ENGAGEMENT_ID, "azure_blob", "validlake/raw", "VALIDATED"),
                (ENGAGEMENT_ID, "azure_blob", "decoylake/raw", "HONEYPOT_SUSPECTED"),
                (ENGAGEMENT_ID, "azure_blob", "validstatic/$web", "VALIDATED"),
                (ENGAGEMENT_ID, "azure_blob", "decoystatic/$web", "HONEYPOT_SUSPECTED"),
                (ENGAGEMENT_ID, "do_spaces", "nyc3/valid-space", "VALIDATED"),
                (ENGAGEMENT_ID, "do_spaces", "nyc3/decoy-space", "HONEYPOT_SUSPECTED"),
            ],
        )
        con.executemany(
            """
            INSERT INTO engagement_seeds
                (engagement_id, seed_value, seed_type, source, status, depth, confidence, metadata_json)
            VALUES (?, ?, 'url', 'artifact', 'pending', 1, 0.74, '{}')
            """,
            [
                (ENGAGEMENT_ID, "gs://validated-gcs/reports/customer-data.csv"),
                (ENGAGEMENT_ID, "gs://decoy-gcs/sample/test-data.json"),
                (
                    ENGAGEMENT_ID,
                    "https://validblob.blob.core.windows.net/public/reports/customer-data.csv",
                ),
                (
                    ENGAGEMENT_ID,
                    "https://decoyblob.blob.core.windows.net/public/sample/test-data.csv",
                ),
                (
                    ENGAGEMENT_ID,
                    "https://validlake.dfs.core.windows.net/raw/reports/customer-data.csv",
                ),
                (
                    ENGAGEMENT_ID,
                    "https://decoylake.dfs.core.windows.net/raw/sample/test-data.csv",
                ),
                (
                    ENGAGEMENT_ID,
                    "https://validstatic.z22.web.core.windows.net/reports/customer-data.csv",
                ),
                (
                    ENGAGEMENT_ID,
                    "https://decoystatic.z22.web.core.windows.net/sample/test-data.csv",
                ),
                (
                    ENGAGEMENT_ID,
                    "https://valid-space.nyc3.digitaloceanspaces.com/reports/customer-data.csv",
                ),
                (
                    ENGAGEMENT_ID,
                    "https://decoy-space.nyc3.digitaloceanspaces.com/sample/test-data.json",
                ),
            ],
        )
        con.commit()
    finally:
        con.close()

    ctx = ContextBuilder(tmp_eng_db, ENGAGEMENT_ID).build()
    rendered = json.dumps(ctx.seed_summary.seeds, sort_keys=True)

    assert "validated-gcs" in rendered
    assert "validblob.blob.core.windows.net/public" in rendered
    assert "validlake.dfs.core.windows.net/raw" in rendered
    assert "validstatic.z22.web.core.windows.net" in rendered
    assert "valid-space.nyc3.digitaloceanspaces.com" in rendered
    assert "decoy-gcs" not in rendered
    assert "decoyblob.blob.core.windows.net/public" not in rendered
    assert "decoylake.dfs.core.windows.net/raw" not in rendered
    assert "decoystatic.z22.web.core.windows.net" not in rendered
    assert "decoy-space.nyc3.digitaloceanspaces.com" not in rendered


def test_context_builder_never_loads_plaintext_credentials(tmp_eng_db, monkeypatch):
    """The ContextBuilder must only load hash counts; never credential values."""
    ctx = ContextBuilder(tmp_eng_db, ENGAGEMENT_ID).build()
    ctx_str = str(ctx.__dict__)
    # The raw hash value should appear (it's metadata), but not 'password', 'passwd' values
    assert "password=" not in ctx_str.lower()
    assert "secret=" not in ctx_str.lower()


def test_context_builder_derives_overall_risk(tmp_eng_db):
    ctx = ContextBuilder(tmp_eng_db, ENGAGEMENT_ID).build()
    assert ctx.overall_risk == "CRITICAL"   # fixture has 1 CRITICAL vuln


def test_context_builder_summarizes_artifacts_by_family_and_type(tmp_eng_db: Path) -> None:
    con = sqlite3.connect(tmp_eng_db)
    con.execute(
        """INSERT INTO exfiltrated_data
           (engagement_id, sha256, size_bytes, artifact_family, artifact_subtype)
           VALUES (?, ?, ?, ?, ?)""",
        (ENGAGEMENT_ID, "ddeeff00", 2048, "crypto_wallet", "ethereum_keystore"),
    )
    con.execute(
        """INSERT INTO exfiltrated_data
           (engagement_id, sha256, size_bytes, artifact_family, artifact_subtype)
           VALUES (?, ?, ?, ?, ?)""",
        (ENGAGEMENT_ID, "11223344", 512, "crypto_wallet", "desktop_exodus"),
    )
    con.commit()
    con.close()

    ctx = ContextBuilder(tmp_eng_db, ENGAGEMENT_ID).build()
    assert ctx.post_exploitation.artifact_summary["crypto_wallet"] == 2
    assert ctx.post_exploitation.artifact_type_summary["crypto_wallet"] == {
        "desktop_exodus": 1,
        "ethereum_keystore": 1,
    }
    assert ctx.post_exploitation.artifact_type_summary["ssh_key"]["unknown"] == 1


def test_context_builder_evidence_capped_at_512(tmp_eng_db):
    con = sqlite3.connect(tmp_eng_db)
    long_evidence = "X" * 1024
    con.execute(
        "INSERT INTO vulnerability_findings (engagement_id, cve_id, title, severity, evidence) "
        "VALUES (?, 'CVE-2024-9999', 'Long evidence test', 'HIGH', ?)",
        (ENGAGEMENT_ID, long_evidence),
    )
    con.commit()
    con.close()
    ctx = ContextBuilder(tmp_eng_db, ENGAGEMENT_ID).build()
    for vuln in ctx.exploits.exploited:
        assert len(vuln.get("evidence", "")) <= 512, (
            "V-09 contract: evidence must be capped at 512 chars by ContextBuilder."
        )


def test_context_builder_counts_distinct_cves_and_sorts_findings_deterministically(tmp_eng_db):
    con = sqlite3.connect(tmp_eng_db)
    con.execute(
        "INSERT INTO vulnerability_findings (engagement_id, cve_id, title, severity, evidence) "
        "VALUES (?, 'CVE-2024-2222', 'Zulu high finding', 'HIGH', 'zulu')",
        (ENGAGEMENT_ID,),
    )
    con.execute(
        "INSERT INTO vulnerability_findings (engagement_id, cve_id, title, severity, evidence) "
        "VALUES (?, 'CVE-2024-1111', 'Alpha critical finding', 'CRITICAL', 'alpha')",
        (ENGAGEMENT_ID,),
    )
    con.execute(
        "INSERT INTO vulnerability_findings (engagement_id, cve_id, title, severity, evidence) "
        "VALUES (?, 'CVE-2024-2222', 'Bravo high finding', 'HIGH', 'bravo')",
        (ENGAGEMENT_ID,),
    )
    con.commit()
    con.close()

    ctx = ContextBuilder(tmp_eng_db, ENGAGEMENT_ID).build()

    assert ctx.exploits.finding_count == 4
    assert ctx.exploits.cve_count == 3
    assert [finding["title"] for finding in ctx.exploits.exploited[:4]] == [
        "Alpha critical finding",
        "SMBv1 Remote Code Execution",
        "Bravo high finding",
        "Zulu high finding",
    ]


def test_context_builder_raises_on_missing_engagement(tmp_eng_db):
    with pytest.raises(ValueError, match="not found"):
        ContextBuilder(tmp_eng_db, engagement_id=999).build()


def test_context_builder_no_monitoring_when_table_absent(tmp_eng_db):
    ctx = ContextBuilder(tmp_eng_db, ENGAGEMENT_ID).build()
    assert ctx.ongoing_intelligence.monitoring_enabled is False


# ── 3. PromptAssembler ────────────────────────────────────────────────────────

def _make_minimal_context(overall_risk: str = "HIGH") -> ReportContext:
    return ReportContext(
        engagement_id     = 1,
        engagement_name   = "Test Engagement",
        operator          = "analyst",
        scope             = ["10.0.0.0/24"],
        start_date        = "2025-01-06",
        end_date          = "2025-01-17",
        recon             = ReconContext(),
        osint             = OsintContext(),
        exploits          = ExploitContext(cve_count=1, high_count=1),
        post_exploitation = PostExploitContext(),
        overall_risk      = overall_risk,
    )


def test_prompt_assembler_minimal_prompt_on_missing_template(tmp_path):
    """When template dir is empty, fall back to minimal inline prompt."""
    assembler = PromptAssembler(template_dir=tmp_path)
    ctx       = _make_minimal_context()
    prompt    = assembler.assemble(ctx)
    assert len(prompt) > 50
    assert "HIGH" in prompt


def test_prompt_assembler_credential_leak_guard_raises():
    assembler = PromptAssembler(template_dir=Path("/nonexistent"))
    ctx       = _make_minimal_context()
    # Inject a fake credential via scope (normally impossible via ContextBuilder)
    ctx.scope = ["password=SuperSecret123"]
    with pytest.raises(ValueError, match="Credential leak"):
        assembler.assemble(ctx)


def test_v12_prompt_assembler_contains_validation_boundary_section_list():
    assembler = PromptAssembler(template_dir=Path("/nonexistent"))
    ctx       = _make_minimal_context()
    prompt    = assembler.assemble(ctx)
    for section_name in [
        "Executive Summary",
        "Reconnaissance Findings",
        "Validation Boundaries & Evidence Handling",
    ]:
        assert section_name in prompt or "executive" in prompt.lower()
    assert "Post-Exploitation Activities" not in prompt


def test_v12_mandatory_sections_do_not_force_post_exploitation_framing() -> None:
    assert "## 6. Validation Boundaries & Evidence Handling" in MANDATORY_SECTIONS
    assert all("Post-Exploitation" not in section for section in MANDATORY_SECTIONS)


def test_prompt_assembler_enforces_token_budget(monkeypatch):
    monkeypatch.setattr("forge.phase6.report_synthesizer.MAX_PROMPT_TOKENS", 8)
    assembler = PromptAssembler(template_dir=Path("/nonexistent"))
    ctx       = _make_minimal_context()
    ctx.scope = ["10.0.0.0/24", "acme.example", "portal.acme.example"]

    with pytest.raises(PromptOverflowError, match="estimated prompt tokens"):
        assembler.assemble(ctx)


# ── 4–12. Validator rules V-01 through V-09 ───────────────────────────────────

def test_v01_passes_with_all_mandatory_sections(full_report_text):
    result = validate_report(full_report_text, overall_risk="HIGH")
    v01_errors = [e for e in result.errors if "[V-01]" in e]
    assert len(v01_errors) == 0


def test_v01_fails_when_section_missing():
    text   = "\n".join(s for s in MANDATORY_SECTIONS if s != MANDATORY_SECTIONS[2])
    result = validate_report(text, overall_risk="HIGH")
    assert any("[V-01]" in e for e in result.errors)


def test_v02_fails_when_risk_absent_from_exec_summary():
    body = " ".join(["word"] * 60)
    text = "\n".join([
        "## 1. Executive Summary",
        body,   # no risk label
    ] + MANDATORY_SECTIONS[1:])
    result = validate_report(text, overall_risk="CRITICAL")
    assert any("[V-02]" in e for e in result.errors)


def test_v02_passes_when_risk_present(full_report_text):
    result = validate_report(full_report_text, overall_risk="HIGH")
    assert not any("[V-02]" in e for e in result.errors)


def test_v03_warns_on_unapproved_internal_ip(full_report_text):
    # Inject an internal IP into the text
    text   = full_report_text + "\n\nNote: host at 192.168.1.50 was compromised."
    result = validate_report(text, overall_risk="HIGH", approved_internal_ips=[])
    assert any("[V-03]" in w for w in result.warnings)


def test_v03_no_warning_for_approved_ip(full_report_text):
    text   = full_report_text + "\n\nNote: host at 192.168.1.50 was compromised."
    result = validate_report(text, overall_risk="HIGH", approved_internal_ips=["192.168.1.50"])
    assert not any("[V-03]" in w for w in result.warnings)


def test_v04_fails_on_credential_leak(full_report_text):
    text   = full_report_text + "\npassword=SuperSecret123"
    result = validate_report(text, overall_risk="HIGH")
    assert any("[V-04]" in e for e in result.errors)


def test_v05_warns_on_short_section():
    lines = []
    for i, section in enumerate(MANDATORY_SECTIONS):
        lines.append(section)
        lines.append("")
        if i == 0:
            # Make Exec Summary very short but include risk label
            lines.append("HIGH risk. Engagement failed.")
        else:
            lines.append(" ".join(["word"] * 60))
        lines.append("")
    result = validate_report("\n".join(lines), overall_risk="HIGH")
    assert any("[V-05]" in w for w in result.warnings)


def test_v06_warns_when_exec_summary_too_long():
    long_body = " ".join(["word"] * 510) + " HIGH"
    lines = ["## 1. Executive Summary", "", long_body, ""]
    for section in MANDATORY_SECTIONS[1:]:
        lines += [section, "", " ".join(["text"] * 60), ""]
    result = validate_report("\n".join(lines), overall_risk="HIGH")
    assert any("[V-06]" in w for w in result.warnings)


def test_v07_fails_on_paste_url(full_report_text):
    text   = full_report_text + "\nSee: https://pastebin.com/abcd1234"
    result = validate_report(text, overall_risk="HIGH")
    assert any("[V-07]" in e for e in result.errors)


def test_v08_fails_on_shellcode_sequence(full_report_text):
    text   = full_report_text + "\nPayload: \\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x31"
    result = validate_report(text, overall_risk="HIGH")
    assert any("[V-08]" in e for e in result.errors)


def test_v08_fails_on_msfvenom_string(full_report_text):
    text   = full_report_text + "\nGenerated with msfvenom -p windows/x64/shell_reverse_tcp"
    result = validate_report(text, overall_risk="HIGH")
    assert any("[V-08]" in e for e in result.errors)


def test_v09_warns_on_long_evidence_block(full_report_text):
    evidence_block = "Evidence: " + "X" * 600
    result = validate_report(full_report_text + "\n" + evidence_block, overall_risk="HIGH")
    assert any("[V-09]" in w for w in result.warnings)


def test_v09_no_warning_on_short_evidence(full_report_text):
    evidence_block = "Evidence: short finding"
    result = validate_report(full_report_text + "\n" + evidence_block, overall_risk="HIGH")
    assert not any("[V-09]" in w for w in result.warnings)


# ── 13. Validator V-10 ────────────────────────────────────────────────────────

def test_v10_warns_when_exec_summary_lacks_monitoring_reference(full_report_text):
    ongoing = OngoingIntelligenceContext(
        monitoring_enabled  = True,
        new_findings_count  = 5,
        high_severity_count = 2,
        monitored_keywords  = ["acme.com"],
    )
    # full_report_text Executive Summary does not contain monitoring keywords
    result = validate_report(full_report_text, overall_risk="HIGH", ongoing_intel=ongoing)
    assert any("[V-10]" in w for w in result.warnings)


def test_v10_passes_when_exec_summary_references_monitoring():
    body = " ".join(["text"] * 60)
    monitoring_ref = "Post-engagement monitoring identified ongoing intelligence findings."
    exec_body  = f"The overall risk is HIGH. {monitoring_ref} {body}"
    lines = [f"## 1. Executive Summary", "", exec_body, ""]
    for section in MANDATORY_SECTIONS[1:]:
        lines += [section, "", " ".join(["word"] * 60), ""]
    text = "\n".join(lines)
    ongoing = OngoingIntelligenceContext(
        monitoring_enabled = True, new_findings_count = 3
    )
    result = validate_report(text, overall_risk="HIGH", ongoing_intel=ongoing)
    assert not any("[V-10]" in w for w in result.warnings)


def test_v10_skipped_when_no_monitoring_findings(full_report_text):
    ongoing = OngoingIntelligenceContext(monitoring_enabled=True, new_findings_count=0)
    result  = validate_report(full_report_text, overall_risk="HIGH", ongoing_intel=ongoing)
    assert not any("[V-10]" in w for w in result.warnings)


def test_v10_skipped_when_monitoring_disabled(full_report_text):
    ongoing = OngoingIntelligenceContext(monitoring_enabled=False, new_findings_count=10)
    result  = validate_report(full_report_text, overall_risk="HIGH", ongoing_intel=ongoing)
    assert not any("[V-10]" in w for w in result.warnings)


# ── 14. Strict mode ───────────────────────────────────────────────────────────

def test_strict_mode_promotes_warnings_to_errors(full_report_text):
    text   = full_report_text + "\n\nHost at 192.168.1.50 was compromised."
    result = validate_report(text, overall_risk="HIGH", strict=True)
    # V-03 is a warning in normal mode; error in strict
    assert any("[V-03]" in e for e in result.errors)
    assert result.passed is False


def test_non_strict_mode_warnings_do_not_fail(full_report_text):
    text   = full_report_text + "\n\nHost at 192.168.1.50 was compromised."
    result = validate_report(text, overall_risk="HIGH", strict=False)
    assert any("[V-03]" in w for w in result.warnings)
    assert result.passed is True


# ── 15. ValidationResult contract ─────────────────────────────────────────────

def test_validation_result_passed_property():
    r = ValidationResult()
    assert r.passed is True
    r.errors.append("error")
    assert r.passed is False


def test_validation_result_summary_passed():
    r = ValidationResult()
    assert "PASSED" in r.summary()


def test_validation_result_summary_with_warnings():
    r = ValidationResult(warnings=["w1"])
    assert "PASSED" in r.summary()
    assert "warning" in r.summary().lower()


def test_validation_result_summary_failed():
    r = ValidationResult(errors=["e1"], warnings=["w1"])
    assert "FAILED" in r.summary()
    assert "1 error" in r.summary()


# ── 16. ReportSynthesizer: model not found ────────────────────────────────────

def test_synthesizer_falls_back_to_template_when_gguf_absent(tmp_eng_db, tmp_path, patch_confirm_approve):
    """When llama_cpp GGUF is missing and no cloud provider is set,
    the synthesizer falls through to deterministic template mode
    (2026-07-06: was previously ModelNotFoundError; now the pipeline
    never fails silently, so operators without any LLM still get a
    factual report from the engagement DB).
    """
    synth = ReportSynthesizer(
        db_path    = tmp_eng_db,
        model_path = tmp_path / "nonexistent.gguf",
        output_dir = tmp_path,
    )
    out = synth.generate(ENGAGEMENT_ID)
    assert out.exists()
    content = out.read_text(encoding="utf-8")
    # Template report identifies itself and has the mandatory section headers.
    assert "template mode, no LLM" in content
    assert "Executive Summary" in content
    assert "Risk Ratings" in content


def test_synthesizer_template_mode_no_llm_needed(tmp_eng_db, tmp_path, patch_confirm_approve):
    """--provider template short-circuits before any LLM machinery even
    tries to load. Verifies the deterministic path is fully independent."""
    synth = ReportSynthesizer(
        db_path    = tmp_eng_db,
        model_path = tmp_path / "nonexistent.gguf",
        output_dir = tmp_path,
        provider   = "template",
    )
    out = synth.generate(ENGAGEMENT_ID)
    assert out.exists()
    content = out.read_text(encoding="utf-8")
    assert "template mode, no LLM" in content
    assert "**Registered-account hits:** 2 across 2 service(s)" in content


def test_synthesizer_template_and_raw_export_include_artifact_seed_relations(
    tmp_eng_db, tmp_path, patch_confirm_approve
):
    _insert_artifact_seed_relation_fixture(tmp_eng_db)

    synth = ReportSynthesizer(
        db_path=tmp_eng_db,
        model_path=tmp_path / "nonexistent.gguf",
        output_dir=tmp_path,
        provider="template",
    )

    out = synth.generate(ENGAGEMENT_ID)
    content = out.read_text(encoding="utf-8")
    payload = json.loads(out.with_suffix(".json").read_text(encoding="utf-8"))
    ctx = ContextBuilder(tmp_eng_db, ENGAGEMENT_ID).build()
    raw_rows = ReportSynthesizer._raw_export_csv_rows(ctx)
    relation_rows = [row for row in raw_rows if row["record_type"] == "seed_relation"]

    assert "#### Recursive Discovery & Cross-Reference Evidence" in content
    assert "artifact_seed_provenance" in content
    assert "artifact_text_extract" in content
    assert "format=webfinger" in content
    assert "format=did.json" in content
    assert "payload_count=3" in content
    assert "payload_count=2" in content
    assert "sources=wayback,commoncrawl" in content
    assert "sources=direct" in content
    assert "root=acme.local" in content
    assert "super-secret" not in content
    assert "key_enc" not in content
    assert "never-render-this" not in content

    relation_context = payload["context"]["seed_summary"]["relations"][0]
    assert relation_context["evidence_metadata"]["rule"] == "artifact_seed_provenance"
    assert relation_context["evidence_metadata"]["extract_rule"] == "artifact_text_extract"
    assert relation_context["evidence_metadata"]["format"] == "webfinger"
    assert relation_context["evidence_metadata"]["archive_sources"] == ["wayback", "commoncrawl"]
    assert relation_context["evidence_metadata"]["provider_sources"] == ["wayback", "commoncrawl"]
    assert relation_context["evidence_metadata"]["root_domain"] == "acme.local"
    assert "key_enc" not in relation_context["evidence_metadata"]
    assert "super-secret" not in json.dumps(payload["context"], sort_keys=True)
    did_relation_context = next(
        item
        for item in payload["context"]["seed_summary"]["relations"]
        if item["evidence_metadata"].get("format") == "did.json"
    )
    assert did_relation_context["source_value"] == "https://id.acme.local/.well-known/did.json"
    assert did_relation_context["target_value"] == "did-owner@acme.local"
    assert "token" not in did_relation_context["evidence_metadata"]
    assert "never-render-this" not in json.dumps(payload["context"], sort_keys=True)

    assert len(relation_rows) == 2
    webfinger_row = next(row for row in relation_rows if "webfinger" in row["relation_evidence"])
    did_row = next(row for row in relation_rows if "did.json" in row["relation_evidence"])
    assert webfinger_row["relation_type"] == "derived_from"
    assert webfinger_row["relation_source"] == "https://id.acme.local/.well-known/webfinger"
    assert webfinger_row["relation_target"] == "press@acme.local"
    assert "artifact_seed_provenance" in webfinger_row["relation_evidence"]
    assert "commoncrawl" in webfinger_row["relation_evidence"]
    assert did_row["relation_source"] == "https://id.acme.local/.well-known/did.json"
    assert did_row["relation_target"] == "did-owner@acme.local"
    assert "sources=direct" in did_row["relation_evidence"]
    assert "super-secret" not in json.dumps(raw_rows, sort_keys=True)
    assert "never-render-this" not in json.dumps(raw_rows, sort_keys=True)


def test_synthesizer_template_and_raw_export_include_archive_url_provenance(
    tmp_eng_db, tmp_path, patch_confirm_approve
):
    con = sqlite3.connect(tmp_eng_db)
    try:
        con.execute(
            """
            CREATE TABLE crawl_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER,
                url TEXT,
                final_url TEXT,
                title TEXT,
                tech_stack_json TEXT,
                discovered_at TEXT
            )
            """
        )
        con.executemany(
            """
            INSERT INTO crawl_results
                (engagement_id, url, final_url, title, tech_stack_json, discovered_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    ENGAGEMENT_ID,
                    "https://portal.acme.local/login?token=redacted",
                    "https://portal.acme.local/login?token=redacted",
                    "Archived login",
                    json.dumps(
                        {
                            "discovered_from": "historical_cdx",
                            "archive_sources": ["wayback"],
                            "provider_sources": ["wayback"],
                            "root_domain": "acme.local",
                        },
                        sort_keys=True,
                    ),
                    "2026-07-15T08:00:00",
                ),
                (
                    ENGAGEMENT_ID,
                    "https://archive.acme.local/config.js",
                    "https://archive.acme.local/config.js",
                    "Archived config",
                    json.dumps(
                        {
                            "discovered_from": "historical_cdx",
                            "archive_sources": ["commoncrawl"],
                            "provider_sources": ["commoncrawl"],
                            "root_domain": "acme.local",
                        },
                        sort_keys=True,
                    ),
                    "2026-07-15T08:01:00",
                ),
            ],
        )
        con.commit()
    finally:
        con.close()

    synth = ReportSynthesizer(
        db_path=tmp_eng_db,
        model_path=tmp_path / "nonexistent.gguf",
        output_dir=tmp_path,
        provider="template",
    )

    out = synth.generate(ENGAGEMENT_ID)
    content = out.read_text(encoding="utf-8")
    payload = json.loads(out.with_suffix(".json").read_text(encoding="utf-8"))
    ctx = ContextBuilder(tmp_eng_db, ENGAGEMENT_ID).build()
    raw_rows = ReportSynthesizer._raw_export_csv_rows(ctx)
    archive_rows = [row for row in raw_rows if row["record_type"] == "archive_url"]

    assert "### 3.3 Passive archive URL provenance" in content
    assert "https://portal.acme.local/login" in content
    assert "token=redacted" not in content
    assert "wayback" in content
    assert "commoncrawl" in content

    archive_context = {
        item["url"]: item
        for item in payload["context"]["recon"]["archive_urls"]
    }
    assert archive_context["https://portal.acme.local/login"]["sources"] == ["wayback"]
    assert archive_context["https://archive.acme.local/config.js"]["sources"] == ["commoncrawl"]

    assert len(archive_rows) == 2
    assert {
        (row["archive_url"], row["archive_sources"], row["archive_root_domain"])
        for row in archive_rows
    } == {
        ("https://portal.acme.local/login", "wayback", "acme.local"),
        ("https://archive.acme.local/config.js", "commoncrawl", "acme.local"),
    }


def test_synthesizer_template_includes_all_validated_findings(
    tmp_eng_db, tmp_path, patch_confirm_approve
):
    con = sqlite3.connect(tmp_eng_db)
    try:
        con.executemany(
            """
            INSERT INTO vulnerability_findings
                (engagement_id, cve_id, title, severity, evidence)
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                (
                    ENGAGEMENT_ID,
                    None,
                    f"Validated deterministic finding {index:02d}",
                    "HIGH",
                    f"evidence-{index:02d}",
                )
                for index in range(1, 12)
            ],
        )
        con.commit()
    finally:
        con.close()

    synth = ReportSynthesizer(
        db_path=tmp_eng_db,
        model_path=tmp_path / "nonexistent.gguf",
        output_dir=tmp_path,
        provider="template",
    )

    out = synth.generate(ENGAGEMENT_ID)
    content = out.read_text(encoding="utf-8")

    assert "### 5.1 Validated findings" in content
    assert "Validated deterministic finding 01" in content
    assert "Validated deterministic finding 11" in content


def test_synthesizer_template_renders_detailed_finding_fields(
    tmp_eng_db, tmp_path, patch_confirm_approve
):
    con = sqlite3.connect(tmp_eng_db)
    try:
        con.execute("ALTER TABLE vulnerability_findings ADD COLUMN target_url TEXT")
        con.execute("ALTER TABLE vulnerability_findings ADD COLUMN description TEXT")
        con.execute("ALTER TABLE vulnerability_findings ADD COLUMN cloud_provider TEXT")
        con.execute("ALTER TABLE vulnerability_findings ADD COLUMN resource_id TEXT")
        con.execute("ALTER TABLE vulnerability_findings ADD COLUMN remediation_cli TEXT")
        con.execute(
            """
            UPDATE vulnerability_findings
            SET target_url=?,
                description=?,
                cloud_provider=?,
                resource_id=?,
                remediation_cli=?
            WHERE engagement_id=?
            """,
            (
                "https://firebaseio.example/.json",
                "Deterministic validation confirmed public Firebase records.",
                "firebase",
                "firebaseio-example",
                "Disable public access and rotate the exposed project configuration.",
                ENGAGEMENT_ID,
            ),
        )
        con.commit()
    finally:
        con.close()

    synth = ReportSynthesizer(
        db_path=tmp_eng_db,
        model_path=tmp_path / "nonexistent.gguf",
        output_dir=tmp_path,
        provider="template",
    )

    out = synth.generate(ENGAGEMENT_ID)
    content = out.read_text(encoding="utf-8")

    assert "### 5.2 Finding details" in content
    assert "#### [CRITICAL] SMBv1 Remote Code Execution" in content
    assert "- **Provider**: firebase" in content
    assert "- **Asset**: https://firebaseio.example/.json" in content
    assert "- **Description**: Deterministic validation confirmed public Firebase records." in content
    assert "- **Recommendation**: Disable public access and rotate the exposed project configuration." in content


def test_synthesizer_template_renders_cloud_validation_metadata(
    tmp_eng_db, tmp_path, patch_confirm_approve
):
    con = sqlite3.connect(tmp_eng_db)
    try:
        con.execute("ALTER TABLE vulnerability_findings ADD COLUMN target_url TEXT")
        con.execute("ALTER TABLE vulnerability_findings ADD COLUMN parameter TEXT")
        con.execute("ALTER TABLE vulnerability_findings ADD COLUMN description TEXT")
        con.execute("ALTER TABLE vulnerability_findings ADD COLUMN cloud_provider TEXT")
        con.execute("ALTER TABLE vulnerability_findings ADD COLUMN resource_id TEXT")
        con.execute("ALTER TABLE vulnerability_findings ADD COLUMN remediation_cli TEXT")
        con.execute(
            """
            CREATE TABLE cloud_validation_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER,
                asset_type TEXT,
                identifier TEXT,
                validation_status TEXT,
                validation_method TEXT,
                http_status INTEGER,
                evidence TEXT,
                notes TEXT,
                checked_at TEXT
            )
            """
        )
        con.execute(
            """
            INSERT INTO cloud_validation_results
                (engagement_id, asset_type, identifier, validation_status, validation_method, http_status, evidence, notes, checked_at)
            VALUES (?, 'aws_s3', 'validated-bucket', 'VALIDATED', 's3_list_bucket', 200, '<ListBucketResult/>',
                    'Bucket listing returned object metadata through a low-impact probe.', '2026-07-14T00:00:00Z')
            """,
            (ENGAGEMENT_ID,),
        )
        con.execute(
            """
            INSERT INTO vulnerability_findings
                (engagement_id, cve_id, title, severity, evidence, target_url, parameter,
                 description, cloud_provider, resource_id, remediation_cli)
            VALUES (?, NULL, 'Validated public S3 bucket listing exposure', 'HIGH',
                    '<ListBucketResult><Contents><Key>reports/customer.csv</Key></Contents></ListBucketResult>',
                    'aws_s3://validated-bucket', 'aws_s3',
                    'Deterministic validation confirmed unauthenticated object metadata enumeration.',
                    'aws', 'validated-bucket',
                    'Block public bucket access and review bucket policy.')
            """,
            (ENGAGEMENT_ID,),
        )
        con.commit()
    finally:
        con.close()

    ctx = ContextBuilder(tmp_eng_db, ENGAGEMENT_ID).build()
    finding = next(
        item
        for item in ctx.exploits.exploited
        if item.get("resource_id") == "validated-bucket"
    )
    assert finding["validation_status"] == "VALIDATED"
    assert finding["validation_method"] == "s3_list_bucket"
    assert finding["validation_http_status"] == 200

    raw_row = next(
        row
        for row in ReportSynthesizer._raw_export_csv_rows(ctx)
        if row["title"] == "Validated public S3 bucket listing exposure"
    )
    assert raw_row["validation_status"] == "VALIDATED"
    assert raw_row["validation_method"] == "s3_list_bucket"
    assert raw_row["validation_http_status"] == "200"

    synth = ReportSynthesizer(
        db_path=tmp_eng_db,
        model_path=tmp_path / "nonexistent.gguf",
        output_dir=tmp_path,
        provider="template",
    )

    out = synth.generate(ENGAGEMENT_ID)
    content = out.read_text(encoding="utf-8")

    assert "- **Validation**: VALIDATED via `s3_list_bucket` HTTP 200" in content
    assert (
        "- **Validation notes**: Bucket listing returned object metadata through a low-impact probe."
        in content
    )

    payload = json.loads(out.with_suffix(".json").read_text(encoding="utf-8"))
    exported_finding = next(
        item
        for item in payload["context"]["exploits"]["exploited"]
        if item.get("resource_id") == "validated-bucket"
    )
    assert exported_finding["validation_status"] == "VALIDATED"
    assert exported_finding["validation_method"] == "s3_list_bucket"


def test_synthesizer_template_and_exports_preserve_key_validation_proof(
    tmp_eng_db, tmp_path, patch_confirm_approve
):
    proof_evidence = (
        "key=AKIA...MPLE; backend=github; "
        "source=https://github.com/acme/repo/blob/main/mobile/google-services.json; "
        "repo=acme/repo; "
        "validation=VALIDATED:aws_sts_get_caller_identity:AccountId=742931608514"
    )
    con = sqlite3.connect(tmp_eng_db)
    try:
        con.execute(
            """
            INSERT INTO vulnerability_findings
                (engagement_id, cve_id, title, severity, evidence)
            VALUES (?, NULL, 'Deterministically validated AWS key exposure', 'HIGH', ?)
            """,
            (ENGAGEMENT_ID, proof_evidence),
        )
        con.commit()
    finally:
        con.close()

    ctx = ContextBuilder(tmp_eng_db, ENGAGEMENT_ID).build()
    finding = next(
        item
        for item in ctx.exploits.exploited
        if item.get("title") == "Deterministically validated AWS key exposure"
    )
    assert "VALIDATED:aws_sts_get_caller_identity" in str(finding.get("evidence") or "")
    assert finding["validation_status"] == "VALIDATED"
    assert finding["validation_method"] == "aws_sts_get_caller_identity"
    assert finding["validation_notes"] == "AccountId=742931608514"

    raw_row = next(
        row
        for row in ReportSynthesizer._raw_export_csv_rows(ctx)
        if row["title"] == "Deterministically validated AWS key exposure"
    )
    assert "VALIDATED:aws_sts_get_caller_identity" in str(raw_row["evidence"])
    assert "backend=github" in str(raw_row["evidence"])
    assert "key_enc" not in str(raw_row["evidence"])

    synth = ReportSynthesizer(
        db_path=tmp_eng_db,
        model_path=tmp_path / "nonexistent.gguf",
        output_dir=tmp_path,
        provider="template",
    )

    out = synth.generate(ENGAGEMENT_ID)
    content = out.read_text(encoding="utf-8")
    assert "Deterministically validated AWS key exposure" in content
    assert "- **Validation**: VALIDATED via `aws_sts_get_caller_identity`" in content
    assert "- **Validation notes**: AccountId=742931608514" in content
    assert "VALIDATED:aws_sts_get_caller_identity" in content
    assert "backend=github" in content
    assert "key_enc" not in content

    payload = json.loads(out.with_suffix(".json").read_text(encoding="utf-8"))
    exported_finding = next(
        item
        for item in payload["context"]["exploits"]["exploited"]
        if item.get("title") == "Deterministically validated AWS key exposure"
    )
    assert "VALIDATED:aws_sts_get_caller_identity" in str(exported_finding.get("evidence") or "")
    assert exported_finding["validation_method"] == "aws_sts_get_caller_identity"
    assert "key_enc" not in json.dumps(exported_finding)


def test_synthesizer_does_not_promote_unlabelled_embedded_validated_evidence(
    tmp_eng_db, tmp_path, patch_confirm_approve
):
    proof_evidence = (
        "key=AKIA...MPLE; status=UNVERIFIED; "
        "VALIDATED:aws_sts_get_caller_identity:AccountId=742931608514"
    )
    con = sqlite3.connect(tmp_eng_db)
    try:
        con.execute(
            """
            INSERT INTO vulnerability_findings
                (engagement_id, cve_id, title, severity, evidence)
            VALUES (?, NULL, 'Unverified AWS key note', 'MEDIUM', ?)
            """,
            (ENGAGEMENT_ID, proof_evidence),
        )
        con.commit()
    finally:
        con.close()

    ctx = ContextBuilder(tmp_eng_db, ENGAGEMENT_ID).build()
    finding = next(
        item
        for item in ctx.exploits.exploited
        if item.get("title") == "Unverified AWS key note"
    )

    assert finding["validation_status"] == ""
    assert finding["validation_method"] == ""
    assert finding["validation_notes"] == ""

    synth = ReportSynthesizer(
        db_path=tmp_eng_db,
        model_path=tmp_path / "nonexistent.gguf",
        output_dir=tmp_path,
        provider="template",
    )

    out = synth.generate(ENGAGEMENT_ID)
    content = out.read_text(encoding="utf-8")
    assert "Unverified AWS key note" in content
    assert "- **Validation**: VALIDATED via `aws_sts_get_caller_identity`" not in content


def test_synthesizer_excludes_unvalidated_key_exposure_rows(
    tmp_eng_db, tmp_path, patch_confirm_approve
):
    con = sqlite3.connect(tmp_eng_db)
    try:
        con.execute("ALTER TABLE vulnerability_findings ADD COLUMN vuln_type TEXT")
        con.execute(
            """
            INSERT INTO vulnerability_findings
                (engagement_id, vuln_type, cve_id, title, severity, evidence)
            VALUES (?, 'DETERMINISTIC_KEY_EXPOSURE', NULL,
                    'Active exposed github credential reference', 'MEDIUM',
                    'key=ghp_...AAAA; validation=ACTIVE:github_user_api:no stable user id')
            """,
            (ENGAGEMENT_ID,),
        )
        con.commit()
    finally:
        con.close()

    ctx = ContextBuilder(tmp_eng_db, ENGAGEMENT_ID).build()
    assert all(
        item.get("title") != "Active exposed github credential reference"
        for item in ctx.exploits.exploited
    )

    synth = ReportSynthesizer(
        db_path=tmp_eng_db,
        model_path=tmp_path / "nonexistent.gguf",
        output_dir=tmp_path,
        provider="template",
    )
    out = synth.generate(ENGAGEMENT_ID)
    content = out.read_text(encoding="utf-8")

    assert "Active exposed github credential reference" not in content
    assert "github_user_api:no stable user id" not in content


def test_synthesizer_excludes_model_list_only_key_exposure_rows(
    tmp_eng_db, tmp_path, patch_confirm_approve
):
    con = sqlite3.connect(tmp_eng_db)
    try:
        con.execute("ALTER TABLE vulnerability_findings ADD COLUMN vuln_type TEXT")
        con.execute(
            """
            INSERT INTO vulnerability_findings
                (engagement_id, vuln_type, cve_id, title, severity, evidence)
            VALUES (?, 'DETERMINISTIC_KEY_EXPOSURE', NULL,
                    'Validated exposed openai credential reference', 'HIGH',
                    'VALIDATED:openai_models_list:OpenAI models ok: models=1 sample=gpt-4o-mini')
            """,
            (ENGAGEMENT_ID,),
        )
        con.commit()
    finally:
        con.close()

    ctx = ContextBuilder(tmp_eng_db, ENGAGEMENT_ID).build()
    assert all(
        item.get("title") != "Validated exposed openai credential reference"
        for item in ctx.exploits.exploited
    )

    synth = ReportSynthesizer(
        db_path=tmp_eng_db,
        model_path=tmp_path / "nonexistent.gguf",
        output_dir=tmp_path,
        provider="template",
    )
    out = synth.generate(ENGAGEMENT_ID)
    content = out.read_text(encoding="utf-8")
    payload = json.loads(out.with_suffix(".json").read_text(encoding="utf-8"))

    assert "Validated exposed openai credential reference" not in content
    assert "openai_models_list" not in content
    assert "Validated exposed openai credential reference" not in json.dumps(payload)


def test_synthesizer_template_uses_validated_finding_and_distinct_cve_counts(
    tmp_eng_db, tmp_path, patch_confirm_approve
):
    con = sqlite3.connect(tmp_eng_db)
    try:
        con.execute(
            "INSERT INTO vulnerability_findings (engagement_id, cve_id, title, severity, evidence) "
            "VALUES (?, 'CVE-2024-1234', 'Duplicate CVE finding', 'HIGH', 'dup')",
            (ENGAGEMENT_ID,),
        )
        con.execute(
            "INSERT INTO vulnerability_findings (engagement_id, cve_id, title, severity, evidence) "
            "VALUES (?, NULL, 'Deterministic non-CVE finding', 'HIGH', 'non-cve')",
            (ENGAGEMENT_ID,),
        )
        con.commit()
    finally:
        con.close()

    synth = ReportSynthesizer(
        db_path=tmp_eng_db,
        model_path=tmp_path / "nonexistent.gguf",
        output_dir=tmp_path,
        provider="template",
    )

    out = synth.generate(ENGAGEMENT_ID)
    content = out.read_text(encoding="utf-8")

    assert "**Validated findings:** 3" in content
    assert "**Distinct CVE references:** 1" in content
    assert "across 3 validated finding(s) and 1 distinct CVE reference(s)." in content


def test_synthesizer_writes_markdown_json_and_pdf_exports(
    tmp_eng_db, tmp_path, patch_confirm_approve
):
    synth = ReportSynthesizer(
        db_path=tmp_eng_db,
        model_path=tmp_path / "nonexistent.gguf",
        output_dir=tmp_path,
        provider="template",
    )
    out = synth.generate(ENGAGEMENT_ID)
    json_out = out.with_suffix(".json")
    pdf_out = out.with_suffix(".pdf")

    assert out.exists()
    assert json_out.exists()
    assert pdf_out.exists()
    assert pdf_out.read_bytes().startswith(b"%PDF-1.4")

    payload = json.loads(json_out.read_text(encoding="utf-8"))
    assert payload["engagement_id"] == ENGAGEMENT_ID
    assert payload["provider"] == "template"
    assert payload["requested_provider"] == "template"
    assert payload["fallback_reason"] is None
    assert payload["format"] == "markdown"
    assert payload["findings_checksum"].startswith("sha256:")
    assert payload["report_lineage"]["requested_provider"] == "template"
    assert payload["report_lineage"]["rendered_provider"] == "template"
    assert payload["report_lineage"]["format"] == "markdown"
    assert payload["report_lineage"]["findings_checksum"] == payload["findings_checksum"]
    assert "## Report Generation Lineage" in payload["report_markdown"]
    assert "- **Requested provider:** template" in payload["report_markdown"]
    assert "ACME Corp" in payload["report_markdown"]


def test_v12_synthesizer_template_uses_validation_boundaries_not_post_exploitation(
    tmp_eng_db, tmp_path, patch_confirm_approve
):
    synth = ReportSynthesizer(
        db_path=tmp_eng_db,
        model_path=tmp_path / "nonexistent.gguf",
        output_dir=tmp_path,
        provider="template",
    )

    out = synth.generate(ENGAGEMENT_ID)
    content = out.read_text(encoding="utf-8")

    assert "## 6. Validation Boundaries & Evidence Handling" in content
    assert "## 6. Post-Exploitation Activities" not in content
    assert "post-exploitation authorised" not in content.lower()


def test_synthesizer_report_write_failure_falls_back_to_raw_exports(
    tmp_eng_db, tmp_path, patch_confirm_approve, monkeypatch
):
    synth = ReportSynthesizer(
        db_path=tmp_eng_db,
        model_path=tmp_path / "nonexistent.gguf",
        output_dir=tmp_path,
        provider="template",
    )

    def _boom(*args, **kwargs):  # noqa: ANN002, ANN003
        raise OSError("disk full")

    monkeypatch.setattr(synth, "_write_companion_exports", _boom)

    out = synth.generate(ENGAGEMENT_ID)
    assert out.suffix == ".json"
    assert out.exists()
    assert out.with_suffix(".csv").exists()

    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["provider"] == "raw_export"
    assert payload["requested_provider"] == "template"
    assert payload["upstream_provider"] == "template"
    assert payload["format"] == "raw_export"
    assert "disk full" in str(payload["fallback_reason"] or "")
    assert "disk full" in payload["report_write_error"]
    assert payload["report_lineage"]["requested_provider"] == "template"
    assert payload["report_lineage"]["rendered_provider"] == "raw_export"
    assert payload["report_lineage"]["format"] == "raw_export"
    assert "disk full" in str(payload["report_lineage"]["fallback_reason"] or "")
    assert "disk full" in str(payload["report_lineage"]["write_error"])


def test_synthesise_output_path_pdf_mirrors_report_family(
    tmp_eng_db, tmp_path, patch_confirm_approve, monkeypatch
):
    data_dir = tmp_path / ".forge_data" / "engagements"
    data_dir.mkdir(parents=True)
    (data_dir / f"{ENGAGEMENT_ID}.db").write_bytes(tmp_eng_db.read_bytes())
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    target = tmp_path / "exports" / "final_report.pdf"
    out = synthesise(
        engagement_id=ENGAGEMENT_ID,
        output_path=str(target),
        assume_yes=True,
        provider="template",
    )

    assert out == target
    assert target.exists()
    assert target.read_bytes().startswith(b"%PDF-1.4")
    assert target.with_suffix(".md").exists()
    assert target.with_suffix(".json").exists()
    assert target.with_suffix(".csv").exists()


def test_synthesise_output_path_json_mirrors_raw_export_fallback(
    tmp_eng_db, tmp_path, patch_confirm_approve, monkeypatch
):
    data_dir = tmp_path / ".forge_data" / "engagements"
    data_dir.mkdir(parents=True)
    (data_dir / f"{ENGAGEMENT_ID}.db").write_bytes(tmp_eng_db.read_bytes())
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")

    def _boom(*args, **kwargs):  # noqa: ANN002, ANN003
        raise OSError("disk full")

    monkeypatch.setattr(ReportSynthesizer, "_write_companion_exports", _boom)

    target = tmp_path / "exports" / "final_report.json"
    out = synthesise(
        engagement_id=ENGAGEMENT_ID,
        output_path=str(target),
        assume_yes=True,
        provider="template",
    )

    assert out == target
    assert target.exists()
    assert target.with_suffix(".csv").exists()
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert payload["provider"] == "raw_export"
    assert payload["requested_provider"] == "template"
    assert payload["upstream_provider"] == "template"


def test_synthesizer_runtime_provider_failure_falls_back_to_template(
    tmp_eng_db, tmp_path, patch_confirm_approve, monkeypatch
):
    synth = ReportSynthesizer(
        db_path=tmp_eng_db,
        model_path=tmp_path / "nonexistent.gguf",
        output_dir=tmp_path,
        provider="auto",
    )
    monkeypatch.setattr(synth, "_ensure_provider_loaded", lambda: None)
    monkeypatch.setattr(
        synth,
        "_infer",
        lambda _prompt: (_ for _ in ()).throw(ProviderUnavailableError("quota exceeded")),
    )
    out = synth.generate(ENGAGEMENT_ID)
    content = out.read_text(encoding="utf-8")
    assert "template mode, no LLM" in content
    assert "LLM fallback engaged: quota exceeded" in content
    assert "Data integrity checksum (structured input)" in content
    assert "## Report Generation Lineage" in content
    assert "- **Requested provider:** auto" in content
    assert "- **Rendered provider:** template" in content
    assert "- **Fallback reason:** quota exceeded" in content
    payload = json.loads(out.with_suffix(".json").read_text(encoding="utf-8"))
    assert payload["provider"] == "template"
    assert payload["requested_provider"] == "auto"
    assert payload["fallback_reason"] == "quota exceeded"
    assert payload["report_lineage"]["requested_provider"] == "auto"
    assert payload["report_lineage"]["rendered_provider"] == "template"
    assert payload["report_lineage"]["fallback_reason"] == "quota exceeded"


def test_synthesizer_auto_cascade_order_accepts_env_aliases(monkeypatch) -> None:
    monkeypatch.delenv("FORGE_LLM_CASCADE_ORDER", raising=False)
    monkeypatch.setenv(
        "LLM_CASCADE_ORDER",
        "claude-3-5-sonnet, gpt-4o, gemini-1.5-pro, local-llama, template",
    )

    assert ReportSynthesizer._configured_auto_cascade_order() == [
        "claude_code",
        "openai_compatible",
        "gemini_cli",
        "llama_cpp",
        "template",
    ]


def test_synthesizer_loads_openai_compatible_provider_from_env(monkeypatch, tmp_path):
    from forge.providers.openai_compatible import OpenAICompatibleProvider

    monkeypatch.setenv("FORGE_OPENAI_BASE_URL", "https://llm.acme.example/v1")
    monkeypatch.setenv("FORGE_OPENAI_MODEL", "acme-report-model")
    monkeypatch.setenv("FORGE_OPENAI_API_KEY", "")

    synth = ReportSynthesizer(
        tmp_path / "engagement.db",
        output_dir=tmp_path,
        assume_yes=True,
        provider="openai_compatible",
    )
    synth._ensure_provider_loaded()

    assert isinstance(synth._llm_provider, OpenAICompatibleProvider)
    assert synth._llm_provider.model_id == "acme-report-model"
    assert synth._llm_provider.endpoint == "https://llm.acme.example/v1"


def test_synthesizer_auto_chain_loads_openai_compatible_provider_from_env(
    monkeypatch, tmp_path
):
    from forge.providers.fallback import FallbackChainProvider

    monkeypatch.setenv("FORGE_LLM_CASCADE_ORDER", "openai_compatible")
    monkeypatch.setenv("FORGE_OPENAI_BASE_URL", "https://llm.acme.example/v1")
    monkeypatch.setenv("FORGE_OPENAI_MODEL", "acme-report-model")
    monkeypatch.setenv("FORGE_OPENAI_API_KEY", "")

    synth = ReportSynthesizer(
        tmp_path / "engagement.db",
        output_dir=tmp_path,
        assume_yes=True,
        provider="auto",
    )
    synth._ensure_provider_loaded()

    assert isinstance(synth._llm_provider, FallbackChainProvider)


def test_synthesizer_auto_uses_local_llama_when_cloud_chain_unavailable(
    tmp_eng_db, tmp_path, patch_confirm_approve, monkeypatch
):
    class _FakeLlama:
        def create_chat_completion(self, **kwargs):  # noqa: ANN003
            del kwargs
            return {
                "choices": [{"message": {"content": _build_valid_report("HIGH")}}],
            }

    synth = ReportSynthesizer(
        db_path=tmp_eng_db,
        model_path=tmp_path / "nonexistent.gguf",
        output_dir=tmp_path,
        provider="auto",
    )

    def _fake_ensure_provider_loaded() -> None:
        raise ValueError("no configured cloud providers detected")

    def _fake_ensure_model_loaded(*, allow_auto_local: bool = False) -> None:
        del allow_auto_local
        synth._llm = _FakeLlama()

    monkeypatch.setattr(synth, "_ensure_provider_loaded", _fake_ensure_provider_loaded)
    monkeypatch.setattr(synth, "_ensure_model_loaded", _fake_ensure_model_loaded)

    out = synth.generate(ENGAGEMENT_ID)
    content = out.read_text(encoding="utf-8")
    payload = json.loads(out.with_suffix(".json").read_text(encoding="utf-8"))

    assert "template mode, no LLM" not in content
    assert "## 1. Executive Summary" in content
    assert payload["provider"] == "llama_cpp"
    assert payload["requested_provider"] == "auto"
    assert payload["fallback_reason"] == "no configured cloud providers detected"


def test_synthesizer_auto_runtime_failure_falls_back_to_local_llama(
    tmp_eng_db, tmp_path, patch_confirm_approve, monkeypatch
):
    class _FakeLlama:
        def create_chat_completion(self, **kwargs):  # noqa: ANN003
            del kwargs
            return {
                "choices": [{"message": {"content": _build_valid_report("HIGH")}}],
            }

    synth = ReportSynthesizer(
        db_path=tmp_eng_db,
        model_path=tmp_path / "nonexistent.gguf",
        output_dir=tmp_path,
        provider="auto",
    )

    def _fake_ensure_provider_loaded() -> None:
        synth._llm_provider = object()

    def _fake_ensure_model_loaded(*, allow_auto_local: bool = False) -> None:
        del allow_auto_local
        synth._llm = _FakeLlama()

    def _fake_infer(prompt: str) -> str:
        if synth._llm_provider is not None:
            raise ProviderUnavailableError("quota exceeded")
        return synth._infer_via_llama_cpp(prompt)

    monkeypatch.setattr(synth, "_ensure_provider_loaded", _fake_ensure_provider_loaded)
    monkeypatch.setattr(synth, "_ensure_model_loaded", _fake_ensure_model_loaded)
    monkeypatch.setattr(synth, "_infer", _fake_infer)

    out = synth.generate(ENGAGEMENT_ID)
    content = out.read_text(encoding="utf-8")
    payload = json.loads(out.with_suffix(".json").read_text(encoding="utf-8"))

    assert "template mode, no LLM" not in content
    assert "## 1. Executive Summary" in content
    assert payload["provider"] == "llama_cpp"
    assert payload["requested_provider"] == "auto"
    assert payload["fallback_reason"] == "quota exceeded"


def test_synthesizer_dry_run_skips_llm(tmp_eng_db, tmp_path, patch_confirm_approve):
    synth = ReportSynthesizer(
        db_path    = tmp_eng_db,
        model_path = tmp_path / "nonexistent.gguf",
        output_dir = tmp_path,
    )
    out = synth.generate(ENGAGEMENT_ID, dry_run=True)
    assert out.exists()
    content = out.read_text()
    assert "Dry-run" in content or len(content) > 10


def test_synthesizer_dry_run_file_contains_engagement_name(tmp_eng_db, tmp_path, patch_confirm_approve):
    synth = ReportSynthesizer(
        db_path    = tmp_eng_db,
        model_path = tmp_path / "nonexistent.gguf",
        output_dir = tmp_path,
    )
    out = synth.generate(ENGAGEMENT_ID, dry_run=True)
    assert "ACME Corp" in out.read_text()


# ── 17. Operator cancel ───────────────────────────────────────────────────────

def test_synthesizer_operator_cancel_raises_no_file(tmp_eng_db, tmp_path, patch_confirm_deny):
    synth = ReportSynthesizer(
        db_path    = tmp_eng_db,
        model_path = tmp_path / "nonexistent.gguf",
        output_dir = tmp_path,
    )
    with pytest.raises(RuntimeError, match="[Cc]ancell?ed"):
        synth.generate(ENGAGEMENT_ID, dry_run=True)
    # No report file should exist
    reports = list(tmp_path.glob("*.md"))
    assert len(reports) == 0


# ── 18. Full LLM path (mocked llama_cpp) ─────────────────────────────────────

def _build_valid_report(overall_risk: str = "HIGH") -> str:
    body = " ".join(["Professional assessment finding."] * 15)
    lines = [f"## 1. Executive Summary", f"", f"The overall risk is {overall_risk}. {body}", ""]
    for section in MANDATORY_SECTIONS[1:]:
        lines += [section, "", body, ""]
    return "\n".join(lines)


def test_synthesizer_mocked_llm_writes_report(tmp_eng_db, tmp_path, patch_confirm_approve):
    fake_gguf = tmp_path / "fake.gguf"
    fake_gguf.write_bytes(b"\x00" * 64)   # non-empty sentinel

    mock_llama_cls = mock.MagicMock()
    mock_llama_cls.return_value.create_chat_completion.return_value = {
        "choices": [{"message": {"content": _build_valid_report("CRITICAL")}}]
    }

    with mock.patch("forge.phase6.report_synthesizer.Llama", mock_llama_cls, create=True):
        synth = ReportSynthesizer(
            db_path    = tmp_eng_db,
            model_path = fake_gguf,
            output_dir = tmp_path,
        )
        # Bypass lazy import guard
        synth._llm = mock_llama_cls.return_value
        out = synth.generate(ENGAGEMENT_ID, dry_run=False)

    assert out.exists()
    assert out.stat().st_size > 0
    assert "CRITICAL" in out.read_text()


def test_synthesizer_persists_feedback_telemetry(tmp_eng_db, tmp_path, patch_confirm_approve):
    fake_gguf = tmp_path / "fake.gguf"
    fake_gguf.write_bytes(b"\x00" * 64)
    mock_llama_cls = mock.MagicMock()
    mock_llama_cls.return_value.create_chat_completion.return_value = {
        "choices": [{"message": {"content": _build_valid_report("CRITICAL")}}]
    }
    with mock.patch("forge.phase6.report_synthesizer.Llama", mock_llama_cls, create=True):
        synth = ReportSynthesizer(
            db_path=tmp_eng_db,
            model_path=fake_gguf,
            output_dir=tmp_path,
        )
        synth._llm = mock_llama_cls.return_value
        synth.generate(ENGAGEMENT_ID, dry_run=False)
    con = sqlite3.connect(tmp_eng_db)
    con.row_factory = sqlite3.Row
    row = con.execute(
        "SELECT quality_score, validator_ok, correction_loops, prompt_hash, response_hash "
        "FROM llm_feedback WHERE engagement_id=? ORDER BY id DESC LIMIT 1",
        (ENGAGEMENT_ID,),
    ).fetchone()
    con.close()
    assert row is not None
    assert row["quality_score"] is not None
    assert row["validator_ok"] == 1
    assert row["correction_loops"] == 0
    assert row["prompt_hash"]
    assert row["response_hash"]


def test_synthesizer_correction_loop_updates_telemetry(tmp_eng_db, tmp_path, patch_confirm_approve):
    fake_gguf = tmp_path / "fake.gguf"
    fake_gguf.write_bytes(b"\x00" * 64)
    first_draft = _build_valid_report("CRITICAL") + "\nOperator used Metasploit framework."
    second_draft = _build_valid_report("CRITICAL")
    mock_llama_cls = mock.MagicMock()
    mock_llama_cls.return_value.create_chat_completion.side_effect = [
        {"choices": [{"message": {"content": first_draft}}]},
        {"choices": [{"message": {"content": second_draft}}]},
    ]
    with mock.patch("forge.phase6.report_synthesizer.Llama", mock_llama_cls, create=True):
        synth = ReportSynthesizer(
            db_path=tmp_eng_db,
            model_path=fake_gguf,
            output_dir=tmp_path,
        )
        synth._llm = mock_llama_cls.return_value
        synth.generate(ENGAGEMENT_ID, dry_run=False)
    assert mock_llama_cls.return_value.create_chat_completion.call_count >= 2
    con = sqlite3.connect(tmp_eng_db)
    con.row_factory = sqlite3.Row
    row = con.execute(
        "SELECT correction_loops, opsec_violation_count, final_approval "
        "FROM llm_feedback WHERE engagement_id=? ORDER BY id DESC LIMIT 1",
        (ENGAGEMENT_ID,),
    ).fetchone()
    con.close()
    assert row is not None
    assert row["correction_loops"] >= 1
    assert row["final_approval"] == 1
