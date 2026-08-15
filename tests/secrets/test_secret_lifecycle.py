from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.secrets.importers import SecretScanImportConfig, import_secret_scan_report
from forge.secrets.lifecycle import (
    create_secret_suppression,
    revocation_guidance_for_secret,
    secret_lifecycle_for_finding,
    secret_prevention_workflow_plan,
    sync_secret_lifecycle,
)


def _build_db(path: Path) -> sqlite3.Connection:
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    apply_schema(con)
    run_migrations(con)
    con.execute(
        """
        INSERT INTO engagements (id, name, scope_json, status, operator)
        VALUES (1001, 'Acme Example', '["acme.example"]', 'ACTIVE', 'delta-one')
        """
    )
    con.execute(
        """
        INSERT INTO key_scanner_findings
            (id, engagement_id, domain, service, pattern_name, source_backend,
             source_url, repo_name, key_redacted, key_enc, validation_state)
        VALUES
            (30, 1001, 'acme.example', 'github', 'GitHub PAT', 'gitleaks',
             'https://github.com/acme/app/blob/main/.env', 'acme/app',
             'ghp_...TEST', 'age1secret', 'ACTIVE'),
            (31, 1001, 'acme.example', 'aws', 'AWS Access Key', 'trufflehog',
             'https://github.com/acme/worker/blob/main/.env', 'acme/worker',
             'AKIA...TEST', 'age1secret2', 'REVOKED')
        """
    )
    con.execute(
        """
        INSERT INTO validation_claims
            (engagement_id, claim_type, key_id, owner, expires_at)
        VALUES
            (1001, 'key', 30, 'appsec@example.com', '2026-09-01T00:00:00Z')
        """
    )
    con.commit()
    return con


def test_secret_lifecycle_routes_owner_and_guidance_without_secret_material(tmp_path: Path) -> None:
    con = _build_db(tmp_path / "engagement.db")
    try:
        result = sync_secret_lifecycle(con, 1001)
        lifecycle = secret_lifecycle_for_finding(con, 1001, 30)
        revoked = secret_lifecycle_for_finding(con, 1001, 31)
    finally:
        con.close()

    assert result["synced"] == 2
    assert result["owner_routed"] == 1
    assert lifecycle["lifecycle_status"] == "owner_routed"
    assert lifecycle["owner"] == "appsec@example.com"
    assert lifecycle["owner_source"] == "validation_claims"
    assert lifecycle["revocation_guidance"]["service"] == "github"
    assert any(item["tool"] == "gitleaks" for item in lifecycle["prevention_guidance"])
    assert any(item["tool"] == "trufflehog" for item in lifecycle["prevention_guidance"])
    assert revoked["lifecycle_status"] == "revoked"
    assert "age1secret" not in str(lifecycle)
    assert "age1secret2" not in str(revoked)


def test_secret_prevention_workflow_plan_groups_value_free_commands(tmp_path: Path) -> None:
    con = _build_db(tmp_path / "engagement.db")
    try:
        plan = secret_prevention_workflow_plan(con, 1001)
        push_plan = secret_prevention_workflow_plan(con, 1001, workflow="push")
    finally:
        con.close()

    blob = json.dumps({"plan": plan, "push": push_plan}, sort_keys=True)
    workflows = {item["workflow"]: item for item in plan["workflows"]}
    push_commands = {
        command["tool"]: command
        for command in workflows["push"]["commands"]
    }
    assert plan["schema"] == "forge.secret_prevention.v1"
    assert plan["summary"]["finding_count"] == 2
    assert plan["summary"]["workflow_count"] == 3
    assert workflows["pre-commit"]["target"]["artifact"] == ".pre-commit-config.yaml"
    assert workflows["pull_request"]["target"]["trigger"] == "pull_request"
    assert workflows["pre-commit"]["artifact_template"]["artifact"] == ".pre-commit-config.yaml"
    assert "gitleaks protect --staged --redact" in workflows["pre-commit"]["artifact_template"]["content"]
    assert "detect-secrets-hook --baseline .secrets.baseline" in workflows["pre-commit"]["artifact_template"]["content"]
    assert workflows["pull_request"]["artifact_template"]["artifact"] == ".github/workflows/forge-secret-scan.yml"
    assert "pull_request:" in workflows["pull_request"]["artifact_template"]["content"]
    assert "gitleaks detect --source . --redact --exit-code 1" in workflows["pull_request"]["artifact_template"]["content"]
    assert workflows["push"]["artifact_template"]["artifact"] == ".git/hooks/pre-push"
    assert "trufflehog git file://. --only-verified --json" in workflows["push"]["artifact_template"]["content"]
    assert "Enable secret scanning and push protection" in workflows["push"]["artifact_template"]["content"]
    assert "trufflehog" in push_commands
    assert "GitHub secret protection" in push_commands
    assert any(command["tool"] == "gitleaks" for command in workflows["pre-commit"]["commands"])
    assert any(command["tool"] == "gitleaks" for command in workflows["pull_request"]["commands"])
    assert push_commands["trufflehog"]["affected_finding_ids"] == [30, 31]
    assert push_plan["workflow_filter"] == "push"
    assert [item["workflow"] for item in push_plan["workflows"]] == ["push"]
    assert "age1secret" not in blob
    assert "age1secret2" not in blob


def test_secret_lifecycle_opens_and_resolves_remediation_items(tmp_path: Path) -> None:
    con = _build_db(tmp_path / "engagement.db")
    try:
        first = sync_secret_lifecycle(con, 1001)
        item = con.execute(
            """
            SELECT finding_table, finding_id, finding_ref, title, severity, owner,
                   status, retest_status, metadata_json
            FROM remediation_items
            WHERE engagement_id=1001 AND finding_table='key_scanner_findings'
              AND finding_ref='30'
            """
        ).fetchone()
        con.execute(
            """
            UPDATE key_scanner_findings
            SET validation_state='REVOKED'
            WHERE engagement_id=1001 AND id=30
            """
        )
        second = sync_secret_lifecycle(con, 1001)
        resolved = con.execute(
            """
            SELECT status, retest_status, metadata_json
            FROM remediation_items
            WHERE engagement_id=1001 AND finding_table='key_scanner_findings'
              AND finding_ref='30'
            """
        ).fetchone()
        audit_rows = con.execute(
            """
            SELECT target, result
            FROM audit_log
            WHERE phase='secrets' AND module='secret_lifecycle'
            ORDER BY id
            """
        ).fetchall()
    finally:
        con.close()

    metadata = json.loads(item["metadata_json"])
    resolved_metadata = json.loads(resolved["metadata_json"])
    assert first["remediation_created"] == 1
    assert first["remediation_updated"] == 0
    assert first["remediation_resolved"] == 0
    assert item["finding_table"] == "key_scanner_findings"
    assert item["finding_id"] == 30
    assert item["finding_ref"] == "30"
    assert item["title"] == "Revoke exposed github credential: GitHub PAT"
    assert item["severity"] == "HIGH"
    assert item["owner"] == "appsec@example.com"
    assert item["status"] == "assigned"
    assert item["retest_status"] == "not_requested"
    assert metadata["source"] == "secret_lifecycle"
    assert metadata["revocation_guidance"]["service"] == "github"
    assert metadata["prevention_guidance"][0]["tool"] == "gitleaks"
    assert second["remediation_resolved"] == 1
    assert resolved["status"] == "resolved"
    assert resolved["retest_status"] == "passed"
    assert resolved_metadata["validation_state"] == "REVOKED"
    assert [row["target"] for row in audit_rows] == [
        "key_scanner_findings:30",
        "key_scanner_findings:30",
    ]
    assert "created service=github state=ACTIVE" in audit_rows[0]["result"]
    assert "resolved service=github state=REVOKED" in audit_rows[1]["result"]
    assert "age1secret" not in json.dumps(
        {"item": dict(item), "resolved": dict(resolved), "audit": [dict(row) for row in audit_rows]}
    )


def test_secret_suppression_marks_lifecycle_suppressed(tmp_path: Path) -> None:
    con = _build_db(tmp_path / "engagement.db")
    try:
        suppression_id = create_secret_suppression(
            con,
            engagement_id=1001,
            key_finding_id=30,
            reason="Known test token in fixture repository",
            created_by="delta-one",
            evidence={"ticket": "SEC-1", "secret": "do-not-store"},
        )
        result = sync_secret_lifecycle(con, 1001)
        lifecycle = secret_lifecycle_for_finding(con, 1001, 30)
        stored_evidence = con.execute(
            "SELECT evidence_json FROM secret_suppressions WHERE id=?",
            (suppression_id,),
        ).fetchone()["evidence_json"]
        remediation_count = con.execute(
            """
            SELECT COUNT(*)
            FROM remediation_items
            WHERE engagement_id=1001 AND finding_table='key_scanner_findings'
            """
        ).fetchone()[0]
    finally:
        con.close()

    assert suppression_id > 0
    assert result["suppressed"] == 1
    assert result["remediation_created"] == 0
    assert lifecycle["lifecycle_status"] == "suppressed"
    assert lifecycle["suppressed"] is True
    assert lifecycle["suppression_id"] == suppression_id
    assert remediation_count == 0
    assert "do-not-store" not in stored_evidence
    assert "do-not-store" not in str(lifecycle)


def test_revocation_guidance_has_generic_fallback() -> None:
    guidance = revocation_guidance_for_secret("unknown-provider", "custom token")

    assert guidance["service"] == "unknown-provider"
    assert guidance["pattern_name"] == "custom token"
    assert "Revoke or rotate" in guidance["rotation_summary"]


def test_gitleaks_report_import_persists_lifecycle_without_raw_secret(tmp_path: Path) -> None:
    raw_secret = "ghp_supersecretvalue1234567890"
    report = json.dumps(
        [
            {
                "RuleID": "github-pat",
                "Description": "GitHub personal access token",
                "File": ".env",
                "StartLine": 4,
                "Secret": raw_secret,
                "Fingerprint": "abc123:.env:github-pat:4",
                "Link": "https://github.com/acme/app/blob/abc123/.env#L4",
            }
        ]
    )
    con = _build_db(tmp_path / "engagement.db")
    try:
        result = import_secret_scan_report(
            con,
            SecretScanImportConfig(
                connector_id="gitleaks_local",
                engagement_id=1001,
                domain="acme.example",
                repo_name="acme/app",
            ),
            report_text=report,
        )
        row = con.execute(
            """
            SELECT id, service, pattern_name, source_backend, source_url,
                   repo_name, key_redacted, key_enc, validation_state,
                   validation_detail
            FROM key_scanner_findings
            WHERE source_backend='gitleaks' AND pattern_name='github-pat'
            """
        ).fetchone()
        lifecycle = secret_lifecycle_for_finding(con, 1001, int(row["id"]))
        audit_result = con.execute(
            """
            SELECT result
            FROM audit_log
            WHERE phase='connectors' AND module='gitleaks_local'
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()["result"]
    finally:
        con.close()

    blob = json.dumps({"result": result, "row": dict(row), "lifecycle": lifecycle, "audit": audit_result})
    assert result["persisted_count"] == 1
    assert result["lifecycle_synced"] >= 3
    assert row["service"] == "github"
    assert row["source_backend"] == "gitleaks"
    assert row["repo_name"] == "acme/app"
    assert row["key_redacted"] == "ghp_...7890"
    assert row["key_enc"] is None
    assert row["validation_state"] == "UNCONFIRMED"
    assert row["validation_detail"].startswith("IMPORTED:gitleaks_json:")
    assert lifecycle["lifecycle_status"] == "revocation_guided"
    assert "persisted=1" in audit_result
    assert raw_secret not in blob


def test_trufflehog_verified_json_import_marks_active_without_raw_secret(tmp_path: Path) -> None:
    raw_secret = "AKIAABCDEFGHIJKLMNOP"
    report = json.dumps(
        {
            "SourceMetadata": {
                "Data": {
                    "Git": {
                        "commit": "abc123",
                        "file": "keys",
                        "repository": "https://github.com/acme/worker",
                        "line": 4,
                    }
                }
            },
            "SourceName": "trufflehog - git",
            "DetectorName": "AWS",
            "Verified": True,
            "Raw": raw_secret,
            "Redacted": "AKIA...MNOP",
            "ExtraData": {"account": "123456789012", "secret": "do-not-store"},
        }
    )
    con = _build_db(tmp_path / "engagement.db")
    try:
        result = import_secret_scan_report(
            con,
            SecretScanImportConfig(
                connector_id="trufflehog_local",
                engagement_id=1001,
                domain="acme.example",
            ),
            report_text=report + "\n",
        )
        row = con.execute(
            """
            SELECT id, service, pattern_name, source_backend, source_url,
                   repo_name, key_redacted, key_enc, validation_state,
                   validation_detail, validated_at
            FROM key_scanner_findings
            WHERE source_backend='trufflehog' AND pattern_name='AWS'
            """
        ).fetchone()
        lifecycle = secret_lifecycle_for_finding(con, 1001, int(row["id"]))
    finally:
        con.close()

    blob = json.dumps({"result": result, "row": dict(row), "lifecycle": lifecycle})
    assert result["persisted_count"] == 1
    assert row["service"] == "aws"
    assert row["repo_name"] == "acme/worker"
    assert row["key_redacted"] == "AKIA...MNOP"
    assert row["key_enc"] is None
    assert row["validation_state"] == "ACTIVE"
    assert row["validated_at"]
    assert row["validation_detail"].startswith("VALIDATED:trufflehog_verified:")
    assert lifecycle["revocation_guidance"]["service"] == "aws"
    assert raw_secret not in blob
    assert "do-not-store" not in blob
