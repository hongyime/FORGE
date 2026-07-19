from __future__ import annotations

import sqlite3
from pathlib import Path

from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.deterministic_findings import DeterministicFindingEngine


def _bootstrap_db(db_path: Path) -> None:
    con = sqlite3.connect(db_path)
    try:
        apply_schema(con)
        run_migrations(con)
        con.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (1001, 'Acme Example', '["acme.example"]', 'ACTIVE', 'delta-one')
            """
        )
        con.commit()
    finally:
        con.close()


def test_deterministic_findings_synthesizes_cloud_and_key_evidence(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO cloud_validation_results
                (engagement_id, asset_type, identifier, validation_status, validation_method, http_status, evidence, notes)
            VALUES
                (1001, 'firebase', 'acme-firebase-prod', 'VALIDATED', 'firebase_database_shallow_read', 200, '{"users":1}', 'Live records observed')
            """
        )
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name, key_redacted, validation_state, validation_detail)
            VALUES
                (1001, 'acme-firebase-prod', 'firebase', 'firebase_mobile_config', 'mobile_config_parse',
                 'app.apk', 'app.apk', 'AIza...7890', 'ACTIVE', 'VALIDATED:firebase_database_shallow_read')
            """
        )
        con.commit()
    finally:
        con.close()

    summary = DeterministicFindingEngine(db_path, 1001).run()

    assert summary.inserted == 2
    assert summary.active_findings >= 2
    assert summary.severity_summary["HIGH"] >= 2

    con = sqlite3.connect(db_path)
    try:
        findings = con.execute(
            """
            SELECT vuln_type, severity, title, cloud_provider, resource_id, evidence
            FROM vulnerability_findings
            WHERE engagement_id=1001
            ORDER BY vuln_type
            """
        ).fetchall()
        assert findings[0] == (
            "DETERMINISTIC_CLOUD_EXPOSURE",
            "HIGH",
            "Validated Firebase data exposure",
            "firebase",
            "acme-firebase-prod",
            '{"users":1}',
        )
        assert findings[1][0] == "DETERMINISTIC_KEY_EXPOSURE"
        assert findings[1][1] == "HIGH"
        assert "key=AIza...7890" in findings[1][5]
        assert "backend=mobile_config_parse" in findings[1][5]
        assert "source=app.apk" in findings[1][5]
        assert "repo=app.apk" in findings[1][5]
        assert "validation=VALIDATED:firebase_database_shallow_read" in findings[1][5]
    finally:
        con.close()


def test_deterministic_findings_scores_validated_supabase_rest_access_high(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO cloud_validation_results
                (engagement_id, asset_type, identifier, validation_status, validation_method, http_status, evidence, notes)
            VALUES
                (1001, 'supabase', 'acme-workspace', 'VALIDATED', 'supabase_rest_root', 200,
                 '[{"id":1,"email":"ops@acme.io"}]', 'Supabase REST endpoint responded successfully.')
            """
        )
        con.commit()
    finally:
        con.close()

    summary = DeterministicFindingEngine(db_path, 1001).run()

    assert summary.inserted == 1
    assert summary.active_findings == 1
    assert summary.severity_summary["HIGH"] == 1

    con = sqlite3.connect(db_path)
    try:
        finding = con.execute(
            """
            SELECT severity, title, cloud_provider, resource_id
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert finding == (
            "HIGH",
            "Validated Supabase data exposure",
            "supabase",
            "acme-workspace",
        )
    finally:
        con.close()


def test_deterministic_findings_keep_validated_legacy_key_only_rows_high(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name,
                 key_redacted, validation_state, validation_detail)
            VALUES
                (1001, '', 'supabase', 'supabase_mobile_config', 'artifact', '',
                 'mobile-config.js', 'eyJh...999', 'ACTIVE',
                 'VALIDATED:supabase_rest_root:Supabase REST endpoint responded successfully.')
            """
        )
        con.commit()
    finally:
        con.close()

    summary = DeterministicFindingEngine(db_path, 1001).run()

    assert summary.inserted == 1
    assert summary.active_findings == 1
    assert summary.severity_summary["HIGH"] == 1

    con = sqlite3.connect(db_path)
    try:
        finding = con.execute(
            """
            SELECT severity, title, target_url
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchone()
        assert finding == (
            "HIGH",
            "Validated exposed supabase credential reference",
            "mobile-config.js",
        )
    finally:
        con.close()


def test_deterministic_findings_skip_low_signal_supabase_key_proof(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name,
                 key_redacted, validation_state, validation_detail)
            VALUES
                (1001, '', 'supabase', 'supabase_mobile_config', 'artifact', '',
                 'mobile-config.js', 'eyJh...999', 'ACTIVE',
                 'VALIDATED:supabase_rest_root:provider returned 200')
            """
        )
        con.commit()
    finally:
        con.close()

    summary = DeterministicFindingEngine(db_path, 1001).run()

    assert summary.inserted == 0
    assert summary.active_findings == 0
    assert all(count == 0 for count in summary.severity_summary.values())

    con = sqlite3.connect(db_path)
    try:
        findings = con.execute(
            """
            SELECT severity, title, target_url, evidence
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchall()
        assert findings == []
    finally:
        con.close()


def test_deterministic_findings_skip_stale_aws_key_proof(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name,
                 key_redacted, validation_state, validation_detail)
            VALUES
                (1001, '', 'aws', 'aws_access_key', 'artifact', '',
                 'mobile-config.js', 'AKIA...MPLE', 'ACTIVE',
                 'VALIDATED:aws_sts_get_caller_identity:AccountId=123456789012 UserId=AIDAEXAMPLE')
            """
        )
        con.commit()
    finally:
        con.close()

    summary = DeterministicFindingEngine(db_path, 1001).run()

    assert summary.inserted == 0
    assert summary.active_findings == 0
    assert all(count == 0 for count in summary.severity_summary.values())

    con = sqlite3.connect(db_path)
    try:
        findings = con.execute(
            """
            SELECT severity, title, target_url, evidence
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchall()
        assert findings == []
    finally:
        con.close()


def test_deterministic_findings_skip_stale_sentry_key_proof(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name,
                 key_redacted, validation_state, validation_detail)
            VALUES
                (1001, '', 'sentry', 'sentry_auth_token', 'artifact', '',
                 'mobile-config.js', 'sntrys_...ABCD', 'ACTIVE',
                 'VALIDATED:sentry_list_organizations:Sentry organizations ok: org_id=0000000000000000 org_slug_present=true org_slug_stable=true')
            """
        )
        con.commit()
    finally:
        con.close()

    summary = DeterministicFindingEngine(db_path, 1001).run()

    assert summary.inserted == 0
    assert summary.active_findings == 0
    assert all(count == 0 for count in summary.severity_summary.values())

    con = sqlite3.connect(db_path)
    try:
        findings = con.execute(
            """
            SELECT severity, title, target_url, evidence
            FROM vulnerability_findings
            WHERE engagement_id=1001
            """
        ).fetchall()
        assert findings == []
    finally:
        con.close()


def test_deterministic_findings_skip_active_key_without_stable_validation_proof(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (id, engagement_id, domain, service, pattern_name, source_backend,
                 source_url, repo_name, key_redacted, validation_state, validation_detail)
            VALUES
                (101, 1001, 'api.acme.example', 'github', 'github_pat_classic',
                 'artifact', 'https://github.com/acme/repo/blob/main/.env',
                 'acme/repo', 'ghp_...AAAA', 'ACTIVE',
                 'ACTIVE:github_user_api:token accepted but no stable user id')
            """
        )
        con.commit()
    finally:
        con.close()

    summary = DeterministicFindingEngine(db_path, 1001).run()

    assert summary.inserted == 0
    con = sqlite3.connect(db_path)
    try:
        findings = con.execute(
            """
            SELECT title
            FROM vulnerability_findings
            WHERE engagement_id=1001 AND vuln_type='DETERMINISTIC_KEY_EXPOSURE'
            """
        ).fetchall()
    finally:
        con.close()
    assert findings == []


def test_deterministic_findings_removes_stale_unvalidated_key_finding_by_repo_target(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (engagement_id, domain, service, pattern_name, source_backend, source_url, repo_name,
                 key_redacted, validation_state, validation_detail)
            VALUES
                (1001, '', 'aws', 'aws_access_key', 'artifact', '',
                 'mobile-config.js', 'AKIA...MPLE', 'ACTIVE',
                 'VALIDATED:aws_sts_get_caller_identity:AccountId=123456789012 UserId=AIDAEXAMPLE')
            """
        )
        con.execute(
            """
            INSERT INTO vulnerability_findings
                (engagement_id, vuln_type, target_url, parameter, severity, title, description, evidence)
            VALUES
                (1001, 'DETERMINISTIC_KEY_EXPOSURE', 'mobile-config.js', 'aws:aws_access_key',
                 'MEDIUM', 'Active exposed aws credential reference',
                 'stale unvalidated key finding', 'validation=VALIDATED:aws_sts_get_caller_identity')
            """
        )
        con.commit()
    finally:
        con.close()

    summary = DeterministicFindingEngine(db_path, 1001).run()

    assert summary.removed == 1
    assert summary.active_findings == 0
    con = sqlite3.connect(db_path)
    try:
        remaining = con.execute(
            """
            SELECT COUNT(*)
            FROM vulnerability_findings
            WHERE engagement_id=1001 AND vuln_type='DETERMINISTIC_KEY_EXPOSURE'
            """
        ).fetchone()[0]
    finally:
        con.close()
    assert remaining == 0


def test_deterministic_findings_remove_non_reportable_cloud_rows(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO cloud_validation_results
                (engagement_id, asset_type, identifier, validation_status, validation_method, http_status, evidence, notes)
            VALUES
                (1001, 'firebase', 'acme-firebase-prod', 'VALIDATED', 'firebase_database_shallow_read', 200, '{"users":1}', 'Live records observed')
            """
        )
        con.commit()
    finally:
        con.close()

    engine = DeterministicFindingEngine(db_path, 1001)
    first = engine.run()
    assert first.inserted == 1

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            UPDATE cloud_validation_results
            SET validation_status='DEAD', validation_method='firebase_http_probe', notes='No reachable endpoint'
            WHERE engagement_id=1001 AND identifier='acme-firebase-prod'
            """
        )
        con.commit()
    finally:
        con.close()

    second = engine.run()
    assert second.removed == 1

    con = sqlite3.connect(db_path)
    try:
        remaining = con.execute(
            "SELECT COUNT(*) FROM vulnerability_findings WHERE engagement_id=1001"
        ).fetchone()[0]
        assert remaining == 0
    finally:
        con.close()


def test_deterministic_findings_remove_cloud_rows_when_validation_downgrades_to_audit_only(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO cloud_validation_results
                (engagement_id, asset_type, identifier, validation_status, validation_method, http_status, evidence, notes)
            VALUES
                (1001, 'aws_s3', 'acme-public-assets', 'VALIDATED', 's3_list_bucket', 200,
                 '<ListBucketResult><Contents><Key>reports/summary.pdf</Key></Contents></ListBucketResult>',
                 'Public object metadata observed')
            """
        )
        con.commit()
    finally:
        con.close()

    engine = DeterministicFindingEngine(db_path, 1001)
    first = engine.run()
    assert first.inserted == 1

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            UPDATE cloud_validation_results
            SET validation_status='ACCESSIBLE_BUT_NO_DATA',
                validation_method='s3_list_bucket',
                notes='Bucket exists but no meaningful records were returned'
            WHERE engagement_id=1001 AND identifier='acme-public-assets'
            """
        )
        con.commit()
    finally:
        con.close()

    second = engine.run()
    assert second.removed == 1
    assert second.active_findings == 0

    con = sqlite3.connect(db_path)
    try:
        rows = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001 AND identifier='acme-public-assets'
            """
        ).fetchall()
        findings = con.execute(
            "SELECT COUNT(*) FROM vulnerability_findings WHERE engagement_id=1001"
        ).fetchone()[0]
        assert rows == [("ACCESSIBLE_BUT_NO_DATA", "s3_list_bucket")]
        assert findings == 0
    finally:
        con.close()


def test_deterministic_findings_skip_low_signal_firebase_bootstrap_metadata(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO cloud_validation_results
                (engagement_id, asset_type, identifier, validation_status, validation_method, http_status, evidence, notes)
            VALUES
                (1001, 'firebase', 'acme-firebase-prod', 'VALIDATED', 'firebase_init_json', 200, '{"projectId":"acme-firebase-prod"}', 'Public bootstrap metadata observed')
            """
        )
        con.commit()
    finally:
        con.close()

    summary = DeterministicFindingEngine(db_path, 1001).run()
    assert summary.active_findings == 0
    assert summary.inserted == 0

    con = sqlite3.connect(db_path)
    try:
        finding_count = con.execute(
            "SELECT COUNT(*) FROM vulnerability_findings WHERE engagement_id=1001"
        ).fetchone()[0]
        assert finding_count == 0
    finally:
        con.close()


def test_deterministic_findings_support_additional_storage_providers(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.executemany(
            """
            INSERT INTO cloud_validation_results
                (engagement_id, asset_type, identifier, validation_status, validation_method, http_status, evidence, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    1001,
                    "aws_s3",
                    "acme-public-assets",
                    "VALIDATED",
                    "s3_list_bucket",
                    200,
                    "<ListBucketResult><Contents><Key>reports/summary.pdf</Key></Contents></ListBucketResult>",
                    "Public object metadata observed",
                ),
                (
                    1001,
                    "gcs",
                    "acme-gcs-public",
                    "VALIDATED",
                    "gcs_list_bucket",
                    200,
                    "<ListBucketResult><Contents><Key>reports/summary.pdf</Key></Contents></ListBucketResult>",
                    "Public object metadata observed",
                ),
                (
                    1001,
                    "azure_blob",
                    "acmeblob/public",
                    "ACCESSIBLE_BUT_NO_DATA",
                    "azure_blob_list_container",
                    403,
                    "<Error><Code>PublicAccessNotPermitted</Code></Error>",
                    "Listing requires authentication",
                ),
                (
                    1001,
                    "do_spaces",
                    "nyc3/acme-space-public",
                    "VALIDATED",
                    "do_spaces_list_bucket",
                    200,
                    "<ListBucketResult><Contents><Key>reports/summary.pdf</Key></Contents></ListBucketResult>",
                    "Public object metadata observed",
                ),
            ],
        )
        con.commit()
    finally:
        con.close()

    summary = DeterministicFindingEngine(db_path, 1001).run()
    assert summary.inserted == 3

    con = sqlite3.connect(db_path)
    try:
        findings = con.execute(
            """
            SELECT severity, title, cloud_provider, resource_id
            FROM vulnerability_findings
            WHERE engagement_id=1001
            ORDER BY title
            """
        ).fetchall()
        assert ("HIGH", "Validated public DigitalOcean Spaces bucket listing exposure", "digitalocean", "nyc3/acme-space-public") in findings
        assert ("HIGH", "Validated public Google Cloud Storage bucket listing exposure", "gcp", "acme-gcs-public") in findings
        assert ("HIGH", "Validated public S3 bucket listing exposure", "aws", "acme-public-assets") in findings
        assert ("azure", "acmeblob/public") not in {(row[2], row[3]) for row in findings}
        validation_rows = con.execute(
            """
            SELECT validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001 AND asset_type='azure_blob'
            """
        ).fetchall()
        assert validation_rows == [("ACCESSIBLE_BUT_NO_DATA", "azure_blob_list_container")]
    finally:
        con.close()


def test_deterministic_findings_keep_storage_metadata_only_probes_low(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.executemany(
            """
            INSERT INTO cloud_validation_results
                (engagement_id, asset_type, identifier, validation_status, validation_method, http_status, evidence, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    1001,
                    "aws_s3",
                    "acme-public-assets",
                    "VALIDATED",
                    "s3_head_probe",
                    200,
                    "{'server': 'AmazonS3'}",
                    "Bucket responded to HEAD request; follow-up listing probe was unavailable.",
                ),
                (
                    1001,
                    "gcs",
                    "acme-gcs-public",
                    "VALIDATED",
                    "gcs_http_probe",
                    200,
                    "<ok />",
                    "Cloud Storage endpoint responded successfully.",
                ),
            ],
        )
        con.commit()
    finally:
        con.close()

    summary = DeterministicFindingEngine(db_path, 1001).run()
    assert summary.inserted == 2

    con = sqlite3.connect(db_path)
    try:
        findings = con.execute(
            """
            SELECT severity, title
            FROM vulnerability_findings
            WHERE engagement_id=1001
            ORDER BY target_url
            """
        ).fetchall()
        assert findings == [
            ("LOW", "Externally reachable S3 bucket detected"),
            ("LOW", "Externally reachable Google Cloud Storage bucket detected"),
        ]
    finally:
        con.close()


def test_deterministic_findings_keep_static_site_only_storage_listings_low(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    _bootstrap_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        con.executemany(
            """
            INSERT INTO cloud_validation_results
                (engagement_id, asset_type, identifier, validation_status, validation_method, http_status, evidence, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    1001,
                    "aws_s3",
                    "acme-public-assets",
                    "ACCESSIBLE_BUT_NO_DATA",
                    "s3_list_bucket",
                    200,
                    "<ListBucketResult><Contents><Key>index.html</Key></Contents></ListBucketResult>",
                    "Bucket listing exposed only directory markers, placeholder objects, or common static-site assets.",
                ),
                (
                    1001,
                    "do_spaces",
                    "nyc3/acme-space-public",
                    "ACCESSIBLE_BUT_NO_DATA",
                    "do_spaces_list_bucket",
                    200,
                    "<ListBucketResult><Contents><Key>index.html</Key></Contents></ListBucketResult>",
                    "Bucket listing exposed only directory markers, placeholder objects, or common static-site assets.",
                ),
            ],
        )
        con.commit()
    finally:
        con.close()

    summary = DeterministicFindingEngine(db_path, 1001).run()
    assert summary.active_findings == 0
    assert summary.inserted == 0

    con = sqlite3.connect(db_path)
    try:
        findings = con.execute(
            "SELECT COUNT(*) FROM vulnerability_findings WHERE engagement_id=1001"
        ).fetchone()[0]
        validation_rows = con.execute(
            """
            SELECT asset_type, validation_status, validation_method
            FROM cloud_validation_results
            WHERE engagement_id=1001
            ORDER BY asset_type
            """
        ).fetchall()
        assert findings == 0
        assert validation_rows == [
            ("aws_s3", "ACCESSIBLE_BUT_NO_DATA", "s3_list_bucket"),
            ("do_spaces", "ACCESSIBLE_BUT_NO_DATA", "do_spaces_list_bucket"),
        ]
    finally:
        con.close()
