from __future__ import annotations

import sqlite3
from pathlib import Path

from forge.deterministic_findings import DeterministicFindingEngine
from forge.phase6.report_synthesizer import ContextBuilder, ReportSynthesizer
from forge.utils.cloud_exposure_gate import latest_cloud_validation_reportability_index

ENGAGEMENT_ID = 710
EXPECTED_TITLE = "Validated public S3 bucket listing exposure"


def _build_alias_latest_db(db_path: Path) -> None:
    con = sqlite3.connect(db_path)
    try:
        con.executescript(
            """
            CREATE TABLE engagements (
                id INTEGER PRIMARY KEY,
                name TEXT,
                status TEXT,
                operator TEXT
            );
            INSERT INTO engagements VALUES
                (710, 'Alias Latest Gate', 'ACTIVE', 'analyst');

            CREATE TABLE vulnerability_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER,
                vuln_type TEXT,
                cve_id TEXT,
                title TEXT,
                severity TEXT,
                evidence TEXT,
                target_url TEXT,
                parameter TEXT,
                description TEXT,
                cloud_provider TEXT,
                resource_id TEXT,
                remediation_cli TEXT,
                UNIQUE (engagement_id, vuln_type, target_url, parameter)
            );

            CREATE TABLE cloud_validation_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER,
                asset_type TEXT,
                identifier TEXT,
                provider_identifier TEXT,
                validation_status TEXT,
                validation_method TEXT,
                http_status INTEGER,
                evidence TEXT,
                notes TEXT,
                checked_at TEXT,
                UNIQUE (engagement_id, asset_type, identifier)
            );
            """
        )
        con.execute(
            """
            INSERT INTO vulnerability_findings
                (engagement_id, vuln_type, cve_id, title, severity, evidence,
                 target_url, parameter, description, cloud_provider, resource_id,
                 remediation_cli)
            VALUES
                (?, 'DETERMINISTIC_CLOUD_EXPOSURE', NULL,
                 'Validated public S3 alias latest exposure', 'HIGH',
                 'deterministic cloud probe evidence',
                 'aws_s3://alias-latest-bucket', 'aws_s3',
                 'Deterministic cloud exposure finding.', 'aws',
                 'alias-latest-bucket',
                 'Block public bucket access and review bucket policy.')
            """,
            (ENGAGEMENT_ID,),
        )
        con.executemany(
            """
            INSERT INTO cloud_validation_results
                (engagement_id, asset_type, identifier, provider_identifier,
                 validation_status, validation_method, http_status, evidence,
                 notes, checked_at)
            VALUES (?, ?, 'alias-latest-bucket', 'AliasLatestExact', ?, ?,
                    ?, ?, ?, ?)
            """,
            [
                (
                    ENGAGEMENT_ID,
                    "aws_s3",
                    "VALIDATED",
                    "s3_list_bucket",
                    200,
                    (
                        "<ListBucketResult><Contents><Key>"
                        "reports/customer-records.csv</Key></Contents></ListBucketResult>"
                    ),
                    "Newer canonical stable proof",
                    "2026-07-02T00:00:00Z",
                ),
                (
                    ENGAGEMENT_ID,
                    "s3",
                    "UNVERIFIED",
                    "s3_list_bucket",
                    403,
                    "older alias blocked probe",
                    "Older alias row must not override canonical proof",
                    "2026-07-01T00:00:00Z",
                ),
            ],
        )
        con.commit()
    finally:
        con.close()


def test_canonical_latest_validation_wins_over_older_alias_rows(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "engagement.db"
    _build_alias_latest_db(db_path)

    con = sqlite3.connect(db_path)
    try:
        reportability = latest_cloud_validation_reportability_index(
            con,
            ENGAGEMENT_ID,
            require_stable_proof=True,
        )
    finally:
        con.close()
    assert reportability[("aws_s3", "alias-latest-bucket")] is True

    finding_summary = DeterministicFindingEngine(db_path, ENGAGEMENT_ID).run()
    assert finding_summary.active_findings == 1
    assert finding_summary.severity_summary["HIGH"] == 1

    ctx = ContextBuilder(db_path, ENGAGEMENT_ID).build()
    titles = {str(item.get("title") or "") for item in ctx.exploits.exploited}
    assert titles == {EXPECTED_TITLE}

    inventory = {
        (str(item["asset_type"]), str(item["identifier"])): item
        for item in ctx.cloud_validation_inventory
    }
    assert set(inventory) == {("aws_s3", "alias-latest-bucket")}
    assert inventory[("aws_s3", "alias-latest-bucket")]["validation_status"] == "VALIDATED"
    assert (
        inventory[("aws_s3", "alias-latest-bucket")]["provider_identifier"]
        == "AliasLatestExact"
    )

    csv_rows = ReportSynthesizer._raw_export_csv_rows(ctx)
    finding_rows = [row for row in csv_rows if row["record_type"] == "finding"]
    validation_rows = [
        row for row in csv_rows if row["record_type"] == "cloud_validation"
    ]
    assert {row["title"] for row in finding_rows} == {EXPECTED_TITLE}
    assert len(validation_rows) == 1
    assert validation_rows[0]["cloud_asset_type"] == "aws_s3"
    assert validation_rows[0]["validation_status"] == "VALIDATED"
    assert validation_rows[0]["stored_validation_status"] == "VALIDATED"
    assert validation_rows[0]["validation_reportable"] == "True"
