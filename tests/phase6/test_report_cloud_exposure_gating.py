from __future__ import annotations

import csv
import json
import sqlite3
from pathlib import Path

from forge.phase6.report_synthesizer import ContextBuilder, ReportSynthesizer


ENGAGEMENT_ID = 606


def _create_cloud_exposure_db(path: Path) -> None:
    con = sqlite3.connect(path)
    try:
        con.executescript(
            """
            CREATE TABLE engagements (
                id INTEGER PRIMARY KEY,
                name TEXT,
                status TEXT,
                operator TEXT,
                start_date TEXT,
                end_date TEXT
            );
            INSERT INTO engagements VALUES
                (606, 'Phase 6 Cloud Gate', 'ACTIVE', 'analyst', '2026-07-01', '2026-07-02');

            CREATE TABLE engagement_scope (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER,
                scope_entry TEXT
            );
            INSERT INTO engagement_scope (engagement_id, scope_entry)
                VALUES (606, 'example.com');

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
                remediation_cli TEXT
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
                checked_at TEXT
            );
            """
        )
        findings = [
            (
                "DETERMINISTIC_CLOUD_EXPOSURE",
                "Latest validated public S3 bucket listing exposure",
                "aws_s3://validated-bucket",
                "aws_s3",
                "aws",
                "validated-bucket",
            ),
            (
                "DETERMINISTIC_CLOUD_EXPOSURE",
                "Stale validated public S3 bucket listing exposure",
                "aws_s3://stale-bucket",
                "aws_s3",
                "aws",
                "stale-bucket",
            ),
            (
                None,
                "Public Google Cloud Storage metadata observed",
                "gcs://metadata-bucket",
                "gcs",
                "gcp",
                "metadata-bucket",
            ),
            (
                "DETERMINISTIC_CLOUD_EXPOSURE",
                "Manual note public S3 bucket exposure",
                "aws_s3://manual-note-bucket",
                "aws_s3",
                "aws",
                "manual-note-bucket",
            ),
        ]
        con.executemany(
            """
            INSERT INTO vulnerability_findings
                (engagement_id, vuln_type, cve_id, title, severity, evidence, target_url,
                 parameter, description, cloud_provider, resource_id, remediation_cli)
            VALUES (606, ?, NULL, ?, 'HIGH', 'deterministic cloud probe evidence', ?,
                    ?, 'Deterministic cloud exposure finding.', ?, ?,
                    'Remediate public cloud exposure.')
            """,
            findings,
        )
        validations = [
            (
                "aws_s3",
                "validated-bucket",
                "UNVERIFIED",
                "s3_list_bucket",
                403,
                "old blocked probe",
                "2026-07-01T00:00:00Z",
            ),
            (
                "aws_s3",
                "validated-bucket",
                "VALIDATED",
                "s3_list_bucket",
                200,
                (
                    "<ListBucketResult><Contents><Key>prod/customer-records.csv"
                    "</Key></Contents></ListBucketResult>"
                ),
                "2026-07-02T00:00:00Z",
            ),
            (
                "stripe",
                "acct-unsupported",
                "UNSUPPORTED",
                "registry_dispatch",
                None,
                "token=raw-validation-secret unsupported provider",
                "2026-07-02T00:00:00Z",
            ),
            (
                "aws",
                "742931608514",
                "VALIDATED",
                "aws_sts_get_caller_identity",
                200,
                "AWS STS GetCallerIdentity ok: AccountId=742931608514",
                "2026-07-02T00:00:01Z",
            ),
            (
                "aws_s3",
                "stale-bucket",
                "VALIDATED",
                "s3_list_bucket",
                200,
                "old object metadata listing",
                "2026-07-01T00:00:00Z",
            ),
            (
                "aws_s3",
                "stale-bucket",
                "UNVERIFIED",
                "s3_list_bucket",
                403,
                "latest blocked probe",
                "2026-07-02T00:00:00Z",
            ),
            (
                "gcs",
                "metadata-bucket",
                "VALIDATED",
                "gcs_http_probe",
                200,
                "placeholder sample metadata only",
                "2026-07-02T00:00:00Z",
            ),
            (
                "aws_s3",
                "manual-note-bucket",
                "VALIDATED",
                "manual_validated_note",
                200,
                "operator note says bucket was public",
                "2026-07-02T00:00:00Z",
            ),
        ]
        con.executemany(
            """
            INSERT INTO cloud_validation_results
                (engagement_id, asset_type, identifier, validation_status, validation_method,
                 http_status, evidence, checked_at)
            VALUES (606, ?, ?, ?, ?, ?, ?, ?)
            """,
            validations,
        )
        con.commit()
    finally:
        con.close()


def test_report_exports_gate_deterministic_cloud_exposures_on_latest_validated_status(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "engagement.db"
    _create_cloud_exposure_db(db_path)

    ctx = ContextBuilder(db_path, ENGAGEMENT_ID).build()
    context_titles = {str(item.get("title") or "") for item in ctx.exploits.exploited}

    assert "Latest validated public S3 bucket listing exposure" in context_titles
    assert "Stale validated public S3 bucket listing exposure" not in context_titles
    assert "Public Google Cloud Storage metadata observed" not in context_titles
    assert "Manual note public S3 bucket exposure" not in context_titles
    inventory_by_identifier = {
        str(item["identifier"]): item for item in ctx.cloud_validation_inventory
    }
    assert inventory_by_identifier["acct-unsupported"]["validation_status"] == "UNSUPPORTED"
    assert inventory_by_identifier["acct-unsupported"]["evidence_summary"] == (
        "token=[REDACTED] unsupported provider"
    )
    assert inventory_by_identifier["742931608514"]["validation_status"] == "VALIDATED"
    assert inventory_by_identifier["742931608514"]["stored_validation_status"] == "VALIDATED"
    assert inventory_by_identifier["742931608514"]["validation_reportable"] is False
    assert inventory_by_identifier["742931608514"]["method"] == "aws_sts_get_caller_identity"
    assert "prod/customer-records.csv" in inventory_by_identifier["validated-bucket"][
        "evidence_summary"
    ]
    assert inventory_by_identifier["manual-note-bucket"]["validation_status"] == "UNVERIFIED"
    assert inventory_by_identifier["manual-note-bucket"]["stored_validation_status"] == "VALIDATED"
    assert inventory_by_identifier["manual-note-bucket"]["validation_reportable"] is False
    assert inventory_by_identifier["manual-note-bucket"]["method"] == "manual_validated_note"
    assert inventory_by_identifier["metadata-bucket"]["validation_status"] == "UNVERIFIED"
    assert inventory_by_identifier["metadata-bucket"]["stored_validation_status"] == "VALIDATED"
    assert inventory_by_identifier["metadata-bucket"]["validation_reportable"] is False
    assert inventory_by_identifier["metadata-bucket"]["method"] == "gcs_http_probe"
    validated_finding = next(
        item
        for item in ctx.exploits.exploited
        if item.get("resource_id") == "validated-bucket"
    )
    assert "prod/customer-records.csv" in validated_finding[
        "validation_evidence_summary"
    ]

    csv_titles = {
        str(row["title"])
        for row in ReportSynthesizer._raw_export_csv_rows(ctx)
        if row["record_type"] == "finding"
    }
    assert csv_titles == {"Latest validated public S3 bucket listing exposure"}
    validation_csv_rows = [
        row
        for row in ReportSynthesizer._raw_export_csv_rows(ctx)
        if row["record_type"] == "cloud_validation"
    ]
    assert {row["cloud_identifier"] for row in validation_csv_rows} >= {
        "validated-bucket",
        "stale-bucket",
        "metadata-bucket",
        "acct-unsupported",
        "742931608514",
    }

    synth = ReportSynthesizer(
        db_path=db_path,
        output_dir=tmp_path / "report",
        provider="template",
        assume_yes=True,
    )
    report_path = synth.generate(ENGAGEMENT_ID)
    markdown = report_path.read_text(encoding="utf-8")
    payload = json.loads(report_path.with_suffix(".json").read_text(encoding="utf-8"))
    exported_titles = {
        str(item.get("title") or "")
        for item in payload["context"]["exploits"]["exploited"]
    }

    assert "Latest validated public S3 bucket listing exposure" in markdown
    assert "Stale validated public S3 bucket listing exposure" not in markdown
    assert "Public Google Cloud Storage metadata observed" not in markdown
    assert "Manual note public S3 bucket exposure" not in markdown
    assert exported_titles == {"Latest validated public S3 bucket listing exposure"}
    assert {
        item["validation_status"]
        for item in payload["context"]["cloud_validation_inventory"]
        if item["identifier"] == "acct-unsupported"
    } == {"UNSUPPORTED"}

    raw_synth = ReportSynthesizer(
        db_path=db_path,
        output_dir=tmp_path / "raw",
        provider="template",
        assume_yes=True,
    )

    def _force_raw_export(*_args: object, **_kwargs: object) -> None:
        raise OSError("force raw export")

    monkeypatch.setattr(raw_synth, "_write_companion_exports", _force_raw_export)
    raw_path = raw_synth.generate(ENGAGEMENT_ID)
    raw_payload = json.loads(raw_path.read_text(encoding="utf-8"))
    raw_titles = {
        str(item.get("title") or "")
        for item in raw_payload["context"]["exploits"]["exploited"]
    }
    with raw_path.with_suffix(".csv").open(encoding="utf-8", newline="") as handle:
        raw_csv_titles = {
            row["title"]
            for row in csv.DictReader(handle)
            if row["record_type"] == "finding"
        }
    with raw_path.with_suffix(".csv").open(encoding="utf-8", newline="") as handle:
        raw_validation_rows = [
            row
            for row in csv.DictReader(handle)
            if row["record_type"] == "cloud_validation"
        ]

    assert raw_payload["format"] == "raw_export"
    assert raw_titles == {"Latest validated public S3 bucket listing exposure"}
    assert raw_csv_titles == {"Latest validated public S3 bucket listing exposure"}
    assert any(
        row["cloud_identifier"] == "acct-unsupported"
        and row["validation_status"] == "UNSUPPORTED"
        for row in raw_validation_rows
    )
    assert any(
        row["cloud_identifier"] == "manual-note-bucket"
        and row["validation_status"] == "UNVERIFIED"
        and row["stored_validation_status"] == "VALIDATED"
        and row["validation_reportable"] == "False"
        for row in raw_validation_rows
    )
    assert any(
        row["cloud_asset_type"] == "aws"
        and row["cloud_identifier"] == "742931608514"
        and row["validation_status"] == "VALIDATED"
        and row["validation_reportable"] == "False"
        for row in raw_validation_rows
    )
    assert "raw-validation-secret" not in json.dumps(raw_payload)
