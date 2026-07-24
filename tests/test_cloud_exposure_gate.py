from __future__ import annotations

import pytest

from forge.phase4.attack_path import AttackGraphBuilder
from forge.phase6.report_synthesizer import ContextBuilder
from forge.utils.cloud_exposure_gate import (
    effective_validation_status,
    is_deterministic_cloud_exposure,
    is_reportable_cloud_validation,
)


@pytest.mark.parametrize(
    ("vuln_type", "title", "asset_type", "target_url", "expected"),
    [
        ("DETERMINISTIC_CLOUD_EXPOSURE", "Any title", "", "", True),
        ("CLOUD_STORAGE_METADATA", "Public GCS metadata observed", "gcs", "", True),
        ("CLOUD_STORAGE_LISTING", "Public S3 listing exposure", "aws_s3", "", True),
        ("FIREBASE_MISCONFIG", "Validated Firebase data exposure", "firebase", "", True),
        (
            "SUPABASE_RLS",
            "Validated Supabase data exposure",
            "supabase",
            "supabase://project",
            True,
        ),
        ("PUBLIC_SERVICE", "Public admin panel detected", "", "https://example.com", False),
        ("CLOUD_STORAGE_LISTING", "Public storage listing exposure", "s3", "", True),
        (
            "CLOUD_STORAGE_LISTING",
            "Public storage listing exposure",
            "google_cloud_storage",
            "",
            True,
        ),
    ],
)
def test_cloud_exposure_gate_is_shared_by_graph_and_report(
    vuln_type: str,
    title: str,
    asset_type: str,
    target_url: str,
    expected: bool,
) -> None:
    helper_result = is_deterministic_cloud_exposure(vuln_type, title, (asset_type,))
    graph_result = AttackGraphBuilder._vuln_is_deterministic_cloud_exposure(
        vuln_type,
        title,
        asset_type,
    )
    report_result = ContextBuilder._finding_is_deterministic_cloud_exposure(
        {
            "vuln_type": vuln_type,
            "title": title,
            "parameter": asset_type,
            "target_url": target_url,
        }
    )

    assert helper_result is expected
    assert graph_result is expected
    assert report_result is expected


def test_key_provider_validation_status_does_not_become_cloud_reportable() -> None:
    evidence = "AWS STS GetCallerIdentity ok: AccountId=742931608514"

    assert effective_validation_status(
        "aws",
        "VALIDATED",
        "aws_sts_get_caller_identity",
        evidence=evidence,
    ) == "VALIDATED"
    assert not is_reportable_cloud_validation(
        "aws",
        "VALIDATED",
        "aws_sts_get_caller_identity",
        evidence=evidence,
        require_stable_proof=True,
    )


@pytest.mark.parametrize(
    ("evidence", "notes"),
    [
        ("placeholder sample metadata only", ""),
        ("{'server':'AmazonS3'}", "low-signal storage metadata"),
        ("<ok />", "honeypot metadata fixture"),
        ("demo metadata response", "synthetic probe"),
    ],
)
def test_storage_metadata_probe_gate_rejects_low_signal_validated_evidence(
    evidence: str,
    notes: str,
) -> None:
    assert not is_reportable_cloud_validation(
        "gcs",
        "VALIDATED",
        "gcs_http_probe",
        evidence=evidence,
        notes=notes,
        require_stable_proof=True,
    )
    assert (
        effective_validation_status(
            "gcs",
            "VALIDATED",
            "gcs_http_probe",
            evidence=evidence,
            notes=notes,
        )
        == "UNVERIFIED"
    )


def test_storage_metadata_probe_gate_keeps_concrete_low_severity_metadata_reviewable() -> None:
    assert is_reportable_cloud_validation(
        "aws_s3",
        "VALIDATED",
        "s3_head_probe",
        evidence="{'server': 'AmazonS3', 'x-amz-bucket-region': 'us-east-1'}",
        notes="Bucket responded to a bounded HEAD request.",
        require_stable_proof=True,
    )
