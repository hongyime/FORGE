from __future__ import annotations

from forge.reporting.evidence_provenance import evidence_provenance_section_rows


def test_evidence_provenance_section_rows_summarize_major_surfaces() -> None:
    sections = {
        "artifact_queue": [
            {
                "Artifact": "https://cdn.acme.example/app.js",
                "Origin": "crawl_results",
                "Status": "parsed",
                "Type": "javascript",
                "Queued": "2026-08-12T10:00:00Z",
            }
        ],
        "crawl_results": [
            {
                "URL": "https://app.acme.example",
                "Source": "crawler",
                "Status": "fetched",
                "Tech": "nginx",
                "Seen": "2026-08-12T10:00:01Z",
            }
        ],
        "cloud_validation_results": [
            {
                "Type": "aws_s3",
                "Asset": "payments-sensitive",
                "Method": "s3_public_listing",
                "Reportable": "no",
                "Status": "VALIDATED",
            }
        ],
        "vulnerability_findings": [
            {
                "Type": "EXPOSED_SERVICE",
                "Validation Method": "passive",
                "Verified": "yes",
                "Severity": "HIGH",
            }
        ],
        "passive_vulns": [
            {
                "Plugin": "nuclei",
                "Validation Method": "template",
                "Verified": "no",
                "Severity": "LOW",
            }
        ],
        "key_scanner_findings": [
            {
                "Backend": "gitleaks",
                "Validation Method": "token_probe",
                "Validation Status": "FAILED",
                "State": "open",
            }
        ],
        "secret_lifecycle_items": [
            {
                "Owner Source": "manual",
                "Lifecycle": "revoked",
                "Repository": "acme/app",
            }
        ],
        "monitoring_snapshots": [{"Kind": "scheduled", "Snapshot": "7"}],
        "monitoring_trend_points": [{"Kind": "trend", "Snapshot": "7"}],
        "monitoring_changes": [{"Type": "host", "Entity": "host:vpn.acme.example"}],
        "monitoring_alerts": [
            {"Type": "added_asset", "Status": "open", "Snapshot": "7"},
            {"Type": "added_finding", "Status": "closed", "Snapshot": "7"},
        ],
        "remediation_items": [
            {
                "Finding": "monitoring_alerts:1",
                "Retest": "pending",
                "Risk Review": "requires_review",
                "Status": "assigned",
                "Ticket": "SEC-2001",
            }
        ],
        "remediation_review_queue": [
            {
                "Finding": "vulnerability_findings:2",
                "Ticket Sync": "jira failed",
                "Retest": "failed",
                "Risk Review": "expired",
                "Status": "needs_review",
                "Reason": "ticket sync failed",
            }
        ],
        "active_validation_jobs": [{"Target": "app.acme.example", "Method": "http_head"}],
        "active_validation_runs": [
            {
                "Target": "app.acme.example",
                "Proof": "http_200",
                "Method": "http_head",
                "Coverage": "safe",
                "Status": "completed",
            }
        ],
        "asset_entities": [{"Type": "host", "Source": "hosts"}],
        "asset_relationships": [{"Type": "owned_by", "Owners": "Network Team"}],
        "asset_graph_fix_candidates": [
            {
                "Reason": "remediate_highest_risk_finding",
                "Owner": "appsec",
                "Action": "create SEC-2001",
                "Score": "95",
            }
        ],
    }

    rows = evidence_provenance_section_rows(sections)
    by_surface = {row["Surface"]: row for row in rows}

    assert [row["Surface"] for row in rows] == [
        "Artifacts and crawl",
        "Cloud validation",
        "Reportable findings",
        "Secrets",
        "Monitoring",
        "Remediation workflow",
        "Active validation",
        "Asset graph",
    ]
    assert by_surface["Artifacts and crawl"]["Records"] == "2"
    assert by_surface["Artifacts and crawl"]["Validation"] == "parsed=1; fetched=1"
    assert by_surface["Cloud validation"]["Tables"] == "cloud_validation_results"
    assert by_surface["Cloud validation"]["Validation"] == "s3_public_listing"
    assert by_surface["Cloud validation"]["Reportability"] == "no=1"
    assert by_surface["Reportable findings"]["Reportability"] == "reportable filtered"
    assert by_surface["Secrets"]["Tables"] == "key_scanner_findings; secret_lifecycle_items"
    assert "token_probe" in by_surface["Secrets"]["Validation"]
    assert by_surface["Monitoring"]["Reportability"] == "open_alerts=1"
    assert "monitoring_alerts" in by_surface["Monitoring"]["Tables"]
    assert "assigned=1" in by_surface["Remediation workflow"]["Workflow"]
    assert "safe" in by_surface["Active validation"]["Reportability"]
    assert "asset_graph_*" in by_surface["Asset graph"]["Tables"]


def test_evidence_provenance_section_rows_empty_truncates_and_preserves_wrapper() -> None:
    assert evidence_provenance_section_rows({}) == []

    long_value = "x" * 220
    sections = {
        "asset_entities": [
            {
                "Type": long_value,
                "Source": long_value,
                "Reason": long_value,
                "Action": long_value,
            }
        ]
    }
    rows = evidence_provenance_section_rows(sections)
    assert rows[0]["Surface"] == "Asset graph"
    assert len(rows[0]["Provenance"]) <= 160
    assert len(rows[0]["Reportability"]) <= 160
    assert len(rows[0]["Workflow"]) <= 160

    from forge.reporting.dashboard import _evidence_provenance_section_rows

    assert _evidence_provenance_section_rows(sections) == rows
