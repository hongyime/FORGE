from __future__ import annotations

from forge.reporting.timeline import operational_timeline_events


def test_operational_timeline_events_shape_and_sort_cross_surface_rows() -> None:
    sections = {
        "audit_log": [
            {
                "When": "2026-08-12T09:00:00Z",
                "Action": "phase-start",
                "Phase": "phase1",
                "Module": "orchestrator",
                "Target": "app.acme.example",
                "Result": "ok",
            }
        ],
        "monitoring_changes": [
            {
                "Seen": "2026-08-12T11:00:00Z",
                "Change": "added",
                "Entity": "host:vpn.acme.example",
                "Before": "",
                "After": "vpn.acme.example",
                "Snapshot": "7",
                "Severity": "CRITICAL",
            }
        ],
        "cloud_validation_results": [
            {
                "Checked": "2026-08-12T10:30:00Z",
                "Asset": "payments-sensitive",
                "Status": "VALIDATED",
                "Evidence": "HTTP 200 listing",
                "Method": "s3_public_listing",
                "Type": "aws_s3",
                "Reportable": "yes",
            }
        ],
        "key_scanner_findings": [
            {
                "Validated": "2026-08-12T10:00:00Z",
                "Service": "Slack",
                "Pattern": "bot token",
                "Validation Status": "FAILED",
                "Validation Proof": "network_error",
                "Validation Method": "token_probe",
                "Backend": "gitleaks",
                "State": "open",
            }
        ],
        "vulnerability_findings": [
            {
                "Seen": "2026-08-12T09:30:00Z",
                "Title": "False positive row",
                "Severity": "LOW",
                "False+": "yes",
                "Validation Status": "UNVERIFIED",
                "Target": "https://old.acme.example",
            }
        ],
        "remediation_items": [
            {
                "Updated": "2026-08-12T08:30:00Z",
                "Title": "Fix VPN exposure",
                "Owner": "appsec",
                "Retest": "pending",
                "Ticket": "SEC-2001",
                "Finding": "monitoring_alerts:1",
                "Status": "assigned",
                "Severity": "CRITICAL",
            }
        ],
    }

    events = operational_timeline_events(
        sections,
        report_history=[
            {
                "generated_at": "2026-08-12T12:00:00Z",
                "artifact_name": "engagement_1001_report.json",
                "provider": "template",
                "export_count": 3,
                "findings_checksum": "sha256:" + ("a" * 180),
                "reportable_validation_count": 2,
                "unreportable_validation_count": 1,
            }
        ],
    )

    assert [event["category"] for event in events[:3]] == [
        "Report",
        "Monitoring change",
        "Cloud validation",
    ]
    report_event = events[0]
    assert report_event["title"] == "engagement_1001_report.json"
    assert report_event["reportability"] == "2 reportable / 1 inventory"
    assert len(report_event["summary"]) <= 260

    cloud_event = next(event for event in events if event["category"] == "Cloud validation")
    assert cloud_event["method"] == "s3_public_listing"
    assert cloud_event["reportability"] == "reportable yes"

    key_event = next(event for event in events if event["category"] == "Secret validation")
    assert key_event["reportability"] == "non-reportable failed"
    assert key_event["status"] == "open"

    finding_event = next(event for event in events if event["category"] == "Reportable finding")
    assert finding_event["reportability"] == "non-reportable false positive"

    remediation_event = next(event for event in events if event["category"] == "Remediation")
    assert remediation_event["summary"] == "owner appsec · retest pending · ticket SEC-2001"


def test_operational_timeline_events_limit_and_dashboard_wrapper_compatibility() -> None:
    sections = {
        "monitoring_alerts": [
            {
                "Updated": f"2026-08-12T10:{index:02d}:00Z",
                "Title": f"Alert {index}",
                "Type": "added_asset",
                "Entity": f"host:{index}.example",
                "Snapshot": str(index),
                "Status": "open",
                "Severity": "HIGH",
            }
            for index in range(45)
        ]
    }

    events = operational_timeline_events(sections)
    assert len(events) == 5
    assert events[0]["title"] == "Alert 4"
    assert events[-1]["title"] == "Alert 0"

    from forge.reporting.dashboard import _operational_timeline_events

    assert _operational_timeline_events(sections) == events


def test_operational_timeline_sanitizes_report_fallback_paths() -> None:
    events = operational_timeline_events(
        {},
        report_history=[
            {
                "generated_at": "2026-08-12T12:00:00Z",
                "artifact_name": "engagement_1001_report.json",
                "fallback_reason": (
                    "GGUF model not found: C:/Users/bryan/.cache/forge/models/"
                    "qwen2.5-1.5b-instruct-q4_k_m.gguf"
                ),
            }
        ],
    )

    assert events[0]["status"] == (
        "GGUF model not found; configure an LLM provider/model or regenerate after local model setup."
    )
    assert "C:/Users/bryan" not in str(events)
    assert "qwen2.5-1.5b-instruct-q4_k_m.gguf" not in str(events)


def test_operational_timeline_sanitizes_scope_manifest_assignments() -> None:
    events = operational_timeline_events(
        {
            "audit_log": [
                {
                    "When": "2026-08-12T09:00:00Z",
                    "Action": "failed",
                    "Result": (
                        "scope_manifest=C:/Users/bryan/OneDrive/01 TOOLKITS/"
                        "forgetoolkit/scope.json status=denied"
                    ),
                }
            ]
        }
    )

    assert events[0]["summary"] == "scope_manifest=[redacted] status=denied"
    assert "TOOLKITS" not in str(events)
