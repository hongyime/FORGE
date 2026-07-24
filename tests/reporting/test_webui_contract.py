from pathlib import Path


WEBUI_APP = Path("forge/reporting/webui/src/App.tsx")


def _app_source() -> str:
    return WEBUI_APP.read_text(encoding="utf-8")


def test_webui_graph_explorer_surfaces_edge_metadata() -> None:
    source = _app_source()

    assert "metadata?: Record<string, unknown>" in source
    assert "metadata: edge.metadata ?? {}" in source
    assert "Edge evidence" in source
    assert "metadataEntries(edge.metadata)" in source


def test_webui_fallback_samples_include_csv_report_exports() -> None:
    source = _app_source()

    assert "engagement_1001_report_20260709T014412.csv" in source
    assert "engagement_1013_report_20260709T014328.csv" in source
    assert source.count("format: 'csv', label: 'CSV'") >= 2


def test_webui_fallback_samples_include_audit_artifact_contract() -> None:
    source = _app_source()

    assert "audit_count: item.audit_count" in source
    assert "const auditArtifacts = detail.artifacts.filter((artifact) => artifact.kind === 'audit')" in source
    assert "audit_1001_manifest_20260709T014413.json" in source
    assert "kind: 'audit'" in source
    assert "label: 'Audit'" in source


def test_webui_prior_report_history_surfaces_degraded_lineage() -> None:
    source = _app_source()

    assert "historyEntry.report_write_error" in source
    assert "Write degradation: {historyEntry.report_write_error}" in source
    assert "historyEntry.findings_checksum" in source
    assert "<span className=\"mono-tag\">{historyEntry.findings_checksum}</span>" in source
    assert "report_family_count?: number" in source
    assert "Report generations" in source
    assert "item.report_family_count" in source
    assert "reportStateFilter?: string" in source
    assert "matchesReportState(item, reportStateFilter)" in source
    assert "<span>Report state</span>" in source
    assert "Raw export fallback" in source


def test_webui_separates_reportable_findings_from_validation_inventory() -> None:
    source = _app_source()

    assert "Reportable validated findings" in source
    assert "<strong>{formatCount(findingRows.length)}</strong>" in source
    assert "findingRows.length + keyFindingRows.length + cloudValidationRows.length" not in source
    assert "Validation inventory" in source
    assert "id=\"validation-inventory\"" in source
    assert "<strong>{formatCount(keyFindingRows.length + cloudValidationRows.length)}</strong>" in source
    assert "No key validation inventory rows captured yet." in source
    assert "No cloud validation inventory rows captured yet." in source
