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
