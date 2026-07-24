# Compact Review/Export Regression Sweep

Date: 2026-07-24

## State

- Current pushed commit before this docs checkpoint: `89cc545`.
- `git status --short` returned clean.
- `.forge_data/engagements` contained `0` entries.
- No live provider calls, network scans, or target probes were run.

## Verification

- `python -m pytest tests\phase6\test_report_synthesizer.py -k "key_findings or validation_proof or validation_metadata or raw_export or fallback" -q`
- Result: `8 passed, 83 deselected`
- `python -m pytest tests\reporting\test_dashboard.py::test_generate_dashboard_filters_unknown_method_graph_snapshot_vuln_nodes tests\reporting\test_dashboard.py::test_generate_dashboard_parses_mtgx_into_detail_graph_payload_when_graphml_missing tests\integration\test_webui_engagement_api.py::test_engagement_vuln_summary_api_uses_reportable_cloud_gate tests\integration\test_webui_engagement_api.py::test_engagement_api_parses_mtgx_graph_payload_when_graphml_is_missing -q`
- Result: `4 passed`
- `python -m pytest tests\phase6\test_report_cloud_exposure_gating.py tests\phase6\test_report_cloud_alias_latest.py -q`
- Result: `2 passed`

API tests emitted only existing `jose.jwt` and SQLite timestamp converter deprecation warnings.

## Next

- Audit remaining long-tail validator proof reviewability.
- Keep live provider calls mocked unless a real scoped target, ROE, and scope manifest are explicitly supplied.
