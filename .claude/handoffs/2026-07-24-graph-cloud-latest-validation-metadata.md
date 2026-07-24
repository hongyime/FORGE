# Graph Cloud Latest Validation Metadata

Date: 2026-07-24

## Completed

- Added a latest cloud-validation metadata index in `forge/reporting/dashboard.py`.
- Updated dashboard/API graph payload filtering so retained CLOUD nodes are refreshed from the latest matching `cloud_validation_results` row.
- Retained CLOUD nodes now show latest effective `validation_status`, raw `stored_validation_status`, `validation_method`, `validation_reportable`, `validation_checked_at`, optional `validation_http_status`, and scrubbed evidence/notes summaries.
- Deterministic VULN/key graph-node filtering behavior is unchanged; stale finding nodes are still removed while CLOUD inventory remains visible for review.

## Verification

- `python -m ruff check forge\reporting\dashboard.py forge\reporting\graph_validation_metadata.py tests\reporting\test_dashboard.py tests\integration\test_webui_engagement_api.py`
- `python -m py_compile forge\reporting\dashboard.py forge\reporting\graph_validation_metadata.py`
- `python -m pytest tests\reporting\test_dashboard.py::test_generate_dashboard_filters_unknown_method_graph_snapshot_vuln_nodes tests\integration\test_webui_engagement_api.py::test_engagement_vuln_summary_api_uses_reportable_cloud_gate -q`
- `python -m pytest tests\reporting\test_dashboard.py::test_generate_dashboard_filters_unknown_method_graph_snapshot_vuln_nodes tests\reporting\test_dashboard.py::test_generate_dashboard_filters_malformed_deterministic_cloud_findings tests\reporting\test_dashboard.py::test_generate_dashboard_parses_mtgx_into_detail_graph_payload_when_graphml_missing -q`
- `python -m pytest tests\integration\test_webui_engagement_api.py::test_engagement_vuln_summary_api_uses_reportable_cloud_gate tests\integration\test_webui_engagement_api.py::test_engagement_detail_api_filters_malformed_deterministic_cloud_findings tests\integration\test_webui_engagement_api.py::test_engagement_api_parses_mtgx_graph_payload_when_graphml_is_missing -q`

Results: focused stale-node slice `2 passed`; adjacent static graph-validation slice `3 passed`; adjacent live API graph-validation slice `3 passed`. API tests emitted only existing `jose.jwt` and SQLite timestamp converter deprecation warnings.

## Next

- Audit raw CSV proof/detail parity for provider-specific validators or remaining long-tail validator proof reviewability.
- Keep live provider calls mocked unless a real scoped target, ROE, and scope manifest are explicitly supplied.
