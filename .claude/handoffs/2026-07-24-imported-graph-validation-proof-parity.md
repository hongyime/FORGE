# Imported Graph Validation-Proof Parity

Date: 2026-07-24

## Completed

- Normalized imported GraphML/MTGX `validation_detail` metadata in `forge/reporting/dashboard.py` into `validation_status`, `validation_method`, and scrubbed `validation_proof`.
- Applied the normalization to `forge.*` MTGX properties, plain GraphML `validation_detail` data fields, and `metadata_json` payloads that contain `validation_detail`.
- Kept existing sensitive metadata stripping intact; proof text is sanitized through `safe_validation_summary`.
- Updated static dashboard and live engagement API MTGX fixtures so returned graph payloads prove the same validation-proof shape as generated graph JSON.

## Verification

- `python -m ruff check forge\reporting\dashboard.py tests\reporting\test_dashboard.py tests\integration\test_webui_engagement_api.py`
- `python -m py_compile forge\reporting\dashboard.py`
- `python -m pytest tests\reporting\test_dashboard.py::test_generate_dashboard_parses_mtgx_into_detail_graph_payload_when_graphml_missing tests\integration\test_webui_engagement_api.py::test_engagement_api_parses_mtgx_graph_payload_when_graphml_is_missing -q`
- Result: `2 passed`; the API test emitted only the existing `jose.jwt` `datetime.utcnow()` deprecation warning.

## Subagent Review

Reviewer subagent `Tesla the 2nd` independently found the same gap:
imported graph payloads preserved free-form `validation_detail` but did not
return parsed `validation_status`, `validation_method`, or `validation_proof`.

## Next

- Audit another concrete deterministic review/export parity gap.
- Best candidate: graph snapshot stale cloud metadata refresh, raw CSV proof/detail parity for provider-specific validators, or remaining long-tail validator proof reviewability.
- Keep live provider calls mocked unless a real scoped target, ROE, and scope manifest are explicitly supplied.
