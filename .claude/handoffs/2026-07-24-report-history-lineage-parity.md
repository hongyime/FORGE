# Report History Lineage Parity

## Result
- Static dashboard report-history cards now show historical report write-degradation details and findings checksums, not only fallback reason/export count.
- React detail report-history cards now show the same historical write-degradation and checksum metadata.
- Live API raw-export detail coverage now asserts the full degraded lineage: requested provider, upstream/render backend, fallback reason, write error, findings checksum, raw-export status, exports, artifacts, and raw JSON/CSV downloads.

## Changed Files
- `forge/reporting/dashboard.py`
- `forge/reporting/webui/src/App.tsx`
- `tests/reporting/test_dashboard.py`
- `tests/reporting/test_webui_contract.py`
- `tests/integration/test_webui_engagement_api.py`

## Verification
- `python -m compileall -q forge\reporting\dashboard.py tests\reporting\test_dashboard.py tests\integration\test_webui_engagement_api.py tests\reporting\test_webui_contract.py`
- `ruff check forge\reporting\dashboard.py tests\reporting\test_dashboard.py tests\integration\test_webui_engagement_api.py tests\reporting\test_webui_contract.py`
- `python -m pytest tests\reporting\test_dashboard.py::test_generate_dashboard_prefers_latest_report_family_and_preserves_history tests\integration\test_webui_engagement_api.py::test_engagement_detail_prefers_latest_report_family_and_preserves_history tests\integration\test_webui_engagement_api.py::test_engagement_detail_surfaces_raw_export_report_family tests\reporting\test_webui_contract.py::test_webui_prior_report_history_surfaces_degraded_lineage -q --color=no`: `4 passed`
- `python -m pytest tests\reporting\test_dashboard.py::test_generate_dashboard_prefers_latest_report_family_and_preserves_history tests\reporting\test_dashboard.py::test_generate_dashboard_surfaces_raw_export_report_family tests\integration\test_webui_engagement_api.py::test_engagement_detail_prefers_latest_report_family_and_preserves_history tests\integration\test_webui_engagement_api.py::test_engagement_detail_surfaces_raw_export_report_family tests\reporting\test_webui_contract.py -q --color=no`: `8 passed, 6 warnings`
- `npm run build` in `forge/reporting/webui`: passed
- `npm run lint` in `forge/reporting/webui`: completed with existing React hook dependency warnings in unrelated sections
- `cleanup_pytest_engagement_dbs()`: `removed=4 remaining=0`, post-scan `0`

## Safety
- No live provider or target calls were made.
- Changes are display/API contract assertions over existing generated report artifacts only.
- Raw-export files are served through the existing engagement artifact endpoint.

## Next
- Continue with another concrete provider/export parity gap or mocked E2E acceptance gap found by current-code audit.
