# Dashboard Malformed Cloud Finding Gate

Date: 2026-07-24

## Completed

- Static dashboard and live API review now fail closed for malformed deterministic cloud exposure findings.
- `forge/reporting/dashboard.py` now requires a deterministic cloud finding row to resolve both validation asset and identifier, and to have a reportable validation-index proof, before it can enter reportable finding tables, severity counts, or `/vuln-summary`.
- Imported graph payload filtering now removes deterministic cloud VULN nodes when the node lacks validation asset/identifier metadata or has no reportable validation-index proof. Dangling edges and critical-path refs are pruned by the existing graph filter.
- The static dashboard test fixture now includes matching deterministic Firebase validation proof when it expects the base `Validated Firebase data exposure` row to remain reportable.

## Files Changed

- `forge/reporting/dashboard.py`
- `tests/reporting/test_dashboard.py`
- `tests/integration/test_webui_engagement_api.py`
- `SPEC.md`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- `python -m py_compile forge\reporting\dashboard.py tests\reporting\test_dashboard.py tests\integration\test_webui_engagement_api.py`
- `python -m ruff check forge\reporting\dashboard.py tests\reporting\test_dashboard.py tests\integration\test_webui_engagement_api.py`
- `python -m pytest -q tests\reporting\test_dashboard.py::test_generate_dashboard_filters_malformed_deterministic_cloud_findings tests\integration\test_webui_engagement_api.py::test_engagement_detail_api_filters_malformed_deterministic_cloud_findings`
- `python -m pytest -q tests\reporting\test_dashboard.py`
- `python -m pytest -q tests\integration\test_webui_engagement_api.py`
- `python -m pytest -q tests\phase6 -k "cloud_exposure or cloud_validation or deterministic_cloud"`
- Pytest engagement cleanup: `removed=4 remaining=0`

## Review

- Sidecar reviewer `Hume` independently confirmed the fail-open dashboard row gate, fail-open graph VULN node gate, and API inheritance paths before the patch.

## Next Gate

Fix latest-validation proof parity for linked key/cloud confirmations. Add duplicate validation-row regressions where an older `VALIDATED` proof and a newer `UNVERIFIED` or non-reportable proof disagree, then make latest matching validation evidence win consistently across deterministic finding synthesis, Phase 6 report/raw exports, dashboard/API summaries, and graph filtering.
