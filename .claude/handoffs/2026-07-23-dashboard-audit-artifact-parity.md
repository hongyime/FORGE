# Dashboard Audit Artifact Parity

Date: 2026-07-23

## Gate Advanced

Review parity (`SPEC.md` V3/V8, T4).

## What Changed

- Static dashboard artifact discovery now separates engagement report exports
  from audit exports.
- Static dashboard detail JSON/HTML surfaces audit files as `kind: "audit"`.
- Live web API detail payloads expose audit files as `kind: "audit"`.
- `report_count` remains report-only and `audit_count` is exposed separately.
- The existing slug artifact download route now serves audit artifacts too.

## Files Changed

- `forge/reporting/dashboard.py`
- `forge/webui/app.py`
- `tests/reporting/test_dashboard.py`
- `tests/integration/test_webui_engagement_api.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- TDD before implementation:
  `python -m pytest tests/reporting/test_dashboard.py::test_generate_dashboard_emits_slug_routes_and_json_contract tests/integration/test_webui_engagement_api.py::test_engagement_list_and_detail_routes -q --color=no`
  -> `2 failed` because audit JSON inflated `report_count`.
- Compile:
  `python -m py_compile forge\reporting\dashboard.py forge\webui\app.py tests\reporting\test_dashboard.py tests\integration\test_webui_engagement_api.py`
  -> passed.
- Ruff:
  `python -m ruff check forge\reporting\dashboard.py forge\webui\app.py tests\reporting\test_dashboard.py tests\integration\test_webui_engagement_api.py`
  -> passed.
- Focused route regression:
  `python -m pytest tests/reporting/test_dashboard.py::test_generate_dashboard_emits_slug_routes_and_json_contract tests/integration/test_webui_engagement_api.py::test_engagement_list_and_detail_routes -q --color=no`
  -> `2 passed`.
- Dashboard parity slice:
  `python -m pytest tests/reporting/test_dashboard.py -k "artifact or route or manifest or provider_matrix or raw_export" -q --color=no`
  -> `7 passed, 10 deselected`.
- Web API parity slice:
  `python -m pytest tests/integration/test_webui_engagement_api.py -k "detail_routes or artifact or manifest or provider_matrix or raw_export" -q --color=no`
  -> `8 passed, 19 deselected`.
- Compact cross-phase smoke:
  `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_kill_chain_artifact_extracted_assets_validate_and_seed_next_iteration_under_scope tests/phase6/test_report_synthesizer.py::test_synthesizer_runtime_provider_failure_falls_back_to_template tests/reporting/test_dashboard.py::test_generate_dashboard_surfaces_provider_matrix_artifacts_and_validation_evidence tests/phase4/test_cloud_validate.py::test_sweep_pending_cloud_asset_validations_scope_checker_skips_denied_assets -q --color=no`
  -> `3 passed, 1 deselected`.
- Cleanup:
  `removed_pytest_engagement_dirs=2`
  `remaining_pytest_engagement_dirs=0`
- Persistent DB inventory:
  `1`, `5010`, `master.db`
- Process check:
  no Python/pytest process remains.

## Safety

Dashboard/API artifact classification and tests only. No live probing, provider
calls, credential use, scope changes, validation-gate changes, report-gate
changes, severity changes, proxy/IP rotation, or rate-limit bypass.

## Next Task

Continue from `docs/engagement_overhaul_tasklist.md` -> `## Compact active
backlog`.
