# React Audit Artifact And Raw CSV E2E Parity

Date: 2026-07-23

## Gate Advanced

Fallback and review parity (`SPEC.md` V3/V8/V9).

## What Changed

- React engagement summary/detail model now carries optional `audit_count`.
- Offline React fallback sample engagements include audit manifest artifacts.
- Detail quick export links now include the first audit artifact as `Audit`
  alongside report exports, detail JSON, and graph.
- The Phase 1 kill-chain raw-export fallback regression now proves CSV lineage
  fields at the end-to-end boundary:
  - `findings_checksum`
  - `report_requested_provider`
  - `report_rendered_provider`
  - `report_format`
  - `fallback_reason`
  - `report_write_error`
- The same regression now checks honeypot-suspected cloud resources stay out of
  reportable finding rows while remaining visible in validation inventory.

## Files Changed

- `forge/reporting/webui/src/App.tsx`
- `tests/phase1/test_engagement_orchestrator.py`
- `tests/reporting/test_webui_contract.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- React contract TDD before implementation:
  `python -m pytest tests/reporting/test_webui_contract.py::test_webui_fallback_samples_include_audit_artifact_contract -q --color=no`
  -> failed on missing `audit_count`.
- Kill-chain raw-export assertion pass after test correction:
  `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_kill_chain_raw_export_fallback_preserves_validated_finding_gate -q --color=no`
  -> `1 passed`.
- React contract:
  `python -m pytest tests/reporting/test_webui_contract.py::test_webui_fallback_samples_include_audit_artifact_contract tests/reporting/test_webui_contract.py::test_webui_fallback_samples_include_csv_report_exports -q --color=no`
  -> `2 passed`.
- React production build:
  `npm run build` in `forge/reporting/webui`
  -> passed.
- React lint:
  `npm run lint` in `forge/reporting/webui`
  -> exited 0 with existing hook-dependency warnings.
- Python compile:
  `python -m py_compile tests\phase1\test_engagement_orchestrator.py tests\reporting\test_webui_contract.py`
  -> passed.
- Ruff:
  `python -m ruff check tests\phase1\test_engagement_orchestrator.py tests\reporting\test_webui_contract.py`
  -> passed.
- Dashboard/API/report/webui slice:
  `python -m pytest tests/phase6/test_report_synthesizer.py::test_synthesizer_report_write_failure_falls_back_to_raw_exports tests/reporting/test_dashboard.py::test_generate_dashboard_emits_slug_routes_and_json_contract tests/integration/test_webui_engagement_api.py::test_engagement_list_and_detail_routes tests/reporting/test_webui_contract.py -q --color=no`
  -> `6 passed, 10 warnings`.
- Compact cross-phase smoke:
  `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_kill_chain_artifact_extracted_assets_validate_and_seed_next_iteration_under_scope tests/phase6/test_report_synthesizer.py::test_synthesizer_runtime_provider_failure_falls_back_to_template tests/reporting/test_dashboard.py::test_generate_dashboard_surfaces_provider_matrix_artifacts_and_validation_evidence tests/phase4/test_cloud_validate.py::test_sweep_pending_cloud_asset_validations_scope_checker_skips_denied_assets -q --color=no`
  -> `3 passed, 1 deselected`.
- Cleanup:
  `removed_pytest_engagement_dirs=1`
  `remaining_pytest_engagement_dirs=0`
- Persistent DB inventory:
  `1`, `5010`, `master.db`
- Process check:
  no Python/pytest process remains.

## Safety

Frontend review contract and test assertions only. No provider calls, live
probing, credential use, scope changes, validation-gate changes, report-gate
changes, severity changes, proxy/IP rotation, or rate-limit bypass.

## Next Task

Continue from `docs/engagement_overhaul_tasklist.md` -> `## Compact active
backlog`.
