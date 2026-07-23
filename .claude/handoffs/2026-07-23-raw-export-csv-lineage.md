# Raw Export CSV Lineage Parity

Date: 2026-07-23

## Gate Advanced

Fallback and review parity (`SPEC.md` V3/V8/V9, T5).

## What Changed

- Phase 6 CSV exports now include report-lineage metadata matching JSON export
  payloads:
  - `findings_checksum`
  - `report_requested_provider`
  - `report_rendered_provider`
  - `report_format`
  - `report_generated_at`
  - `fallback_reason`
  - `report_write_error`
- Normal companion CSV exports receive the same checksum/provider lineage.
- Last-resort raw-export CSV files include fallback reason and write-error
  detail, so CSV-only consumers can audit the render degradation path without
  opening the JSON.

## Files Changed

- `forge/phase6/report_synthesizer.py`
- `tests/phase6/test_report_synthesizer.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- TDD before implementation:
  `python -m pytest tests/phase6/test_report_synthesizer.py::test_synthesizer_report_write_failure_falls_back_to_raw_exports -q --color=no`
  -> failed with `KeyError: 'findings_checksum'`.
- Compile:
  `python -m py_compile forge\phase6\report_synthesizer.py tests\phase6\test_report_synthesizer.py`
  -> passed.
- Ruff:
  `python -m ruff check forge\phase6\report_synthesizer.py tests\phase6\test_report_synthesizer.py`
  -> passed.
- Focused Phase 6 fallback:
  `python -m pytest tests/phase6/test_report_synthesizer.py::test_synthesizer_report_write_failure_falls_back_to_raw_exports tests/phase6/test_report_synthesizer.py::test_synthesise_output_path_json_mirrors_raw_export_fallback tests/phase6/test_report_synthesizer.py::test_synthesizer_runtime_provider_failure_falls_back_to_template -q --color=no`
  -> `3 passed`.
- Phase 6 raw-export/fallback selector:
  `python -m pytest tests/phase6/test_report_synthesizer.py -k "raw_export or fallback or checksum or lineage" -q --color=no`
  -> `4 passed, 78 deselected`.
- Cloud-exposure raw fallback gate:
  `python -m pytest tests/phase6/test_report_cloud_exposure_gating.py -q --color=no`
  -> `1 passed`.
- Dashboard/API raw-export detail checks:
  `python -m pytest tests/reporting/test_dashboard.py::test_generate_dashboard_surfaces_raw_export_report_family tests/integration/test_webui_engagement_api.py::test_engagement_detail_surfaces_raw_export_report_family -q --color=no`
  -> `2 passed, 2 warnings`.
- Compact cross-phase smoke:
  `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_kill_chain_artifact_extracted_assets_validate_and_seed_next_iteration_under_scope tests/phase6/test_report_synthesizer.py::test_synthesizer_runtime_provider_failure_falls_back_to_template tests/reporting/test_dashboard.py::test_generate_dashboard_surfaces_provider_matrix_artifacts_and_validation_evidence tests/phase4/test_cloud_validate.py::test_sweep_pending_cloud_asset_validations_scope_checker_skips_denied_assets -q --color=no`
  -> `3 passed, 1 deselected`.
- Cleanup:
  `removed_pytest_engagement_dirs=3`
  `remaining_pytest_engagement_dirs=0`
- Persistent DB inventory:
  `1`, `5010`, `master.db`
- Process check:
  no Python/pytest process remains.

## Safety

Report export metadata parity only. No LLM/provider call expansion, live
probing, credential use, scope changes, validation-gate changes, report-gate
changes, severity changes, proxy/IP rotation, or rate-limit bypass.

## Next Task

Continue from `docs/engagement_overhaul_tasklist.md` -> `## Compact active
backlog`.
