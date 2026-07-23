# Web App Manifest Relative URL Recursion

Date: 2026-07-23

## Gate Advanced

Discovery, recursion, and artifact analysis (`SPEC.md` V1/V3/V4/V5).

## What Changed

- Added `web_manifest_urls` to `forge.utils.artifact_web_manifest`.
- Source-gated `manifest.json` and `webmanifest` artifacts now resolve relative
  URL pivots from `start_url`, `scope`, `shortcuts[].url`,
  `share_target.action`, `protocol_handlers[].url`, `icons[].src`, and
  `screenshots[].src`.
- Added a thin `web_manifest_metadata` URL-family adapter in
  `forge.engagement_orchestrator.ArtifactQueueProcessor`.
- Generic JSON lookalikes remain excluded from the Web App Manifest-specific
  parser.

## Files Changed

- `forge/utils/artifact_web_manifest.py`
- `forge/engagement_orchestrator.py`
- `tests/phase1/test_artifact_web_manifest_metadata.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- TDD before implementation:
  `python -m pytest tests/phase1/test_artifact_web_manifest_metadata.py -q --color=no`
  -> failed with missing `web_manifest_urls`.
- Focused manifest plus adjacent format/label checks:
  `python -m pytest tests/phase1/test_artifact_web_manifest_metadata.py tests/phase1/test_artifact_public_metadata_labels.py tests/phase1/test_artifact_api_format_labels.py -q --color=no`
  -> `4 passed`.
- Compile:
  `python -m py_compile forge\utils\artifact_web_manifest.py forge\engagement_orchestrator.py tests\phase1\test_artifact_web_manifest_metadata.py`
  -> passed.
- Ruff:
  `python -m ruff check forge\utils\artifact_web_manifest.py forge\engagement_orchestrator.py tests\phase1\test_artifact_web_manifest_metadata.py`
  -> passed.
- Exact engagement-backed manifest/root metadata tests:
  `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_web_app_manifest_artifacts tests/phase1/test_engagement_orchestrator.py::test_kill_chain_dry_run_processes_remote_root_metadata_seeds -q --color=no -o addopts=''`
  -> `2 passed`.
- Compact cross-phase smoke:
  `python -m pytest tests/phase1/test_artifact_web_manifest_metadata.py tests/phase1/test_artifact_jwks_metadata.py tests/phase1/test_engagement_orchestrator.py::test_kill_chain_artifact_extracted_assets_validate_and_seed_next_iteration_under_scope tests/phase6/test_report_synthesizer.py::test_synthesizer_runtime_provider_failure_falls_back_to_template tests/reporting/test_dashboard.py::test_generate_dashboard_surfaces_provider_matrix_artifacts_and_validation_evidence tests/phase4/test_cloud_validate.py::test_sweep_pending_cloud_asset_validations_scope_checker_skips_denied_assets -q --color=no`
  -> `7 passed, 1 deselected`.
- Cleanup:
  no test-owned engagement DBs found.
- Persistent engagement inventory:
  `1`, `5010`, `master.db`.

## Safety

Passive static Web App Manifest parsing only. No app launch, app-store lookup,
manifest fetch expansion, provider call, live probing, credential use, scope
relaxation, proxy/IP rotation, rate-limit bypass, validation-gate change,
report-gate change, or severity change.

## Next Task

Continue from `docs/engagement_overhaul_tasklist.md` -> `## Compact active
backlog`. Prefer another concrete passive parser, identity normalization,
provider-proof, graph/report parity, or cleanup proof gap.
