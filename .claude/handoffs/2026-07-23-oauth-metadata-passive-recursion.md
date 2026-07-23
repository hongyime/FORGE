# OAuth/OpenID Metadata Passive Recursion

Date: 2026-07-23

## Gate Advanced

Discovery, recursion, and artifact analysis (`SPEC.md` V1/V3/V4/V5).

## What Changed

- Added `forge.utils.artifact_oauth_metadata`.
- Source-gated OAuth/OIDC `.well-known` labels now resolve relative endpoint and
  documentation URL fields into deterministic recursive URL pivots:
  `openid-configuration`, `oauth-authorization-server`,
  `oauth-protected-resource`, `openid-federation`, `uma2-configuration`, and
  `smart-configuration`.
- Added a thin `oauth_metadata` URL-family adapter in
  `forge.engagement_orchestrator.ArtifactQueueProcessor`.
- Generic JSON lookalikes remain excluded from the OAuth-specific parser.

## Files Changed

- `forge/utils/artifact_oauth_metadata.py`
- `forge/engagement_orchestrator.py`
- `tests/phase1/test_artifact_oauth_metadata.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- TDD before implementation:
  `python -m pytest tests/phase1/test_artifact_oauth_metadata.py -q --color=no`
  -> failed with missing `forge.utils.artifact_oauth_metadata`.
- Focused helper/integration plus adjacent well-known metadata:
  `python -m pytest tests/phase1/test_artifact_oauth_metadata.py tests/phase1/test_artifact_well_known_service_metadata.py tests/phase1/test_artifact_well_known_identity_metadata.py tests/phase1/test_artifact_well_known_api_metadata.py -q --color=no`
  -> `8 passed`.
- Compile:
  `python -m py_compile forge\utils\artifact_oauth_metadata.py forge\engagement_orchestrator.py tests\phase1\test_artifact_oauth_metadata.py`
  -> passed.
- Ruff:
  `python -m ruff check forge\utils\artifact_oauth_metadata.py forge\engagement_orchestrator.py tests\phase1\test_artifact_oauth_metadata.py`
  -> passed.
- Existing remote OpenID/OAuth engagement-backed regressions:
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "remote_openid_configuration_seed or remote_oauth_authorization_server_seed or remote_oauth_resource_metadata_seeds" -q --color=no -o addopts=''`
  -> `3 passed, 756 deselected`.
- Compact cross-phase smoke:
  `python -m pytest tests/phase1/test_artifact_oauth_metadata.py tests/phase1/test_engagement_orchestrator.py::test_kill_chain_artifact_extracted_assets_validate_and_seed_next_iteration_under_scope tests/phase6/test_report_synthesizer.py::test_synthesizer_runtime_provider_failure_falls_back_to_template tests/reporting/test_dashboard.py::test_generate_dashboard_surfaces_provider_matrix_artifacts_and_validation_evidence tests/phase4/test_cloud_validate.py::test_sweep_pending_cloud_asset_validations_scope_checker_skips_denied_assets -q --color=no`
  -> `5 passed, 1 deselected`.
- Cleanup:
  no test-owned engagement DBs found.
- Persistent engagement inventory:
  `1`, `5010`, `master.db`.

## Safety

Passive static metadata parsing only. No OAuth/OIDC endpoint request, token
request, authentication attempt, provider call, live probing, scope relaxation,
proxy/IP rotation, rate-limit bypass, validation-gate change, report-gate
change, or severity change.

## Next Task

Continue from `docs/engagement_overhaul_tasklist.md` -> `## Compact active
backlog`. Prefer another concrete passive parser, identity normalization,
provider-proof, graph/report parity, or cleanup proof gap.
