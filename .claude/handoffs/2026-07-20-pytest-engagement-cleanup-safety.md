# Pytest Engagement Cleanup Safety Handoff

Date: 2026-07-20

Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`.

End goal: FORGE must remain one deterministic authorized engagement pipeline
from scoped multi-seed intake through bounded recursive discovery, static
artifact enrichment, non-destructive validation-before-reporting, rule-engine
findings/severity, graph/dashboard/report/audit review, guaranteed template/raw
fallback when LLM/API narrative providers fail, and automated test-data cleanup.

## Checkpoint

- Fixed `scripts/run_phase1_orchestrator_partitions.py` cleanup candidate
  selection.
- `pytest-of-*` directories are now treated as pytest owner containers, never as
  removable run directories.
- Cleanup removes only actual `pytest-*` run directories that contain
  `engagement.db`, including direct children under `pytest-of-*`.
- Candidate discovery is deterministic and deduped.

## Backprop

- Added `SPEC.md` invariant `V11`: automated cleanup may remove only proven
  test-owned engagement artifacts and must not delete broad pytest owner
  containers or persistent engagement DBs that are not proven artifacts from the
  current test run.
- Added `SPEC.md` bug note `B5`: old cleanup treated `pytest-of-*` owner
  containers as removable pytest run directories when a nested `engagement.db`
  existed.

## Verification

- TDD regression before implementation:
  `python -m pytest tests\scripts\test_run_phase1_orchestrator_partitions.py -q --color=no`
  failed because cleanup returned `pytest-of-bryan` instead of nested
  `pytest-42`.
- Compile:
  `python -m py_compile scripts\run_phase1_orchestrator_partitions.py tests\scripts\test_run_phase1_orchestrator_partitions.py`
- Lint:
  `python -m ruff check scripts\run_phase1_orchestrator_partitions.py tests\scripts\test_run_phase1_orchestrator_partitions.py`
- Focused cleanup tests:
  `python -m pytest tests\scripts\test_run_phase1_orchestrator_partitions.py -q --color=no`
  -> `5 passed`.
- Adjacent monotonic engagement-ID tests:
  `python -m pytest tests\phase1\test_engagement_ids.py -q --color=no`
  -> `3 passed`.
- Compact cross-phase smoke:
  `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_kill_chain_artifact_extracted_assets_validate_and_seed_next_iteration_under_scope tests/phase6/test_report_synthesizer.py::test_synthesizer_runtime_provider_failure_falls_back_to_template tests/reporting/test_dashboard.py::test_generate_dashboard_emits_slug_routes_and_json_contract tests/reporting/test_dashboard.py::test_generate_dashboard_surfaces_provider_matrix_artifacts_and_validation_evidence tests/phase4/test_cloud_validate.py::test_sweep_pending_cloud_asset_validations_scope_checker_skips_denied_assets tests/phase4/test_attack_path.py::TestGraphBuildArtifacts::test_graph_build_all_writes_native_mtgx_workspace -q --color=no`
  -> `5 passed, 1 deselected`.
- Real temp cleanup:
  `cleanup_pytest_engagement_dbs()` removed pytest engagement dirs after
  targeted tests and smoke, then left `remaining_pytest_engagement_dirs=0`.
- Persistent workspace `.forge_data/engagements` inventory remains `1`, `5010`,
  and `master.db`; these were not deleted because they are not proven test
  artifacts from this run.
- No pytest/Python process remains after cleanup verification.

## Safety Boundary

This is test cleanup tooling only. No production engagement deletion, target
network, live probing, provider call, credential use, scope relaxation,
proxy/IP rotation, rate-limit bypass, validation/report-gate change, severity
change, or finding creation was added.

## Next Suggested Tasks

- Continue the active backlog audit before writing more runtime code.
- Prefer dashboard/graph/report parity, raw export fallback, MTGX analyst
  fidelity, or a concrete identity-provider/passive-artifact parser gap.
- Keep every new task mapped to the locked end-goal gates: intake, discovery,
  recursion, artifact analysis, validation, scoring, review, fallback, or
  testing/cleanup.
