# Configurable Kill-Chain Budgets

Date: 2026-07-24

## Checkpoint

Completed the configurable recursion/concurrency budget gate for the
deterministic authorized ASM kill chain.

## Code Changes

- `forge/utils/kill_chain_options.py`
  - Added bounded integer normalization helper.
  - Added `normalize_kill_chain_synthesis_depth()`.
  - Added `normalize_kill_chain_validation_batch_limit()`.
- `forge/cli.py`
  - Reads `FORGE_KILL_CHAIN_SYNTHESIS_DEPTH`, default `3`, bounds `1..5`.
  - Reads `FORGE_KILL_CHAIN_VALIDATION_BATCH_LIMIT`, default `16`, bounds
    `1..64`.
  - Invalid env values fail closed through `typer.BadParameter`.
  - `EngagementSynthesisEngine` now receives the normalized depth.
  - Pending cloud key/asset validation sweeps use the normalized batch limit.
  - `engagement_runs.metadata_json` records both effective budget values.
- `SPEC.md`
  - Added B23 so future agents treat these env vars as part of the deterministic
    run contract.
- Active handoff docs
  - Updated `docs/engagement_overhaul_tasklist.md`.
  - Updated `docs/claude_continue_checklist.md`.
  - Updated `docs/claude_quick_handoff.md`.

## Verification

- `python -m py_compile forge\cli.py forge\utils\kill_chain_options.py tests\phase1\test_kill_chain_options.py tests\phase1\test_cli_parallel_dispatch.py tests\phase1\test_engagement_orchestrator.py`
- `python -m ruff check forge\cli.py forge\utils\kill_chain_options.py tests\phase1\test_kill_chain_options.py tests\phase1\test_cli_parallel_dispatch.py tests\phase1\test_engagement_orchestrator.py`
- `python -m pytest -q tests\phase1\test_kill_chain_options.py tests\phase1\test_cli_parallel_dispatch.py::test_kill_chain_rejects_budget_env_out_of_range tests\phase1\test_engagement_orchestrator.py::test_kill_chain_passes_report_provider_and_loop_overrides_to_final_report_generation`
- `python -m pytest -q tests\phase1\test_kill_chain_convergence.py`
- `python -m pytest -q tests\phase1\test_engagement_orchestrator.py::test_kill_chain_dry_run_records_recent_run_telemetry_metadata`
- `python -m pytest -q -m slow tests\phase1\test_engagement_orchestrator.py::test_kill_chain_drains_multiple_pending_cloud_validation_batches`
- `python -m pytest -q -m slow tests\phase1\test_engagement_orchestrator.py::test_kill_chain_multi_iteration_mixes_local_artifacts_social_recursion_and_auto_template_fallback`
- `git diff --check`

## Notes

- Bare `pytest.exe` returned exit code `1` without output in this environment.
  `python -m pytest` is the reliable invocation and passed.
- The two heavy engagement scenarios are marked `slow`; run them with `-m slow`
  because repo defaults exclude slow tests.

## Next Gate

Fix React engagement-detail review labeling:

- Only reportable validated findings should appear under "Validated findings".
- `UNVERIFIED`, `DEAD`, honeypot-suspected, and metadata-only cloud/key rows
  should render under validation inventory with explicit status.
- Add focused `tests/reporting/test_webui_contract.py` assertions.

