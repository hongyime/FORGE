# Auto-Run Finalization Ordering

Date: 2026-07-24
Commit: `fa25d99`

## Gate

Audit / review / deterministic completion. Optional `--auto-run-detected`
follow-on actions must land before the run is marked complete and before the
run audit manifest is written.

## Changed

- Replaced the early `finish_run(status="completed")` block with a local
  `_complete_engagement_run()` helper.
- Completion now runs after prerequisite detection and after one of the terminal
  branches:
  - no prerequisites;
  - manual-only prerequisites;
  - auto-run prerequisites;
  - interactive prompt;
  - non-TTY skipped prompt.
- Final run metadata now records prerequisite execution mode and counts.
- Dashboard refresh now happens after completion, so review surfaces are built
  after late DB changes and after the run manifest exists.
- The auto-run regression asserts:
  - metadata includes `prereq_execution_mode="auto_run"`;
  - `prereq_auto_run` audit row exists;
  - stored run manifest `audit_log` row count equals current DB `audit_log`
    row count after auto-run.

## Verification

- `python -m compileall -q forge\cli.py tests\phase1\test_engagement_orchestrator.py`
- `ruff check forge\cli.py tests\phase1\test_engagement_orchestrator.py`
- `python -m pytest tests\phase1\test_engagement_orchestrator.py -k "parallel_batches_detected_prereqs_when_auto_run_enabled" -q --color=no`
- `python -m pytest tests\phase1\test_engagement_orchestrator.py -k "dry_run_records_recent_run_telemetry_metadata or parallel_batches_prereport_finalization_modules or parallel_batches_detected_prereqs_when_auto_run_enabled or pause_request_transitions_run_to_paused_metadata or scope_manifest_denies_out_of_scope_remote_artifact_download" -q --color=no`
- `python -m pytest tests\phase1\test_kill_chain_convergence.py -q --color=no`
- `python -m pytest tests\phase1\test_kill_chain_multiseed_recursive_e2e.py::test_kill_chain_multiseed_recursive_discovery_stabilizes_with_validated_output -q --color=no`
- Pytest engagement cleanup: `removed=4 remaining=0 post_scan=0`

## Next

Audit Fan-out J direct cloud validation call boundaries and ensure every direct
cloud asset validation path passes the available scope checker/denied callback
into lower-level validators.
