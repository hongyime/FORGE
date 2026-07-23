# Fan-Out J Direct Validation Scope Callback

Date: 2026-07-24
Commit: `87a3a5d`

## Gate

Validation boundary / Fan-out J. Direct cloud asset validation must receive the
same scope checker and denied callback as pending cloud asset sweeps.

## Changed

- The per-iteration direct `run_cloud_asset_validate_batch()` call now passes:
  - `scope_checker=_cloud_asset_is_in_scope`;
  - `scope_denied_callback=_record_cloud_asset_scope_denied`.
- The existing cloud pivot regression now asserts the fake direct validator
  receives non-null callbacks.
- The fake direct validator probes both:
  - `("supabase", "allowed") -> True`;
  - `("firebase", "denied") -> False`.
- The regression still proves only the allowed Supabase target reaches direct
  validation and the denied Firebase target remains `UNVERIFIED` /
  `scope_manifest` inventory with audit evidence.

## Verification

- `python -m compileall -q forge\cli.py tests\phase1\test_engagement_orchestrator.py`
- `ruff check forge\cli.py tests\phase1\test_engagement_orchestrator.py`
- `python -m pytest tests\phase1\test_engagement_orchestrator.py -k "scope_manifest_denies_out_of_scope_cloud_validation_pivot" -q --color=no`
- `python -m pytest tests\phase1\test_engagement_orchestrator.py -k "scope_manifest_denies_out_of_scope_cloud_validation_pivot or scope_manifest_denies_out_of_scope_key_validation_source or scope_manifest_denies_out_of_scope_remote_artifact_download" -q --color=no`
- `python -m pytest tests\phase4\test_cloud_validate.py -k "run_cloud_asset_validate_batch_scope_checker_skips_denied_assets or run_cloud_asset_validate_batch_parallelizes_scope_gate_and_preserves_order or sweep_pending_cloud_asset_validations_scope_checker_skips_denied_assets or sweep_pending_cloud_asset_validations_denies_storage_assets_without_probe_or_findings" -q --color=no`
- Pytest engagement cleanup: `removed=4 remaining=0 post_scan=0`

## Next

Audit configurable recursion/concurrency budgets. Sidecar audit noted hardcoded
`EngagementSynthesisEngine(..., depth_limit=3)` and pending validation batch
size `16`; decide whether those should be engagement/env configurable with
bounded deterministic defaults.
