# Validation Sweep Claims

Date: 2026-07-19

## Summary

Pending cloud key and cloud-asset sweeps now claim rows before provider validation. This closes the duplicate-provider-call window where multiple workers could select the same pending rows before any validation result was persisted.

## Files Changed

- `forge/db/schema.py`
- `forge/db/migrations.py`
- `forge/db/validation.py`
- `forge/phase4/validation_claims.py`
- `forge/phase4/cloud_validate.py`
- `tests/phase1/test_multi_seed_schema.py`
- `tests/phase4/test_cloud_validate.py`

## Behavior

- New canonical table: `validation_claims`.
- Key claims are unique by `(engagement_id, claim_type, key_id)`.
- Asset claims are unique by `(engagement_id, claim_type, asset_type, identifier)`.
- Claim selection runs inside `BEGIN IMMEDIATE`.
- Stale claims are purged before new selection.
- Completed sweeps release only claims owned by that sweep.
- `sweep_pending_cloud_validations()` and `sweep_pending_cloud_asset_validations()` skip already-claimed rows before any provider call.
- Claim implementation lives in `forge/phase4/validation_claims.py` so `cloud_validate.py` remains a caller, not a larger utility dump.

## Verification

- `python -m py_compile forge\phase4\validation_claims.py forge\db\schema.py forge\db\migrations.py forge\db\validation.py forge\phase4\cloud_validate.py tests\phase1\test_multi_seed_schema.py tests\phase4\test_cloud_validate.py` -> passed
- `python -m ruff check forge\phase4\validation_claims.py forge\db\schema.py forge\db\migrations.py forge\db\validation.py forge\phase4\cloud_validate.py tests\phase1\test_multi_seed_schema.py tests\phase4\test_cloud_validate.py` -> `All checks passed!`
- `python -m pytest tests\phase1\test_multi_seed_schema.py tests\phase4\test_cloud_validate.py -q --color=no` -> `146 passed`
- `python -m pytest tests\distributed tests\integration\test_playbooks.py tests\integration\test_engagement_pipeline.py tests\phase1\test_kill_chain_multiseed_recursive_e2e.py -q --color=no -m "slow or not slow"` -> `33 passed`

## Review Notes

- Claude CLI still returned `Reached max turns` with no usable findings.
- Explicit Codex CLI GPT model retries were rejected by the local ChatGPT-backed account.
- Default Codex CLI review could not inspect because its Windows sandbox could not launch `pwsh.exe`: `CreateProcessAsUserW failed: 5`.
- No external review findings were available; local tests and manual diff review are the evidence.

## Safety

Concurrency/audit-state hardening only. No new provider endpoints, live probe expansion, credential use, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive validation, report-gate change, exploitation, persistence, lateral movement, or post-exploitation behavior was added.

## Next Tasks

- Add hash-chained per-run audit manifest if evidence-grade auditability is the next priority.
- Continue code-size discipline by keeping new feature logic in focused modules and moving future large tests out of mega files when feasible.
