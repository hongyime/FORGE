# 2026-07-20 Run Audit Manifest Handoff

## Summary

Completed the evidence-lineage checkpoint for engagement runs. Every explicit `EngagementRunTracker.finish_run()` now attempts to write one immutable `run_audit_manifests` row for that run. The manifest chains to the previous manifest hash for the same engagement and captures DB/artifact digests without storing raw DB rows. Sidecar reviewer `Planck` found five correctness/security issues in the first draft; all are fixed with regressions.

## Changed Files

- `forge/audit/manifest.py`
- `forge/audit/__init__.py`
- `forge/db/schema.py`
- `forge/db/migrations.py`
- `forge/db/validation.py`
- `forge/engagement_orchestrator.py`
- `tests/audit/test_run_audit_manifest.py`
- `tests/phase1/test_multi_seed_schema.py`
- `docs/claude_continue_checklist.md`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_quick_handoff.md`

## Behavior

- New canonical table: `run_audit_manifests`.
- New migration: `0021_run_audit_manifests`; `TARGET_VERSION`/canonical schema now resolves to v21.
- Manifest payload includes:
  - `manifest_version`
  - `engagement_id`
  - `run_id`
  - `generated_at`
  - `previous_manifest_hash`
  - root engagement metadata digest
  - per-run captured DB row refs plus row/content digests
  - report and graph artifact byte SHA-256 hashes when discoverable from safe run metadata
- Manifest payload omits raw rows and excludes secret-shaped columns such as `*_enc`, password/hash/plaintext fields, request/response bodies, payloads, auth/cookie/token fields, and command/exfil paths from row digests.
- Artifact digests are limited to expected files under a `reports` directory whose names match FORGE report/graph output patterns; only file names, sizes, and SHA-256 hashes are persisted. Oversized artifacts are recorded as skipped without hashing bytes.
- Operationally transient tables `validation_claims`, `task_progress`, and `run_audit_manifests` are excluded from DB digests.
- `verify_run_audit_manifest()` first checks that stored canonical `manifest_json` hashes to the stored `manifest_hash`, then recomputes only captured row refs so later runs can append rows without invalidating older manifests. Edits/deletes of captured rows and artifact drift still fail verification.
- `EngagementRunTracker.finish_run()` commits the run status first, then best-effort writes the manifest in a separate post-commit step so artifact hashing does not expand the run-completion write transaction.

## Verification

All commands run from `C:\Users\bryan\OneDrive\01 TOOLKITS\forgetoolkit`:

```powershell
python -m pytest tests\audit\test_run_audit_manifest.py tests\phase1\test_multi_seed_schema.py tests\phase1\test_schema_validation.py -q --color=no
```

Result: `11 passed`.

```powershell
ruff check forge\audit\manifest.py forge\db\schema.py forge\db\migrations.py forge\db\validation.py forge\engagement_orchestrator.py tests\audit\test_run_audit_manifest.py tests\phase1\test_multi_seed_schema.py --output-format=concise
```

Result: `All checks passed!`.

```powershell
python -m compileall forge\audit\manifest.py forge\db\schema.py forge\db\migrations.py forge\db\validation.py forge\engagement_orchestrator.py -q
```

Result: passed.

```powershell
python -m pytest tests\phase1\test_multi_seed_schema.py tests\phase4\test_cloud_validate.py -q --color=no
```

Result: `146 passed`.

```powershell
python -m pytest tests\audit\test_hash_chain.py tests\audit\test_run_audit_manifest.py -q --color=no
```

Result: `12 passed`.

```powershell
python -m pytest tests\distributed tests\integration\test_playbooks.py tests\integration\test_engagement_pipeline.py tests\phase1\test_kill_chain_multiseed_recursive_e2e.py -q --color=no -m "slow or not slow"
```

Result: `33 passed`.

```powershell
python -m pytest tests\phase1\test_engagement_orchestrator.py -q --color=no -k "EngagementRunTracker or engagement_run_tracker or seed_run_tracker or tracker"
```

Result: `4 passed, 780 deselected`.

## Review Status

- Claude attempt 1: `Reached max turns (8)`.
- Claude attempt 2: blocked by Anthropic real-time cyber safeguard for cybersecurity content.
- Multi-agent explorer `Planck` (`019f7b72-fa11-7693-b6db-a5c39db71191`) found five issues: stored manifest JSON tamper was not detected, older manifests were invalidated by normal later rows, root `engagements` metadata was omitted, arbitrary `report_path` metadata could leak path/fingerprint data, and the finish hook expanded the pre-commit critical section. All five were fixed and covered by tests.

## Safety Notes

This checkpoint is audit/evidence hardening only. It does not add provider calls, live probing, credential use, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive validation, report-gate changes, exploitation, persistence, lateral movement, or post-exploitation behavior.

## Next Tasks

- Consider surfacing manifest hash/verification status in dashboard/API run detail views.
- Consider adding an operator command such as `forge audit manifest verify --engagement <id> --run <id>` if users need manual verification outside Python.
- Continue code-size/runtime discipline: split slow or mega tests into focused feature files when touching those areas.
