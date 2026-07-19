# 2026-07-20 Run Manifest Export Bundle Handoff

## Summary

Added portable export bundles for run audit manifests so operators can archive evidence outside the mutable engagement database. This builds on the hash-chained manifest and dashboard/API visibility checkpoints.

## Changed Files

- `forge/audit/manifest.py`
- `forge/audit/manifest_bundle.py`
- `forge/audit/__init__.py`
- `forge/cli.py`
- `tests/audit/test_run_audit_manifest_bundle.py`
- `tests/audit/test_run_audit_manifest_cli.py`
- `docs/claude_continue_checklist.md`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_quick_handoff.md`

## Behavior

- New public helper: `read_run_audit_manifest(...)`.
- New module: `forge.audit.manifest_bundle`.
- New public helper: `export_run_audit_manifest_bundle(...)`.
- New CLI command:
  `forge audit manifest-export --engagement <id> [--run-id <id>] [--output <zip>] [--json]`
- Bundle contents:
  - `manifest.json`: stored hash-chain manifest from `run_audit_manifests`.
  - `verification.json`: export-time verification receipt with `ok`, stored hash, recomputed hash, and reason.
  - `checksums.sha256`: checksums for payload files in the ZIP.
  - `README.md`: operator-readable bundle summary.
- ZIP member order and timestamps are deterministic.
- Default output path is `reports/engagement_<id>_run_<run>_manifest_<hash>.zip`.
- CLI exits `0` when export-time verification succeeds.
- CLI exits `2` when verification fails, but still writes the bundle so the failed receipt can be archived.
- CLI exits `1` when the engagement DB/run/manifest is missing or the engagement reference is invalid.

## Verification

Commands run from `C:\Users\bryan\OneDrive\01 TOOLKITS\forgetoolkit`:

```powershell
python -m compileall forge\audit\manifest.py forge\audit\manifest_bundle.py forge\audit\__init__.py forge\cli.py tests\audit\test_run_audit_manifest_bundle.py tests\audit\test_run_audit_manifest_cli.py -q
```

Result: passed.

```powershell
ruff check forge\audit\manifest.py forge\audit\manifest_bundle.py forge\audit\__init__.py forge\cli.py tests\audit\test_run_audit_manifest_bundle.py tests\audit\test_run_audit_manifest_cli.py
```

Result: `All checks passed!`.

```powershell
python -m pytest tests\audit\test_run_audit_manifest_bundle.py tests\audit\test_run_audit_manifest_cli.py tests\audit\test_run_audit_manifest.py -q --color=no
```

Result: `10 passed`.

## Review Status

Claude read-only review at `%TEMP%\forge-claude-manifest-bundle-review-out.txt` returned only `Reached max turns (4)` with no usable findings. The prompt asked Claude to check raw data leakage, nondeterminism, verification semantics, CLI exit codes, unsafe output behavior, and missing tests.

## Safety Notes

This checkpoint is offline evidence export only. It does not add provider calls, live probing, credential use, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive validation, report-gate changes, exploitation, persistence, lateral movement, or post-exploitation behavior.

## Next Tasks

- Add optional cryptographic signing for exported bundles if operators need tamper-evident proof beyond hashes.
- Add append-only remote archival support only if scoped customer storage is explicitly configured.
- Continue reducing mega-file test footprint when touching adjacent artifact/orchestrator areas.
