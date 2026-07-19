# 2026-07-20 Run Manifest Visibility Handoff

## Summary

Completed the dashboard/API/CLI visibility layer for hash-chained run audit manifests. Operators can now see whether the latest run has a manifest, inspect a short integrity hash in dashboard views, request verification from the live run API, and verify a run from the CLI.

## Changed Files

- `forge/audit/manifest.py`
- `forge/audit/__init__.py`
- `forge/cli.py`
- `forge/reporting/dashboard.py`
- `forge/reporting/webui/src/App.tsx`
- `forge/webui/app.py`
- `tests/audit/test_run_audit_manifest.py`
- `tests/audit/test_run_audit_manifest_cli.py`
- `tests/integration/test_webui_engagement_api.py`
- `tests/reporting/test_dashboard.py`
- `docs/claude_continue_checklist.md`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_quick_handoff.md`

## Behavior

- New helper: `summarize_run_audit_manifest(conn, db_path, engagement_id, run_id, verify=True)`.
- Public payload key: `audit_manifest`.
- Safe payload fields include `present`, `verified`, `verification_status`, `manifest_hash`, `short_hash`, `previous_manifest_hash`, `generated_at`, `reason`, and `recomputed_hash` when verification runs.
- The summary helper handles missing old-schema tables as `unavailable`, missing completed-run manifests as `missing`, and unfinished runs as `pending`.
- Static dashboard generation verifies latest run summaries and recent run rows because it is an explicit export operation.
- Live engagement list summaries return manifest metadata as `not_checked` to avoid repeated artifact hashing.
- Live engagement detail verifies the latest run.
- `/api/engagements/{ref}/runs` returns `not_checked` by default and verifies when `?verify_manifests=true`.
- React dashboard overview/detail surfaces short hash plus status without exposing raw manifest JSON.
- New CLI command: `forge audit manifest-verify --engagement <numeric-id> [--run-id <id>] [--json]`.
- CLI exit codes: `0` verified, `2` verification mismatch, `1` missing DB/run or invalid engagement reference.

## Verification

Commands run from `C:\Users\bryan\OneDrive\01 TOOLKITS\forgetoolkit`:

```powershell
python -m compileall forge\audit\manifest.py forge\audit\__init__.py forge\reporting\dashboard.py forge\webui\app.py forge\cli.py tests\audit\test_run_audit_manifest.py tests\audit\test_run_audit_manifest_cli.py tests\reporting\test_dashboard.py tests\integration\test_webui_engagement_api.py -q
```

Result: passed.

```powershell
ruff check forge\audit\manifest.py forge\audit\__init__.py forge\reporting\dashboard.py forge\webui\app.py forge\cli.py tests\audit\test_run_audit_manifest.py tests\audit\test_run_audit_manifest_cli.py tests\reporting\test_dashboard.py tests\integration\test_webui_engagement_api.py
```

Result: `All checks passed!`.

```powershell
python -m pytest tests\audit\test_run_audit_manifest.py tests\audit\test_run_audit_manifest_cli.py tests\reporting\test_dashboard.py::test_generate_dashboard_emits_slug_routes_and_json_contract tests\integration\test_webui_engagement_api.py::test_engagement_list_and_detail_routes -q --color=no
```

Result: `10 passed`.

```powershell
python -m pytest tests\audit\test_hash_chain.py tests\audit\test_run_audit_manifest.py tests\audit\test_run_audit_manifest_cli.py tests\reporting\test_dashboard.py tests\integration\test_webui_engagement_api.py -q --color=no -k "manifest or engagement_list_and_detail_routes or hash_chain"
```

Result: `19 passed, 40 deselected`.

```powershell
npm run build
```

Run from `forge\reporting\webui`. Result: passed.

```powershell
npm run lint
```

Run from `forge\reporting\webui`. Result: exit `0` with existing React hook dependency warnings at `src/App.tsx:1776`, `src/App.tsx:1825`, and `src/App.tsx:3333`.

## Review Status

- Earlier explorer result recommended using `audit_manifest`, avoiding `manifest_json` leakage, verifying detail views, and keeping list verification opt-in.
- Claude retry for this checkpoint returned `Reached max turns (5)` with no usable findings.

## Safety Notes

This checkpoint is audit/evidence visibility only. It does not add provider calls, live probing, credential use, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive validation, report-gate changes, exploitation, persistence, lateral movement, or post-exploitation behavior.

## Next Tasks

- Consider external trust-boundary support for manifests, such as signed manifest bundles or append-only export to customer storage.
- Consider adding UI affordances to explicitly trigger latest-run manifest verification instead of relying on detail-load verification.
- Continue reducing mega-file test footprint when touching adjacent artifact/orchestrator areas.
