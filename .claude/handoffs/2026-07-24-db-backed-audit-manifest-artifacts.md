# DB-Backed Audit Manifest Artifacts Checkpoint

## Result
- Static dashboard and live web API now expose a safe downloadable audit artifact even when no manual `audit_*.json` file exists beside reports.
- Completed runs already store canonical audit manifests in `run_audit_manifests`; the dashboard/API now materialize a safe summary JSON artifact named `audit_{engagement_id}_run_{run_id}_{short_hash}.json`.
- The materialized artifact includes hash/status metadata and intentionally excludes raw `manifest_json`.
- Existing manual audit sidecars still win, preserving legacy behavior.
- Live list views materialize/count without verification; detail/download paths write verified summaries.

## Changed Files
- `forge/reporting/dashboard.py`
- `forge/webui/app.py`
- `tests/reporting/test_dashboard.py`
- `tests/integration/test_webui_engagement_api.py`

## Verification
- TDD failures reproduced first:
  - Static dashboard audit count was `0` when only the DB manifest existed.
  - Live web API audit count was `0` when only the DB manifest existed.
- `python -m compileall -q forge\reporting\dashboard.py forge\webui\app.py tests\reporting\test_dashboard.py tests\integration\test_webui_engagement_api.py`
- `ruff check forge\reporting\dashboard.py forge\webui\app.py tests\reporting\test_dashboard.py tests\integration\test_webui_engagement_api.py`
- Focused static dashboard audit artifact route test -> `1 passed, 19 deselected`
- Focused web UI API audit artifact test -> `1 passed, 35 deselected, 10 warnings`
- Full static dashboard file -> `20 passed`
- Full web UI engagement API file -> `36 passed, 71 warnings`
- Pytest engagement DB cleanup: `removed=4 remaining=0 post_scan=0`

## Safety
- No live probing, external target interaction, credential use, provider calls, or persistent non-test DB mutation.
- The generated artifact is a dashboard-safe summary only and does not expose stored `manifest_json`.

## Next
- Continue the compact backlog in `docs/engagement_overhaul_tasklist.md`.
- Recommended next audit target: broader mocked kill-chain acceptance parity or current-code audit for remaining review-surface mismatches outside report/audit lineage.
