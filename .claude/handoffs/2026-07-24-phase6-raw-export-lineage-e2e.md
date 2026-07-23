# Phase 6 Raw-Export Lineage E2E Checkpoint

## Result
- Added a mocked integration slice proving actual Phase 6 raw-export last-resort artifacts agree across:
  - generated raw-export JSON lineage,
  - static dashboard detail payload,
  - live web API engagement detail summary,
  - JSON artifact download,
  - CSV artifact download.
- Fixed dashboard report-family ordering for the raw fallback edge case where a failed report-family write leaves an orphan markdown artifact with the same timestamp as the raw-export JSON/CSV family.
- Dashboard family sorting now uses JSON-backed family presence as a deterministic tie-breaker after mtime, so auditable JSON lineage wins over orphan markdown in same-run fallback conditions.

## Changed Files
- `forge/reporting/dashboard.py`
- `tests/integration/test_webui_engagement_api.py`

## Verification
- TDD failure reproduced first: raw-export E2E selected a provider-empty orphan markdown report family instead of the raw-export JSON/CSV lineage family.
- `python -m compileall -q forge\reporting\dashboard.py tests\integration\test_webui_engagement_api.py`
- `ruff check forge\reporting\dashboard.py tests\integration\test_webui_engagement_api.py`
- Focused template/raw-export lineage E2E slice -> `2 passed, 34 deselected, 6 warnings`
- Focused dashboard raw/latest report-family slice -> `2 passed, 18 deselected`
- Full web UI engagement API file -> `36 passed, 71 warnings`
- Full static dashboard file -> `20 passed`
- Pytest engagement DB cleanup: `removed=4 remaining=0 post_scan=0`

## Safety
- No live probing, external target interaction, credential use, provider calls, or persistent non-test DB mutation.
- Test uses deterministic template provider, forced local write failure, and local temporary files only.

## Next
- Continue the compact backlog in `docs/engagement_overhaul_tasklist.md`.
- Recommended next audit target: broader mocked kill-chain acceptance parity or a current-code audit for remaining dashboard/report/audit surface mismatches outside report lineage.
