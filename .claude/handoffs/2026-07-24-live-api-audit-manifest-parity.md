# Live API Audit Manifest Verification Parity

Date: 2026-07-24

## Summary

Live API engagement review now matches static dashboard audit-manifest
verification defaults.

- `/api/engagements` summaries verify the latest run audit manifest by default.
- `/api/engagements/{ref}/runs` verifies manifests by default.
- Operators can still request cheaper non-verifying run rows with
  `?verify_manifests=false`, which returns `verification_status:
  not_checked` explicitly.

This closes the static/live drift where the dashboard detail payload showed
`verified` while the live list and default run list showed `not_checked` for
the same manifest.

## Changed Files

- `forge/webui/app.py`
- `tests/integration/test_webui_engagement_api.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- `python -m compileall forge\webui\app.py tests\integration\test_webui_engagement_api.py`
- `python -m ruff check forge\webui\app.py tests\integration\test_webui_engagement_api.py`
- `python -m pytest tests\integration\test_webui_engagement_api.py -k "list_and_detail_routes or engagement_run_controls_are_logged_and_reviewable" -q`
- `python -m pytest tests\reporting\test_dashboard.py -k "emits_slug_routes_and_json_contract" -q`

Focused tests passed: `2 passed` total across the two pytest invocations.

## Next Suggested Audit

Audit another concrete dashboard/API/report artifact or validation-review parity
gap. Good candidates: run-summary fields in pause/resume control routes, audit
manifest artifact download payloads, or validation inventory shape parity
between static detail JSON and live API detail JSON.
