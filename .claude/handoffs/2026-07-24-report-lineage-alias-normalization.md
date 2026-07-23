# Report Lineage Alias Normalization Checkpoint

## Result
- Legacy `GET /reports/{workflow_id}` accepts Phase 6-shaped `report_markdown` payloads in addition to `report_md`, `markdown`, and `content`.
- Workflow report lineage now normalizes `rendered_provider` into `render_backend`, preserves both names for API consumers, and maps nested `write_error` into `report_write_error`.
- Static dashboard and web API report summaries now fall back to nested `report_lineage` values for `rendered_provider`, `upstream_provider`, `fallback_reason`, `write_error`, `format`, `generated_at`, and `findings_checksum`.

## Changed Files
- `forge/api/routes/reports.py`
- `forge/reporting/dashboard.py`
- `tests/integration/test_mvp_workflow.py`
- `tests/integration/test_webui_engagement_api.py`
- `tests/reporting/test_dashboard.py`

## Verification
- TDD failures reproduced first:
  - Legacy report route returned `425` for `report_markdown`.
  - Dashboard/web API raw-export summaries rendered `raw_export` instead of nested upstream `template`.
- `python -m compileall -q forge\api\routes\reports.py forge\reporting\dashboard.py tests\integration\test_mvp_workflow.py tests\reporting\test_dashboard.py tests\integration\test_webui_engagement_api.py`
- `ruff check forge\api\routes\reports.py forge\reporting\dashboard.py tests\integration\test_mvp_workflow.py tests\reporting\test_dashboard.py tests\integration\test_webui_engagement_api.py`
- `python -m pytest tests\integration\test_mvp_workflow.py -q --color=no` -> `5 passed`
- `python -m pytest tests\reporting\test_dashboard.py -q --color=no` -> `20 passed`
- `python -m pytest tests\integration\test_webui_engagement_api.py -q --color=no` -> `34 passed, 65 warnings`
- Pytest engagement DB cleanup: `removed=3 remaining=0 post_scan=0`

## Reviewer Attempts
- Claude reviewer failed: OAuth session expired and could not be refreshed.
- Codex reviewer with `gpt-5.2` failed: model unsupported for the CLI account.
- Codex reviewer with `gpt-5` failed: model unsupported for the CLI account.
- Codex default reviewer started with read-only sandbox, but could not spawn PowerShell due Windows sandbox access denied; stopped by main agent.

## Safety
- No live probing, external target interaction, credential use, provider calls, or scope expansion.
- Change is API/dashboard normalization only.

## Next
- Continue the compact backlog in `docs/engagement_overhaul_tasklist.md`.
- Recommended next gate: verify end-to-end report lineage agreement between Phase 6 generated artifacts, static dashboard payloads, and web API artifact downloads in one mocked integration slice.
