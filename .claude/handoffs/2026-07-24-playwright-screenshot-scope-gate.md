# Playwright Screenshot Scope Gate

Date: 2026-07-24
Project: `C:\Users\bryan\OneDrive\01 TOOLKITS\forgetoolkit`
Branch: `main`

## Current State

FORGE remains locked to `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`: one authorized,
deterministic ASM pipeline from scoped multi-seed intake through bounded
recursive discovery, static artifact analysis, non-destructive validation,
rule-engine scoring, dashboard/report/graph/audit review, and guaranteed
template/raw fallback.

This checkpoint closes a scoped discovery gap in screenshot capture:
`_crawl_http()` had a final redirect URL gate, but `crawl_target(...,
screenshot=True)` could still let Playwright navigate or request off-scope
resources before the HTTP crawler ran.

## Changes Made

- Updated `forge/phase1/crawler.py` so Playwright installs a route guard before
  `page.goto()`.
- The route guard aborts off-scope HTTP(S) requests using the same
  `scope_filter` as the crawler.
- Screenshot writing is skipped if the browser final URL is off-scope.
- Added
  `tests/phase1/test_crawler.py::test_crawl_target_screenshot_aborts_out_of_scope_browser_redirect`
  using fake Playwright objects; no browser or network is required.

## Verification

- `python -m py_compile forge\phase1\crawler.py tests\phase1\test_crawler.py`
- `python -m ruff check forge\phase1\crawler.py tests\phase1\test_crawler.py`
- `python -m pytest tests\phase1\test_crawler.py::test_crawl_target_screenshot_aborts_out_of_scope_browser_redirect -q --color=no`
- `python -m pytest tests\phase1\test_crawler.py -q --color=no`

Results: compile passed; Ruff passed; focused screenshot scope test passed (`1
passed`); full crawler unit file passed (`4 passed`). Workspace
`.forge_data/engagements` contained `0` entries after the run.

## Important Context

No live probing expansion, crawler pacing, retry policy, provider calls, proxy
behavior, validation gate, severity rule, report, dashboard, or API behavior was
changed. This is a deterministic scope gate for the optional screenshot path.

## Immediate Next Step

Fix `GET /workflows/{workflow_id}/status` unknown-workflow handling.
`WorkflowEngine.get_status()` raises `KeyError` for missing workflows, so the
route's dead `result is None` 404 branch should be replaced or guarded with
deterministic 404 handling. Suggested focused test:
`tests/integration/test_history_routes.py::test_status_unknown_workflow_returns_404`.
