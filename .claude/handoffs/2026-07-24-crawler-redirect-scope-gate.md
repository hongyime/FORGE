# Crawler Redirect Scope Gate

Date: 2026-07-24
Project: `C:\Users\bryan\OneDrive\01 TOOLKITS\forgetoolkit`
Branch: `main`

## Current State

FORGE remains locked to `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`: one authorized,
deterministic ASM pipeline from scoped multi-seed intake through bounded
recursive discovery, static artifact analysis, non-destructive validation,
rule-engine scoring, dashboard/report/graph/audit review, and guaranteed
template/raw fallback.

This checkpoint closes a scoped discovery gap: `_crawl_http()` checked the
requested URL before fetch, but did not scope-check the final URL returned after
HTTP redirects before recording crawl output.

## Changes Made

- Updated `forge/phase1/crawler.py` so the final `resp.url` is checked against
  `scope_filter` before output is recorded or links are extracted.
- Added
  `tests/phase1/test_crawler.py::test_crawl_http_drops_out_of_scope_redirect_final_url`
  with a fake in-scope request that redirects to `https://evil.example/`.

## Verification

- `python -m py_compile forge\phase1\crawler.py tests\phase1\test_crawler.py`
- `python -m ruff check forge\phase1\crawler.py tests\phase1\test_crawler.py`
- `$env:PYTHONDONTWRITEBYTECODE='1'; python -m pytest -q -p no:cacheprovider tests\phase1\test_crawler.py::test_crawl_http_drops_out_of_scope_redirect_final_url --color=no`
- `python -m pytest tests\phase1\test_crawler.py -q --color=no`

Results: compile passed; Ruff passed; focused off-scope redirect test passed
(`1 passed`); full crawler unit file passed (`3 passed`). Workspace
`.forge_data/engagements` contained `0` entries after the run.

## Important Context

No live probing behavior, request pacing, retry policy, provider calls, proxy
behavior, validation gate, severity rule, report, dashboard, or API behavior was
changed. This is a deterministic pre-persistence scope gate for redirected crawl
responses.

## Immediate Next Step

Fix workflow history API `limit` validation so
`GET /workflows/{workflow_id}/history?limit=0` and negative limits return 422
instead of falling through to an unbounded state-store history query. Suggested
focused test:
`tests/integration/test_history_routes.py::test_history_rejects_non_positive_limit`.
