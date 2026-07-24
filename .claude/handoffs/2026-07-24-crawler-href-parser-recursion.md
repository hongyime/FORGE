# Crawler Href Parser Recursion Checkpoint

Date: 2026-07-24

Goal stage: discovery/recursion.

## Summary

`forge.phase1.crawler._extract_links()` now uses Python's `HTMLParser` instead
of a lowercase double-quoted string search. `_crawl_http()` can now follow
same-origin links written with uppercase `HREF` attributes or single-quoted href
values while preserving the existing skips for empty, fragment, and
`javascript:` hrefs.

No live probing, pacing, retry, provider, proxy, validation, severity, report,
dashboard, or API behavior changed.

## Files

- `forge/phase1/crawler.py`
- `tests/phase1/test_crawler.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- `python -m py_compile forge\phase1\crawler.py tests\phase1\test_crawler.py`
- `python -m ruff check forge\phase1\crawler.py tests\phase1\test_crawler.py`
- `python -m pytest -q tests\phase1\test_crawler.py -k crawl_http_follows_single_quoted_href_links --color=no` -> `1 passed, 4 deselected`
- `python -m pytest tests\phase1\test_crawler.py -q --color=no` -> `5 passed`
- `.forge_data/engagements` count after tests: `0`

## Next

Fix the dashboard cloud asset validation alias join gap found by read-only
subagent audit. `cloud_assets.asset_type='s3'` can display as `aws_s3` while
missing a latest validation row stored as
`cloud_validation_results.asset_type='aws_s3'`. Normalize both sides of the
join and add a focused dashboard regression.
