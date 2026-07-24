# Recursive URL Seed Canonicalization Checkpoint

Date: 2026-07-24

Goal stage: discovery/recursion.

## Summary

Recursive discovered URL persistence now uses a shared CLI HTTP URL canonicalizer
before archive-provider dedupe, URL metadata keying, crawl row insertion, URL
seed insertion, existing crawl/seed duplicate checks, URL seed resume keys,
scope decisions, and Playwright eligibility checks.

Historical/provider variants like
`HTTPS://archive.acme.example:443/config.js#bundle` and
`https://shared.acme.example/app.js#wayback` collapse to canonical HTTP(S) URLs
while preserving archive/provider metadata merging. Existing `robots.txt` /
`sitemap.xml`, artifact URL, root-domain, and scope-manifest gates remain in
place after canonicalization.

No live probing, provider behavior, rate-limit behavior, validation gate,
severity rule, report generation, dashboard, API, or frontend behavior changed.

## Files

- `forge/cli.py`
- `tests/phase1/test_engagement_orchestrator.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- `python -m py_compile forge\cli.py tests\phase1\test_engagement_orchestrator.py`
- `python -m ruff check forge\cli.py tests\phase1\test_engagement_orchestrator.py`
- `python -m pytest tests\phase1\test_engagement_orchestrator.py::test_kill_chain_wayback_commoncrawl_preserves_url_level_archive_source -q --color=no` -> `1 passed`
- `python -m pytest tests\phase1\test_engagement_orchestrator.py -k "wayback_commoncrawl_preserves_url_level_archive_source or parallel_batches_wayback_host_parse" -q --color=no` -> `2 passed, 763 deselected`
- Reviewer subagent: no blocking findings
- `.forge_data/engagements` count after tests: `0`

## Next

Audit one current-code deterministic kill-chain, passive-recursion, validation,
report/export, dashboard/API review, or cleanup gap not already covered by
recent crawler URL canonicalization, dashboard alias validation, or report-route
checkpoints.
