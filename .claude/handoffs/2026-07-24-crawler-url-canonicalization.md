# Crawler URL Canonicalization Recursion Checkpoint

Date: 2026-07-24

Goal stage: discovery/recursion.

## Summary

`forge.phase1.crawler._crawl_http()` now canonicalizes the seed URL, fetched
final URLs, and every extracted link before recursive queue/fetch decisions.
Canonical crawl URLs drop fragments, lowercase scheme/host, remove default
HTTP/HTTPS ports, reject non-HTTP(S), and mark links as queued before enqueueing
so repeated fragment variants cannot create duplicate crawl work or noisy
dashboard crawl rows.

A reviewer subagent found a blocking default-port origin-equivalence issue in
the first patch. That issue is fixed: `https://acme.example:443/` and
`https://acme.example/` now share the same canonical origin, and
`http://acme.example:80/app#top` canonicalizes to `http://acme.example/app`.

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
- `python -m pytest tests\phase1\test_crawler.py -k "canonicalizes" -q --color=no` -> `3 passed, 5 deselected`
- `python -m pytest tests\phase1\test_crawler.py -k "crawl_http and href" -q --color=no` -> `1 passed, 5 deselected`
- `python -m pytest tests\phase1\test_crawler.py -q --color=no` -> `8 passed`
- `.forge_data/engagements` count after tests: `0`

## Next

Canonicalize recursive discovered URL seeds before persistence. Read-only audit
found `_prepare_discovered_seed_url()` in `forge/cli.py` still strips raw
strings only, so recursive discovery can store variants such as
`HTTPS://acme.example:443/app#x` after the crawler path already normalized them.
Add a CLI-local canonical URL helper, use it before dedupe/insert, keep
`robots.txt`/`sitemap.xml` exclusions, preserve scope checks after
canonicalization, and add a focused orchestrator regression.
