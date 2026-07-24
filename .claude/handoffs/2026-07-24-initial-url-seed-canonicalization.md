# Initial URL Seed Canonicalization Checkpoint

Date: 2026-07-24

Goal stage: intake/discovery.

## Summary

Operator-supplied initial `url` and `apk_url` seeds now canonicalize before
initial seed dedupe and persistence, using the same HTTP canonicalizer as
recursive URL persistence. Equivalent raw variants such as
`HTTPS://ACME.EXAMPLE:443/login#top` and `https://acme.example/login` persist
as one canonical URL seed. Mobile bundle URL variants with default ports and
fragments persist as one canonical `apk_url` seed.

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
- `python -m pytest tests\phase1\test_engagement_orchestrator.py -k canonicalizes_duplicate_initial_url_seeds -q --color=no` -> `1 passed, 765 deselected`
- `python -m pytest tests\phase1\test_engagement_orchestrator.py -k "canonicalizes_duplicate_initial_domain_and_email_seeds or canonicalizes_duplicate_initial_url_seeds" -q --color=no` -> `2 passed, 764 deselected`
- `.forge_data/engagements` count after tests: `0`

## Next

Make legacy `ReportingAgent` deterministic fallback lineage API-reviewable. Add
payload-only `report_lineage` / `fallback_reason` metadata for disabled,
provider-unavailable, and generic fallback branches without changing markdown
content or adding raw findings/secrets.
