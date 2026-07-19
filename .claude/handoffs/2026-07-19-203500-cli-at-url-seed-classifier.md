# CLI URL Seed Classifier Handoff

Date: 2026-07-19

## Change

`forge kill-chain` now classifies HTTP(S) URLs before applying the email regex, matching the canonical orchestrator classifier.

This prevents passive metadata URLs containing email-like query values from being persisted as email seeds. Example covered by regression:

```text
https://acme.example/.well-known/webfinger?resource=acct:alice@acme.example
```

The URL now persists as `seed_type=url`, does not enter the `emails` table, and remains eligible for URL/artifact recursive discovery.

## Files

- `forge/cli.py`
- `tests/phase1/test_cli_parallel_dispatch.py`
- `docs/claude_quick_handoff.md`
- `docs/claude_continue_checklist.md`
- `docs/engagement_overhaul_tasklist.md`

## Verification

TDD regression failed before the fix with:

```text
AssertionError: assert ('email',) == ('url',)
```

Final checks:

```powershell
.venv\Scripts\python.exe -m py_compile forge\cli.py tests\phase1\test_cli_parallel_dispatch.py
.venv\Scripts\python.exe -m ruff check forge\cli.py tests\phase1\test_cli_parallel_dispatch.py
.venv\Scripts\python.exe -m pytest tests\phase1\test_cli_parallel_dispatch.py::test_kill_chain_url_seed_with_at_query_stays_url tests\phase1\test_engagement_orchestrator.py::test_kill_chain_discovered_url_seeds_reenter_same_iteration_surface_mining tests\phase1\test_engagement_orchestrator.py::test_kill_chain_passive_text_mining_promotes_robots_and_sitemap_urls_without_live_network -q --color=no -m "slow or not slow"
```

Results:

- Compile passed.
- Ruff passed.
- Focused pytest passed: `3 passed`.

## Review

Multi-agent explorer `Dewey` found the classifier drift and affected recursion path. Claude CLI read-only review could not be used because the local Claude account's real-time cyber safeguard blocked the prompt.

## Safety Boundary

Classifier ordering only. No live probing expansion, provider call expansion, credential use, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, report-gate change, or post-exploitation behavior was added.
