# Compact Kill-Chain Dashboard Smoke Handoff

Date: 2026-07-24

## Goal Lock

FORGE remains `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`: scoped multi-seed intake,
bounded recursive discovery, static artifact enrichment, non-destructive
validation-before-reporting, deterministic severity/risk scoring,
graph/dashboard/report/audit review, and deterministic template/raw fallback
when LLM/API narrative providers fail.

## Completed Checkpoint

Added a compact engagement-backed regression that ties the previously split
kill-chain, report fallback, graph, validation inventory, and dashboard review
contracts together in one mocked run.

- New test: `tests/phase1/test_kill_chain_dashboard_smoke.py`.
- The mocked `kill_chain()` path proves homepage HTML discovers a remote APK.
- The remote APK static parser extracts Firebase, Supabase, AWS, Slack,
  Mailchimp, Azure, email, and URL pivots.
- Recursive discovery persists the artifact email and portal URL seeds.
- Firebase, Supabase, AWS, Slack, and Azure validation inventory reaches
  dashboard detail JSON as `VALIDATED`.
- Mailchimp ping remains `UNVERIFIED` inventory only and does not become a
  deterministic finding.
- `provider=auto` report generation falls back to deterministic template on
  mocked `ProviderUnavailableError("rate limit")`.
- Dashboard detail JSON exposes report lineage, validation inventory,
  key-scanner proof review rows, and graph validation metadata without leaking
  raw secrets.

## Verification

- `python -m py_compile tests\phase1\test_kill_chain_dashboard_smoke.py tests\reporting\test_dashboard.py tests\phase6\test_report_synthesizer.py`
- `python -m ruff check tests\phase1\test_kill_chain_dashboard_smoke.py tests\reporting\test_dashboard.py tests\phase6\test_report_synthesizer.py` -> `All checks passed!`
- `python -m pytest tests\phase1\test_kill_chain_dashboard_smoke.py -q --color=no -m "slow or not slow"` -> `1 passed in 27.46s`
- `python -m pytest tests\reporting\test_dashboard.py -k "validation_proof or unverified_key_validation or key_validation or graph_validation" -q --color=no` -> `5 passed, 22 deselected`
- `python -m pytest tests\phase6\test_report_synthesizer.py -k "fallback or validation_proof or key_findings or raw_export" -q --color=no` -> `20 passed, 84 deselected`
- Workspace `.forge_data/engagements` count after verification: `0`.

## Safety Notes

No live provider calls, live target probing, endpoint behavior, credential-use
expansion, proxy/rate-limit behavior, scope behavior, report gate, severity
rule, or destructive validation behavior changed. The new coverage uses local
mocked HTML, mocked artifact download, mocked cloud HTTP client, and mocked key
validators only.

## Next Task

Pick one concrete current-code deterministic review/export or passive-recursion
gap not already covered by this smoke. Prefer a small modular test/helper over
adding to `tests/phase1/test_engagement_orchestrator.py`. Keep live provider
calls mocked unless the user supplies an explicit ROE/scope manifest and target.
