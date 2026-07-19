# Sentry Proof Hash Gate Handoff

Date: 2026-07-19
Commit: `2bd7d0c fix(cloud): require sentry org slug proof hash`

## What Changed

- `SentryAuthTokenValidator` still uses the existing read-only organizations endpoint, but active proof now includes `org_slug_hash=<sha256(slug)[:16]>` beside the stable org id.
- `parse_validated_detail()` now downgrades Sentry `VALIDATED:sentry_list_organizations` proof unless `org_id`, `org_slug_present=true`, `org_slug_stable=true`, and a non-repeated hex `org_slug_hash` are all present.
- Phase 4 `_validated_identifier_from_detail("sentry", ...)` now applies the same hash requirement before returning a validated identifier for persistence/reporting.
- Dashboard and graph fixtures were updated to display/truncate the stricter proof without rendering the raw org slug or name.

## Verification

- `.venv\Scripts\python.exe -m py_compile forge\utils\intel\secret_finder.py forge\utils\validation_proof.py forge\phase4\cloud_validate.py tests\core\test_validation_proof.py tests\phase2\test_secret_finder.py tests\phase4\test_cloud_validate.py tests\phase1\test_deterministic_findings.py tests\reporting\test_dashboard.py tests\phase1\test_engagement_orchestrator.py`
- `.venv\Scripts\python.exe -m ruff check forge\utils\intel\secret_finder.py forge\utils\validation_proof.py forge\phase4\cloud_validate.py tests\core\test_validation_proof.py tests\phase2\test_secret_finder.py tests\phase4\test_cloud_validate.py tests\phase1\test_deterministic_findings.py tests\reporting\test_dashboard.py tests\phase1\test_engagement_orchestrator.py`
- `.venv\Scripts\python.exe -m pytest tests\core\test_validation_proof.py tests\phase2\test_secret_finder.py -k sentry tests\phase1\test_deterministic_findings.py::test_deterministic_findings_skip_sentry_key_without_slug_hash tests\phase1\test_deterministic_findings.py::test_deterministic_findings_skip_stale_sentry_key_proof tests\reporting\test_dashboard.py::test_generate_dashboard_surfaces_key_validation_proof_rows tests\reporting\test_dashboard.py::test_generate_dashboard_downgrades_stale_key_validation_proof_rows tests\phase4\test_cloud_validate.py::test_non_cloud_validation_identifier_parser_rejects_low_signal_success_details tests\phase4\test_cloud_validate.py::test_sweep_pending_cloud_validations_processes_social_messaging_and_collaboration_provider_tokens_without_cloud_finding tests\phase4\test_cloud_validate.py::test_sweep_pending_cloud_validations_downgrades_newer_provider_active_results_without_stable_proof -q --color=no -m "slow or not slow"` -> `12 passed, 237 deselected`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py::test_kill_chain_local_opendocument_artifacts_feed_validation_graph_and_template_report -q --color=no -m "slow or not slow"` -> `1 passed`

## Review

- Sidecar `Hume` found the original boolean-only proof promotion gap.
- Sidecar `Maxwell` found the first patch's 64-character repeated-hash edge case.
- Claude CLI read-only review at `%TEMP%\forge-claude-sentry-proof-review.txt` returned `Reached max turns (4)` with no useful findings.

## Safety

This checkpoint only hardens validation proof formatting and downstream report/graph gating. It does not add Sentry endpoints, widen provider calls, use extra credentials, relax scope, add proxy/IP rotation, bypass rate limits, or weaken report gates.
