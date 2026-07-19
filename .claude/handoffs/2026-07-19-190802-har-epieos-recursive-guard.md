# HAR + Epieos Recursive Guard Handoff

Date: 2026-07-19

## Scope

- Addressed code-size discipline without broad rewrites: HAR scalar/content/image parsing was extracted to `forge/utils/artifact_har.py`, with HAR-specific regressions in `tests/phase1/test_artifact_har.py`.
- Fixed reviewer-identified recursive discovery correctness gaps:
  - Federated Epieos identities on known non-federated platform hosts are rejected before row creation.
  - Persisted bad federated account IDs such as `acct:octocat@github.com` no longer become recursive username or host seeds during synthesis.
  - Top-level provider-key arrays such as `"github": [{...}]` are now parsed.
  - HAR files now use a bounded 16 MiB parse cap instead of truncating to the generic 1 MiB artifact cap before JSON parsing.

## Files Changed

- `forge/engagement_orchestrator.py`
- `forge/utils/artifact_har.py`
- `forge/utils/intel/social_scraper.py`
- `tests/phase1/test_artifact_har.py`
- `tests/phase1/test_engagement_orchestrator.py`
- `tests/phase2/test_social_scraper.py`
- `docs/claude_continue_checklist.md`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- `.venv\Scripts\python.exe -m py_compile forge\utils\intel\social_scraper.py forge\engagement_orchestrator.py tests\phase2\test_social_scraper.py tests\phase1\test_artifact_har.py tests\phase1\test_engagement_orchestrator.py` -> passed
- `.venv\Scripts\python.exe -m ruff check forge\utils\intel\social_scraper.py forge\engagement_orchestrator.py tests\phase2\test_social_scraper.py tests\phase1\test_artifact_har.py tests\phase1\test_engagement_orchestrator.py` -> `All checks passed!`
- `.venv\Scripts\python.exe -m pytest tests\phase2\test_social_scraper.py::TestParseEpieosResponse::test_rejects_federated_profiles_on_non_federated_social_hosts tests\phase2\test_social_scraper.py::TestParseEpieosResponse::test_recurse_provider_key_arrays_for_profiles tests\phase1\test_engagement_orchestrator.py::test_synthesis_engine_promotes_federated_acct_ids_to_recursive_user_and_instance_seeds tests\phase1\test_artifact_har.py -q --color=no -m "slow or not slow"` -> `8 passed`
- `.venv\Scripts\python.exe -m pytest tests\phase2\test_social_scraper.py -q --color=no` -> `72 passed`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py -q --color=no -k "har or image_response or ocrs_image or ocrs_modern_image or image_metadata" -m "slow or not slow"` -> `21 passed, 790 deselected`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py -q --color=no -k "normalize_root_domain or verified_claimed_and_associated_domain_aliases or matrix_federated_and_nostr or managed_cloud_social_profile_urls or social_profile_domain or social_profile_pivot or raw_social_profile or identity_recursion or social_profile_related_host or social_profile or federated_acct" -m "slow or not slow"` -> `101 passed, 710 deselected`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py::test_kill_chain_artifact_extracted_assets_validate_and_seed_next_iteration_under_scope tests\phase6\test_report_synthesizer.py::test_synthesizer_runtime_provider_failure_falls_back_to_template tests\reporting\test_dashboard.py::test_generate_dashboard_emits_slug_routes_and_json_contract tests\reporting\test_dashboard.py::test_generate_dashboard_surfaces_provider_matrix_artifacts_and_validation_evidence tests\phase4\test_cloud_validate.py::test_sweep_pending_cloud_asset_validations_scope_checker_skips_denied_assets tests\phase4\test_attack_path.py::TestGraphBuildArtifacts::test_graph_build_all_writes_native_mtgx_workspace -q --color=no -m "slow or not slow"` -> `6 passed`
- Scoped cleanup check for `.forge_data/engagements` -> `remaining_test_like_engagement_dbs=0`

## Review

- OpenAI sidecar reviewer `019f79fd-b3c9-7b00-b4e3-722e35947e4c` found three actionable issues: overbroad federated host acceptance, HAR JSON truncation before structured parsing, and missing provider-key array recursion. All three are fixed with regressions.
- Claude CLI read-only review was attempted with `claude -p --model sonnet --max-turns 3 --allowedTools 'Read,Grep,Glob'`, but local Claude returned: `You've hit your session limit - resets 6:50pm (Asia/Singapore)`.

## Safety Notes

- Changes are passive parsing, normalization, bounded local validation, and tests only.
- No credential use, authentication attempt, live probing expansion, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate weakening was added.
- HAR parsing cap is bounded at 16 MiB to support valid HARs containing OCR-cap-sized base64 image responses while avoiding unbounded file reads.

## Next Tasks

- Extract Epieos social-host matching/profile URL guard logic into a compact helper module without changing behavior.
- Continue ratcheting `forge/engagement_orchestrator.py`, `forge/cli.py`, `forge/utils/intel/social_scraper.py`, and mega tests by moving only touched feature areas into small modules with focused tests.
- Rerun Claude read-only audit after the local session reset.
- If a Git repository is initialized later, commit this checkpoint before further refactors.
