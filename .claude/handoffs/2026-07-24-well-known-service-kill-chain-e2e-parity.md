# Well-Known Service Metadata Kill-Chain E2E Parity

Date: 2026-07-24
Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`

## Completed

- Added compact E2E local `.well-known` fixtures for `did-configuration.json`, `keybase.txt`, `smart-configuration`, and `terraform.json`.
- Proved owner emails, stripped service metadata URL pivots, DID host recursion, static Terraform registry URLs, and Supabase/Firebase refs enter recursive engagement state.
- Proved templated service metadata URLs and sensitive query strings do not persist as recursive URL seeds.
- Proved service metadata cloud refs flow through validation inventory, graph cloud/assets, deterministic findings, deterministic template fallback report context, report JSON validation inventory, raw CSV validation rows, audit closeout, and cleanup.
- Hardened `smart-configuration` OAuth URL extraction to strip sensitive query parameters before returning recursive URL candidates.
- Extended Terraform DNS host extraction to `.well-known/terraform.json` without executing Terraform.
- Raised the E2E graph export cap from 600 to 700 nodes so the expanded compact fixture retains asserted service metadata review nodes.

## Files Changed

- `forge/engagement_orchestrator.py`
- `forge/utils/artifact_oauth_metadata.py`
- `tests/phase1/test_artifact_oauth_metadata.py`
- `tests/phase1/test_artifact_terraform_dns_records.py`
- `tests/phase1/kill_chain_multiseed_fixture.py`
- `tests/phase1/test_kill_chain_multiseed_recursive_e2e.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`
- `.claude/handoffs/2026-07-24-well-known-service-kill-chain-e2e-parity.md`

## Verification

- `.venv\Scripts\python.exe -m compileall forge\utils\artifact_oauth_metadata.py forge\engagement_orchestrator.py tests\phase1\test_artifact_oauth_metadata.py tests\phase1\test_artifact_terraform_dns_records.py tests\phase1\kill_chain_multiseed_fixture.py tests\phase1\test_kill_chain_multiseed_recursive_e2e.py`
- `.venv\Scripts\python.exe -m ruff check forge\utils\artifact_oauth_metadata.py forge\engagement_orchestrator.py tests\phase1\test_artifact_oauth_metadata.py tests\phase1\test_artifact_terraform_dns_records.py tests\phase1\kill_chain_multiseed_fixture.py tests\phase1\test_kill_chain_multiseed_recursive_e2e.py`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_well_known_service_metadata.py tests\phase1\test_artifact_oauth_metadata.py tests\phase1\test_artifact_terraform_dns_records.py tests\phase1\test_artifact_did_metadata.py tests\phase1\test_artifact_helpers.py -q --color=no` -> `17 passed`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_kill_chain_multiseed_recursive_e2e.py -q --color=no` -> `1 passed in 276.84s`
- Cleanup removed 13 test-owned DB/report files and left `remaining_test_owned_files=0`.
- Workspace engagement inventory remains `1`, `5010`, `master.db`.
- No tracked Python/pytest/Claude/Gemini process remains.

## Safety

Mocked/offline E2E and passive well-known service metadata only. No Terraform execution, DID resolution call, Keybase lookup, SMART endpoint call, provider call beyond mocked validators, live probing, credential use, scope relaxation, validation-gate change, report-gate change, severity change, proxy/IP rotation, or rate-limit bypass.

## Next

Continue moving remaining safe sequential enrichers under the bounded worker-pool path beyond the existing D1/D2/D5 parse work. Start with the smallest deterministic slice that reduces sequential kill-chain runtime while preserving stable result ordering, scope/ROE gates, provider pacing, audit logging, and cleanup.
