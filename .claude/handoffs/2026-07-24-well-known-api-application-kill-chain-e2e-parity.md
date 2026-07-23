# Well-Known API/Application Metadata Kill-Chain E2E Parity

Date: 2026-07-24
Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`

## Completed

- Added compact E2E local `.well-known` fixtures for `agent-card.json`, `api-catalog`, `open-resource-discovery`, `mercure`, and `webweaver.json`.
- Proved owner emails, stripped API/application URL pivots, and Supabase/Firebase refs enter recursive engagement state.
- Proved templated API/application URLs and sensitive query strings do not persist as recursive URL seeds.
- Proved API/application metadata cloud refs flow through validation inventory, graph cloud/assets, deterministic findings, deterministic template fallback report context, report JSON validation inventory, raw CSV validation rows, audit closeout, and cleanup.
- Added shared API/application artifact URL sanitizer hardening so helper functions strip sensitive query parameters before returning recursive URL candidates while preserving non-sensitive parameters.
- Raised the E2E graph export cap from 480 to 600 nodes so the expanded compact fixture retains asserted API/application review nodes.

## Files Changed

- `forge/utils/artifact_url_sanitizer.py`
- `forge/utils/artifact_agent_card_metadata.py`
- `forge/utils/artifact_api_catalog_metadata.py`
- `forge/utils/artifact_open_resource_discovery.py`
- `forge/utils/artifact_mercure_metadata.py`
- `forge/utils/artifact_webweaver_metadata.py`
- `tests/phase1/test_artifact_api_application_metadata_sanitizer.py`
- `tests/phase1/kill_chain_multiseed_fixture.py`
- `tests/phase1/test_kill_chain_multiseed_recursive_e2e.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`
- `.claude/handoffs/2026-07-24-well-known-api-application-kill-chain-e2e-parity.md`

## Verification

- `.venv\Scripts\python.exe -m compileall forge\utils\artifact_url_sanitizer.py forge\utils\artifact_agent_card_metadata.py forge\utils\artifact_api_catalog_metadata.py forge\utils\artifact_open_resource_discovery.py forge\utils\artifact_mercure_metadata.py forge\utils\artifact_webweaver_metadata.py tests\phase1\test_artifact_api_application_metadata_sanitizer.py tests\phase1\kill_chain_multiseed_fixture.py tests\phase1\test_kill_chain_multiseed_recursive_e2e.py`
- `.venv\Scripts\python.exe -m ruff check forge\utils\artifact_url_sanitizer.py forge\utils\artifact_agent_card_metadata.py forge\utils\artifact_api_catalog_metadata.py forge\utils\artifact_open_resource_discovery.py forge\utils\artifact_mercure_metadata.py forge\utils\artifact_webweaver_metadata.py tests\phase1\test_artifact_api_application_metadata_sanitizer.py tests\phase1\kill_chain_multiseed_fixture.py tests\phase1\test_kill_chain_multiseed_recursive_e2e.py`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_api_application_metadata_sanitizer.py tests\phase1\test_artifact_well_known_api_metadata.py tests\phase1\test_artifact_agent_card_metadata.py tests\phase1\test_artifact_api_catalog_metadata.py tests\phase1\test_artifact_open_resource_discovery_metadata.py tests\phase1\test_artifact_mercure_metadata.py tests\phase1\test_artifact_webweaver_metadata.py tests\phase1\test_artifact_helpers.py -q --color=no` -> `16 passed`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_kill_chain_multiseed_recursive_e2e.py -q --color=no` -> `1 passed in 258.90s`
- Final cleanup left `remaining_test_owned_files=0`.
- Workspace engagement inventory remains `1`, `5010`, `master.db`.

## Safety

Mocked/offline E2E and passive well-known API/application metadata only. No A2A agent call, API catalog fetch, ORD call, Mercure subscription, WebWeaver call, provider call beyond mocked validators, live probing, credential use, scope relaxation, validation-gate change, report-gate change, severity change, proxy/IP rotation, or rate-limit bypass.

## Next

Add well-known service metadata compact E2E parity. Use the smallest local `did-configuration.json`, `keybase.txt`, `smart-configuration`, and `terraform.json` fixture set that proves contacts, sanitized recursive URLs, cloud refs, passive review inventory, validation inventory where applicable, graph/report/audit review, deterministic fallback output, and cleanup.
