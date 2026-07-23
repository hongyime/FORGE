# Well-Known Privacy/Vendor Metadata Kill-Chain E2E Parity

Date: 2026-07-24
Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`

## Completed

- Added compact E2E local `.well-known` fixtures for `gpc.json`, `tdmrep.json`, `pubvendors.json`, `trust.txt`, `dnt-policy.txt`, and `privacy-sandbox-attestations.json`.
- Proved owner emails, stripped privacy/vendor/trust/DNT/sandbox URL pivots, and Supabase/Firebase refs enter recursive engagement state.
- Proved templated privacy/vendor URLs and sensitive query strings do not persist as recursive URL seeds.
- Proved privacy/vendor metadata cloud refs flow through validation inventory, graph nodes, deterministic findings, deterministic template fallback report context, raw CSV validation rows, audit closeout, and cleanup.
- Raised the E2E graph export cap from 380 to 480 nodes so the expanded compact fixture retains asserted privacy/vendor review nodes.

## Files Changed

- `tests/phase1/kill_chain_multiseed_fixture.py`
- `tests/phase1/test_kill_chain_multiseed_recursive_e2e.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`
- `.claude/handoffs/2026-07-24-well-known-privacy-kill-chain-e2e-parity.md`

## Verification

- `.venv\Scripts\python.exe -m compileall tests\phase1\kill_chain_multiseed_fixture.py tests\phase1\test_kill_chain_multiseed_recursive_e2e.py`
- `.venv\Scripts\python.exe -m ruff check tests\phase1\kill_chain_multiseed_fixture.py tests\phase1\test_kill_chain_multiseed_recursive_e2e.py`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_well_known_privacy_metadata.py tests\phase1\test_artifact_public_metadata_links.py tests\phase1\test_artifact_public_metadata_labels.py tests\phase1\test_artifact_helpers.py -q --color=no` -> `12 passed`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_kill_chain_multiseed_recursive_e2e.py -q --color=no` -> `1 passed in 237.24s`
- Cleanup removed 13 test-owned DB/report files and left `remaining_test_owned_files=0`.
- Workspace engagement inventory remains `1`, `5010`, `master.db`.

## Safety

Mocked/offline E2E and passive well-known privacy/vendor metadata only. No provider call beyond mocked validators, live probing, credential use, policy/vendor API call, browser privacy-sandbox behavior, scope relaxation, validation-gate change, report-gate change, severity change, proxy/IP rotation, or rate-limit bypass.

## Next

Add well-known API/application metadata compact E2E parity. Use the smallest local `agent-card.json`, `api-catalog`, `open-resource-discovery`, `mercure`, or `webweaver.json` fixture set that proves contacts, sanitized recursive URLs, cloud refs, passive review inventory, validation inventory where applicable, graph/report/audit review, deterministic fallback output, and cleanup.
