# Well-Known Supply-Chain Metadata Kill-Chain E2E Parity

Date: 2026-07-24
Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`

## Completed

- Added compact E2E local `.well-known` fixtures for CSAF, SBOM, passkey endpoints, SSH known-hosts, and PKI validation metadata.
- Proved owner emails, stripped documentation/API/passkey URL pivots, SSH known-host passive subdomain inventory, and Supabase/Firebase refs enter recursive engagement state.
- Proved templated supply-chain URLs and sensitive query strings do not persist as recursive URL seeds.
- Proved supply-chain metadata cloud refs flow through validation inventory, graph nodes, deterministic findings, deterministic template fallback report context, raw CSV validation rows, audit closeout, and cleanup.
- Raised the E2E graph export cap from 300 to 380 nodes so the expanded compact fixture retains asserted supply-chain review nodes.

## Files Changed

- `tests/phase1/kill_chain_multiseed_fixture.py`
- `tests/phase1/test_kill_chain_multiseed_recursive_e2e.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`
- `.claude/handoffs/2026-07-24-well-known-supply-chain-kill-chain-e2e-parity.md`

## Verification

- `.venv\Scripts\python.exe -m compileall tests\phase1\kill_chain_multiseed_fixture.py tests\phase1\test_kill_chain_multiseed_recursive_e2e.py`
- `.venv\Scripts\python.exe -m ruff check tests\phase1\kill_chain_multiseed_fixture.py tests\phase1\test_kill_chain_multiseed_recursive_e2e.py`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_well_known_security_metadata.py tests\phase1\test_artifact_passkey_metadata.py tests\phase1\test_artifact_public_metadata_labels.py tests\phase1\test_artifact_helpers.py -q --color=no` -> `12 passed`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_kill_chain_multiseed_recursive_e2e.py -q --color=no` -> `1 passed in 336.11s`
- Cleanup left `remaining_test_owned_files=0`.
- Workspace engagement inventory remains `1`, `5010`, `master.db`.
- A stale global-Python pytest process holding a prior compact E2E temp DB was identified by exact command line and stopped before final cleanup.

## Safety

Mocked/offline E2E and passive well-known supply-chain/security metadata only. No provider call beyond mocked validators, live probing, credential use, package/SBOM/passkey/SSH/PKI execution, scope relaxation, validation-gate change, report-gate change, severity change, proxy/IP rotation, or rate-limit bypass.

## Next

Add well-known privacy/vendor metadata compact E2E parity. Use the smallest local `trust.txt`, `gpc.json`, `tdmrep.json`, or adjacent public vendor metadata fixture set that proves contacts, sanitized recursive URLs, cloud refs, passive review inventory, validation inventory where applicable, graph/report/audit review, deterministic fallback output, and cleanup.
