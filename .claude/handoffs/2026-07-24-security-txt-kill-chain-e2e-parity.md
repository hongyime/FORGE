# Security.txt Kill-Chain E2E Parity

Date: 2026-07-24

## Goal Gate

Advances deterministic artifact analysis, recursive discovery, validation,
review, fallback, and cleanup gates for `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`.

## Completed

- Added local `.well-known/security.txt` to the compact multi-seed kill-chain
  E2E under normal artifact intake.
- Proved `security.txt` disclosure contact email becomes a recursive email
  seed.
- Proved report, policy, and hiring URLs become recursive URL seeds with
  sensitive query strings stripped.
- Proved Supabase and Firebase refs from the same security metadata artifact
  validate non-destructively.
- Proved security metadata cloud refs create deterministic findings and appear
  in graph nodes, deterministic template fallback report context, raw CSV
  validation rows, audit closeout, and cleanup.
- Raised the test-local graph export cap from 150 to 220 nodes so the expanded
  compact fixture retains all asserted review nodes instead of pruning prior
  mobile-inventory assertions.

## Verification

- `python -m compileall tests\phase1\kill_chain_multiseed_fixture.py tests\phase1\test_kill_chain_multiseed_recursive_e2e.py`
- `python -m ruff check tests\phase1\kill_chain_multiseed_fixture.py tests\phase1\test_kill_chain_multiseed_recursive_e2e.py`
- `python -m pytest tests\phase1\test_artifact_public_metadata_labels.py tests\phase1\test_artifact_public_metadata_links.py tests\phase1\test_artifact_helpers.py -q --color=no` -> `10 passed`
- `python -m pytest tests\phase1\test_kill_chain_multiseed_recursive_e2e.py -q --color=no` first exposed graph-cap pruning, then passed -> `1 passed in 163.48s`
- Cleanup removed 26 test-owned temp DB/report files and left
  `remaining_test_owned_files=0`.
- Persistent workspace inventory remains `1`, `5010`, `master.db`.

## Safety

Mocked/offline E2E and passive security metadata only. No provider call beyond
mocked validators, live probing, credential use, scope relaxation,
validation-gate change, report-gate change, severity change, proxy/IP rotation,
or rate-limit bypass.

## Next

Add `llms.txt` / public AI metadata compact E2E parity. Use the smallest local
public AI metadata fixture that proves owner contacts, markdown or field-link
documentation/API URL pivots, cloud refs, validation inventory,
graph/report/audit review, deterministic fallback output, and cleanup.
