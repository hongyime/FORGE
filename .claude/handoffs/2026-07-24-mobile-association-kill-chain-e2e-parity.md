# Mobile Association Kill-Chain E2E Parity

Date: 2026-07-24

## Goal Gate

Advances deterministic artifact analysis, recursive discovery, validation,
review, fallback, and cleanup gates for `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`.

## Completed

- Added local `.well-known/assetlinks.json` and
  `.well-known/apple-app-site-association` fixtures to the compact multi-seed
  kill-chain E2E under normal artifact intake.
- Proved Asset Links and AASA owner emails plus stripped documentation URL
  pivots become recursive engagement seeds.
- Proved Supabase refs emitted from the same mobile association artifacts are
  validated and included in deterministic report/graph review.
- Proved Android/iOS passive app inventory reaches `cloud_assets`, graph cloud
  nodes, report validation inventory, and raw CSV validation rows with terminal
  `UNSUPPORTED` status.
- Proved malformed Android package and AASA app IDs are excluded.
- Proved unsupported passive mobile app inventory does not create vulnerability
  findings.
- Updated the compact E2E validation mock to mirror the real registry fallback:
  passive mobile app asset types return `UNSUPPORTED` with `registry_lookup`.

## Verification

- `python -m compileall tests\phase1\kill_chain_multiseed_fixture.py tests\phase1\test_kill_chain_multiseed_recursive_e2e.py`
- `python -m ruff check tests\phase1\kill_chain_multiseed_fixture.py tests\phase1\test_kill_chain_multiseed_recursive_e2e.py`
- `python -m pytest tests\phase1\test_artifact_assetlinks_metadata.py tests\phase1\test_artifact_aasa_metadata.py tests\phase4\test_cloud_validation_registry_contract.py -q --color=no` -> `3 passed`
- `python -m pytest tests\phase1\test_kill_chain_multiseed_recursive_e2e.py -q --color=no` -> `1 passed in 154.56s`
- Cleanup removed 14 test-owned temp DB/report files and left
  `remaining_test_owned_files=0`.
- Persistent workspace inventory remains `1`, `5010`, `master.db`.

## Safety

Mocked/offline E2E and passive mobile-association inventory only. No app-store
lookup, app download, provider call beyond mocked validators, live probing,
credential use, scope relaxation, validation-gate change, report-gate change,
severity change, proxy/IP rotation, or rate-limit bypass.

## Next

Add `security.txt` / well-known security metadata compact E2E parity. Use the
smallest local security metadata fixture that proves disclosure contacts,
policy or documentation URLs, cloud refs, validation inventory,
graph/report/audit review, deterministic fallback output, and cleanup.
