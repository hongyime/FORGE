# Web Manifest Kill-Chain E2E Parity

Date: 2026-07-24

## Goal Gate

Advances deterministic artifact analysis, recursive discovery, validation,
review, fallback, and cleanup gates for `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`.

## Completed

- Added local `site.webmanifest` to the compact multi-seed kill-chain E2E
  fixture under normal artifact intake.
- Proved manifest owner email plus stripped `start_url`, `scope`, shortcut,
  share-target, icon URL, and Supabase inventory pivots reach recursive
  engagement state before validation, graph generation, deterministic template
  fallback reporting, audit logging, and cleanup.
- Tightened E2E assertions for `manifestvault` validation, graph cloud/finding
  nodes, report inclusion, template fallback lineage, and raw fragment
  suppression.
- Set `FORGE_SAFE_MODE=1` in the compact E2E.
- Narrowed direct URL extraction so Web App Manifest artifact URLs strip
  fragments before persistence, aligning local absolute URL extraction with the
  source-gated manifest parser contract.

## Verification

- `python -m compileall forge\engagement_orchestrator.py tests\phase1\test_kill_chain_multiseed_recursive_e2e.py tests\phase1\kill_chain_multiseed_fixture.py`
- `python -m ruff check forge\engagement_orchestrator.py tests\phase1\test_kill_chain_multiseed_recursive_e2e.py tests\phase1\kill_chain_multiseed_fixture.py`
- `python -m pytest tests\phase1\test_artifact_web_manifest_metadata.py -q --color=no` -> `2 passed`
- `python -m pytest tests\phase1\test_kill_chain_multiseed_recursive_e2e.py -q --color=no` -> `1 passed in 147.20s`
- Cleanup removed 26 test-owned temp DB/report files and left
  `remaining_test_owned_files=0`.
- Persistent workspace inventory remains `1`, `5010`, `master.db`.

## Safety

Mocked/offline E2E plus passive manifest URL normalization only. No external
target, provider call, live probing, credential use, scope relaxation,
validation-gate change, report-gate change, severity change, proxy/IP rotation,
or rate-limit bypass.

## Next

Add Asset Links / Apple app-site-association compact E2E parity. Use the
smallest local `assetlinks.json` and/or `apple-app-site-association` fixture
that proves mobile association metadata reaches passive mobile inventory,
recursive seed/cross-reference state, validation inventory or terminal
unsupported status, graph/report/audit review, deterministic fallback output,
and cleanup.
