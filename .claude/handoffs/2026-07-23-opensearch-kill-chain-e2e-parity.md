# 2026-07-23 OpenSearch Kill-Chain E2E Parity

Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`.

Gate advanced: representative T1/T2 kill-chain proof. Existing invariants:
`V1`, `V3`, `V4`, `V5`, `V8`, `V9`, `V10`, and `V11`.

## What changed

- Extended the focused mocked multi-seed recursive kill-chain E2E fixture with
  a local `opensearch.xml` artifact under the normal artifact intake root.
- The E2E now proves OpenSearch owner email and stripped URL pivots become
  recursive engagement seeds in the same run that completes cloud validation,
  graph generation, deterministic template fallback reporting, audit logging,
  and cleanup checks.
- This keeps the earlier helper/local/remote parser coverage while adding an
  actual kill-chain closeout proof point.

## Verification

- Focused E2E:
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_kill_chain_multiseed_recursive_e2e.py -q --color=no`
  -> `1 passed in 47.54s`.
- Compile:
  `.venv\Scripts\python.exe -m compileall tests\phase1\test_kill_chain_multiseed_recursive_e2e.py`
  -> passed.
- Ruff:
  `.venv\Scripts\python.exe -m ruff check tests\phase1\test_kill_chain_multiseed_recursive_e2e.py`
  -> passed.
- Cleanup/inventory:
  `temp_pytest_engagement_dbs=0`; workspace engagement inventory unchanged at
  `1`, `5010`, `master.db`.

## Safety

Mocked/offline E2E only. No external target, provider call, live probing,
credential use, authentication, scope relaxation, validation-gate change,
report-gate change, severity change, proxy/IP rotation, or rate-limit bypass.

## Continue Next

Continue the active backlog in
`docs/engagement_overhaul_tasklist.md` -> `## Compact active backlog`.
Preferred next gate remains a concrete T1/T2 kill-chain gap that improves real
recursive discovery, validation inventory, graph/report review, or cleanup.
