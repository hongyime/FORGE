# 2026-07-24 JSON Feed Passive Recursion

Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`.

Gate advanced: discovery/recursion/static artifact analysis under `SPEC.md`
`T2`, with existing invariants `V1`, `V3`, `V4`, and `V5`.

## What changed

- Added `forge.utils.artifact_json_feed_metadata`.
- Source-gated JSON Feed artifacts now label as `json-feed` for `feed.json`,
  `jsonfeed.json`, and `json-feed.json`.
- JSON Feed parsing passively promotes concrete URLs from `home_page_url`,
  `feed_url`, `next_url`, author URLs, hub URLs, item URLs, item external URLs,
  images, banner images, and attachment URLs into the existing recursive seed
  path.
- Query strings and fragments are stripped before helper URL persistence.
- Templated URLs are excluded.
- Relative JSON Feed URLs resolve only when the source artifact has an HTTP(S)
  base.
- `jsonfeed.org/version/*` standards URLs are suppressed as metadata rather
  than recursive targets.

## Verification

- TDD red first:
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_json_feed_metadata.py -q --color=no`
  failed on missing `forge.utils.artifact_json_feed_metadata`.
- Focused JSON Feed regression:
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_json_feed_metadata.py -q --color=no`
  -> `4 passed`.
- Adjacent metadata/static regression:
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_json_feed_metadata.py tests\phase1\test_artifact_feed_metadata.py tests\phase1\test_artifact_opensearch_metadata.py tests\phase1\test_artifact_saml_metadata.py tests\phase1\test_artifact_oauth_metadata.py tests\phase1\test_artifact_jwks_metadata.py tests\phase1\test_artifact_web_manifest_metadata.py tests\phase1\test_artifact_remote_static_classification.py -q --color=no`
  -> `42 passed`.
- Compile:
  `.venv\Scripts\python.exe -m compileall forge\utils\artifact_json_feed_metadata.py forge\engagement_orchestrator.py tests\phase1\test_artifact_json_feed_metadata.py`
  -> passed.
- Ruff:
  `.venv\Scripts\python.exe -m ruff check forge\utils\artifact_json_feed_metadata.py forge\engagement_orchestrator.py tests\phase1\test_artifact_json_feed_metadata.py`
  -> passed.
- Cleanup:
  removed temp pytest engagement DBs with a path-verified Python unlink script;
  `remaining_temp_pytest_engagement_dbs=0`; workspace engagement inventory
  unchanged at `1`, `5010`, `master.db`.

## Safety

Passive static JSON Feed parsing only. No feed polling, provider call, live
probing, credential use, authentication, scope relaxation, validation-gate
change, report-gate change, severity change, proxy/IP rotation, or rate-limit
bypass.

## Continue Next

Continue the active backlog in
`docs/engagement_overhaul_tasklist.md` -> `## Compact active backlog`.
Preferred next gate remains a concrete T1/T2 kill-chain gap that improves real
recursive discovery, validation inventory, graph/report review, or cleanup.
