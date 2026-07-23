# 2026-07-24 RSS/Atom Feed Passive Recursion

Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`.

Gate advanced: discovery/recursion/static artifact analysis under `SPEC.md`
`T2`, with existing invariants `V1`, `V3`, `V4`, and `V5`.

## What changed

- Added `forge.utils.artifact_feed_metadata`.
- Source-gated feed artifacts now label as `feed.xml`, `rss.xml`, or
  `atom.xml` for filenames and extensionless `/feed`, `/rss`, and `/atom`
  remote routes.
- Feed XML parsing passively promotes concrete URLs from RSS/Atom `<link>`,
  Atom `href`, permalink `guid`, enclosure URLs, and media content URLs into
  the existing recursive seed path.
- Query strings and fragments are stripped before helper URL persistence.
- Templated URLs are excluded.
- Relative feed URLs resolve only when the source artifact has an HTTP(S) base.
- Remote cache filename selection keeps source-aware feed filenames for
  extensionless routes.
- Atom and Media RSS XML namespace URLs are suppressed as standards metadata
  rather than recursive targets.

## Verification

- TDD red first:
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_feed_metadata.py -q --color=no`
  failed on missing `forge.utils.artifact_feed_metadata`.
- Focused feed regression:
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_feed_metadata.py -q --color=no`
  -> `5 passed`.
- Adjacent metadata/static regression:
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_feed_metadata.py tests\phase1\test_artifact_opensearch_metadata.py tests\phase1\test_artifact_saml_metadata.py tests\phase1\test_artifact_oauth_metadata.py tests\phase1\test_artifact_jwks_metadata.py tests\phase1\test_artifact_web_manifest_metadata.py tests\phase1\test_artifact_remote_static_classification.py -q --color=no`
  -> `38 passed`.
- Compile:
  `.venv\Scripts\python.exe -m compileall forge\utils\artifact_feed_metadata.py forge\engagement_orchestrator.py tests\phase1\test_artifact_feed_metadata.py`
  -> passed.
- Ruff:
  `.venv\Scripts\python.exe -m ruff check forge\utils\artifact_feed_metadata.py forge\engagement_orchestrator.py tests\phase1\test_artifact_feed_metadata.py`
  -> passed.
- Cleanup:
  removed temp pytest engagement DBs with a path-verified Python unlink script;
  `remaining_temp_pytest_engagement_dbs=0`; workspace engagement inventory
  unchanged at `1`, `5010`, `master.db`.

## Safety

Passive static feed XML parsing only. No feed polling, provider call, live
probing, credential use, authentication, scope relaxation, validation-gate
change, report-gate change, severity change, proxy/IP rotation, or rate-limit
bypass.

## Continue Next

Continue the active backlog in
`docs/engagement_overhaul_tasklist.md` -> `## Compact active backlog`.
Preferred next gate remains a concrete T1/T2 kill-chain gap that improves real
recursive discovery, validation inventory, graph/report review, or cleanup.
