# 2026-07-23 OpenSearch Description Passive Recursion

Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`.

Gate advanced: discovery/recursion/static artifact analysis under `SPEC.md`
`T2`, with existing invariants `V1`, `V3`, `V4`, and `V5`.

## What changed

- Added `forge.utils.artifact_opensearch_metadata`.
- Source-gated OpenSearch Description artifacts now label as
  `opensearch-description` for names/routes such as `opensearch.xml`,
  `open-search.xml`, `opensearchdescription.xml`, and `/opensearch`.
- OpenSearch XML parsing passively promotes concrete URL pivots from
  `<Url template=...>`, `moz:SearchForm`, and image links into the existing
  artifact URL-seed path.
- Search template query values such as `{searchTerms}` are stripped before seed
  persistence; templated hosts and paths are excluded.
- Relative URLs resolve only when the source artifact has an HTTP(S) base.
- Remote cache filename selection keeps source-aware `opensearch.xml` names for
  extensionless `/opensearch` routes.

## Verification

- TDD red first:
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_opensearch_metadata.py -q --color=no`
  failed on missing `forge.utils.artifact_opensearch_metadata`.
- Focused OpenSearch regression:
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_opensearch_metadata.py -q --color=no`
  -> `5 passed`.
- Adjacent metadata/static regression:
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_opensearch_metadata.py tests\phase1\test_artifact_saml_metadata.py tests\phase1\test_artifact_oauth_metadata.py tests\phase1\test_artifact_jwks_metadata.py tests\phase1\test_artifact_web_manifest_metadata.py tests\phase1\test_artifact_remote_static_classification.py -q --color=no`
  -> `33 passed`.
- Compile:
  `.venv\Scripts\python.exe -m compileall forge\utils\artifact_opensearch_metadata.py forge\engagement_orchestrator.py tests\phase1\test_artifact_opensearch_metadata.py`
  -> passed.
- Ruff:
  `.venv\Scripts\python.exe -m ruff check forge\utils\artifact_opensearch_metadata.py forge\engagement_orchestrator.py tests\phase1\test_artifact_opensearch_metadata.py`
  -> passed.
- Cleanup:
  removed temp pytest engagement DBs with a path-verified Python unlink script;
  `remaining_temp_pytest_engagement_dbs=0`; workspace engagement inventory
  unchanged at `1`, `5010`, `master.db`.

## Safety

Passive static OpenSearch XML parsing only. No search execution, provider call,
live probing, credential use, authentication, scope relaxation, validation-gate
change, report-gate change, severity change, proxy/IP rotation, or rate-limit
bypass.

## Continue Next

Continue the active backlog in
`docs/engagement_overhaul_tasklist.md` -> `## Compact active backlog`.
Preferred next gate remains the smallest mocked E2E or focused integration test
that proves another missing `T1`/`T2` recursive discovery path advances into a
secondary seed, validation inventory, graph/report review, or cleanup.
