# Service Worker Static Recursion Handoff

Date: 2026-07-24

Checkpoint: service-worker/precache static recursion is implemented and tested.

## What Changed

- Added a source-gated `service-worker-js` artifact label in
  `forge/utils/artifact_js_runtime_config.py` for:
  `service-worker*.js`, `workbox*.js`, `precache-manifest*.js`,
  `firebase-messaging-sw.js`, `OneSignalSDKWorker.js`, and
  `OneSignalSDKUpdaterWorker.js`.
- Added service-worker candidate extraction for `importScripts()` HTTP(S) URLs
  and Firebase messaging `projectId` / `project_id` refs.
- Wired the new parser into `ArtifactQueueProcessor._js_runtime_text_candidate_values()`
  and browser endpoint extraction so `apiUrl`-style config is handled only for
  the source-gated service-worker label.
- Added focused parser and engagement-backed persistence tests in
  `tests/phase1/test_artifact_js_runtime_config.py`.
- Recorded the bug contract as `SPEC.md` `B34`.

## Safety Boundary

This is passive static parsing only. It does not execute service-worker code,
does not add live probing, and does not weaken validation/report gates. Generic
`app.js` remains excluded from structured JS parsing.

## Verification

- `python -m compileall forge/engagement_orchestrator.py forge/utils/artifact_js_runtime_config.py`
- `ruff check forge/engagement_orchestrator.py forge/utils/artifact_js_runtime_config.py tests/phase1/test_artifact_js_runtime_config.py`
- `python -m pytest tests/phase1/test_artifact_js_runtime_config.py -q`
  -> `5 passed`
- `python -m pytest tests/phase1/test_artifact_js_runtime_config.py tests/phase1/test_artifact_api_format_labels.py tests/phase1/test_artifact_js_runtime_workers.py -q`
  -> `7 passed`

## Next Recommended Task

Add the mocked local-safe E2E fixture:

`tests/phase1/test_kill_chain_multiseed_recursive_e2e.py::test_kill_chain_multiseed_service_worker_precache_recurses_to_validated_report_outputs`

The fixture should prove page/manifest -> service worker -> precache/Workbox
artifact recursion into mixed cloud assets, validation inventory, validated
findings only, graph/report/raw exports, dashboard review visibility, fallback
lineage, and cleanup. Keep all provider behavior mocked/local; no live network
or real provider dependency is needed.
