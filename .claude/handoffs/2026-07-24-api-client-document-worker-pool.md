# API-Client Document Worker-Pool Checkpoint

Date: 2026-07-24

## Completed

- [x] Converted generic API-client document traversal to dispatch the current
  mapping/list child layer through `ArtifactQueueProcessor._run_ordered_local_batch`.
- [x] Kept nested recursion serial inside worker jobs to avoid nested
  worker-pool oversubscription.
- [x] Preserved URL-object candidates, direct URL fields, variable mappings,
  sensitive-query stripping, source-gated API-client parsing, and final serial
  URL normalization/dedupe.
- [x] Added focused regression coverage in
  `tests/phase1/test_artifact_api_client_document_workers.py`.
- [x] Kept the change passive and local to static API-client collection parsing.

## Verification

- [x] Compile check
  - `.venv\Scripts\python.exe -m compileall forge\engagement_orchestrator.py tests\phase1\test_artifact_api_client_document_workers.py`
- [x] Ruff check
  - `.venv\Scripts\python.exe -m ruff check forge\engagement_orchestrator.py tests\phase1\test_artifact_api_client_document_workers.py`
- [x] Focused worker regression
  - `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_api_client_document_workers.py -q --color=no`
  - Result: `2 passed`
- [x] Existing worker plus persisted integration
  - `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_api_client_workers.py tests\phase1\test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_api_spec_and_client_collection_artifacts -q --color=no`
  - Result: `16 passed`
- [x] Runtime cleanup check
  - Result: `remaining_api_client_document_runtime_files=0`

## Safety Boundary

- Passive static API-client collection parsing only.
- No API-client execution.
- No request replay.
- No endpoint probing.
- No HTTP probing, provider calls, live probing, credential use, scope/ROE
  relaxation, validation/report-gate change, severity change, proxy/IP
  rotation, rate-limit bypass, or destructive behavior.

## Continue Next

- Re-audit remaining static parser/enricher candidates.
- Currently ranked candidates:
  - Observability structured walk.
  - Orchestration structured walk.
  - Security-scanner JSON structured walk.
- Select one proven-safe bounded worker-pool migration with compact focused
  coverage.
