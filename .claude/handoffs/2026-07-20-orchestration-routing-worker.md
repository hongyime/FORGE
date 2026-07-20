# Orchestration Routing Worker Checkpoint

## Summary

`ArtifactQueueProcessor._orchestration_document_url_candidates()` now normalizes routing-rule strings through the existing bounded ordered local worker helper. Traversal, caps, dedupe, and appending remain serial, so output ordering and source gates are preserved.

## Safety Boundary

- Pure local parsing/prep only.
- No provider calls, DB writes, network I/O, validation, live probing, scope relaxation, pacing/backoff change, proxy/IP rotation, rate-limit bypass, report-gate change, exploitation, or destructive behavior.

## Verification

- `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py tests\phase1\test_artifact_orchestration_workers.py`
- `python -m ruff check forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py tests\phase1\test_artifact_orchestration_workers.py`
- `python -m pytest tests\phase1\test_artifact_orchestration_workers.py tests\phase1\test_artifact_helpers.py -k "orchestration or kubernetes_annotation or helm_lock" -q --color=no` -> `3 passed, 27 deselected`
- `python -m pytest tests\phase1\test_engagement_orchestrator.py -k "orchestration_structured_payload or artifact_nomad or parallelizes" -q --color=no` -> `278 passed, 482 deselected`

## Review

Explorer `Copernicus` identified the safe worker migration candidate.
