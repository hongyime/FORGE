# Remote Artifact Parallel Attribution Handoff

Date: 2026-07-24

## Completed

- Hardened `ArtifactQueueProcessor._download_remote_artifacts()` in
  `forge/engagement_orchestrator.py` so the parallel future map stores
  `(result_index, request)` instead of only the result index.
- Added `tests/phase1/test_artifact_remote_scope_parallel.py` to prove mixed
  scope-skipped, allowed-failing, and allowed-successful downloads keep the
  correct artifact IDs, URLs, and errors.

## Finding

Inspection showed the suspected bug was not active: the old value was already
the original request index, not a compact allowed-list index. The code change is
therefore a clarity hardening and regression guard, not a behavior change.

## Verification Run

- `python -m ruff check forge/engagement_orchestrator.py tests/phase1/test_artifact_remote_scope_parallel.py`
- `python -m py_compile forge/engagement_orchestrator.py tests/phase1/test_artifact_remote_scope_parallel.py`
- `python -m pytest tests/phase1/test_artifact_remote_scope_parallel.py -q`
  - `1 passed`
- `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_kill_chain_scope_manifest_denies_out_of_scope_remote_artifact_download -q`
  - `1 passed`

## Next Task

Add recursive second-pass artifact queue convergence coverage proving an
artifact URL discovered during artifact text parsing is parsed on the next
`ArtifactQueueProcessor.process()` pass and feeds cloud/seed discovery onward.
