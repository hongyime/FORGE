# API Client Host/Path URL Object Handoff

Date: 2026-07-20

## Acceptance Stages

- Artifact analysis
- Recursion
- Testing/cleanup

## Gap

Source-aware API-client artifacts already recognized Postman, Insomnia,
Hoppscotch, Thunder Client, Bruno, Dredd, Schemathesis, Pactum, and related
formats. However, Postman-style URL objects with concrete `host`/`hostname` plus
`path`/`pathname` but no explicit `raw` or `protocol` were dropped, so scraped
API-client collections could miss recursive URL pivots.

## Change

`ArtifactQueueProcessor._api_client_url_object_looks_supported()` now accepts
host/path URL objects without explicit protocol. The existing URL builder
defaults those concrete pivots to HTTPS. Host-only objects remain suppressed,
localhost values are still filtered by the downstream candidate normalizer, and
direct string `url` fields remain on the existing path to avoid duplicate
raw/normalized candidates.

## Files Changed

- `forge/engagement_orchestrator.py`
- `tests/phase1/test_artifact_api_client_workers.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- TDD regression before fix:
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_api_client_workers.py::test_api_client_url_objects_default_host_path_to_https_without_protocol -q --color=no` -> failed with empty output.
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_api_client_workers.py::test_api_client_url_objects_default_host_path_to_https_without_protocol -q --color=no` -> `1 passed`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py -k "api_client_text_structured_payload" -q --color=no` -> `13 passed, 746 deselected`
- `.venv\Scripts\python.exe -m py_compile forge\engagement_orchestrator.py tests\phase1\test_artifact_api_client_workers.py`
- `.venv\Scripts\ruff.exe check forge\engagement_orchestrator.py tests\phase1\test_artifact_api_client_workers.py`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_api_client_workers.py tests\phase1\test_artifact_api_format_labels.py -q --color=no` -> `8 passed`

## Review

Claude sidecar review was attempted through the hidden wrapper, but no output
file was created after the startup window and the wrapper process was
terminated. Local audit and TDD regression identified and verified the gap.

## Safety

Passive static API-client parsing only. No provider call, live probing,
credential use, scope relaxation, proxy/IP rotation, rate-limit bypass,
validation/report-gate change, or persistent non-test engagement DB mutation
changed.

## Next Step

Continue with the active backlog: audit another concrete identity-provider
payload shape or passive artifact/parser source shape before code. If no gap is
found, switch to release-level mocked E2E/report-fallback tests or safe
mega-test/module splits.
