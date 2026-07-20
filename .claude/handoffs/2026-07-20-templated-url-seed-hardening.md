# Templated URL Seed Hardening Handoff

Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`

## Acceptance Stage

Recursion and artifact analysis.

## Change

Artifact URL seed persistence now rejects raw or URL-decoded template markers.
This prevents malformed host-meta/WebFinger template fragments such as
`resource=%7Buri` from becoming recursive URL or related-host seeds after the
direct URL extractor truncates the original `{uri}` template.

The existing literal template rejection for values such as
`https://{tenant}.acme.example/api` is preserved.

## Files

- `forge/engagement_orchestrator.py`
- `tests/phase1/test_artifact_provenance.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- TDD focused regression failed before implementation:
  `python -m pytest tests\phase1\test_artifact_provenance.py::test_artifact_url_seed_persistence_rejects_templated_urls -q --color=no`
  -> `%7Buri` inserted three seeds.
- Focused regression after implementation:
  `python -m pytest tests\phase1\test_artifact_provenance.py::test_artifact_url_seed_persistence_rejects_templated_urls -q --color=no`
  -> `1 passed`.
- Compile:
  `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_artifact_provenance.py`.
- Ruff:
  `python -m ruff check forge\engagement_orchestrator.py tests\phase1\test_artifact_provenance.py`
  -> `All checks passed!`.
- Artifact provenance file:
  `python -m pytest tests\phase1\test_artifact_provenance.py -q --color=no`
  -> `3 passed`.
- Adjacent provenance/Matrix/public metadata/helper slice:
  `python -m pytest tests\phase1\test_artifact_provenance.py tests\phase1\test_artifact_matrix_metadata.py tests\phase1\test_artifact_public_metadata_links.py tests\phase1\test_artifact_helpers.py -q --color=no`
  -> `15 passed`.
- Remote well-known metadata slow fixture:
  `python -m pytest tests\phase1\test_engagement_orchestrator.py::test_kill_chain_dry_run_processes_remote_well_known_metadata_seeds -m slow -q --color=no`
  -> `1 passed`.
- Cleanup check:
  `.forge_data\engagements` contained only `1`, `5010`, and `master.db`.

## Safety

Persistence-gate hardening only. No URL fetching, provider call, live probing,
credential use, scope relaxation, proxy/IP rotation, rate-limit bypass,
report-gate change, severity change, or deterministic finding creation.

## Next

Continue the active backlog: audit another concrete identity-provider payload
shape or passive artifact/parser source shape. If no recursive pivot gap is
found, switch to release-level mocked end-to-end/report-fallback tests or safe
mega-test/module splits.
