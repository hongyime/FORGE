# Host-Meta Relative Href Recursion Handoff

Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`

## Acceptance Stage

Recursion and artifact analysis.

## Change

Source-aware `.well-known/host-meta` XML parsing now resolves concrete relative
`<Link href="...">` values against the remote artifact `source_url` and feeds
them into the existing recursive URL seed persistence path.

Covered examples:

- `./profile`
- `../users/alice`

LRDD `template` attributes remain excluded, and generic XML files with the same
field shape are not source-gated into host-meta parsing.

## Files

- `forge/utils/artifact_host_meta_metadata.py`
- `forge/engagement_orchestrator.py`
- `tests/phase1/test_artifact_host_meta_metadata.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- TDD focused regression failed before implementation:
  `python -m pytest tests\phase1\test_artifact_host_meta_metadata.py -q --color=no`
  -> missing relative host-meta href URL seeds.
- Focused regression after implementation:
  `python -m pytest tests\phase1\test_artifact_host_meta_metadata.py -q --color=no`
  -> `1 passed`.
- Compile:
  `python -m py_compile forge\utils\artifact_host_meta_metadata.py forge\engagement_orchestrator.py tests\phase1\test_artifact_host_meta_metadata.py`.
- Ruff:
  `python -m ruff check forge\utils\artifact_host_meta_metadata.py forge\engagement_orchestrator.py tests\phase1\test_artifact_host_meta_metadata.py`
  -> `All checks passed!`.
- Adjacent host-meta/well-known/provenance/helper slice:
  `python -m pytest tests\phase1\test_artifact_host_meta_metadata.py tests\phase1\test_artifact_well_known_link_metadata.py tests\phase1\test_artifact_well_known_identity_metadata.py tests\phase1\test_artifact_well_known_api_metadata.py tests\phase1\test_artifact_provenance.py tests\phase1\test_artifact_helpers.py -q --color=no`
  -> `18 passed`.
- Adjacent classification/format/public-label/helper slice:
  `python -m pytest tests\phase1\test_artifact_host_meta_metadata.py tests\phase1\test_artifact_well_known_link_metadata.py tests\phase1\test_artifact_remote_static_classification.py tests\phase1\test_artifact_api_format_labels.py tests\phase1\test_artifact_public_metadata_labels.py tests\phase1\test_artifact_helpers.py -q --color=no`
  -> `28 passed`.
- Remote well-known metadata slow fixture:
  `python -m pytest tests\phase1\test_engagement_orchestrator.py::test_kill_chain_dry_run_processes_remote_well_known_metadata_seeds -m slow -q --color=no`
  -> `1 passed`.
- Cleanup check:
  `.forge_data\engagements` contained only `1`, `5010`, and `master.db`.

## Safety

Passive static host-meta XML parsing only. No LRDD/WebFinger request, profile
request, provider call, live probing, credential use, scope relaxation, proxy/IP
rotation, rate-limit bypass, report-gate change, severity change, or
deterministic finding creation.

## Next

Continue the active backlog: audit another concrete identity-provider payload
shape or passive artifact/parser source shape. If no recursive pivot gap is
found, switch to release-level mocked end-to-end/report-fallback tests or safe
mega-test/module splits.
