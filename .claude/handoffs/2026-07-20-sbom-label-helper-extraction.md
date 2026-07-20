# SBOM Label Helper Extraction

Date: 2026-07-20

## Goal Gate

`T7`: split or wrap large legacy modules when it reduces risk without changing
verified behavior.

## What Changed

- Moved SBOM multi-suffix format-label mapping and helper logic from
  `forge/engagement_orchestrator.py` into `forge/utils/artifact_sbom.py`.
- `engagement_orchestrator.py` now imports `sbom_multisuffix_format_label()` and
  remains a thin caller at the artifact format-label decision point.
- The existing SBOM format-label regression now also directly covers the helper.

## Verification

- `python -m py_compile forge\utils\artifact_sbom.py forge\engagement_orchestrator.py tests\phase1\test_artifact_sbom_format_labels.py`
- `python -m ruff check forge\utils\artifact_sbom.py forge\engagement_orchestrator.py tests\phase1\test_artifact_sbom_format_labels.py` ->
  `All checks passed!`
- `python -m pytest tests\phase1\test_artifact_sbom_format_labels.py tests\phase1\test_artifact_api_format_labels.py tests\phase1\test_artifact_well_known_security_metadata.py -q --color=no` ->
  `5 passed`

## Safety Boundary

Behavior-preserving refactor only. No artifact parsing expansion, provider
call, target network access, live probing, credential use, scope relaxation,
proxy/IP rotation, rate-limit bypass, validation/report-gate change, severity
change, or deterministic finding creation.

## Next Suggested Step

Continue from `docs/engagement_overhaul_tasklist.md` ->
`## Compact active backlog`. Prefer a concrete passive parser/identity gap, or
another small helper extraction from `engagement_orchestrator.py` only when
covered by focused tests.
