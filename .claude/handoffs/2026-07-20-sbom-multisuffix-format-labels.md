# SBOM Multi-Suffix Artifact Format Labels

Date: 2026-07-20

## Goal Gate

`V3/V4/V5/T2`: passive artifact analysis and recursive-discovery provenance.

## What Changed

- `forge/engagement_orchestrator.py` now labels explicit SBOM multi-suffix
  names before generic suffix fallback:
  `*.cyclonedx.json`, `*.cyclonedx.xml`, `*.cyclonedx.yaml`, `*.cyclonedx.yml`,
  `*.cdx.json`, `*.cdx.xml`, `*.cdx.yaml`, `*.cdx.yml`, `*.spdx.json`,
  `*.spdx.yaml`, `*.spdx.yml`, `*.syft.json`, `*.syft.yaml`, and `*.syft.yml`.
- Explicit SBOM labels now outrank broad inventory-name artifact heuristics, so
  `inventory.spdx.json` persists as `spdx` rather than `ansible-inventory`.
- `SPEC.md` has backprop row `B4` documenting the precedence failure mode.
- `tests/phase1/test_artifact_sbom_format_labels.py` proves both direct helper
  labels and persisted artifact queue metadata.

## Verification

- Before implementation:
  `python -m pytest tests\phase1\test_artifact_sbom_format_labels.py -q --color=no` ->
  `2 failed`
- After first implementation, the test exposed the precedence bug:
  `inventory.spdx.json` was `ansible-inventory`
- Final checks:
  `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_artifact_sbom_format_labels.py`
- `python -m ruff check forge\engagement_orchestrator.py tests\phase1\test_artifact_sbom_format_labels.py` ->
  `All checks passed!`
- `python -m pytest tests\phase1\test_artifact_sbom_format_labels.py -q --color=no` ->
  `2 passed`
- `python -m pytest tests\phase1\test_artifact_sbom_format_labels.py tests\phase1\test_artifact_api_format_labels.py tests\phase1\test_artifact_well_known_security_metadata.py -q --color=no` ->
  `5 passed`
- Cleanup inventory unchanged: `.forge_data\engagements` contains `1`, `5010`, `master.db`

## Safety Boundary

Passive artifact classification/reviewability only. No artifact execution,
provider call, target network access, live probing, credential use, scope
relaxation, proxy/IP rotation, rate-limit bypass, validation/report-gate
change, severity change, or deterministic finding creation.

## Next Suggested Step

Continue from `docs/engagement_overhaul_tasklist.md` ->
`## Compact active backlog`. Prefer another concrete passive parser/identity
gap or a small T7 split that reduces `engagement_orchestrator.py` risk without
changing behavior.
