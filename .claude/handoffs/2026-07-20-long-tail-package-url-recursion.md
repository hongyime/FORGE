# Long-Tail Package URL Recursion

Date: 2026-07-20

## Goal Gate

`T2 / V1,V3,V4,V5`: passive artifact parsing and recursive discovery.

## What Changed

- Added `forge/utils/artifact_package_url.py` with
  `long_tail_package_url_registry_candidate()`.
- CycloneDX/SPDX text package URLs now promote these additional ecosystems into
  deterministic recursive URL seeds:
  Swift Package Index, CocoaPods, pub.dev, Hex.pm, CRAN, and Hugging Face.
- `engagement_orchestrator.py` remains a thin caller from the existing package
  URL extraction path.
- `tests/phase1/test_artifact_package_url_ecosystems.py` proves both direct
  helper mappings and persisted recursive seeds from a CycloneDX artifact.

## Verification

- Before implementation:
  `python -m pytest tests\phase1\test_artifact_package_url_ecosystems.py -q --color=no` ->
  failed with zero recursive seeds.
- `python -m py_compile forge\utils\artifact_package_url.py forge\engagement_orchestrator.py tests\phase1\test_artifact_package_url_ecosystems.py`
- `python -m ruff check forge\utils\artifact_package_url.py forge\engagement_orchestrator.py tests\phase1\test_artifact_package_url_ecosystems.py` ->
  `All checks passed!`
- `python -m pytest tests\phase1\test_artifact_package_url_ecosystems.py -q --color=no` ->
  `2 passed`
- `python -m pytest tests\phase1\test_artifact_package_url_ecosystems.py tests\phase1\test_artifact_sbom_format_labels.py tests\phase1\test_artifact_package_manager_config.py -q --color=no` ->
  `49 passed`
- Cleanup inventory unchanged: `.forge_data\engagements` contains `1`, `5010`, `master.db`

## Safety Boundary

Passive SBOM/package metadata parsing only. No package download, artifact
execution, registry API call, provider call, target network access, live
probing, credential use, scope relaxation, proxy/IP rotation, rate-limit bypass,
validation/report-gate change, severity change, or deterministic finding
creation.

## Next Suggested Step

Continue from `docs/engagement_overhaul_tasklist.md` ->
`## Compact active backlog`. Prefer another concrete passive parser/identity
gap, or a focused validation/report parity proof if parser coverage is adequate.
