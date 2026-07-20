# Microsoft Identity Association Metadata Handoff

Date: 2026-07-20

## Acceptance Stages

- Artifact analysis
- Recursion
- Review
- Testing/cleanup

## Source Notes

Microsoft documents `microsoft-identity-association.json` for publisher-domain
verification under `/.well-known/`. The documented JSON shape contains
`associatedApplications[].applicationId` values. IANA search did not verify this
as an IANA-registered well-known suffix, so continuation docs intentionally
describe it as Microsoft-documented metadata rather than IANA-listed metadata.

## Gap

The metadata route previously classified as generic `json`, and the
`applicationId` GUID values did not feed any passive recursive inventory. That
made a common Entra/Microsoft identity payload a dead end for graph/review
correlation.

## Change

- `/.well-known/microsoft-identity-association.json` now labels as
  `microsoft-identity-association.json`.
- `/.well-known/microsoft-identity-association` now labels as
  `microsoft-identity-association`.
- `applicationId` GUID values in static artifact text now emit passive
  `azure_ad_app` cloud-asset inventory rows with source
  `artifact_microsoft_identity_association`.
- Normal generic pivots from the same payload, such as email, URL, and Supabase
  refs, still recurse through the existing artifact path.

## Files Changed

- `forge/engagement_orchestrator.py`
- `tests/phase1/test_artifact_well_known_microsoft_identity_metadata.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- TDD focused regression before fix:
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_well_known_microsoft_identity_metadata.py -q --color=no` -> failed on generic `json` labeling and missing app-ID pivot.
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_well_known_microsoft_identity_metadata.py -q --color=no` -> `2 passed`
- `.venv\Scripts\python.exe -m py_compile forge\engagement_orchestrator.py tests\phase1\test_artifact_well_known_microsoft_identity_metadata.py`
- `.venv\Scripts\ruff.exe check forge\engagement_orchestrator.py tests\phase1\test_artifact_well_known_microsoft_identity_metadata.py`
- Adjacent well-known/public metadata slice -> `17 passed`
- Adjacent orchestrator metadata selector -> `21 passed, 738 deselected`
- Persistent engagement DB cleanup scan remained `1`, `5010`, `master.db`.

## Safety

Passive static metadata parsing/inventory only. No Microsoft Graph, Entra,
Azure API, app verification, provider call, live probing, credential use, scope
relaxation, proxy/IP rotation, rate-limit bypass, validation/report-gate change,
or persistent non-test engagement DB mutation changed.

## Next Step

Continue with the active backlog: audit another concrete identity-provider
payload shape or passive artifact/parser source shape before code. If no gap is
found, switch to release-level mocked E2E/report-fallback tests or safe
mega-test/module splits.
