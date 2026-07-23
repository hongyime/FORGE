# SAML Metadata Passive Recursion Handoff

Date: 2026-07-23

## Checkpoint

- Added compact helper `forge.utils.artifact_saml_metadata`.
- Wired SAML metadata labels and URL extraction into `forge/engagement_orchestrator.py` as thin adapters.
- Added focused regression file `tests/phase1/test_artifact_saml_metadata.py`.

## Behavior

- Source-gated SAML metadata artifacts now classify as `saml-metadata`.
- Recognized local/remote shapes include `saml-metadata.xml`, `idp-metadata.xml`,
  `sp-metadata.xml`, `FederationMetadata.xml`, and scoped `/saml/metadata`.
- Passive XML parsing promotes recursive URL seeds from `entityID`, `Location`,
  `ResponseLocation`, `OrganizationURL`, and `AdditionalMetadataLocation`.
- Relative endpoints resolve only when the artifact source is HTTP(S).
- Protocol-relative endpoints normalize to HTTPS.
- Query strings and fragments are stripped to avoid storing SAML request,
  relay-state, token, or signature material.
- The shared generic direct URL sanitizer also strips XML-escaped SAML protocol
  query keys before direct URL persistence.
- Mocked remote artifact processing now proves downloaded SAML metadata keeps
  `downloaded_from_remote` provenance on derived seeds.

## Safety

- Static XML parsing only.
- No SSO request, token request, authentication attempt, IdP/SP call, provider
  call, live probing, credential use, validation-gate change, report-gate
  change, severity change, proxy/IP rotation, or rate-limit bypass.

## Verification

- TDD first failure:
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_saml_metadata.py -q --color=no`
  failed with `ModuleNotFoundError: No module named 'forge.utils.artifact_saml_metadata'`.
- Focused SAML:
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_saml_metadata.py -q --color=no`
  -> `6 passed`.
- Adjacent metadata/helper/static slice:
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_saml_metadata.py tests\phase1\test_artifact_oauth_metadata.py tests\phase1\test_artifact_jwks_metadata.py tests\phase1\test_artifact_web_manifest_metadata.py tests\phase1\test_artifact_helpers.py tests\phase1\test_artifact_remote_static_classification.py -q --color=no`
  -> `36 passed`.
- Compile:
  `.venv\Scripts\python.exe -m compileall forge\utils\artifact_saml_metadata.py forge\engagement_orchestrator.py tests\phase1\test_artifact_saml_metadata.py`
  -> passed.
- Ruff:
  `.venv\Scripts\python.exe -m ruff check forge\utils\artifact_saml_metadata.py forge\engagement_orchestrator.py tests\phase1\test_artifact_saml_metadata.py`
  -> `All checks passed!`.
- Cleanup scan:
  `temp_pytest_engagement_dirs=0`; workspace persistent DB inventory remains
  `1`, `5010`, `master.db`.

## Review

- Read-only sidecar review found that absolute SAML URLs could still leak
  `SAMLRequest` / `RelayState` material through the generic direct URL
  extractor before the source-gated SAML parser emitted stripped URLs.
- Fixed by HTML-unescaping candidates before shared query filtering and adding
  SAML protocol query keys to `_artifact_url_query_key_is_sensitive()`.
- Read-only sidecar review also requested processor-level remote provenance
  coverage; added a mocked remote artifact queue/download regression.
- Claude CLI read-only review was attempted twice; this local build rejected
  `-C`, then failed because the OAuth session was expired.

## Next

- Continue `SPEC.md` `T1`/`T2`: add the smallest mocked E2E or focused
  integration test proving one passive discovery path advances into secondary
  recursion, validation inventory, graph/report review, or fallback/cleanup.
- Prefer a real kill-chain path over UI-only polish.
