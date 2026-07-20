# ATProto DID Web Host Recursion Handoff

Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`

## Acceptance Stage

Recursion and artifact analysis.

## Change

Source-aware `.well-known/atproto-did` parsing now promotes valid line-oriented
`did:web:` identifiers into recursive host seeds through the existing host-seed
persistence path.

Covered example:

- `did:web:identity.acme.example`

Generic text files with the same `did:web:` string shape remain excluded from
this source-gated parser.

## Files

- `forge/utils/artifact_did_metadata.py`
- `forge/engagement_orchestrator.py`
- `tests/phase1/test_artifact_atproto_did_metadata.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- TDD focused regression failed before implementation:
  `python -m pytest tests\phase1\test_artifact_atproto_did_metadata.py -q --color=no`
  -> missing `identity.acme.example` ATProto DID web host seed.
- Focused regression after implementation:
  `python -m pytest tests\phase1\test_artifact_atproto_did_metadata.py -q --color=no`
  -> `1 passed`.
- Compile:
  `python -m py_compile forge\utils\artifact_did_metadata.py forge\engagement_orchestrator.py tests\phase1\test_artifact_atproto_did_metadata.py`.
- Ruff:
  `python -m ruff check forge\utils\artifact_did_metadata.py forge\engagement_orchestrator.py tests\phase1\test_artifact_atproto_did_metadata.py`
  -> `All checks passed!`.
- ATProto plus DID/identity/service metadata slice:
  `python -m pytest tests\phase1\test_artifact_atproto_did_metadata.py tests\phase1\test_artifact_did_metadata.py tests\phase1\test_artifact_well_known_identity_metadata.py tests\phase1\test_artifact_well_known_service_metadata.py -q --color=no`
  -> `6 passed`.
- Adjacent ATProto/DID/provenance/public metadata/helper slice:
  `python -m pytest tests\phase1\test_artifact_atproto_did_metadata.py tests\phase1\test_artifact_did_metadata.py tests\phase1\test_artifact_provenance.py tests\phase1\test_artifact_public_metadata_labels.py tests\phase1\test_artifact_helpers.py -q --color=no`
  -> `15 passed`.
- Remote well-known metadata slow fixture:
  `python -m pytest tests\phase1\test_engagement_orchestrator.py::test_kill_chain_dry_run_processes_remote_well_known_metadata_seeds -m slow -q --color=no`
  -> `1 passed`.
- Cleanup check:
  `.forge_data\engagements` contained only `1`, `5010`, and `master.db`.

## Safety

Passive static ATProto DID metadata parsing only. No DID resolution, WebFinger
lookup, provider call, live probing, credential use, scope relaxation, proxy/IP
rotation, rate-limit bypass, report-gate change, severity change, or
deterministic finding creation.

## Next

Continue the active backlog: audit another concrete identity-provider payload
shape or passive artifact/parser source shape. If no recursive pivot gap is
found, switch to release-level mocked end-to-end/report-fallback tests or safe
mega-test/module splits.
