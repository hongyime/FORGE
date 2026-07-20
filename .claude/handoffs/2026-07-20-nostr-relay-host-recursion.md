# Nostr Relay Host Recursion Handoff

Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`

## Acceptance Stage

Recursion and artifact analysis.

## Change

Source-aware `.well-known/nostr.json` parsing now promotes valid `ws://` and
`wss://` relay endpoint hosts into recursive host seeds through the existing
host-seed persistence path.

Covered examples:

- `wss://relay.acme.example`
- `wss://relay2.acme.example:443/path`

Generic JSON files with the same relay-shaped WebSocket URL strings remain
excluded from this source-gated parser.

## Files

- `forge/utils/artifact_nostr_metadata.py`
- `forge/engagement_orchestrator.py`
- `tests/phase1/test_artifact_nostr_metadata.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- TDD focused regression failed before implementation:
  `python -m pytest tests\phase1\test_artifact_nostr_metadata.py -q --color=no`
  -> missing `relay.acme.example` Nostr relay host seed.
- Focused regression after implementation:
  `python -m pytest tests\phase1\test_artifact_nostr_metadata.py -q --color=no`
  -> `1 passed`.
- Compile:
  `python -m py_compile forge\utils\artifact_nostr_metadata.py forge\engagement_orchestrator.py tests\phase1\test_artifact_nostr_metadata.py`.
- Ruff:
  `python -m ruff check forge\utils\artifact_nostr_metadata.py forge\engagement_orchestrator.py tests\phase1\test_artifact_nostr_metadata.py`
  -> `All checks passed!`.
- Nostr plus ATProto/DID/identity/service metadata slice:
  `python -m pytest tests\phase1\test_artifact_nostr_metadata.py tests\phase1\test_artifact_atproto_did_metadata.py tests\phase1\test_artifact_did_metadata.py tests\phase1\test_artifact_well_known_identity_metadata.py tests\phase1\test_artifact_well_known_service_metadata.py -q --color=no`
  -> `7 passed`.
- Adjacent Nostr/ATProto/DID/provenance/public metadata/helper slice:
  `python -m pytest tests\phase1\test_artifact_nostr_metadata.py tests\phase1\test_artifact_atproto_did_metadata.py tests\phase1\test_artifact_did_metadata.py tests\phase1\test_artifact_provenance.py tests\phase1\test_artifact_public_metadata_labels.py tests\phase1\test_artifact_helpers.py -q --color=no`
  -> `16 passed`.
- Remote well-known metadata slow fixture:
  `python -m pytest tests\phase1\test_engagement_orchestrator.py::test_kill_chain_dry_run_processes_remote_well_known_metadata_seeds -m slow -q --color=no`
  -> `1 passed`.

## Safety

Passive static Nostr metadata parsing only. No relay connection, Nostr lookup,
provider call, live probing, credential use, scope relaxation, proxy/IP
rotation, rate-limit bypass, report-gate change, severity change, or
deterministic finding creation.

## Next

Continue the active backlog: audit another concrete identity-provider payload
shape or passive artifact/parser source shape. If no recursive pivot gap is
found, switch to release-level mocked end-to-end/report-fallback tests or safe
mega-test/module splits.
