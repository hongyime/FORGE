# Nostr Relay Key-Map Recursion Handoff

Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`

## Acceptance Stage

Recursion and artifact analysis.

## Change

Source-aware `.well-known/nostr.json` relay parsing now also promotes relay
endpoint URLs used as map keys into recursive host seeds through the existing
host-seed persistence path.

Covered examples:

- `wss://relay-key.acme.example`
- `ws://relay-lab.acme.example:80/socket`

## Files

- `forge/utils/artifact_nostr_metadata.py`
- `tests/phase1/test_artifact_nostr_metadata.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- TDD focused regression failed before implementation:
  `python -m pytest tests\phase1\test_artifact_nostr_metadata.py::test_nostr_relay_url_map_keys_become_recursive_host_seeds -q --color=no`
  -> missing `relay-key.acme.example` Nostr relay-key host seed.
- Focused Nostr metadata file after implementation:
  `python -m pytest tests\phase1\test_artifact_nostr_metadata.py -q --color=no`
  -> `2 passed`.
- Compile:
  `python -m py_compile forge\utils\artifact_nostr_metadata.py tests\phase1\test_artifact_nostr_metadata.py`.
- Ruff:
  `python -m ruff check forge\utils\artifact_nostr_metadata.py tests\phase1\test_artifact_nostr_metadata.py`
  -> `All checks passed!`.
- Nostr plus ATProto/DID/identity/service metadata slice:
  `python -m pytest tests\phase1\test_artifact_nostr_metadata.py tests\phase1\test_artifact_atproto_did_metadata.py tests\phase1\test_artifact_did_metadata.py tests\phase1\test_artifact_well_known_identity_metadata.py tests\phase1\test_artifact_well_known_service_metadata.py -q --color=no`
  -> `8 passed`.
- Adjacent Nostr/ATProto/DID/provenance/public metadata/helper slice:
  `python -m pytest tests\phase1\test_artifact_nostr_metadata.py tests\phase1\test_artifact_atproto_did_metadata.py tests\phase1\test_artifact_did_metadata.py tests\phase1\test_artifact_provenance.py tests\phase1\test_artifact_public_metadata_labels.py tests\phase1\test_artifact_helpers.py -q --color=no`
  -> `17 passed`.
- Remote well-known metadata slow fixture:
  `python -m pytest tests\phase1\test_engagement_orchestrator.py::test_kill_chain_dry_run_processes_remote_well_known_metadata_seeds -m slow -q --color=no`
  -> `1 passed`.
- Cleanup check:
  `.forge_data\engagements` contained only `1`, `5010`, and `master.db`.

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
