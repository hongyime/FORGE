# Public Metadata Link Recursion Handoff

Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`

## Acceptance Stage

Recursion and artifact analysis.

## Change

Source-aware public metadata parsing now promotes document links found in
`llms.txt`, `ai.txt`, `humans.txt`, `security.txt`, and `trust.txt` into
recursive URL seeds when the artifact source URL is HTTP(S).

Covered link shapes:

- Markdown links such as `[OpenAPI](./openapi.yaml)`.
- Simple metadata fields such as `Policy: ./ai-policy.txt`.
- Absolute, root-relative, dot-relative, parent-relative, and useful bare
  document targets.

Generic text files with the same Markdown link shape remain excluded from this
source-gated parser.

## Files

- `forge/utils/artifact_public_metadata_links.py`
- `forge/engagement_orchestrator.py`
- `tests/phase1/test_artifact_public_metadata_links.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- TDD focused regression failed before implementation:
  `python -m pytest tests\phase1\test_artifact_public_metadata_links.py -q --color=no`
  -> missing `https://acme.example/llms-full.txt` URL seed.
- Focused regression after implementation:
  `python -m pytest tests\phase1\test_artifact_public_metadata_links.py -q --color=no`
  -> `1 passed`.
- Compile:
  `python -m py_compile forge\utils\artifact_public_metadata_links.py forge\engagement_orchestrator.py tests\phase1\test_artifact_public_metadata_links.py`.
- Ruff:
  `python -m ruff check forge\utils\artifact_public_metadata_links.py forge\engagement_orchestrator.py tests\phase1\test_artifact_public_metadata_links.py`
  -> `All checks passed!`.
- Adjacent public metadata/helper/email-security slice:
  `python -m pytest tests\phase1\test_artifact_public_metadata_links.py tests\phase1\test_artifact_public_metadata_labels.py tests\phase1\test_artifact_email_security_metadata.py tests\phase1\test_artifact_helpers.py -q --color=no`
  -> `11 passed`.
- Remote root metadata slow fixture:
  `python -m pytest tests\phase1\test_engagement_orchestrator.py::test_kill_chain_dry_run_processes_remote_root_metadata_seeds -m slow -q --color=no`
  -> `1 passed`.
- Cleanup check:
  `.forge_data\engagements` contained only `1`, `5010`, and `master.db`.

## Safety

Passive static public-metadata link parsing only. No link fetch beyond existing
recursive URL seed persistence, provider call, live probing, credential use,
scope relaxation, proxy/IP rotation, rate-limit bypass, report-gate change,
severity change, or deterministic finding creation.

## Next

Continue the active backlog: audit another concrete identity-provider payload
shape or passive artifact/parser source shape. If no recursive pivot gap is
found, switch to release-level mocked end-to-end/report-fallback tests or safe
mega-test/module splits.
