# MTA-STS MX Recursion Checkpoint

Date: 2026-07-20

## Acceptance Stage

Artifact analysis and recursion.

## Goal

Close one concrete passive metadata/source-shape gap: `mta-sts.txt` already
recursed generic contact emails, policy URLs, and cloud refs, but structured
`mx:` hosts were not promoted as recursive host pivots.

## Changes

- Added `forge/utils/artifact_email_security_metadata.py` with
  `mta_sts_mx_hosts()`.
- Wired `ArtifactQueueProcessor` through a source-gated `mta-sts.txt` adapter in
  the existing generic text `network_hosts` family.
- Added `tests/phase1/test_artifact_email_security_metadata.py` to prove
  concrete and wildcard MX hosts become recursive host seeds, generic text
  `mx:` lookalikes remain excluded, and existing email/URL/Supabase recursion
  still works.

## Verification

- TDD focused regression before implementation:
  `python -m pytest tests/phase1/test_artifact_email_security_metadata.py -q --color=no`
  failed on missing wildcard MX host promotion.
- Focused regression after implementation:
  `python -m pytest tests/phase1/test_artifact_email_security_metadata.py -q --color=no`
  -> `1 passed`.
- Compile:
  `python -m py_compile forge\\utils\\artifact_email_security_metadata.py forge\\engagement_orchestrator.py tests\\phase1\\test_artifact_email_security_metadata.py`.
- Ruff:
  `python -m ruff check forge\\utils\\artifact_email_security_metadata.py forge\\engagement_orchestrator.py tests\\phase1\\test_artifact_email_security_metadata.py`
  -> all checks passed.
- Adjacent public metadata/helper/email-security slice:
  `python -m pytest tests/phase1/test_artifact_public_metadata_labels.py tests/phase1/test_artifact_email_security_metadata.py tests/phase1/test_artifact_helpers.py -q --color=no`
  -> `10 passed`.
- Corrected slow well-known selector:
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "mta_sts or security_txt or well_known" -m slow -q --color=no`
  -> `1 passed, 758 deselected`.
- Exact remote well-known fixture:
  `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_kill_chain_dry_run_processes_remote_well_known_metadata_seeds -m slow -q --color=no`
  -> `1 passed`.
- Cleanup inventory remained `1`, `5010`, `master.db`.

## Retry Note

One adjacent command used stale nodeid
`test_kill_chain_dry_run_processes_remote_service_metadata_seeds` and selected
no tests. It was not accepted as evidence; the corrected well-known selector and
exact nodeid above passed.

## Safety

Passive static MTA-STS parsing only. No DNS lookup, SMTP probing, MTA-STS policy
fetch, provider call, live probing, credential use, scope relaxation,
proxy/IP rotation, rate-limit bypass, report-gate change, severity change, or
deterministic finding creation.

## Review

Subagent spawn was attempted for a read-only audit, but the agent thread limit
was reached. The checkpoint proceeded locally against the locked end-goal
contract.

## Next Work

Continue from `docs/engagement_overhaul_tasklist.md` -> `## Compact active
backlog`. The next implementation target remains another concrete
identity-provider payload shape or passive artifact/parser source shape; if no
missing recursive pivot is found, switch to release-level mocked
E2E/report-fallback tests or safe module splits.
