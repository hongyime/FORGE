# Ads.txt Publisher Account Inventory Checkpoint

Date: 2026-07-20

## Acceptance Stage

Artifact analysis and recursion.

## Goal

Close one concrete passive artifact/source-shape gap: `ads.txt` and
`app-ads.txt` already recursed generic emails, URLs, and cloud refs, but did not
persist the declared ad-system publisher account IDs as first-class passive
inventory.

## Changes

- Added `forge/utils/artifact_ad_metadata.py` to parse static ads.txt-style
  declaration lines into `ad_publisher_account` resource inventory.
- Wired `ArtifactQueueProcessor` through a thin source-gated orchestrator
  adapter for `ads.txt` and `app-ads.txt` only.
- Added `ad_publisher_account` to the cloud-validation registry contract so the
  passive type reaches terminal `UNSUPPORTED` without provider calls or
  findings.
- Added `tests/phase1/test_artifact_ad_metadata.py` to prove valid declarations
  persist, malformed/assignment/unknown-relationship lines are ignored, and
  existing email/URL/Supabase recursion still works.

## Verification

- TDD focused regression before implementation:
  `python -m pytest tests/phase1/test_artifact_ad_metadata.py -q --color=no`
  failed on missing `ad_publisher_account`.
- Focused regression after implementation:
  `python -m pytest tests/phase1/test_artifact_ad_metadata.py -q --color=no`
  -> `1 passed`.
- Compile:
  `python -m py_compile forge\\utils\\artifact_ad_metadata.py forge\\engagement_orchestrator.py tests\\phase1\\test_artifact_ad_metadata.py tests\\phase4\\test_cloud_validation_registry_contract.py`.
- Ruff:
  `python -m ruff check forge\\utils\\artifact_ad_metadata.py forge\\engagement_orchestrator.py tests\\phase1\\test_artifact_ad_metadata.py tests\\phase4\\test_cloud_validation_registry_contract.py`
  -> all checks passed.
- Adjacent helper/ad metadata:
  `python -m pytest tests/phase1/test_artifact_helpers.py tests/phase1/test_artifact_ad_metadata.py -q --color=no`
  -> `9 passed`.
- Validation registry:
  `python -m pytest tests/phase4/test_cloud_validation_registry_contract.py -q --color=no`
  -> `1 passed`.
- Remote root metadata slow fixture:
  `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_kill_chain_dry_run_processes_remote_root_metadata_seeds -m slow -q --color=no`
  -> `1 passed`.
- Adjacent public/mobile metadata slice:
  `python -m pytest tests/phase1/test_artifact_public_metadata_labels.py tests/phase1/test_artifact_assetlinks_metadata.py tests/phase1/test_artifact_aasa_metadata.py tests/phase1/test_artifact_web_manifest_metadata.py tests/phase1/test_artifact_ad_metadata.py -q --color=no`
  -> `5 passed`.
- Cleanup inventory remained `1`, `5010`, `master.db`.

## Safety

Passive static metadata inventory only. No ad exchange lookup, sellers.json
expansion, provider call, live probing, credential use, scope relaxation,
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
