# Poetry Global Config/Auth Passive Recursion Checkpoint

Date: 2026-07-20

Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`.

## Gate Advanced

Artifact analysis and recursion. This checkpoint improves deterministic,
source-aware passive package-manager artifact handling without executing
artifacts or contacting any package registry, provider, or target service.

## What Changed

- `pypoetry/config.toml` classifies as `poetry-config`.
- `pypoetry/auth.toml` classifies as `poetry-auth`.
- Cached remote names ending in `.poetry-auth` also classify as `poetry-auth`.
- Generic `config.toml` and `auth.toml` remain excluded unless source-gated by
  the immediate `pypoetry` parent.
- The package-manager helper regression now proves Poetry auth repository URLs,
  owner emails, and Supabase refs flow through existing passive artifact
  recursion.
- Embedded repository credentials such as `poetry-auth-token-do-not-store`
  remain stripped from persisted seeds/evidence.

## Why This Gap Mattered

Official Poetry documentation lists global configuration under `pypoetry`, notes
that repository credentials may be read from `auth.toml`, and states local
configuration precedence includes `poetry.toml`. FORGE already recognized the
project-local `poetry.toml`; this checkpoint adds the source-aware global config
and auth file path without broadening generic TOML handling.

## Files Changed

- `forge/utils/artifact_package_manager_config.py`
- `tests/phase1/test_artifact_package_manager_config.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- TDD helper regression failed before implementation:
  `5 failed, 47 passed`.
- `python -m pytest tests\phase1\test_artifact_package_manager_config.py -q --color=no`
  -> `52 passed`
- `python -m py_compile forge\utils\artifact_package_manager_config.py tests\phase1\test_artifact_package_manager_config.py`
- `python -m ruff check forge\utils\artifact_package_manager_config.py tests\phase1\test_artifact_package_manager_config.py`
- `python -m pytest tests\phase1\test_artifact_package_manager_config.py tests\phase1\test_engagement_orchestrator.py -k "package_manager_config or package_manager_credential_configs or python_conda_credentials" -q --color=no`
  -> `53 passed, 758 deselected`
- Compact smoke covering artifact recursion, validation gating, report fallback,
  and dashboard surfacing -> `4 passed, 1 deselected`
- Cleanup removed four pytest engagement dirs and left
  `remaining_pytest_engagement_dirs=0`.
- Persistent engagement inventory remained `1`, `5010`, `master.db`.
- No Python or pytest process remained after verification.

## Safety Boundary

Passive static classification only. No package download, registry API call,
provider call, target network, live probing, credential use, scope relaxation,
proxy/IP rotation, rate-limit bypass, validation/report-gate change, severity
change, or finding creation was added.

## Continue Next

Use `docs/engagement_overhaul_tasklist.md` -> `## Compact active backlog` as
the canonical continuation order. The next valid task should audit a concrete
release-gate gap before editing code, preferably dashboard/graph/report parity,
raw export fallback, cleanup proof, MTGX analyst fidelity, or a concrete
identity-provider/passive-artifact parser gap.
