# Poetry Config Passive Recursion Checkpoint

Date: 2026-07-20

Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`.

## Gate Advanced

Artifact analysis and recursion. This checkpoint improves deterministic passive
package-manager artifact handling without executing artifacts or contacting any
package registry, provider, or target service.

## What Changed

- `poetry.toml` classifies as `poetry-config`.
- Cached remote names ending in `.poetry-config` also classify as
  `poetry-config`.
- Remote `poetry.toml` URLs now route through the package-manager config
  artifact path instead of generic TOML handling.
- The package-manager helper regression now proves Poetry repository URLs,
  owner emails, and cloud refs flow through existing passive artifact recursion.
- Embedded repository credentials such as `poetry-token-do-not-store` remain
  stripped from persisted seeds/evidence.

## Why This Gap Mattered

Official Poetry documentation states local project configuration is stored in a
`poetry.toml` file separate from `pyproject.toml`, and warns that it can contain
user-specific or sensitive information. FORGE already recognized `poetry.lock`
but missed the local config file, so exposed Poetry repository/source settings
could fall back to generic TOML metadata.

## Files Changed

- `forge/utils/artifact_package_manager_config.py`
- `tests/phase1/test_artifact_package_manager_config.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- TDD helper regression failed before implementation:
  `4 failed, 43 passed`.
- `python -m pytest tests\phase1\test_artifact_package_manager_config.py -q --color=no`
  -> `47 passed`
- `python -m py_compile forge\utils\artifact_package_manager_config.py tests\phase1\test_artifact_package_manager_config.py`
- `python -m ruff check forge\utils\artifact_package_manager_config.py tests\phase1\test_artifact_package_manager_config.py`
- `python -m pytest tests\phase1\test_artifact_package_manager_config.py tests\phase1\test_engagement_orchestrator.py -k "package_manager_config or package_manager_credential_configs or python_conda_credentials" -q --color=no`
  -> `48 passed, 758 deselected`
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
