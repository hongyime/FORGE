# Conda/Mamba Config Passive-Recursion Checkpoint

Date: 2026-07-20

## Summary

Conda and Mamba package-manager configuration artifacts are now source-aware.
`.condarc`, `condarc`, `.mambarc`, `mambarc`, and cached remote
`*.conda-config` / `*.mamba-config` files keep `conda-config` /
`mamba-config` artifact formats instead of generic basename labels.

Package channel URLs and owner emails continue into recursive engagement seeds,
and embedded channel credentials remain absent from persisted DB text.

## Files

- `forge/utils/artifact_package_manager_config.py`
- `tests/phase1/test_artifact_package_manager_config.py`
- `tests/phase1/test_engagement_orchestrator.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- `.venv\Scripts\python.exe -m py_compile forge\utils\artifact_package_manager_config.py tests\phase1\test_artifact_package_manager_config.py tests\phase1\test_engagement_orchestrator.py`
- `.venv\Scripts\ruff.exe check forge\utils\artifact_package_manager_config.py tests\phase1\test_artifact_package_manager_config.py tests\phase1\test_engagement_orchestrator.py`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_package_manager_config.py -q --color=no` -> `35 passed`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py -k "package_index_url_credentials or python_conda or condarc or package_manager" -q --color=no` -> `2 passed, 758 deselected`

## Safety

Passive static package-manager config parsing only. No Conda/Mamba execution,
package install/restore, channel authentication, provider calls, live probing,
credential use, scope relaxation, proxy/IP rotation, rate-limit bypass,
destructive behavior, or report-gate change.
