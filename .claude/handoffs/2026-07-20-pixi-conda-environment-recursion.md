# Pixi/Conda Environment Recursion Handoff

Date: 2026-07-20

## Checkpoint

Exact Pixi and Conda environment/lock artifacts now keep source-aware artifact
formats during passive static extraction:

- `pixi.toml` -> `pixi-manifest`
- `pixi.lock` -> `pixi-lock`
- `environment.yml` / `environment.yaml` -> `conda-environment`
- `conda-lock.yml` / `conda-lock.yaml` -> `conda-lock`

These labels also survive cached remote artifact suffixes such as
`*.pixi-manifest`, `*.pixi-lock`, `*.conda-environment`, and `*.conda-lock`.
Generic lookalikes such as `runtime-environment.yml` and `pixi-notes.toml`
remain generic to avoid broad false-positive source labeling.

## Why It Matters

Pixi and Conda environment manifests often contain package channels, service
URLs, owner metadata, and public infrastructure references. FORGE should passively
extract those pivots into recursive engagement seeds without executing package
manager commands, authenticating to package channels, or persisting embedded URL
credentials in cleartext.

## Verification

- `.venv\Scripts\python.exe -m py_compile forge\utils\artifact_package_manager_config.py tests\phase1\test_artifact_package_manager_config.py tests\phase1\test_engagement_orchestrator.py`
- `.venv\Scripts\ruff.exe check forge\utils\artifact_package_manager_config.py tests\phase1\test_artifact_package_manager_config.py tests\phase1\test_engagement_orchestrator.py`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_package_manager_config.py -q --color=no` -> `45 passed`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py -k "package_index_url_credentials or python_conda or condarc or package_manager" -q --color=no` -> `2 passed, 758 deselected`
- Direct classifier probe confirmed exact Pixi/Conda labels and generic handling for broad lookalikes.

## Safety Boundaries

Passive static package-manager/environment parsing only. No Pixi/Conda execution,
package install/lock use, channel authentication, provider calls, live probing,
credential use, scope relaxation, proxy/IP rotation, rate-limit bypass,
destructive behavior, or report-gate change.

## Next Suggested Work

Continue closing concrete passive-recursion gaps that improve the deterministic
authorized kill-chain path. Prefer focused helpers/tests over expanding
`forge/engagement_orchestrator.py` or mega test files.
