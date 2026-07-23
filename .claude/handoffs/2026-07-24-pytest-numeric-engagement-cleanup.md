# Pytest Numeric Engagement Cleanup Checkpoint

## Result
- Pytest cleanup detection now identifies test-owned engagement databases created as direct `engagement.db` files and numeric `.forge_data/engagements/<id>.db` files.
- Detection remains scoped to pytest temp run directories discovered by the existing cleanup script.
- Repository-persistent `.forge_data` inventory is intentionally untouched.

## Changed Files
- `scripts/run_phase1_orchestrator_partitions.py`
- `tests/scripts/test_run_phase1_orchestrator_partitions.py`

## Verification
- `python -m compileall -q scripts\run_phase1_orchestrator_partitions.py tests\scripts\test_run_phase1_orchestrator_partitions.py`
- `ruff check scripts\run_phase1_orchestrator_partitions.py tests\scripts\test_run_phase1_orchestrator_partitions.py`
- `python -m pytest tests\scripts\test_run_phase1_orchestrator_partitions.py -q --color=no`: `6 passed`

## Safety
- Cleanup only removes pytest-owned run directories under the pytest temp-root discovery path.
- Repo-like `.forge_data/engagements` paths outside pytest temp run directories are covered by regression test and preserved.

## Next
- If focused E2E tests continue to leave temp DBs outside the partition runner, add a `pytest_sessionfinish` hook that reuses this detector against pytest temp roots only.
