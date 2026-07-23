# Deterministic Seed Conflict Relations

Date: 2026-07-24

## Checkpoint

Closed the gap where `conflicts_with` was schema-valid and consumed by
confidence synthesis, but no deterministic producer created conflict relations.

## Code Changes

- `forge/engagement_orchestrator.py`
  - Added conservative same-anchor identity collision detection after normal
    seed/relation derivation and before confidence refresh.
  - Creates `conflicts_with` rows only when one email/phone anchor has
    incompatible `same_entity` name/company targets.
  - Evidence records the rule, anchor seed, target type, target values, and
    original relation evidence.
  - Existing `_refresh_seed_confidence()` consumes these rows, so affected
    seeds record `conflict_count` and `conflicts_with` in synthesis metadata.
- `tests/phase1/test_engagement_orchestrator.py`
  - Added a focused fixture regression for conflicting names and companies tied
    to one phone anchor.

## Verification

- `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
- `ruff check forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
- `python -m pytest tests\phase1\test_engagement_orchestrator.py -q -k "identity_collisions or seed_confidence"`
  - Result: `4 passed, 756 deselected`
- `python -m pytest tests\phase1\test_engagement_orchestrator.py::test_synthesis_engine_creates_conflict_relations_for_identity_collisions -q`
  - Result: `1 passed`
- `python -m pytest tests\phase1\test_kill_chain_convergence.py -q`
  - Result: `3 passed`

## Next Gate

Gate evasion, brute-force, auth-bypass, and post-exploitation prerequisite
hints out of the default authorized ASM kill-chain completion path. Keep any
such suggestions explicit opt-in/manual-only with clear ROE metadata.
