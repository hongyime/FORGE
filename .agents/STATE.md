# Current Task: A/B/C safety, export, test, and UI verification

**Status:** A and B gates CLOSED and PUSHED | HEAD: `ebbdae1` | Date: 2026-09-14

## This session — completed and pushed

All A/B/C defect work described in the handoff has been resolved, tested, and pushed.

| Commit | Gate | What |
|--------|------|------|
| `ea97a98` | Rust | Drop PyErr::Display in unit tests — pyo3 0.29 no host Python; 21/21 pass |
| `16ce013` | A-export | Canonical graph exports: tier-zero/nemesis/neo4j schema parity |
| `bc584d1` | B-test | Worker peak tests need >4 items to exceed sequential threshold |
| `ebbdae1` | A-retention | Retention confirm gate requires literal True — V14/B658 |

### Test gates verified before commit

| Suite | Result |
|-------|--------|
| `cargo test --lib -- credentials spray` | 21/21 pass |
| `tests/connectors/` (excl. test_registry.py) | 102 pass |
| `tests/cli/test_artifacts_status_cli.py` | 13 pass |
| `tests/webui/test_artifacts.py` | 8 pass |
| `tests/phase1/test_artifact_api_spec_workers.py` | 2 pass |
| Retention focused slice | 16 pass |

### Graph export fixes in `16ce013`

- **tier_zero.py**: `asset_graph_nodes/edges` → `asset_entities/asset_relationships` with JOIN; entity_key/entity_type canonical columns; summary text avoids "attack paths"
- **nemesis_export.py**: `findings`→`vulnerability_findings`, `seeds`→`engagement_seeds`, `pattern`→`pattern_name`, `state`→`validation_state`; URL param sanitization via `strip_sensitive_url_query`; per-section skip logging instead of silent pass
- **neo4j_export.py**: `node_type`/`edge_type`/`node_id`/`source_node_id`/`target_node_id` checked first before legacy fallbacks

## Remaining open items (C gate + future)

- **test_registry.py hangs** — identified as a network-hang test; always exclude: `--ignore=tests/connectors/test_registry.py`
- **Live browser proof** for artifact status, Sigma graph, timeline — C gate not yet completed
- **Explore #14** Agent Ecosystem implementation — gate requires Bryan's explicit approval
- `docs/competitive_upgrade_consolidated_backlog.md` is git-tracked ✓ (no issue)

## Prior session handoff (preserved)

**Status**: COMPLETED | Session date: 2026-09-11 | Commits: `5148227..34236b4`

<!-- MOLT_AUTO_START -->
## Auto State

- Updated: 2026-09-14 (session wrap)
- Machine: PRAWN-E14
- Harness: claude
- Branch: main
- HEAD: ebbdae1
- Dirty files: 0
- Resume hint: Read .agents/STATE.md. A/B gates closed. C-gate (browser proof) and Explore #14 (needs approval) remain.
<!-- MOLT_AUTO_END -->
