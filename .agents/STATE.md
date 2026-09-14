# Current Task: Explore #14 Agent Ecosystem + test_registry fix

**Status:** ALL WORK COMPLETE | HEAD: `2e1eedd` | Date: 2026-09-15

## A/B/C gate status — all done (from previous sessions)

| Gate | Commit | What |
|------|--------|------|
| A-retention | `ebbdae1` | Retention confirm gate requires literal True — V14/B658; 16/16 pass |
| A-export | `16ce013` | tier-zero/nemesis/neo4j canonical schema parity |
| B-test | `bc584d1` | Worker peak tests reconciled (5 items to exceed sequential threshold) |
| Rust | `ea97a98` | pyo3 0.29 no-host-Python unit tests — 21/21 pass |
| C-proof | (isolated run) | demo proof-pack, artifacts status, graph build, tier-zero, dashboard verified |

## Explore #14 — Agent Ecosystem (Bryan approved 2026-09-15)

Implemented in commit `2e1eedd` — pushed to origin/main.

| File | What |
|------|------|
| `forge/agents/event_bus.py` | In-process pub/sub; bounded asyncio.Queue per topic; 5 allowed topics |
| `forge/agents/capability_manifest.py` | `forge.agent.capability.v1` schema validation; plugin_id pattern check |
| `forge/agents/base_plugin.py` | `ForgePlugin` ABC; `TaskSpec`/`TaskResult`; ROE+scope gate in `execute_task` |
| `forge/agents/coordinator.py` | `TaskCoordinator`: register/route/track tasks; publishes lifecycle events |
| `forge/agents/cli.py` | `forge agents list` and `forge agents task-status` (read-only only) |
| `forge/agents/__init__.py` | Updated exports |
| `forge/cli_registry.py` | Added `agents_app` to `ForgeCliApps` + registration |
| `tests/unit/test_agents_event_bus.py` | 13 unit tests |
| `tests/unit/test_agents_coordinator.py` | 9 unit tests |
| `tests/unit/test_agents_plugin_base.py` | 7 unit tests |
| Total | 29/29 pass |

## test_registry.py fix

`tests/connectors/test_registry.py` marked with `pytestmark = pytest.mark.network`.
`pyproject.toml` adds `network` marker and excludes it from default addopts.
File no longer hangs default runs — use `-m network` to run explicitly.

## Remaining open items

- **test_registry.py** — marked `@pytest.mark.network`; runs only with `-m network` (no longer hanging default suite)

## Prior session handoffs (preserved)

**2026-09-14**: .venv rebuilt (Python 3.12, uv), llama-cpp-python==0.3.8 CPU wheel, retention 16/16 PASS.
**2026-09-11**: Commits `5148227..34236b4` — Rust NTLM/cargo fixes, Explore #14 plan, Explore #15 OpenGraph, spray pyo3 fix.

<!-- MOLT_AUTO_START -->
## Auto State

- Updated: 2026-09-15 (session)
- Machine: PRAWN-E14
- Harness: claude
- Branch: main
- HEAD: 2e1eedd
- Dirty files: 0
- Resume hint: Explore #14 shipped (2e1eedd). No open work items. test_registry.py is now @network-marked.
<!-- MOLT_AUTO_END -->
