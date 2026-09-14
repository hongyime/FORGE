# Current Task: A/B/C safety, export, test, and UI verification

**Status:** .venv FULLY REBUILT AND VERIFIED | HEAD: `c7ae44f` | Date: 2026-09-14

## A/B/C gate status — all done

| Gate | Commit | What |
|------|--------|------|
| A-retention | `ebbdae1` | Retention confirm gate requires literal True — V14/B658; 16/16 pass |
| A-export | `16ce013` | tier-zero/nemesis/neo4j canonical schema parity |
| B-test | `bc584d1` | Worker peak tests reconciled (5 items to exceed sequential threshold) |
| Rust | `ea97a98` | pyo3 0.29 no-host-Python unit tests — 21/21 pass |
| C-proof | (isolated run) | demo proof-pack, artifacts status, graph build, tier-zero, dashboard verified |

### C-gate CLI proof — completed in isolated FORGE_DATA_DIR

All five commands ran from `FORGE_DATA_DIR=C:\Users\bryan\AppData\Local\Temp\forge-qa-data` with `cwd=forge-qa-cwd` (isolated, outside repo):

| Command | Result |
|---------|--------|
| `forge demo proof-pack --engagement 9901` | ✅ DB + report + graph + STIX artifacts generated |
| `forge artifacts status --engagement 9901 --json` | ✅ 1 complete, 0 failed, parser lineage present |
| `forge graph build --engagement 9901 --format json` | ✅ 9 nodes · 8 edges · weight 85.2 |
| `forge graph tier-zero --engagement 9901 --json` | ✅ 1 tier-zero asset, canonical entity_key/entity_type schema |
| `forge dashboard` | ✅ 24,576-byte dashboard.html generated |

### `.venv` rebuilt — fresh Python 3.12 at `C:\forge\.venv`

Old OneDrive copy (23 missing files, caused file-lock hangs) deleted. Fresh venv built with `uv` from `pyproject.toml`. All packages installed including `llama-cpp-python==0.3.8` (CPU wheel from `https://abetlen.github.io/llama-cpp-python/whl/cpu`). Verified: **retention slice 16/16 PASS** on new venv. Note: `importlib.metadata` uses normalized name `llama_cpp_python`; `m.distribution('llama-cpp-python')` returns 0.3.8 correctly.


Old source folder `C:\Users\bryan\OneDrive\01 TOOLKITS\forgetoolkit` kept per instruction; can be removed now that the new venv is verified.

## Remaining open items

- **Explore #14** Agent Ecosystem implementation — gate requires Bryan's explicit approval
- **test_registry.py** hangs on network — always exclude: `--ignore=tests/connectors/test_registry.py`

## Prior session handoffs (preserved)

**2026-09-11**: Commits `5148227..34236b4` — Rust NTLM/cargo fixes, Explore #14 plan, Explore #15 OpenGraph, spray pyo3 fix.

<!-- MOLT_AUTO_START -->
## Auto State

- Updated: 2026-09-14 (session wrap)
- Machine: PRAWN-E14
- Harness: claude
- Branch: main
- HEAD: c7ae44f
- Dirty files: 0
- Resume hint: .venv complete. All A/B/C gates closed. Only Explore #14 (Bryan approval needed) remains.
<!-- MOLT_AUTO_END -->
