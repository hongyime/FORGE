# FORGE Modularity Refactor Plan

**Author:** Kiro (yolo agent)  
**Date:** 2026-08-06  
**Repo:** `hongyime/FORGE` at commit `ce2196d` on `origin/main`  
**Paths:** `C:\Users\bryan\OneDrive\01 TOOLKITS\forgetoolkit` (OneDrive, has venv) or `X:\01 REPOSITORIES\FORGE` (non-OneDrive, no venv)

---

## Problem

Three mega-files violate every modularity principle:

| File | Lines | Why it's bad |
|---|---|---|
| `forge/cli.py` | 20,244 | Contains ALL CLI commands + the entire 15K-line kill_chain function + 300 shared helpers |
| `forge/engagement_orchestrator.py` | ~25,000 | Contains seed classifier, synthesis engine, spider loop, persistence helpers, cloud_ref detection, identity normalization hooks |
| `forge/phase6/report_synthesizer.py` | ~4,500 | Contains context builder, cascade provider, template renderer, persistence layer |

OneDrive scanning, IDE indexing, agent context windows, and code review all suffer.

---

## Constraints

1. **Entry point must stay `forge.cli:main`** — that's what `pyproject.toml [project.scripts]` declares
2. **`from forge.cli import kill_chain`** is used in 143+ test call sites — can't break that import
3. **Typer app objects (`osint_app`, `cloud_app`, etc.) must register commands at import time** — the sub-modules need to import and decorate from the shared app objects
4. **No behavioral changes** — pure structural refactor, zero logic edits
5. **Tests must pass after each commit** — incremental, not big-bang

---

## Phase 1: Extract CLI helpers (lines 82-400) → `forge/cli_helpers.py`

**What moves:**
- `_cli_float_env`, `_cli_int_env` (env-var readers)
- `_web_fetch_request_delay_seconds`, `_identity_lookup_max_workers`, `_validation_max_workers`, `_artifact_processor_max_workers`
- `_provider_max_workers`, `_normalized_provider_env_key`, `_provider_batch_stagger_seconds`
- `_module_subprocess_timeout_seconds`, `_timeout_stream_text`
- `_run_forge_module_subprocess` (subprocess runner)
- `_append_cli_option_once`, `_append_cli_flag_once`, `_append_scope_manifest_arg`
- `_detected_prereq_child_argv`
- `_module_provider_key`, `_provider_limited_worker_count`, `_provider_launch_delays`, `_sleep_provider_launch_delay`
- `_load_scope_manifest`, `_scope_manifest_values`, `_scope_manifest_seed_targets`, `_validate_scope_manifest_seed_values`
- `_path_under`
- `_direct_cli_load_scope_lists`, `_direct_cli_require_roe`

**How:**
```python
# forge/cli_helpers.py
"""Shared CLI helper functions extracted from forge/cli.py for modularity."""
from __future__ import annotations
import json, logging, os, subprocess, time
from pathlib import Path
from typing import Any, Optional, Sequence
# ... paste the functions ...
```

```python
# forge/cli.py (top, after existing imports)
from forge.cli_helpers import (
    _cli_float_env, _cli_int_env, _web_fetch_request_delay_seconds,
    _identity_lookup_max_workers, _validation_max_workers,
    _artifact_processor_max_workers, _run_forge_module_subprocess,
    _load_scope_manifest, _validate_scope_manifest_seed_values,
    _scope_manifest_seed_targets, _direct_cli_load_scope_lists,
    _direct_cli_require_roe, _path_under,
    # ... all others
)
```

**Line savings:** ~320 lines removed from cli.py  
**Risk:** Low — these are pure functions with no shared mutable state  
**Verify:** `pytest tests/hardening/ tests/orchestrator/ -q`

---

## Phase 2: Extract OSINT commands (lines 1936-3400) → `forge/cli_osint.py`

**What moves:**
- All `@osint_app.command(...)` decorated functions
- Their local helper functions (anything used only within that block)

**How:**
```python
# forge/cli_osint.py
"""OSINT CLI commands — Phase 2 intelligence operations."""
from __future__ import annotations
import sqlite3, json
from pathlib import Path
from typing import Optional

from forge.cli import osint_app, console, ForgeConfig
from forge.cli_helpers import _direct_cli_load_scope_lists, _direct_cli_require_roe
# ... paste all @osint_app.command functions ...
```

```python
# forge/cli.py (at the bottom of imports section)
import forge.cli_osint  # noqa: F401 — registers osint_app commands via decorators
```

**Line savings:** ~1,464 lines  
**Risk:** Medium — need to verify all closures/shared vars used by osint commands are importable  
**Verify:** `forge osint --help` + `pytest tests/phase2/ -q`

---

## Phase 3: Extract cloud commands (lines 3407-3940) → `forge/cli_cloud.py`

Same pattern as Phase 2.

**What moves:** All `@cloud_app.command(...)` functions  
**Line savings:** ~533 lines  
**Verify:** `forge cloud --help` + `pytest tests/phase4/ -q`

---

## Phase 4: Extract graph commands (lines 3944-4770) → `forge/cli_graph.py`

Same pattern.

**What moves:** All `@graph_app.command(...)` functions  
**Line savings:** ~826 lines  
**Verify:** `forge graph --help`

---

## Phase 5: Extract post-ex commands (lines 4776-4940) → `forge/cli_post.py`

Same pattern.

**What moves:** All `@post_app.command(...)` functions  
**Line savings:** ~164 lines  
**Verify:** `forge post --help`

---

## Phase 6: Extract report commands (lines 4942-5040) → `forge/cli_report.py`

Same pattern.

**What moves:** All `@report_app.command(...)` functions  
**Line savings:** ~98 lines  
**Verify:** `forge report --help`

---

## Phase 7: Split engagement_orchestrator.py (~25K lines)

After cli.py is done. Target modules:

| New file | Content | Est. lines |
|---|---|---|
| `forge/orchestrator/__init__.py` | Re-exports for backward compat | 50 |
| `forge/orchestrator/classifier.py` | `_classify_seed_value`, `_hostname_is_cloud_ref`, `_CLOUD_REF_HOSTNAME_SUFFIXES/REGEXES`, `_is_mobile_bundle_url/path`, `_looks_like_company_name/person_name` | ~200 |
| `forge/orchestrator/synthesis.py` | `EngagementSynthesisEngine` class | ~3000 |
| `forge/orchestrator/spider.py` | The recursive spider loop (currently inlined in kill_chain but called via orchestrator) | ~2000 |
| `forge/orchestrator/persistence.py` | All `_persist_*`, `_upsert_*`, `_insert_audit_*` DB helpers | ~1500 |
| `forge/engagement_orchestrator.py` | Thin wrapper that imports from orchestrator/* for backward compat | ~100 |

**Critical constraint:** `from forge.engagement_orchestrator import _classify_seed_value` is used in 15+ test files. The backward-compat wrapper at `forge/engagement_orchestrator.py` must re-export everything:

```python
# forge/engagement_orchestrator.py (after refactor — thin re-export shell)
"""Backward-compatible re-exports. Real implementations live in forge/orchestrator/."""
from forge.orchestrator.classifier import (
    _classify_seed_value,
    _hostname_is_cloud_ref,
    _CLOUD_REF_HOSTNAME_SUFFIXES,
    _CLOUD_REF_HOSTNAME_REGEXES,
    _is_mobile_bundle_url,
)
from forge.orchestrator.synthesis import EngagementSynthesisEngine
# ... etc
```

---

## Phase 8: Split report_synthesizer.py (~4,500 lines)

| New file | Content | Est. lines |
|---|---|---|
| `forge/phase6/synthesizer/__init__.py` | Re-exports | 30 |
| `forge/phase6/synthesizer/context.py` | `ContextBuilder`, `ReportContext`, all context dataclasses | ~800 |
| `forge/phase6/synthesizer/cascade.py` | `_AUTO_CASCADE_DEFAULT_ORDER`, `_build_auto_chain`, `FallbackChainProvider`, provider loading | ~400 |
| `forge/phase6/synthesizer/render.py` | `_render_fallback_report`, template rendering, Markdown assembly | ~600 |
| `forge/phase6/synthesizer/persist.py` | `_persist_report_with_fallback`, `_write_report`, `_write_raw_export_fallback`, file I/O | ~500 |
| `forge/phase6/report_synthesizer.py` | Thin re-export shell | ~50 |

---

## Execution order (dependency-safe)

```
Phase 1 (cli_helpers.py)        → commit, test, push
Phase 2 (cli_osint.py)          → commit, test, push  
Phase 3 (cli_cloud.py)          → commit, test, push
Phase 4 (cli_graph.py)          → commit, test, push
Phase 5 (cli_post.py)           → commit, test, push
Phase 6 (cli_report.py)         → commit, test, push
--- cli.py now ~17K lines (kill_chain still inline) ---
Phase 7 (orchestrator split)    → commit, test, push
Phase 8 (report_synthesizer)    → commit, test, push
```

Each phase is one atomic commit. If any breaks tests, revert that one commit.

---

## After completion — expected file sizes

| File | Before | After |
|---|---|---|
| `forge/cli.py` | 20,244 | ~17,000 (kill_chain stays) |
| `forge/cli_helpers.py` | 0 (new) | ~320 |
| `forge/cli_osint.py` | 0 (new) | ~1,464 |
| `forge/cli_cloud.py` | 0 (new) | ~533 |
| `forge/cli_graph.py` | 0 (new) | ~826 |
| `forge/cli_post.py` | 0 (new) | ~164 |
| `forge/cli_report.py` | 0 (new) | ~98 |
| `forge/engagement_orchestrator.py` | ~25,000 | ~100 (re-export shell) |
| `forge/orchestrator/classifier.py` | 0 (new) | ~200 |
| `forge/orchestrator/synthesis.py` | 0 (new) | ~3,000 |
| `forge/orchestrator/spider.py` | 0 (new) | ~2,000 |
| `forge/orchestrator/persistence.py` | 0 (new) | ~1,500 |
| `forge/phase6/report_synthesizer.py` | ~4,500 | ~50 (re-export shell) |
| `forge/phase6/synthesizer/*.py` | 0 (new) | ~2,400 total |

---

## How to prompt next session

```
Resume FORGE modularity refactor. Plan in docs/modularity_refactor_plan.md.
Repo: C:\Users\bryan\OneDrive\01 TOOLKITS\forgetoolkit  
Latest: ce2196d on origin/main (hongyime/FORGE)
GitHub PAT: [paste fresh token]

Execute Phase 1 through Phase 6 (cli.py extraction into sub-modules).
Each phase: extract → verify imports → run pytest → commit → push.
Use subagents to parallelize Phases 2-6 if all share the same pattern.
After all 6 phases: run full test bank to confirm zero regressions.
Then continue with Phase 7 (orchestrator split) and Phase 8 (report_synthesizer split).
```

---

## What NOT to do

- Do NOT convert `forge/cli.py` into a package (`forge/cli/__init__.py`) — that breaks the `forge.cli:main` entry point in pyproject.toml without also updating the installed package metadata
- Do NOT move `kill_chain()` out of cli.py yet — it has 15K lines of inline state and 143 test call sites that import it from `forge.cli`
- Do NOT rename any public function — backward compat first, cleanup later
- Do NOT edit logic — this is PURE structural extraction, zero behavior changes
