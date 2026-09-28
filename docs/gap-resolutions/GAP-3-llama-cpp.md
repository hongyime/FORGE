# GAP-3 — llama_cpp Local LLM

**Status:** RECOMMENDED — DROP from cutover scope (Option a)  
**Resolution phase:** Phase 5 (pyproject.toml cleanup)  
**Date assessed:** 2026-09-28  

---

## 1. What is this gap?

`pyproject.toml` declares:
```
llama-cpp-python==0.3.8
```

This provides a local GGUF model inference backend used for Phase 6 report
synthesis when no SaaS LLM is available. The Python module lives at
`forge/providers/llama_cpp.py` and is imported lazily (guarded by try/except)
in the provider router.

---

## 2. Current Python Callsites

Grep of `forge/` for `llama_cpp` imports — 18 files with matches:

| File | Role |
|---|---|
| `forge/providers/llama_cpp.py` | Provider implementation — wraps `llama_cpp.Llama` |
| `forge/providers/router.py` | Provider cascade: tries backends in order |
| `forge/providers/registry.py` | Provider registry — registers `llama_cpp` as a backend |
| `forge/providers/__init__.py` | Re-exports provider classes |
| `forge/providers/base.py` | Base class (referenced by all providers) |
| `forge/providers/discovery.py` | Auto-discovers available backends |
| `forge/providers/cli.py` | CLI-level provider flag handling |
| `forge/providers/openai_compatible.py` | OpenAI-compatible provider (sibling to llama_cpp) |
| `forge/phase6/__init__.py` | Phase 6 imports provider chain |
| `forge/phase6/report_synthesizer.py` | Uses provider cascade for report text |
| `forge/phase6/aggregate_stats.py` | Stats fed into report |
| `forge/cli.py` | `--report-provider llama_cpp` flag |
| `forge/cli_report.py` | `forge report generate --provider llama_cpp` |
| `forge/config.py` | `FORGE_LLM_PROVIDER=llama_cpp` env config |
| `forge/tui/main_menu.py` | TUI includes llama_cpp as provider option |
| `forge/webui/__init__.py` | Web UI provider selection |
| `forge/webui/kill_chain_launch.py` | Kill-chain launch includes provider selection |
| `forge/doctor.py` | `forge doctor` reports llama_cpp availability |

**18 Python files** reference `llama_cpp`. However, these are all in the **provider
abstraction layer** — the cascade pattern means `llama_cpp` is one optional backend,
not a hard dependency on any specific operation.

---

## 3. Current Dev State

The user has explicitly set `FORGE_LLM_PROVIDER=template` for all development.
From `docker/docker-compose.prod.yml` (pre-edit, also post-edit):

```yaml
FORGE_LLM_PROVIDER: "${FORGE_LLM_PROVIDER:-template}"
```

The `template` provider is the **deterministic no-LLM fallback** that produces
reports without any model inference. It is the default and it works completely.

The `auto` cascade already handles:
1. Local LLM CLIs (Kiro/Claude/Codex/Gemini — detected in PATH)
2. OpenRouter (free-model path when `OPENROUTER_API_KEY` is set)
3. `llama_cpp` (local GGUF, explicit only)
4. `template` (deterministic fallback — always works)

---

## 4. Rust-Side Equivalent

The `forge-reporting` crate in `native/crates/forge-reporting/` implements the
Rust report pipeline. It does **not** have a `llama_cpp` equivalent — the Rust
reporting crate is designed around:
- Template-based deterministic reports (always available)
- HTTP-based LLM provider calls (OpenRouter, OpenAI-compatible)
- No local GGUF inference in the Rust stack

This is intentional: local GGUF inference via `llama-cpp-python` is a heavy
optional dependency that requires a matching compiled `.so` against the system's
BLAS/CUDA stack. It is unsuitable as a required Rust dependency.

---

## 5. Resolution Options

### Option (a) — DROP llama_cpp from cutover scope (RECOMMENDED)

**Approach:** At Phase 5, remove `llama-cpp-python==0.3.8` from `pyproject.toml`
dependencies. The Rust reporting crate never gets a GGUF backend. Users who need
local GGUF can:
- Use `FORGE_LLM_PROVIDER=template` (zero-LLM deterministic report)
- Set `OPENROUTER_API_KEY` + free-model path (already in Rust cascade)
- Run a local OpenAI-compatible server (LM Studio, Ollama) and point at it

**Tradeoffs:**

| Pro | Con |
|---|---|
| Eliminates 500 MB+ native lib dependency | Loses embedded GGUF local inference |
| `template` provider already covers dev/offline use | Operators with downloaded models lose a convenience path |
| OpenRouter free-model path is already in Rust reporting | Offline-only operators must switch to template |
| No Rust GGUF backend needed | |

**Verdict:** **RECOMMENDED.** The user has explicitly stated dev uses `template`
provider. The gap is self-closing because `template` + OpenRouter already handle
every practical scenario.

---

### Option (b) — Port to Rust `ggml-rs` or `llm` crate

**Approach:** Use the `llm` crate (formerly `llm-chain`) or `ggml-rs` to run GGUF
models natively in Rust.

**Tradeoffs:**

| Pro | Con |
|---|---|
| Pure Rust stack | `llm` crate is not production-stable for complex prompts |
| No Python dependency | GGUF format / quantization support is incomplete vs. llama.cpp |
| | Heavy work — BLAS/CUDA linkage, model loading, sampling |
| | Weeks of engineering for marginal benefit given template fallback |

**Verdict:** Not recommended. The engineering cost does not justify it when
template + OpenRouter already cover the use case.

---

### Option (c) — Keep `llama_cpp` as opt-in sidecar

**Approach:** Keep `llama-cpp-python` in a separate `docker/Dockerfile.llama-sidecar`
image. Rust services call it over HTTP (`/v1/completions` — it's OpenAI-compatible).

**Tradeoffs:**

| Pro | Con |
|---|---|
| Preserves local GGUF path for advanced operators | Adds another optional container |
| Reuses existing OpenAI-compatible provider in Rust | Operators must download GGUF models separately |

**Verdict:** Acceptable but over-engineered for dev scope. If an operator needs
GGUF, running a standalone Ollama container already achieves the same outcome with
zero FORGE maintenance.

---

## 6. Recommended Action: Option (a) — DROP at Phase 5

### Phase 5 actions (NOT executed today)

```python
# In pyproject.toml — REMOVE at Phase 5:
# "llama-cpp-python==0.3.8",         ← remove this line

# Also remove from mypy ignores in pyproject.toml:
# "llama_cpp.*",                       ← remove this line (line 219)
# "forge/providers/llama_cpp.py",      ← delete this file
```

```powershell
# Verification after Phase 5 removal:
Select-String -Path "C:\forge\pyproject.toml" -Pattern "llama" | Should -BeNullOrEmpty
Select-String -Path "C:\forge\native\**\*.rs" -Pattern "llama" -Recurse | Should -BeNullOrEmpty
```

### Note to cutover plan (add to `docs/rust-cutover-plan.md` §7)

> **GAP-3 resolution (2026-09-28):** `llama-cpp-python` is dropped from Phase 5
> cleanup scope. Rust `forge-reporting` uses template + OpenRouter cascade.
> No Rust GGUF backend will be implemented. Operators needing local GGUF should
> run an Ollama container pointed at via `OPENROUTER_API_KEY`-compatible endpoint
> or use `FORGE_LLM_PROVIDER=template`.

---

## 7. What Remains for Phase 5

At Phase 5, the operator must:

1. Remove `llama-cpp-python==0.3.8` from `pyproject.toml` `[project.dependencies]`
2. Remove `"llama_cpp.*"` from `[tool.mypy.overrides]` in `pyproject.toml`
3. Delete `forge/providers/llama_cpp.py`
4. Remove `llama_cpp` from provider registry and router (or gate behind `FORGE_SAFE_MODE=0`)
5. Remove `--provider llama_cpp` from CLI help text in Rust `forge-cli`

---

## 8. References

- `pyproject.toml` line 33: `llama-cpp-python==0.3.8`
- `pyproject.toml` line 219: `"llama_cpp.*"` in mypy ignore list
- `pyproject.toml` line 207: "llama_cpp lazy import" note in ignore comment
- 18 Python files with `llama_cpp` references (all in provider abstraction layer)
- `FORGE_LLM_PROVIDER=template` — user confirmed dev-only, no LLM needed
- `native/crates/forge-reporting/` — Rust reporting has no GGUF backend (by design)
