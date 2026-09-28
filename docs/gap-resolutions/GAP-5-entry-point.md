# GAP-5 — Python Entry Point Migration

**Status:** RECOMMENDED — dual-run bridge documented, no changes today  
**Resolution phase:** Phase 4 (dual-run) → Phase 5 (Python entry point retired)  
**Date assessed:** 2026-09-28  

---

## 1. What is this gap?

After Python Phase 5 deletion, the `forge` command must map to the Rust binary,
not the Python `forge.cli:main` entry point. Today there are two separate
entry points:

| Entry point | Installed by | Binary location |
|---|---|---|
| `forge` (Python shim) | `pip install -e .` | `.venv/Scripts/forge.exe` (Windows) |
| `forge-cli` (Rust binary) | `cargo install --path native/crates/forge-cli` | `~/.cargo/bin/forge-cli.exe` |

The Rust binary is named `forge-cli` (from `native/crates/forge-cli/Cargo.toml`:
`name = "forge-cli"`). It does **not** yet produce a binary named `forge` — this
is the naming gap.

---

## 2. Current State

### Python entry point (`pyproject.toml` lines 119–120)

```toml
[project.scripts]
forge = "forge.cli:main"
```

When `pip install -e .` (or `pip install .`) is run, it installs a `forge.exe`
shim in the venv's Scripts directory. This shim calls `forge.cli:main` —
the Python CLI entry point.

### Rust CLI crate (`native/crates/forge-cli/Cargo.toml`)

```toml
[package]
name = "forge-cli"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true

[dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

The package name is `forge-cli`. By default, `cargo build` produces a binary
named `forge-cli.exe` on Windows (matching the package name). There is no
`[[bin]]` section specifying a different output name.

---

## 3. The Name Gap

After Phase 4 cutover, the Rust binary should respond to the bare `forge` command.
There are two ways to achieve this:

### Method A — Rename the Rust binary via `[[bin]]` in Cargo.toml

```toml
# Add to native/crates/forge-cli/Cargo.toml:
[[bin]]
name = "forge"
path = "src/cli.rs"   # or src/main.rs — verify actual entrypoint
```

This makes `cargo build` produce `forge.exe`. This is the cleanest solution.

**Status:** Not executed today (Phase 5 territory). Requires confirming that
`src/cli.rs` is the binary entry point (it has a `main` function or re-exports
one). Verify first:

```powershell
Select-String -LiteralPath "C:\forge\native\crates\forge-cli\src\cli.rs" -Pattern "fn main"
Select-String -LiteralPath "C:\forge\native\crates\forge-cli\src\lib.rs" -Pattern "fn main"
```

### Method B — PATH ordering (Phase 4 dual-run bridge)

During Phase 4 (dual-run), both Python and Rust CLIs are installed. PATH ordering
determines which `forge` wins:

```
C:\Users\<user>\.cargo\bin\forge-cli.exe   ← Rust (not yet named "forge")
C:\forge\.venv\Scripts\forge.exe           ← Python (named "forge")
```

To prefer Rust in Phase 4 without renaming:
1. Create a wrapper `forge.bat` or `forge.ps1` in a high-priority PATH directory
   that calls `forge-cli.exe`
2. Or rename the Rust binary (Method A above) and install it earlier in PATH

---

## 4. Bridge Strategy (Phase 4 Dual-Run)

During Phase 4, the recommendation is:

1. Keep `pip install -e .` active → Python `forge` shim still works
2. `cargo install --path native/crates/forge-cli --offline` → installs `forge-cli.exe`
3. Add `[[bin]] name = "forge"` to `forge-cli/Cargo.toml` → binary is now `forge.exe`
4. Ensure `~/.cargo/bin` precedes `.venv/Scripts/` in PATH
5. Test: `forge --help` should invoke Rust, not Python

For Windows specifically, verify PATH priority:

```powershell
# Check which 'forge' wins:
(Get-Command forge -ErrorAction SilentlyContinue).Source

# Expected after Phase 4:
# C:\Users\<user>\.cargo\bin\forge.exe   (Rust)
# NOT .venv\Scripts\forge.exe            (Python)
```

---

## 5. Verification Steps (Pre-Phase 4)

Before entering Phase 4, confirm the Rust CLI produces the expected help output:

```powershell
# Step 1: Build Rust CLI
$env:PATH = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64;$env:PATH"
$env:LIB = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\lib\x64;C:\Program Files (x86)\Windows Kits\10\lib\10.0.26100.0\um\x64;C:\Program Files (x86)\Windows Kits\10\lib\10.0.26100.0\ucrt\x64"
$env:INCLUDE = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\include;C:\Program Files (x86)\Windows Kits\10\include\10.0.26100.0\ucrt;C:\Program Files (x86)\Windows Kits\10\include\10.0.26100.0\um;C:\Program Files (x86)\Windows Kits\10\include\10.0.26100.0\shared"
cargo build --release --offline --manifest-path native/Cargo.toml -p forge-cli

# Step 2: Verify binary exists
Test-Path "C:\forge\native\target\release\forge-cli.exe"

# Step 3: Run --help and verify expected output
& "C:\forge\native\target\release\forge-cli.exe" --help

# Step 4: Verify key commands are present
& "C:\forge\native\target\release\forge-cli.exe" kill-chain --help
& "C:\forge\native\target\release\forge-cli.exe" report --help

# Step 5: Compare Python --help vs Rust --help (no regressions)
forge --help              # Python
forge-cli --help          # Rust
# Diff to identify missing subcommands
```

---

## 6. Phase 5 Actions (NOT executed today)

```toml
# 1. Add to native/crates/forge-cli/Cargo.toml:
[[bin]]
name = "forge"
path = "src/cli.rs"

# 2. Rebuild and install
# cargo install --path native/crates/forge-cli --offline --force

# 3. Remove Python entry point from pyproject.toml:
# [project.scripts]
# forge = "forge.cli:main"   ← DELETE this section

# 4. Verify PATH produces Rust binary:
# (Get-Command forge).Source   → should be ~/.cargo/bin/forge.exe

# 5. Run smoke test:
# forge --help
# forge kill-chain --help
# forge report generate --help
```

---

## 7. Notes on `pyproject.toml`

**DO NOT modify `pyproject.toml` today.** The Python entry point must survive
through Phase 4. Removing it before Phase 4 is complete would break the Python
CLI for all operators still on the Python stack.

The entry point migration is a **Phase 5 task**, not a pre-cutover task.

---

## 8. References

- `native/crates/forge-cli/Cargo.toml` — `name = "forge-cli"`, no `[[bin]]` override
- `pyproject.toml` lines 119–120: `forge = "forge.cli:main"`
- `native/crates/forge-cli/src/cli.rs` — CLI implementation (main entry point)
- `native/crates/forge-cli/src/lib.rs` — library surface
- `docs/rust-cutover-plan.md` §2.1 — "Python entry point (`pyproject.toml` line 120): `forge = forge.cli:main`"
- Task instruction: "DO NOT modify pyproject.toml today — that's Phase 5 territory"
