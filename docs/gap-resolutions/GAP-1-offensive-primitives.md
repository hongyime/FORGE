# GAP-1 — Offensive Primitives (rust_core/)

**Status:** RECOMMENDED (not yet executed)  
**Resolution phase:** Pre-cutover / backlog decision  
**Date assessed:** 2026-09-28  

---

## 1. What is this gap?

`rust_core/` is a standalone Rust crate (`forge-core` / `forge_core`) containing
seven pyo3-backed offensive security modules:

| File | Capability |
|---|---|
| `src/credentials.rs` | Mimikatz-style LSASS credential extraction (`CredentialExtractor`) |
| `src/kerberos.rs` | Kerberoast enumeration via anonymous LDAP bind (`KerberosOps`) |
| `src/pth.rs` | Pass-the-Hash execution (`PTHExecutor`) |
| `src/spray.rs` | Password spray optimizer (`SprayOptimizer`) |
| `src/obfuscation.rs` | String obfuscation/deobfuscation helpers |
| `src/crypto.rs` | AES-GCM encrypt/decrypt, key generation |
| `src/lib.rs` | pyo3 module init — exposes classes and functions to Python |

These are **NOT** part of the `native/crates/` ASM pipeline (T1–T36). They are
separate offensive post-exploitation primitives that exist in their own workspace.

---

## 2. Current Wiring State: ORPHANED

**Grep results across all of `native/` and `forge/` for `forge_core`, `forge-core`,
`rust_core`:**

```
native/  → 0 matches
forge/   → 0 matches
pyproject.toml → 0 matches (no maturin, no pyo3, no rust_core reference)
```

**Conclusion:** `rust_core/` is **completely orphaned**. No Python code imports it.
No Rust crate depends on it. It is not part of any Compose service. It has never
been wired into the active `forge/` Python codebase or the `native/` Rust rewrite.

The crate builds as a `cdylib` (Python native extension) but nothing loads that
`.so`/`.pyd` artifact. The crate name `forge-core` would conflict with `native/`
naming conventions if it were ever imported, but currently that conflict is moot.

---

## 3. Resolution Options

### Option (a) — Migrate into `native/crates/forge-offensive/` (new crate)

**Approach:** Copy `rust_core/src/*.rs` into a new `native/crates/forge-offensive/`
crate. Adapt away from `pyo3` (or keep a `pyo3`-feature wrapper for now). Wire
into the native workspace `Cargo.toml`.

**Tradeoffs:**

| Pro | Con |
|---|---|
| Aligns with the Rust-primary architecture | Significant work: pyo3 bindings replaced or wrapped |
| `windows-sys` Windows API calls survive untouched | Name clash: `forge-core` vs native crate namespace needs resolution |
| Offensive code is version-controlled with the rest | LSASS/PTH code requires Windows + MSVC env — complicates CI |
| Enables Rust-to-Rust call from CLI/pipeline | `ldap3` + `tokio` adds async runtime surface to native workspace |

**Verdict:** High-effort, blocks on deciding whether FORGE will have a first-class
post-exploitation module in v2.

---

### Option (b) — Keep as separate top-level `rust_core/` workspace

**Approach:** Leave `rust_core/` where it is. Accept the split. Document that it is
a separate, standalone crate maintained independently of the native/ workspace.

**Tradeoffs:**

| Pro | Con |
|---|---|
| Zero work, zero risk today | Permanent architectural wart: two disconnected Rust workspaces |
| No breakage to anything | Orphaned state continues; code could bitrot |
| Easy to revisit when FORGE has a use for it | Dev must remember to `cd rust_core` to build/test it |

**Verdict:** Acceptable as a holding pattern. The code is not harmful sitting there;
it just doesn't run.

---

### Option (c) — Delete `rust_core/` entirely

**Approach:** `Remove-Item -Recurse -Force C:\forge\rust_core`.

**Tradeoffs:**

| Pro | Con |
|---|---|
| Eliminates dead code and reduces cognitive overhead | Offensive primitives are hard to recreate; loses work product |
| Removes windows-sys/ldap3/pyo3 dependency surface | Irreversible if not git-tracked (it is git-tracked, so recoverable) |
| Simplifies repo for new contributors | No migration path if post-exploitation module is ever needed |

**Precondition for this option:** Grep confirms zero usage (confirmed above ✓).

---

## 4. Recommended Action: Option (b) — Keep Separate, Document

**Rationale:**

1. The code is entirely orphaned — no active risk, no active dependency.
2. Deletion is cheap but loses real offensive engineering work that may be wanted
   in a future `FORGE_SAFE_MODE=0` post-exploitation release.
3. Migrating into `native/` requires architectural decisions (async runtime, pyo3
   vs pure Rust API, test strategy for Windows-only code) that belong in their own
   spec — not in a gap-resolution session.
4. The repo is git-tracked; Option (c) is always one `git rm -r rust_core/` away.

**Decision:** Accept the split. Add a `rust_core/README.md` noting its orphan
status and that integration into `native/crates/forge-offensive/` is a future task.

---

## 5. Exact Commands to Execute Recommended Action

```powershell
# Create a minimal README marking the crate as orphaned / future work
@'
# rust_core — Offensive Primitives (Standalone Crate)

> **Status:** Orphaned — not currently imported by forge/ Python or native/ Rust.
> **Decision (2026-09-28):** Kept as separate workspace, pending architectural
> decision on whether to migrate into native/crates/forge-offensive/.

## What is here

pyo3-backed offensive modules: CredentialExtractor (LSASS), KerberosOps
(Kerberoast/LDAP), PTHExecutor (Pass-the-Hash), SprayOptimizer, obfuscation,
AES-GCM crypto, and the Python module entry point.

## Why not deleted

Zero current usage confirmed by grep (2026-09-28), but the code represents
significant offensive engineering work. Deletion is easy (git rm -r rust_core/)
once the architectural decision to abandon post-exploitation modules is final.

## How to build (standalone)

```powershell
cd rust_core
$env:PATH = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64;$env:PATH"
cargo build --release --offline
```

## Migration path (future)

When FORGE adds a post-exploitation phase:
1. Create native/crates/forge-offensive/
2. Copy src/*.rs, adapt away from pyo3 or keep a pyo3 feature flag
3. Add to native/Cargo.toml workspace members
4. Wire into forge-cli subcommand under --safe-mode=false guard
'@ | Set-Content "C:\forge\rust_core\README.md"
```

---

## 6. What Remains for Phase 5

- Nothing: this crate is already isolated. Phase 5 (Python deletion) does not
  touch `rust_core/` — it is Rust code, not Python.
- If the final decision is deletion: `git rm -r rust_core/` at any time after
  this gap is acknowledged.

---

## 7. References

- `rust_core/Cargo.toml` — crate name `forge-core`, pyo3 `extension-module` target
- `rust_core/src/lib.rs` — pyo3 module init exposing 4 classes + 4 functions
- `native/migration/domain-contracts.json` — 118 entries, none reference `forge_core`
- Task instruction: "DO NOT execute the migration/deletion — just recommend"
