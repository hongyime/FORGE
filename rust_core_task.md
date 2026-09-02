# FORGE Rust Core Development - Legacy Prompt

## Current Status

This file is historical context, not a verified completion report and not the
active implementation plan. The current verified status is in
`OBFUSCATION_RESULTS.md` and `FORGE_RUST_HANDOFF.md`.

Do not use this prompt to implement stealth, sensor avoidance, credential theft,
or EDR/AV bypass behavior. Current completed Rust work is limited to a minimal
PyO3 extension with AES helper functions plus placeholder classes.

## Context
Windows security toolkit Rust prototype. Python codebase considered a Rust
rewrite for:
- Better performance (10-50x faster)
- Native packaging
- No Python interpreter dependency

## Current State
Rust core project scaffolded at `rust_core/` with:
- Basic module structure (kerberos, credentials, pth, spray, crypto, obfuscation)
- PyO3 FFI bindings configured
- Placeholder implementations

## Tasks for Codex

### Task 1: Implement Real Kerberos Operations
**File**: `rust_core/src/kerberos.rs`
**Requirements**:
1. Parse `.kirbi` files (ASN.1 format)
2. Extract TGT/TGS tickets
3. Implement ticket injection (Windows LsaCallAuthenticationPackage)
4. Check scope before operations
5. Obfuscate all sensitive strings using the obfuscation module
6. Use legitimate constants (KRB_AS_REQ, KRB_TGS_REQ, etc.)

**Example usage**:
```rust
let ops = KerberosOps::new(
    "ROE-123".to_string(),
    Some(vec!["target.local".to_string()]),
    false,  // allow_lsass
    true,   // allow_kerberoast
)?;

let tickets = ops.parse_kirbi("/path/to/ticket.kirbi")?;
```

### Task 2: Implement Credentials Extraction

Deferred pending an explicit authorized defensive design and safety review.

**File**: `rust_core/src/credentials.rs`
**Requirements**:
1. Implement LSASS memory parsing (Windows-only)
2. Implement SAM database parsing
3. Extract NTLM hashes from memory
4. Extract DCC (Domain Cached Credentials)
5. Use obfuscated syscalls (NtQuerySystemInformation, NtReadVirtualMemory)
6. Check scope and permissions

Do not add sensor-avoidance behavior.

### Task 3: Implement Pass-the-Hash
**File**: `rust_core/src/pth.rs`
**Requirements**:
1. Create NTLM hash authentication
2. Execute commands with token impersonation
3. Use WMI/WinRM/SMBexec techniques (choose one)
4. Obfuscate command arguments
5. Implement cleanup (destroy tokens)

### Task 4: Implement Password Spraying
**File**: `rust_core/src/spray.rs`
**Requirements**:
1. LDAP/SAMBA authentication
2. Rate limiting to avoid lockouts
3. Calculate optimal delay based on lockout policy
4. Support multiple protocols (LDAP, Kerberos, NTLM)
5. Test credentials without logging

### Task 5: Implement Crypto Operations
**File**: `rust_core/src/crypto.rs`
**Requirements**:
1. AES-256-GCM encryption/decryption
2. ChaCha20-Poly1305 (alternative)
3. Argon2 password hashing
4. Secure key generation
5. Use zeroize::Zeroizing for key memory

### Task 6: FFI Bindings
**File**: `rust_core/src/lib.rs`
**Requirements**:
1. Expose all modules to Python
2. Use PyO3 async for long operations
3. Return errors as Python exceptions
4. Add docstrings for each function

### Task 7: Build Configuration
**File**: `rust_core/Cargo.toml`
**Requirements**:
1. Validate all dependencies compile
2. Test with `cargo build --release`
3. Verify binary size < 5MB
4. Strip debug symbols
5. Enable LTO

## Critical Constraints
- **NO `unwrap()` or `expect()`** - use proper error handling
- **NO hardcoded strings** - use obfuscation module
- **ALL operations scope-checked**
- **ALL exports use ROE ID**
- **ZERO plaintext sensitive data in memory longer than needed**

## Obfuscation Patterns
Use these patterns for sensitive strings:
```rust
// Use obfuscation module
use crate::obfuscation::{obfuscate_string, deobfuscate_string};

// Example: obfuscate "mimikatz"
let obfuscated = obfuscate_string("mimikatz".to_string(), 0x42);
// Deobfuscate when needed
let original = deobfuscate_string(obfuscated, 0x42)?;
```

## Testing Requirements
After implementation:
1. Run `cargo test` - all tests must pass
2. Run `cargo build --release` - binary must compile
3. Run `cargo clippy` - no warnings
4. Test for local Defender false positives in an authorized environment

## Output Specification
- Pure Rust code (no unsafe unless absolutely necessary)
- Full documentation comments
- Unit tests for each public function
- Integration tests for Python FFI

## Deliverables
1. Completed `rust_core/src/*.rs` files
2. Working Python import: `import forge_core`
3. Test script demonstrating functionality
4. Build instructions for Windows/Linux

---

Run this task with Codex CLI:
```bash
codex exec --model gpt-5.2 --task-file rust_core_task.md
```

Or provide inline:
```bash
codex exec --model gpt-5.2 --task "$(cat rust_core_task.md)"
```

## Codex Verification Status (2026-09-01, commit f3041c1)

### What Works
- obfuscated/ verified: 19 files, 2.06 MiB
- forge_loader.load("kerberos_ops") returns module and exposes KerberosOps
- Direct import: `from obfuscated.kerberos.kerberos_ops import KerberosOps` works with required safety args
- forge_core.pyd: 351,744 bytes at repo root, AES roundtrip verified
- cargo test --release: 9 passed
- pytest tests/test_obfuscated.py -v: 6 passed
- Defender: no forge-related detections

### What Was Fixed
- .gitignore: added explicit ignore rules for Cargo/Rust output and root extension copy
- Untracked 432 committed rust_core/target build artifacts from git index
- obfuscated package initializers: fixed direct PyArmor package imports
- tests/test_obfuscated.py: strengthened to check loader class exposure and direct imports in clean subprocess
- FORGE_RUST_HANDOFF.md: removed stale "currently blocked" wording

### Still Limited (Placeholder Scaffolding — NOT Production Behavior)

The following methods compile and pass gate checks but return empty/stub results.
Do NOT claim "Rust core complete" beyond AES-GCM/BLAKE3 crypto.

| File | Line | Method | Status | What Real Implementation Needs |
|------|------|--------|--------|-------------------------------|
| kerberos.rs | 50 | parse_kirbi() | Returns empty Vec | asn1-rs for ASN.1 parsing of .kirbi format |
| kerberos.rs | 57 | enumerate_kerberoast_candidates() | Returns empty Vec | LDAP queries to domain controller |
| credentials.rs | 51 | extract_from_lsass() | Returns empty Vec | Windows API: DuplicateTokenEx, OpenProcess, MiniDumpWriteDump or in-memory parsing |
| credentials.rs | 67 | extract_from_sam() | Returns empty Vec | Obfuscated syscalls for registry access |
| pth.rs | 36 | execute() | Returns placeholder string | NTLM authentication implementation |

### Next Steps for Real Native Behavior
1. Each method requires explicit safe feature flags before implementation
2. Each method requires authorization checks beyond current ROE/scope gates
3. Implement behind `#[cfg(feature = "native-kerberos")]` etc. to keep placeholder as default
4. Full security review required before any credential/PTH behavior ships
