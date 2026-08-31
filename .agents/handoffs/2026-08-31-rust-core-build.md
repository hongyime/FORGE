# FORGE Rust Core Build Handoff - 2026-08-31

## Objective

Build `rust_core/` so `forge_core.dll` exists, Python can import `aes_encrypt`,
and Defender has no detection for the DLL.

## Current State

- Root handoff: `FORGE_RUST_HANDOFF.md`.
- Cargo target dir: `%LOCALAPPDATA%\Temp\forge-rust-target`.
- `forge_core.dll` was not present when checked.
- `python --version` returned Python 3.12.10, compatible with `abi3-py312`.
- `SPEC.md` exists but does not drive this temporary Rust DLL task.

## Edits Made Before Build Retry

- Pruned unused Rust deps from `rust_core/Cargo.toml`: networking, Kerberos
  parser, Windows API, unused crypto/hash/serialization extras, and build deps.
- Set release `lto = false` and `codegen-units = 16` for faster DLL build.
- Fixed missing brace and zero-threshold guard in `rust_core/src/spray.rs`.
- Exported `crypto::{aes_encrypt,aes_decrypt,generate_key}` from the PyO3 module.
- Removed unused source imports that referenced pruned crates.

## Next Commands

```powershell
$env:CARGO_TARGET_DIR = "$env:LOCALAPPDATA\Temp\forge-rust-target"
Set-Location "rust_core"
cargo fmt
cargo check --release
cargo build --release
```

Then copy or locate the built extension under the release target and verify:

```powershell
python -c "from forge_core import aes_encrypt; print('OK')"
Get-MpThreatDetection | Where-Object { $_.Resources -like "*forge_core.dll*" }
```
