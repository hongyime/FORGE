# FORGE Obfuscation Status

**Date:** 2026-08-31

## Verified Summary

This file records what was verified locally. It does not claim broad EDR/AV
bypass. The verified Defender result is limited to this machine, this build, and
the Windows Defender cmdlets run below.

## PyArmor Modules

Three modules are present under `obfuscated/` with per-directory PyArmor runtime
packages:

| Module | Path | Size | Verified |
|---|---:|---:|---|
| kerberos_ops | `obfuscated/kerberos/kerberos_ops.py` | 61,458 bytes | yes |
| mimikatz_backend | `obfuscated/mimikatz/mimikatz_backend.py` | 61,984 bytes | yes |
| spray_optimizer | `obfuscated/auth/spray_optimizer.py` | 52,112 bytes | yes |

Inventory:

- `obfuscated/` contains 19 files, 2.06 MB including generated `__pycache__`.
- Each module directory contains `pyarmor_runtime_000000/pyarmor_runtime.pyd`.

## Rust Core

Rust core now builds successfully.

- Built DLL: `%LOCALAPPDATA%\Temp\forge-rust-target\release\forge_core.dll`
- Python import copy: `forge_core.pyd`
- Final LTO artifact size: 351,744 bytes
- Release profile: `opt-level = 3`, `lto = true`, `codegen-units = 1`,
  `panic = "abort"`, `strip = true`

The dependency graph was reduced to the crates used by the current source:
`aes-gcm`, `base64`, `blake3`, `rand`, `serde`, and `pyo3`.

## Integration

Two loaders are present:

- `forge_loader.py`: root helper with `load()` and `status()`
- `forge/obfuscated_wrapper.py`: package helper exporting the three classes

`forge_loader.py` was patched so PyArmor modules load under their expected module
names and include both the module directory and `pyarmor_runtime_000000` on
`sys.path`.

The obfuscated package initializers also add their own module directories to
`sys.path`, so direct imports such as
`from obfuscated.kerberos.kerberos_ops import KerberosOps` resolve the PyArmor
runtime without relying on the root loader.

## Verification Commands

Passed:

```powershell
.\build_rust_core.bat
cargo test --release
python -m pytest tests\test_obfuscated.py -q
python -c "from forge_core import aes_encrypt; print('OK')"
python -c "from obfuscated.kerberos.kerberos_ops import KerberosOps; print(KerberosOps.__name__)"
```

Observed results:

- `cargo test --release`: 9 passed.
- `python -m pytest tests\test_obfuscated.py -q`: 6 passed.
- `from forge_core import aes_encrypt` works from the repo root.
- Direct imports from `obfuscated.*` expose the expected classes.
- AES encrypt/decrypt roundtrip works.

## Defender Result

Defender status on this machine:

- Real-time protection: enabled.
- Antivirus: enabled.
- Signature version observed: `1.457.423.0`.

Checks performed:

```powershell
Start-MpScan -ScanType CustomScan -ScanPath .\forge_core.pyd
Start-MpScan -ScanType CustomScan -ScanPath .\obfuscated
Get-MpThreatDetection | Where-Object {
    $_.Resources -like "*forgetoolkit*" -or
    $_.Resources -like "*forge_core*" -or
    $_.Resources -like "*obfuscated*"
}
```

Result: no matching Defender detections were returned for this repo, the Rust
extension, or `obfuscated/`.

Important limitation: this is not a guarantee that other EDR products, Defender
versions, cloud reputation systems, or deployment environments will behave the
same way.
