# FORGE Obfuscation and Rust Build Results

**Date:** 2026-08-31

## Result

The previous "Rust blocked" state is resolved. The current verified result is:

- PyArmor outputs exist for the three requested modules.
- `forge_core.dll` builds successfully.
- Repo-root `forge_core.pyd` imports from Python.
- Rust AES encrypt/decrypt works.
- The strengthened integration test passes.
- Windows Defender returned no matching detections after separate local custom
  scans of `forge_core.pyd` and `obfuscated/`.

This is local verification, not a general EDR/AV bypass claim.

## Artifacts

| Artifact | Location | Size | Status |
|---|---:|---:|---|
| Rust DLL | `%LOCALAPPDATA%\Temp\forge-rust-target\release\forge_core.dll` | 351,744 bytes | built |
| Python extension copy | `forge_core.pyd` | 351,744 bytes | importable |
| Kerberos obfuscated module | `obfuscated/kerberos/kerberos_ops.py` | 61,458 bytes | present |
| Mimikatz obfuscated module | `obfuscated/mimikatz/mimikatz_backend.py` | 61,984 bytes | present |
| Spray obfuscated module | `obfuscated/auth/spray_optimizer.py` | 52,112 bytes | present |

`obfuscated/` currently contains 19 files totaling 2.06 MB, including generated
`__pycache__` files from verification imports.

## Fixes Applied During Validation

### Rust core

- Added the missing Rust AES exports to the PyO3 module:
  `aes_encrypt`, `aes_decrypt`, and `generate_key`.
- Fixed `rust_core/src/spray.rs` syntax and divide-by-zero handling.
- Pruned unused heavy dependencies from `rust_core/Cargo.toml`.
- Re-enabled optimized release settings after dependency pruning:
  `lto = true`, `codegen-units = 1`, and `strip = true`.
- Updated `build_rust_core.bat` to use
  `%LOCALAPPDATA%\Temp\forge-rust-target` and recreate `forge_core.pyd`.

### Loader and tests

- Fixed `forge_loader.py` so PyArmor modules expose their expected classes.
- Fixed obfuscated package initializers so direct `obfuscated.*` imports can
  resolve the PyArmor runtime without going through `forge_loader.py`.
- Strengthened `tests/test_obfuscated.py`; it now fails if any class/runtime is
  missing, verifies direct package imports, and verifies the Rust AES import
  path.

## Verification

Passed:

```powershell
.\build_rust_core.bat
cargo test --release
python -m pytest tests\test_obfuscated.py -q
python -c "from forge_core import aes_encrypt; print('OK')"
python -c "from obfuscated.kerberos.kerberos_ops import KerberosOps; print(KerberosOps.__name__)"
```

Observed:

- `.\build_rust_core.bat`: build OK, DLL and `.pyd` copy produced.
- `cargo test --release`: 9 passed.
- `python -m pytest tests\test_obfuscated.py -q`: 6 passed.
- `python -c "from forge_core import aes_encrypt; print('OK')"`: `OK`.
- Direct `obfuscated.*` imports expose the expected classes.

## Defender Checks

The combined multi-path Defender scan failed with a generic Defender error, so
it is not counted as evidence. Separate scans completed:

```powershell
Start-MpScan -ScanType CustomScan -ScanPath .\forge_core.pyd
Start-MpScan -ScanType CustomScan -ScanPath .\obfuscated
```

After those scans, this query returned no rows:

```powershell
Get-MpThreatDetection | Where-Object {
    $_.Resources -like "*forgetoolkit*" -or
    $_.Resources -like "*forge_core*" -or
    $_.Resources -like "*obfuscated*"
}
```

## Claim Check

| Claim | Verdict |
|---|---|
| 3 modules obfuscated | Verified |
| 19 files, 2.06 MB under `obfuscated/` | Verified, includes generated `__pycache__` |
| `forge_core.pyd` exists | Verified |
| Rust AES encryption works | Verified |
| `from forge_core import aes_encrypt` works | Verified |
| All three modules load through `forge_loader.py` | Verified after patching `forge_loader.py` |
| Direct imports from `obfuscated.*` expose classes | Verified after patching package initializers |
| Full integration test passes | Verified after strengthening `tests/test_obfuscated.py` |
| Defender has no matching detections locally | Verified |
| Broad EDR/AV evasion is proven | Not proven and not claimed |
