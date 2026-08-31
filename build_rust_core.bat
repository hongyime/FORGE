@echo off
REM FORGE Rust Core - Build Retry Script
REM Redirects target dir off OneDrive to avoid file-lock/sync issues.

setlocal
set "CARGO_TARGET_DIR=%LOCALAPPDATA%\Temp\forge-rust-target"
echo [FORGE] Building rust_core to %CARGO_TARGET_DIR%
pushd "%~dp0rust_core"
cargo build --release
set RC=%ERRORLEVEL%
popd
if %RC%==0 (
    echo [FORGE] Build OK.
    echo [FORGE] Binary: %CARGO_TARGET_DIR%\release\forge_core.dll
    copy /Y "%CARGO_TARGET_DIR%\release\forge_core.dll" "%~dp0forge_core.pyd" >nul
    if not exist "%~dp0rust_core\target\release" mkdir "%~dp0rust_core\target\release"
    copy /Y "%CARGO_TARGET_DIR%\release\forge_core.dll" "%~dp0rust_core\target\release\" 2>nul
    echo [FORGE] Python import copy: %~dp0forge_core.pyd
) else (
    echo [FORGE] Build FAILED with code %RC%.
    echo         See rust_core_task.md - Known Blockers.
)
endlocal
exit /b %RC%
