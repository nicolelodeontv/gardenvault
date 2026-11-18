@echo off
setlocal
cd /d "%~dp0"
where node >nul 2>nul || (echo Node.js 22+ is required.& exit /b 1)
where npm >nul 2>nul || (echo npm is required.& exit /b 1)
where rustc >nul 2>nul || (echo Rust stable is required.& exit /b 1)
where cargo >nul 2>nul || (echo Cargo is required.& exit /b 1)
call npm install --no-audit --no-fund
if errorlevel 1 exit /b 1
call npm test
if errorlevel 1 exit /b 1
call npm run tauri -- icon src-tauri/icons/gardenvault.svg
if errorlevel 1 exit /b 1
cargo fmt --manifest-path src-tauri/Cargo.toml --all
if errorlevel 1 exit /b 1
cargo test --manifest-path src-tauri/Cargo.toml
if errorlevel 1 exit /b 1
call npm run tauri:build
if errorlevel 1 exit /b 1
echo Build complete. Installer output: src-tauri\target\release\bundle\nsis\
endlocal
