@echo off
setlocal
cd /d "%~dp0"
title Reset Demo Files

echo ======================================================================
echo           SECURE ZERO-TRUST FILE SHARING - RESET DEMO DATA
echo ======================================================================
echo.
echo This script removes uploaded encrypted file blobs (*.aes) and resets
echo the file index in storage/metadata.json, while preserving the demo user accounts.
echo.
set /p CONFIRM="Are you sure you want to clear demo files? (Y/N): "
if /i not "%CONFIRM%"=="Y" (
    echo Reset cancelled.
    pause
    exit /b 0
)

echo.
del /q storage\*.aes 2>nul
node -e "const fs = require('fs'); const p = 'storage/metadata.json'; if (fs.existsSync(p)) { const d = JSON.parse(fs.readFileSync(p, 'utf8')); d.files = {}; fs.writeFileSync(p, JSON.stringify(d, null, 2)); console.log('[OK] Reset file metadata index.'); }"

echo [OK] Demo files removed.
echo Demo accounts remain ready for testing:
echo   - asha  / asha123
echo   - rao   / rao123
echo   - ravi  / ravi123
echo   - admin / admin123
echo.
pause
