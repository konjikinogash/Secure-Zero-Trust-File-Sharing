@echo off
setlocal
cd /d "%~dp0"
title Secure Zero-Trust File Sharing Server (Local Demo)

echo ======================================================================
echo           SECURE ZERO-TRUST FILE SHARING SYSTEM (DEMO)
echo ======================================================================
echo.
echo Server Address:  http://127.0.0.1:4173
echo Security Model:  Default-Deny (Authorization checked on every request)
echo Cryptography:    AES-256-GCM (fresh random IV) + SHA-256 integrity
echo Transport:       Local-only HTTP bound strictly to 127.0.0.1
echo.
echo Demo Accounts:
echo   - asha  / asha123   (Role: Student)
echo   - rao   / rao123    (Role: Faculty)
echo   - ravi  / ravi123   (Role: Student)
echo   - admin / admin123  (Role: Admin)
echo.
echo Launching your default web browser to http://127.0.0.1:4173 ...
start "" "http://127.0.0.1:4173"
echo.
echo [SERVER LOGS] Leave this window visible to monitor ALLOW / DENY events.
echo Press Ctrl+C in this console window to stop the server at any time.
echo ----------------------------------------------------------------------

node server.js
if errorlevel 1 (
    "C:\Program Files\nodejs\node.exe" server.js
)

echo.
echo Server has terminated.
pause
