@echo off
rem Quick environment check - runs setup.ps1 and keeps the window open.
setlocal
cd /d "%~dp0"
echo ============================================
echo  MiscBox environment check
echo ============================================
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup.ps1"
echo.
echo Done. Report: %~dp0env-report.json
pause
