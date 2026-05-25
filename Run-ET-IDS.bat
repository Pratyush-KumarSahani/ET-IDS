@echo off
setlocal

cd /d "%~dp0"
title ET-IDS Local Dashboard

echo.
echo ET-IDS local setup wizard
echo -------------------------
echo This will install Python requirements if needed, start live capture,
echo and open the dashboard at http://localhost:8000.
echo.
echo For live packet capture, close this window and run this file as Administrator
echo if Windows asks for capture permissions.
echo.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start_ids.ps1" -OpenDashboard

echo.
echo ET-IDS stopped. You can close this window.
pause
