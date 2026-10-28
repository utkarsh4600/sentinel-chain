@echo off
title Sentinel Chain — Enterprise Cyber Defense Platform
echo ============================================================
echo   SENTINEL CHAIN PLATFORM STARTUP
echo   Post-Quantum AI Cyber Defense & Blockchain Evidence
echo ============================================================
echo.

cd /d "%~dp0"

echo [*] Starting Python REST & Web Server on port 8000...
echo [*] Opening Web Platform in default browser: http://localhost:8000
echo [*] REST API Explorer: http://localhost:8000/api/docs
echo.

start "" "http://localhost:8000"
python server.py

pause
