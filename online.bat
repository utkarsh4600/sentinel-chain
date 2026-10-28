@echo off
title Sentinel Chain — Go Online
cd /d "%~dp0"
echo ========================================================
echo   SENTINEL CHAIN — GO ONLINE
echo ========================================================
echo.
echo [1/2] Starting local Python REST & Web Server in background...
start "" python server.py
timeout /t 2 >nul

echo [2/2] Generating instant live public HTTPS URL via secure tunnel...
echo (Press Ctrl+C when you want to stop the public tunnel)
echo.
echo Connecting tunnel to localhost:8000...
echo.
ssh -o StrictHostKeyChecking=no -R 80:localhost:8000 a.pinggy.io

pause
