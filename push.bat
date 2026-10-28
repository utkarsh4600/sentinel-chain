@echo off
title Push Sentinel Chain to GitHub
cd /d "%~dp0"
echo ========================================================
echo   Pushing Sentinel Chain to GitHub...
echo ========================================================
git add .
git commit -m "Update Sentinel Chain platform"
git push -u origin main
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Push failed. If authentication is needed, run:
    echo   gh auth login
) else (
    echo.
    echo ========================================================
    echo   SUCCESSFULLY PUSHED TO GITHUB!
    echo ========================================================
)
pause
