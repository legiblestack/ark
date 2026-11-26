@echo off
REM ARK - Network Security Monitor : installer
REM Double-click this file to install ARK for the current user.

cd /d "%~dp0"

if not exist "ARK.exe" (
    echo.
    echo   ERROR: ARK.exe not found in this folder.
    echo   Build it first:  powershell -ExecutionPolicy Bypass -File build-exe.ps1
    echo   Then run INSTALL.bat from the dist\ folder.
    echo.
    pause
    exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"

echo.
pause
