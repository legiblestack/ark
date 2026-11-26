@echo off
REM ARK - Network Security Monitor - one-click launcher (auto-elevates to Administrator)
REM Double-click this file. It will request admin rights, start the server,
REM and open http://localhost:8088 in your default browser.

REM --- Self-elevate if not already running as Administrator ---
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator privileges...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"

where /q node
if errorlevel 1 (
    echo ERROR: Node.js is not installed or not on PATH.
    echo Install it from https://nodejs.org/ then re-run this file.
    pause
    exit /b 1
)

echo.
echo ========================================
echo  ARK - Network Security Monitor  (Administrator)
echo ========================================
echo  Opening http://localhost:8088 ...
echo  Keep this window open while you use the tool.
echo  Close it (or press Ctrl+C) to stop the server.
echo ========================================
echo.

REM Free port 8088 if a previous ARK instance is still holding it (we're elevated, so this can stop it).
REM If it can't be freed, the server falls back to another port on its own.
powershell -NoProfile -Command "(Get-NetTCPConnection -LocalPort 8088 -State Listen -ErrorAction SilentlyContinue).OwningProcess | ForEach-Object { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }"

REM Let the server open the browser itself: it knows which port it actually got,
REM which may not be 8088 if something else already had it.
set ARK_OPEN_BROWSER=1

REM Start the server (blocks until you close the window)
node server.js

pause
