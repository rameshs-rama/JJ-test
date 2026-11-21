@echo off
rem Double-click this file to run the Wi-Fi checkup on Windows.
rem It only reads information; it does not change any settings.
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
    py -3 wifi_checkup.py %*
) else (
    python wifi_checkup.py %*
    if errorlevel 9009 (
        echo.
        echo Python is not installed. Install it from https://www.python.org/downloads/
        echo ^(tick "Add python.exe to PATH" during setup^), then double-click this file again.
    )
)
echo.
pause
