@echo off
setlocal
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
  echo Python was not found in PATH.
  echo Download Python from:
  echo https://www.python.org/downloads/
  echo.
  echo During install, tick "Add python.exe to PATH".
  pause
  exit /b 1
)

python pcap_dashboard.py
if errorlevel 1 (
  echo.
  echo Dashboard exited with an error.
  pause
)

