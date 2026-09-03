@echo off
setlocal
cd /d "%~dp0"

echo === Pcap Data Validation setup check ===
echo.

echo [Python]
where python
if errorlevel 1 (
  echo Python missing. Download: https://www.python.org/downloads/
  goto :done
)
python --version
echo.

echo [Python modules]
python -c "import importlib.util; mods=['tkinter','matplotlib','PIL']; [print((m + ': OK') if importlib.util.find_spec(m) else (m + ': MISSING')) for m in mods]"
echo.

echo [Wireshark CLI tools]
where tshark
if errorlevel 1 echo tshark not found in PATH. Default location is usually C:\Program Files\Wireshark\tshark.exe
where mergecap
if errorlevel 1 echo mergecap not found in PATH. It should be installed with Wireshark.
where capinfos
if errorlevel 1 echo capinfos not found in PATH. It should be installed with Wireshark.
echo.

echo [Optional FFmpeg]
where ffmpeg
if errorlevel 1 echo ffmpeg not found. Optional download: https://ffmpeg.org/download.html

:done
echo.
pause
