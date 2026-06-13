@echo off
setlocal
cd /d "%~dp0"
echo This check uses Npcap packet capture and active L2 probes. Right-click and choose "Run as administrator".
echo If Npcap is missing, run Install-Npcap.bat first.
echo.
NetFixInspector.exe loop --seconds 15 --probes 5 --output NetFixInspector-loop-report.json
echo.
echo Report saved to: %cd%\NetFixInspector-loop-report.json
echo.
pause
