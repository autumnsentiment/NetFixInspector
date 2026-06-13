@echo off
setlocal
cd /d "%~dp0"
NetFixInspector.exe npcap --output NetFixInspector-npcap-report.json
echo.
echo Report saved to: %cd%\NetFixInspector-npcap-report.json
echo.
pause
