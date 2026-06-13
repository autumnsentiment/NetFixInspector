@echo off
setlocal
cd /d "%~dp0"
NetFixInspector.exe dhcp --timeout 3 --output NetFixInspector-dhcp-report.json
echo.
echo Report saved to: %cd%\NetFixInspector-dhcp-report.json
echo.
pause
