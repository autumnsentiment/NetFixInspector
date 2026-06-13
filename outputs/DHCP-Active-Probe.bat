@echo off
setlocal
cd /d "%~dp0"
echo For best results, right-click this file and choose "Run as administrator".
echo.
NetFixInspector.exe dhcp --active --timeout 5 --output NetFixInspector-dhcp-active-report.json
echo.
echo Report saved to: %cd%\NetFixInspector-dhcp-active-report.json
echo.
pause
