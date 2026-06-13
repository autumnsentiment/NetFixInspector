@echo off
setlocal
cd /d "%~dp0"
NetFixInspector.exe nat --timeout 3 --output NetFixInspector-nat-report.json
echo.
echo Report saved to: %cd%\NetFixInspector-nat-report.json
echo.
pause
