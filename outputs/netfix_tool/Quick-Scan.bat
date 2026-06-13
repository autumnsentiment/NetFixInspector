@echo off
setlocal
cd /d "%~dp0"
NetFixInspector.exe scan --skip-packet --no-external-inbound --timeout 2 --output NetFixInspector-quick-report.json
echo.
echo Report saved to: %cd%\NetFixInspector-quick-report.json
echo.
pause
