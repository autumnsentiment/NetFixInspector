@echo off
cd /d "%~dp0"
NetFixInspector.exe port --host example.com --port 443 --family both --count 3 --timeout 3 --output NetFixInspector-port-report.json
echo.
echo Report saved to: %cd%\NetFixInspector-port-report.json
pause
