@echo off
setlocal
cd /d "%~dp0"
NetFixInspector.exe dns --timeout 2 --provider cloudflare --output NetFixInspector-dns-report.json
echo.
echo Report saved to: %cd%\NetFixInspector-dns-report.json
echo.
pause
