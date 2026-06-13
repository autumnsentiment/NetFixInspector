@echo off
setlocal
cd /d "%~dp0"
NetFixInspector.exe repair --flush-dns --reset-stack --output NetFixInspector-repair-dryrun.json
echo.
echo Report saved to: %cd%\NetFixInspector-repair-dryrun.json
echo.
pause
