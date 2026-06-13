@echo off
setlocal
set "SCRIPT_DIR=%~dp0"
py -3 "%SCRIPT_DIR%netfix.py" %*
if errorlevel 9009 (
  python "%SCRIPT_DIR%netfix.py" %*
)
