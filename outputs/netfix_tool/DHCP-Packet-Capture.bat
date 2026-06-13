@echo off
setlocal
cd /d "%~dp0"
echo This check uses Npcap packet capture. Right-click and choose "Run as administrator" for best results.
echo If Npcap is missing, run Install-Npcap.bat first.
echo.
NetFixInspector.exe dhcp --active --seconds 20 --timeout 5 --output NetFixInspector-dhcp-packet-report.json
echo.
echo Report saved to: %cd%\NetFixInspector-dhcp-packet-report.json
echo.
pause
