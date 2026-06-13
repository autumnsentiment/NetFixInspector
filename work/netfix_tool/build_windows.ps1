param(
    [string]$OutDir = ".\dist",
    [switch]$InstallDeps
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

if ($InstallDeps) {
    py -3 -m pip install -r requirements.txt pyinstaller
}

py -3 -m PyInstaller `
    --onefile `
    --console `
    --name NetFixInspector `
    --distpath $OutDir `
    --workpath ".\build" `
    --specpath ".\build" `
    ".\netfix.py"

Write-Host "Built: $((Resolve-Path $OutDir).Path)\NetFixInspector.exe"
