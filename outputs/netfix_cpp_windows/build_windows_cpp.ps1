param(
    [string]$BuildDir = ".\build",
    [string]$OutDir = "..\..\outputs",
    [string]$NpcapRoot = "",
    [switch]$WithNpcap,
    [string]$Generator = "Visual Studio 17 2022"
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

if (-not (Get-Command cmake -ErrorAction SilentlyContinue)) {
    throw "cmake was not found. Install CMake and run this from a VS2022 Developer PowerShell."
}

$cmakeArgs = @(
    "-S", ".",
    "-B", $BuildDir,
    "-G", $Generator,
    "-A", "x64"
)

if ($WithNpcap) {
    if ($NpcapRoot) {
        Write-Host "Npcap SDK path was provided but is no longer required: $NpcapRoot"
    }
    Write-Host "Npcap is loaded dynamically at runtime. Building the same portable exe."
    $cmakeArgs += @("-DNETFIX_WITH_NPCAP=ON")
} else {
    $cmakeArgs += @("-DNETFIX_WITH_NPCAP=OFF")
}

cmake @cmakeArgs
cmake --build $BuildDir --config Release

$exe = Join-Path $BuildDir "dist\Release\NetFixInspector.exe"
if (-not (Test-Path $exe)) {
    $exe = Join-Path $BuildDir "dist\NetFixInspector.exe"
}
if (-not (Test-Path $exe)) {
    throw "Build completed but NetFixInspector.exe was not found."
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Copy-Item -Force $exe (Join-Path $OutDir "NetFixInspector.exe")
Write-Host "Built: $(Resolve-Path (Join-Path $OutDir 'NetFixInspector.exe'))"
