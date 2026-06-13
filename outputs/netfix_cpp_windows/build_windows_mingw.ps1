param(
    [string]$ToolchainBin = "",
    [string]$OutDir = "..\..\outputs"
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

if (-not $ToolchainBin) {
    $candidate = Get-ChildItem ..\tools\llvm-mingw -Recurse -Filter x86_64-w64-mingw32-clang++.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($candidate) {
        $ToolchainBin = Split-Path -Parent $candidate.FullName
    }
}

if (-not $ToolchainBin) {
    throw "ToolchainBin was not provided and x86_64-w64-mingw32-clang++.exe was not found."
}

$Cxx = Join-Path $ToolchainBin "x86_64-w64-mingw32-clang++.exe"
if (-not (Test-Path $Cxx)) {
    throw "Compiler not found: $Cxx"
}

New-Item -ItemType Directory -Force -Path .\dist | Out-Null

$sources = @(
    ".\src\main.cpp",
    ".\src\cli.cpp",
    ".\src\report.cpp",
    ".\src\net_win.cpp",
    ".\src\probe.cpp",
    ".\src\pcap_checks.cpp"
)

& $Cxx `
    -std=c++17 `
    -O2 `
    -DUNICODE `
    -D_UNICODE `
    -DWIN32_LEAN_AND_MEAN `
    -DNOMINMAX `
    -D_WIN32_WINNT=0x0A00 `
    -DNTDDI_VERSION=0x0A000000 `
    -I .\include `
    @sources `
    -static `
    -municode `
    -lws2_32 `
    -liphlpapi `
    -lwinhttp `
    -o .\dist\NetFixInspector.exe

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Copy-Item -Force .\dist\NetFixInspector.exe (Join-Path $OutDir "NetFixInspector.exe")
Write-Host "Built: $((Resolve-Path (Join-Path $OutDir 'NetFixInspector.exe')).Path)"
