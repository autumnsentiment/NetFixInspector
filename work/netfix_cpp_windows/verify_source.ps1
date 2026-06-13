$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

$required = @(
    "CMakeLists.txt",
    "build_windows_cpp.ps1",
    "README_zh.md",
    "include\cli.h",
    "include\report.h",
    "include\net_win.h",
    "include\probe.h",
    "include\pcap_checks.h",
    "include\util.h",
    "src\main.cpp",
    "src\cli.cpp",
    "src\report.cpp",
    "src\net_win.cpp",
    "src\probe.cpp",
    "src\pcap_checks.cpp"
)

foreach ($path in $required) {
    if (-not (Test-Path $path)) {
        throw "Missing required file: $path"
    }
}

$cmake = Get-Content .\CMakeLists.txt -Raw
foreach ($needle in @("project(NetFixInspectorCpp", "NETFIX_WITH_NPCAP", "Ws2_32", "Iphlpapi", "Winhttp")) {
    if ($cmake -notlike "*$needle*") {
        throw "CMakeLists.txt missing expected token: $needle"
    }
}

$main = Get-Content .\src\main.cpp -Raw
foreach ($command in @("scan", "connectivity", "dns", "nat", "ipv6", "dhcp", "loop", "repair", "npcap")) {
    if ($main -notlike "*$command*") {
        throw "main.cpp does not reference command: $command"
    }
}

Write-Host "C++ source layout verification passed."
