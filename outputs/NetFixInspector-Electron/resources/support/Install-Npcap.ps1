param(
    [string]$InstallerPath = "",
    [switch]$Silent
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

function Test-NpcapInstalled {
    $paths = @(
        "$env:WINDIR\System32\Npcap\wpcap.dll",
        "$env:WINDIR\System32\Npcap\Packet.dll",
        "$env:WINDIR\System32\wpcap.dll"
    )
    foreach ($path in $paths) {
        if (Test-Path $path) {
            return $true
        }
    }
    return $false
}

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (Test-NpcapInstalled) {
    Write-Host "Npcap already appears to be installed."
    if (Test-Path (Join-Path $ScriptDir "NetFixInspector.exe")) {
        & (Join-Path $ScriptDir "NetFixInspector.exe") npcap
    }
    exit 0
}

if (-not (Test-IsAdmin)) {
    Write-Host "Requesting Administrator privileges for Npcap installation..."
    $args = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"")
    if ($InstallerPath) { $args += @("-InstallerPath", "`"$InstallerPath`"") }
    if ($Silent) { $args += "-Silent" }
    Start-Process -FilePath "powershell.exe" -ArgumentList $args -Verb RunAs -Wait
    exit $LASTEXITCODE
}

if (-not $InstallerPath) {
    $searchRoots = @(
        $ScriptDir,
        (Join-Path $ScriptDir "third_party\npcap"),
        (Join-Path $ScriptDir "npcap"),
        (Join-Path (Split-Path -Parent $ScriptDir) "third_party\npcap")
    )
    $candidate = $null
    foreach ($root in $searchRoots) {
        if (Test-Path $root) {
            $candidate = Get-ChildItem -Path $root -Filter "npcap*.exe" -File -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending |
                Select-Object -First 1
            if ($candidate) { break }
        }
    }
    if ($candidate) {
        $InstallerPath = $candidate.FullName
    }
}

if (-not $InstallerPath -or -not (Test-Path $InstallerPath)) {
    Write-Host "No local Npcap installer was found."
    Write-Host "Opening the official Npcap download page. Download the installer, then run this script again."
    Write-Host "For redistribution, use your licensed Npcap OEM installer and place it beside this script or in third_party\npcap before packaging."
    Start-Process "https://npcap.com/#download"
    exit 2
}

$arguments = @("/winpcap_mode=yes", "/admin_only=no")
if ($Silent) {
    Write-Host "Silent mode requested. This only works with a licensed Npcap OEM installer."
    $arguments = @("/S") + $arguments
}

Write-Host "Starting Npcap installer: $InstallerPath"
Write-Host "Arguments: $($arguments -join ' ')"
$process = Start-Process -FilePath $InstallerPath -ArgumentList $arguments -Wait -PassThru
Write-Host "Npcap installer exit code: $($process.ExitCode)"

if (Test-NpcapInstalled) {
    Write-Host "Npcap installation detected."
    if (Test-Path (Join-Path $ScriptDir "NetFixInspector.exe")) {
        & (Join-Path $ScriptDir "NetFixInspector.exe") npcap
    }
    exit 0
}

Write-Host "Npcap was not detected after installation. Reboot if the installer requested it, then run Npcap-Status.bat."
exit 1
