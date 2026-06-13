param(
    [string]$BackendExe = "..\..\outputs\NetFixInspector.exe",
    [string]$OutDir = "..\..\outputs\NetFixInspector-Electron",
    [string]$NpcapInstallerDir = ".\third_party\npcap",
    [switch]$RequireBundledNpcap
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

$backend = Resolve-Path $BackendExe
New-Item -ItemType Directory -Force -Path .\backend | Out-Null
Copy-Item -Force $backend.Path .\backend\NetFixInspector.exe
if (Test-Path .\support) {
    Remove-Item -LiteralPath .\support -Recurse -Force
}
New-Item -ItemType Directory -Force -Path .\support | Out-Null
Copy-Item -Force ..\..\outputs\Install-Npcap.ps1 .\support\Install-Npcap.ps1
Copy-Item -Force ..\..\outputs\Install-Npcap.bat .\support\Install-Npcap.bat
Copy-Item -Force ..\..\outputs\NOTICE_NPCAP.txt .\support\NOTICE_NPCAP.txt
New-Item -ItemType Directory -Force -Path .\support\third_party\npcap | Out-Null
Copy-Item -Force .\third_party\npcap\README.txt .\support\third_party\npcap\README.txt

$npcapSource = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($NpcapInstallerDir)
$installers = @()
if (Test-Path $npcapSource) {
    $installers = @(Get-ChildItem -LiteralPath $npcapSource -Filter "npcap*.exe" -File -ErrorAction SilentlyContinue)
}

if ($installers.Count -gt 0) {
    $npcapDest = Join-Path $ScriptDir "support\third_party\npcap"
    foreach ($installer in $installers) {
        Copy-Item -Force $installer.FullName (Join-Path $npcapDest $installer.Name)
    }
    Write-Host "Bundled Npcap installer(s): $($installers.Name -join ', ')"
} else {
    $message = "No licensed Npcap installer found in $npcapSource. Put your Npcap OEM installer there as npcap*.exe to bundle it."
    if ($RequireBundledNpcap) {
        throw $message
    }
    Write-Host "$message The packaged app will open the official Npcap download page."
}

$env:CSC_IDENTITY_AUTO_DISCOVERY = "false"

if (-not (Test-Path .\node_modules)) {
    npm install
}

npm run dist

$built = Join-Path $ScriptDir "dist\win-unpacked"
if (-not (Test-Path $built)) {
    throw "Electron output not found: $built"
}

$resolvedOut = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutDir)
if (Test-Path $resolvedOut) {
    try {
        Remove-Item -LiteralPath $resolvedOut -Recurse -Force -ErrorAction Stop
    } catch {
        Write-Warning "Could not fully remove existing Electron output: $($_.Exception.Message)"
        Write-Warning "Will overwrite in place and rebuild mutable resource folders."
        foreach ($relative in @("resources\support", "resources\backend")) {
            $target = Join-Path $resolvedOut $relative
            if (Test-Path $target) {
                Remove-Item -LiteralPath $target -Recurse -Force -ErrorAction Stop
            }
        }
    }
}
New-Item -ItemType Directory -Force -Path $resolvedOut | Out-Null
try {
    Copy-Item -Path (Join-Path $built '*') -Destination $resolvedOut -Recurse -Force -ErrorAction Stop
} catch {
    Write-Warning "Full output copy was blocked: $($_.Exception.Message)"
    Write-Warning "Copying changed app resources only. Close NetFixInspector and rerun for a fully refreshed unpacked folder."
    $resourceOut = Join-Path $resolvedOut "resources"
    New-Item -ItemType Directory -Force -Path $resourceOut | Out-Null
    Copy-Item -Force (Join-Path $built "resources\app.asar") (Join-Path $resourceOut "app.asar")
    foreach ($relative in @("resources\support", "resources\backend")) {
        $source = Join-Path $built $relative
        $target = Join-Path $resolvedOut $relative
        if (Test-Path $target) {
            Remove-Item -LiteralPath $target -Recurse -Force -ErrorAction Stop
        }
        Copy-Item -Path $source -Destination $target -Recurse -Force -ErrorAction Stop
    }
    Copy-Item -Force (Join-Path $built "NetFixInspector.exe") (Join-Path $resolvedOut "NetFixInspector.exe")
}
Copy-Item -Force .\README_zh.md (Join-Path $resolvedOut "README_zh.md")
Copy-Item -Force .\LICENSE (Join-Path $resolvedOut "LICENSE")

$portableCandidates = @(Get-ChildItem -LiteralPath (Join-Path $ScriptDir "dist") -Filter "*.exe" -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like "*Portable*.exe" -or $_.Name -like "*NetFixInspector*.exe" } |
    Sort-Object LastWriteTime -Descending)
if ($portableCandidates.Count -gt 0) {
    $portableOut = Join-Path (Split-Path -Parent $resolvedOut) "NetFixInspector-Electron-Portable.exe"
    Copy-Item -Force $portableCandidates[0].FullName $portableOut
    Write-Host "Electron portable exe: $portableOut"
}
Write-Host "Electron output: $resolvedOut"
