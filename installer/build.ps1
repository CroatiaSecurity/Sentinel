# Sentinel Installer Build Script
# Usage: .\build.ps1

$ErrorActionPreference = "Stop"

Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "   Sentinel - Building Installer      " -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan

# 0. Read version from single source of truth
$VersionFile = Join-Path $PSScriptRoot "..\version.txt"
$Version = (Get-Content $VersionFile -Raw).Trim()
Write-Host "Version: $Version" -ForegroundColor Green

# 0.1 Stamp all .csproj files with the version
$CsprojFiles = Get-ChildItem (Join-Path $PSScriptRoot "..") -Recurse -Filter "*.csproj"
foreach ($csproj in $CsprojFiles) {
    $content = Get-Content $csproj.FullName -Raw
    $content = $content -replace '<Version>[^<]+</Version>', "<Version>$Version</Version>"
    Set-Content $csproj.FullName -Value $content -NoNewline
}
Write-Host "Stamped $($CsprojFiles.Count) .csproj files with version $Version" -ForegroundColor Yellow

# 0.2 Stamp Inno Setup script
$SetupScript = Join-Path $PSScriptRoot "setup.iss"
$issContent = [System.IO.File]::ReadAllText($SetupScript)
$issContent = $issContent -replace 'AppVersion=.*', "AppVersion=$Version"
$issContent = $issContent -replace 'OutputBaseFilename=SentinelSetup-.*', "OutputBaseFilename=SentinelSetup-$Version"
[System.IO.File]::WriteAllText($SetupScript, $issContent)

# 1. Clean previous build artifacts and publish folder
$PublishDir = Join-Path $PSScriptRoot "..\publish"
$SrcDir = Join-Path $PSScriptRoot "..\src"
Write-Host "Cleaning bin/obj and publish outputs..." -ForegroundColor Yellow
Get-ChildItem -Path $SrcDir -Include bin,obj -Directory -Recurse | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
if (Test-Path $PublishDir) {
    Remove-Item -Path $PublishDir -Recurse -Force -ErrorAction SilentlyContinue
}

# 2. Build and Publish Service (win-x64 self-contained single-file)
Write-Host "Publishing Sentinel Service (win-x64 self-contained)..." -ForegroundColor Yellow
$ServiceProj = Join-Path $PSScriptRoot "..\src\Sentinel.Service\Sentinel.Service.csproj"
& "C:\Program Files\dotnet\dotnet.exe" publish $ServiceProj -c Release -r win-x64 --self-contained -p:PublishSingleFile=true -p:PublishReadyToRun=false -o (Join-Path $PublishDir "service")

# 3. Build and Publish Agent (win-x64 self-contained single-file)
Write-Host "Publishing Sentinel Agent (win-x64 self-contained)..." -ForegroundColor Yellow
$AgentProj = Join-Path $PSScriptRoot "..\src\Sentinel.Agent\Sentinel.Agent.csproj"
& "C:\Program Files\dotnet\dotnet.exe" publish $AgentProj -c Release -r win-x64 --self-contained -p:PublishSingleFile=true -o (Join-Path $PublishDir "agent")

# 3a. Copy Sentinel.ico and version.txt to publish outputs
Write-Host "Deploying Sentinel.ico and version.txt to publish directories..." -ForegroundColor Yellow
$IconSource = Join-Path $PSScriptRoot "assets\Sentinel.ico"
Copy-Item $IconSource -Destination (Join-Path $PublishDir "agent\Sentinel.ico") -Force
Copy-Item $IconSource -Destination (Join-Path $PublishDir "service\Sentinel.ico") -Force
Copy-Item $VersionFile -Destination (Join-Path $PublishDir "agent\version.txt") -Force
Copy-Item $VersionFile -Destination (Join-Path $PublishDir "service\version.txt") -Force

# 3b. Offline PE/URL ML models (trained via tools/Sentinel.MlTrainer)
$MlModelsSrc = Join-Path $PSScriptRoot "..\src\Sentinel.Core\MlModels"
foreach ($target in @("service", "agent")) {
    $dest = Join-Path $PublishDir "$target\MlModels"
    if (Test-Path $MlModelsSrc) {
        New-Item -ItemType Directory -Path $dest -Force | Out-Null
        Get-ChildItem $MlModelsSrc -Filter "*.zip" -ErrorAction SilentlyContinue | ForEach-Object {
            Copy-Item $_.FullName -Destination $dest -Force
            Write-Host "Copied ML model $($_.Name) -> $target\MlModels" -ForegroundColor Yellow
        }
    }
}

# 4. Locate Inno Setup Compiler (ISCC.exe)
Write-Host "Locating Inno Setup compiler..." -ForegroundColor Yellow
$DefaultIsccPaths = @(
    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
    "C:\Program Files\Inno Setup 6\ISCC.exe",
    "C:\Program Files (x86)\Inno Setup 7\ISCC.exe",
    "C:\Program Files\Inno Setup 7\ISCC.exe"
)

$IsccPath = $null
foreach ($Path in $DefaultIsccPaths) {
    if (Test-Path $Path) {
        $IsccPath = $Path
        break
    }
}

if (-not $IsccPath) {
    # Try searching in PATH
    $IsccPath = Get-Command ISCC.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
}

if (-not $IsccPath) {
    Write-Host "ERROR: Inno Setup compiler (ISCC.exe) was not found in default locations or system PATH." -ForegroundColor Red
    Write-Host "Please install Inno Setup 6 (https://jrsoftware.org/isdl.php) and try again." -ForegroundColor Red
    Exit 1
}

Write-Host "Found Inno Setup at: $IsccPath" -ForegroundColor Green

# 5. Compile the Installer
Write-Host "Compiling installer with Inno Setup..." -ForegroundColor Yellow
$SetupScript = Join-Path $PSScriptRoot "setup.iss"
& $IsccPath $SetupScript

Write-Host "==============================================" -ForegroundColor Green
Write-Host "Build completed successfully!" -ForegroundColor Green
Write-Host "Installer output: installer\SentinelSetup-$Version.exe" -ForegroundColor Green
Write-Host "==============================================" -ForegroundColor Green

# 6. Copy installer to releases folder for push.ps1 pickup
$ReleasesDir = Join-Path $PSScriptRoot "..\releases\$Version"
if (-not (Test-Path $ReleasesDir)) { New-Item -ItemType Directory -Path $ReleasesDir -Force | Out-Null }
$InstallerPath = Join-Path $PSScriptRoot "SentinelSetup-$Version.exe"
if (Test-Path $InstallerPath) {
    Copy-Item $InstallerPath -Destination $ReleasesDir -Force
    Write-Host "Copied installer to releases\$Version\ for GitHub Release upload" -ForegroundColor Green
} else {
    Write-Host "WARNING: Installer not found at expected path, skipping releases copy" -ForegroundColor Yellow
}

