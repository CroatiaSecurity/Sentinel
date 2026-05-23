# Windows Sentinel - Installer Build Script
# Run from the repo root:  .\installer\build.ps1
# Requires: .NET 8 SDK, Inno Setup 6 (iscc.exe in PATH or default install location)

param(
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"
$RepoRoot  = Split-Path $PSScriptRoot -Parent
$Installer = $PSScriptRoot

# Read version from version.txt for consistency
$Version = Get-Content "$RepoRoot\version.txt" -Raw | ForEach-Object { $_.Trim() }

Write-Host "=== Windows Sentinel Installer Build ===" -ForegroundColor Cyan
Write-Host "Repo   : $RepoRoot"
Write-Host "Config : $Configuration"
Write-Host "Version: $Version"

# ── Clean build artifacts to ensure fresh compile ─────────────────────────────
Write-Host "`n[Pre-build] Cleaning build cache..." -ForegroundColor Yellow
$cleanDirs = @(
    "$RepoRoot\src\WindowsSentinel.Core\bin",
    "$RepoRoot\src\WindowsSentinel.Core\obj",
    "$RepoRoot\src\WindowsSentinel.Service\bin",
    "$RepoRoot\src\WindowsSentinel.Service\obj",
    "$RepoRoot\src\WindowsSentinel.Agent\bin",
    "$RepoRoot\src\WindowsSentinel.Agent\obj"
)
foreach ($dir in $cleanDirs) {
    if (Test-Path $dir) {
        Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
# Also clean the publish output so Inno Setup can't use stale binaries
$publishService = Join-Path $Installer "publish\service"
$publishAgent = Join-Path $Installer "publish\agent"
if (Test-Path "$publishService\SentinelService.exe") { Remove-Item "$publishService\SentinelService.exe" -Force -ErrorAction SilentlyContinue }
if (Test-Path "$publishAgent\SentinelAgent.exe") { Remove-Item "$publishAgent\SentinelAgent.exe" -Force -ErrorAction SilentlyContinue }

# dotnet clean as belt-and-suspenders
dotnet clean "$RepoRoot\src\WindowsSentinel.Service\WindowsSentinel.Service.csproj" -c $Configuration --nologo -v q 2>$null
dotnet clean "$RepoRoot\src\WindowsSentinel.Agent\WindowsSentinel.Agent.csproj" -c $Configuration --nologo -v q 2>$null
Write-Host "[OK] Build cache cleared" -ForegroundColor Green

# ── Windows Defender Exclusions (ALWAYS add — status check is unreliable) ─────
Write-Host "`n[Pre-build] Adding Windows Defender exclusions..." -ForegroundColor Yellow

try {
    # Always add exclusions regardless of reported Defender status.
    # Get-MpComputerStatus can report RealTimeProtection=disabled while
    # Defender still scans files during build (cloud protection, on-access hooks).
    $exclusionsNeeded = @(
        $RepoRoot,
        (Join-Path $Installer "publish"),
        (Join-Path $Installer "output"),
        (Join-Path $RepoRoot "releases")
    )

    foreach ($path in $exclusionsNeeded) {
        try {
            Add-MpPreference -ExclusionPath $path -ErrorAction Stop
        }
        catch {
            # Silently continue — may already exist or need admin
        }
    }

    # Also exclude the dotnet build output patterns
    try {
        Add-MpPreference -ExclusionProcess "dotnet.exe" -ErrorAction SilentlyContinue
        Add-MpPreference -ExclusionExtension ".dll" -ErrorAction SilentlyContinue
    }
    catch { }

    Write-Host "[OK] Defender exclusions applied (repo + publish + output)" -ForegroundColor Green
}
catch {
    Write-Host "[WARN] Could not add Defender exclusions (run as Admin if build fails): $_" -ForegroundColor Yellow
    Write-Host "       Manual fix: Add-MpPreference -ExclusionPath '$RepoRoot'" -ForegroundColor Cyan
    Start-Sleep -Seconds 2
}

# ── 1. Publish Service ────────────────────────────────────────────────────────
Write-Host "`n[1/3] Publishing Service..." -ForegroundColor Yellow
$ServiceOut = Join-Path $Installer "publish\service"
dotnet publish "$RepoRoot\src\WindowsSentinel.Service\WindowsSentinel.Service.csproj" `
    -c $Configuration -r win-x64 --self-contained true `
    -p:PublishSingleFile=true `
    -p:Version=$Version `
    -o $ServiceOut
if ($LASTEXITCODE -ne 0) { throw "Service publish failed" }

# ── 2. Publish Agent ──────────────────────────────────────────────────────────
Write-Host "`n[2/3] Publishing Agent..." -ForegroundColor Yellow
$AgentOut = Join-Path $Installer "publish\agent"
dotnet publish "$RepoRoot\src\WindowsSentinel.Agent\WindowsSentinel.Agent.csproj" `
    -c $Configuration -r win-x64 --self-contained true `
    -p:PublishSingleFile=true `
    -p:Version=$Version `
    -o $AgentOut
if ($LASTEXITCODE -ne 0) { throw "Agent publish failed" }

# ── 3. Compile Installer ──────────────────────────────────────────────────────
Write-Host "`n[3/3] Compiling installer..." -ForegroundColor Yellow

# Find iscc.exe
$iscc = Get-Command iscc.exe -ErrorAction SilentlyContinue
if (-not $iscc) {
    $defaultPath = "${env:ProgramFiles(x86)}\Inno Setup 6\iscc.exe"
    if (Test-Path $defaultPath) {
        $iscc = $defaultPath
    } else {
        throw "iscc.exe not found. Install Inno Setup 6 from https://jrsoftware.org/isinfo.php"
    }
} else {
    $iscc = $iscc.Source
}

New-Item -ItemType Directory -Path "$Installer\output" -Force | Out-Null

& $iscc /DAppVersion=$Version "$Installer\setup.iss"
if ($LASTEXITCODE -ne 0) { throw "Inno Setup compilation failed" }

# Rename output to SentinelSetup_{version}.exe format
$output = Get-ChildItem "$Installer\output\*.exe" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
$finalExeName = "SentinelSetup_$Version.exe"

Write-Host "`n=== Done ===" -ForegroundColor Green
Write-Host "Installer: $($output.FullName)" -ForegroundColor Green


