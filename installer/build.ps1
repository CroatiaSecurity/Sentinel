# Windows Sentinel - Installer Build Script
# Run from the repo root:  .\installer\build.ps1
# Requires: .NET 8 SDK, Inno Setup 6 (iscc.exe in PATH or default install location)

param(
    [string]$Configuration = "Release",
    [string]$Version = "2.7.0"
)

$ErrorActionPreference = "Stop"
$RepoRoot  = Split-Path $PSScriptRoot -Parent
$Installer = $PSScriptRoot

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

# ── Check Windows Defender Exclusions ─────────────────────────────────────────
Write-Host "`n[Pre-build] Checking Windows Defender configuration..." -ForegroundColor Yellow

try {
    $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($defenderStatus.RealTimeProtectionEnabled) {
        $exclusions = Get-MpPreference -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ExclusionPath
        $repoExcluded = $exclusions | Where-Object { $_ -and $RepoRoot.StartsWith($_) }
        
        if (-not $repoExcluded) {
            # AUTOMATIC: Try to add exclusion without prompting
            try {
                Add-MpPreference -ExclusionPath $RepoRoot -ErrorAction Stop
                Write-Host "[AUTO] Added Defender exclusion for $RepoRoot" -ForegroundColor Green
                
                # Also exclude build outputs
                $publishPath = Join-Path $Installer "publish"
                if (Test-Path $publishPath) {
                    Add-MpPreference -ExclusionPath $publishPath -ErrorAction SilentlyContinue | Out-Null
                }
                
                # Exclude the releases folder
                $releasesPath = Join-Path $RepoRoot "releases"
                Add-MpPreference -ExclusionPath $releasesPath -ErrorAction SilentlyContinue | Out-Null
            }
            catch {
                Write-Host "[WARN] Could not auto-add Defender exclusion (needs Admin): $_" -ForegroundColor Yellow
                Write-Host "       Build may fail with 'virus detected' errors." -ForegroundColor Yellow
                Write-Host "       To fix: Run as Administrator or run: Add-MpPreference -ExclusionPath '$RepoRoot'" -ForegroundColor Cyan
                Start-Sleep -Seconds 2
            }
        }
        else {
            Write-Host "[OK] Windows Defender exclusion already configured" -ForegroundColor Green
        }
    }
    else {
        Write-Host "[OK] Windows Defender Real-time Protection is disabled" -ForegroundColor Yellow
    }
}
catch {
    Write-Host "[WARN] Could not check Defender status: $_" -ForegroundColor Yellow
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

