# Windows Sentinel Installer Build Script
# Usage: .\build.ps1

$ErrorActionPreference = "Stop"

Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "   Windows Sentinel - Building Installer      " -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan

# 1. Clean previous build artifacts and publish folder
$PublishDir = Join-Path $PSScriptRoot "..\publish"
$SrcDir = Join-Path $PSScriptRoot "..\src"
Write-Host "Cleaning bin/obj and publish outputs..." -ForegroundColor Yellow
Get-ChildItem -Path $SrcDir -Include bin,obj -Directory -Recurse | Remove-Item -Recurse -Force
if (Test-Path $PublishDir) {
    Remove-Item -Path $PublishDir -Recurse -Force
}

# 2. Build and Publish Service (win-x64 self-contained single-file)
Write-Host "Publishing Sentinel Service (win-x64 self-contained)..." -ForegroundColor Yellow
$ServiceProj = Join-Path $PSScriptRoot "..\src\WindowsSentinel.Service\WindowsSentinel.Service.csproj"
& "C:\Program Files\dotnet\dotnet.exe" publish $ServiceProj -c Release -r win-x64 --self-contained -p:PublishSingleFile=true -p:PublishReadyToRun=false -o (Join-Path $PublishDir "service")

# 3. Build and Publish Agent (win-x64 self-contained single-file)
Write-Host "Publishing Sentinel Agent (win-x64 self-contained)..." -ForegroundColor Yellow
$AgentProj = Join-Path $PSScriptRoot "..\src\WindowsSentinel.Agent\WindowsSentinel.Agent.csproj"
& "C:\Program Files\dotnet\dotnet.exe" publish $AgentProj -c Release -r win-x64 --self-contained -p:PublishSingleFile=true -o (Join-Path $PublishDir "agent")

# 3a. Copy Sentinel.ico to publish outputs for runtime icon access
Write-Host "Deploying Sentinel.ico to publish directories..." -ForegroundColor Yellow
$IconSource = Join-Path $PSScriptRoot "assets\Sentinel.ico"
Copy-Item $IconSource -Destination (Join-Path $PublishDir "agent\Sentinel.ico") -Force
Copy-Item $IconSource -Destination (Join-Path $PublishDir "service\Sentinel.ico") -Force

# 4. Locate Inno Setup Compiler (ISCC.exe)
Write-Host "Locating Inno Setup compiler..." -ForegroundColor Yellow
$DefaultIsccPaths = @(
    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
    "C:\Program Files\Inno Setup 6\ISCC.exe"
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
Write-Host "Installer output: installer\WindowsSentinelSetup-5.9.0.exe" -ForegroundColor Green
Write-Host "==============================================" -ForegroundColor Green

