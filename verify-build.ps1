# Windows Sentinel - Build Verification Script
# Run from the repo root:  .\verify-build.ps1
# Verifies that the project compiles without errors

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path $PSScriptRoot -Parent

Write-Host "=== Windows Sentinel Build Verification ===" -ForegroundColor Cyan
Write-Host "Repo: $RepoRoot" -ForegroundColor Cyan

# Verify .NET SDK is available
try {
    $dotnetVersion = dotnet --version
    Write-Host "[OK] .NET SDK version: $dotnetVersion" -ForegroundColor Green
}
catch {
    Write-Host "[FAIL] .NET SDK not found" -ForegroundColor Red
    exit 1
}

# Build all projects
Write-Host "`n[Building] Compiling all projects..." -ForegroundColor Yellow

$projects = @(
    "$RepoRoot\src\WindowsSentinel.Core\WindowsSentinel.Core.csproj",
    "$RepoRoot\src\WindowsSentinel.Service\WindowsSentinel.Service.csproj",
    "$RepoRoot\src\WindowsSentinel.Agent\WindowsSentinel.Agent.csproj"
)

foreach ($project in $projects) {
    Write-Host "  Building: $(Split-Path $project -Leaf)" -ForegroundColor Yellow
    dotnet build $project --nologo --no-restore
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[FAIL] Build failed for $(Split-Path $project -Leaf)" -ForegroundColor Red
        exit 1
    }
}

Write-Host "`n[OK] All projects built successfully" -ForegroundColor Green
Write-Host "Build verification complete." -ForegroundColor Cyan
