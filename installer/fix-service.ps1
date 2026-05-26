# Quick fix: Re-register and start Windows Sentinel service
# Run as Administrator

$ServiceName = "Windows Sentinel"
$AppDir = "${env:ProgramFiles}\WindowsSentinel"
$ServiceExe = Join-Path $AppDir "SentinelService.exe"

if (-not (Test-Path $ServiceExe)) {
    Write-Host "ERROR: SentinelService.exe not found at $ServiceExe" -ForegroundColor Red
    Write-Host "Please run the installer first." -ForegroundColor Yellow
    exit 1
}

# Check if service already exists
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    Write-Host "Service already exists (Status: $($svc.Status))" -ForegroundColor Yellow
    if ($svc.Status -ne 'Running') {
        Write-Host "Starting service..." -ForegroundColor Cyan
        sc.exe start $ServiceName
    }
} else {
    Write-Host "Service not found — re-registering..." -ForegroundColor Yellow
    sc.exe create $ServiceName binPath= "$ServiceExe" start= auto DisplayName= "$ServiceName"
    sc.exe description $ServiceName "Windows Sentinel - Endpoint Detection and Response"
    sc.exe failure $ServiceName reset= 86400 actions= restart/1000/restart/5000/restart/30000
    Write-Host "Starting service..." -ForegroundColor Cyan
    sc.exe start $ServiceName
}

# Verify
Start-Sleep -Seconds 2
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq 'Running') {
    Write-Host "OK: Windows Sentinel is running (PID: $((Get-Process SentinelService -ErrorAction SilentlyContinue).Id))" -ForegroundColor Green
} else {
    Write-Host "WARNING: Service may not have started. Check Event Viewer." -ForegroundColor Red
}
