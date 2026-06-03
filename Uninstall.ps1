# === Windows Sentinel 5.6.0 Manual Uninstall (run as Admin) ===

# 1. Stop service
sc.exe stop "Windows Sentinel"
Start-Sleep -Seconds 3

# 2. Kill processes
taskkill /F /IM WindowsSentinel.Service.exe 2>$null
taskkill /F /IM WindowsSentinel.Agent.exe 2>$null
Start-Sleep -Seconds 1

# 3. Delete service from SCM
sc.exe delete "Windows Sentinel"

# 4. Remove registry auto-start key
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsSentinelAgent" -ErrorAction SilentlyContinue

# 5. Reset ACLs and delete install directory
$dir = "$env:ProgramFiles\WindowsSentinel"
if (Test-Path $dir) {
    icacls $dir /reset /T /C /Q
    Remove-Item $dir -Recurse -Force
}
$dir32 = "${env:ProgramFiles(x86)}\WindowsSentinel"
if (Test-Path $dir32) {
    icacls $dir32 /reset /T /C /Q
    Remove-Item $dir32 -Recurse -Force
}

# 6. Remove Inno Setup uninstall registry entries
@(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
) | ForEach-Object {
    Get-ChildItem $_ -EA SilentlyContinue |
        Where-Object { $_.GetValue("DisplayName") -like "*Windows Sentinel*" } |
        ForEach-Object { Remove-Item $_.PSPath -Recurse -Force }
}

Write-Host "Uninstall complete. ProgramData logs preserved." -ForegroundColor Green