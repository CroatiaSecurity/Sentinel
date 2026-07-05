# Restore GameClient.exe from Sentinel quarantine
# Run this as Administrator (quarantine is DPAPI machine-scoped)

Add-Type -AssemblyName System.Security

$quarantineDir = "C:\ProgramData\WindowsSentinel\Quarantine"
$targetDir = "D:\Steam\steamapps\common\Star Trek Online\Star Trek Online\Live\x64"

if (-not (Test-Path $targetDir)) {
    Write-Host "Target directory not found: $targetDir" -ForegroundColor Red
    Write-Host "Edit this script with the correct Star Trek Online install path."
    exit 1
}

# Take the most recent quarantined GameClient.exe
$quarantined = Get-ChildItem $quarantineDir -Filter "*GameClient*" | Sort-Object LastWriteTime -Descending | Select-Object -First 1

if (-not $quarantined) {
    Write-Host "No quarantined GameClient.exe found." -ForegroundColor Yellow
    exit 0
}

Write-Host "Restoring from: $($quarantined.FullName)"

# Read and decrypt (DPAPI LocalMachine scope)
$encrypted = [System.IO.File]::ReadAllBytes($quarantined.FullName)
$decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect($encrypted, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)

# Write restored file
$targetPath = Join-Path $targetDir "GameClient.exe"
[System.IO.File]::WriteAllBytes($targetPath, $decrypted)

Write-Host "Restored GameClient.exe to: $targetPath" -ForegroundColor Green
Write-Host "Size: $($decrypted.Length) bytes"

# Clean up both quarantine entries
Get-ChildItem $quarantineDir -Filter "*GameClient*" | Remove-Item -Force
Write-Host "Removed quarantine entries." -ForegroundColor Green
