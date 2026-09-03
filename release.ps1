$env:PATH = "C:\Program Files\Git\cmd;C:\Program Files\Git\bin;" + $env:PATH
$gh = "C:\Program Files\GitHub CLI\gh.exe"
$installer = "installer\SentinelSetup-2.4.2.exe"

$notes = @"
## v2.4.2 — restore working upgrade installer

v2.3.9 slim-down dropped ``ResetInstallDirAcls``, so a hardened install
(Users Deny-Write on the install dir) fails Inno overwrite of ``unins000.exe``
with **Access is denied**.

2.4.2 restores the v2.3.7 unlock: takeown/icacls on ``unins000.*``, grant
Administrators full control, remove Users Deny, and taskkill leftover
Service/Agent. ``--prepare-upgrade`` also unlocks natively for later upgrades.

2.4.0 and 2.4.1 remain published.

## Installation
Requires .NET Framework 4.8. Run as Administrator.
Cancel any stuck 2.4.1 Setup wizard first, then run this installer.
"@

if (Test-Path $gh) {
    & $gh release create v2.4.2 $installer --title "Sentinel 2.4.2" --notes $notes -R CroatiaSecurity/Sentinel
} else {
    Write-Host "gh.exe not found - installer is at $installer and releases\2.4.2\"
}
