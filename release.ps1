$env:PATH = "C:\Program Files\Git\cmd;C:\Program Files\Git\bin;" + $env:PATH
$gh = "C:\Program Files\GitHub CLI\gh.exe"
$installer = "installer\SentinelSetup-2.5.4.exe"

$notes = @"
## v2.5.4 — compiled config; HMAC in the binary

Disk JSON is not loaded. The threat-proxy HMAC is compiled in.
config.enc cannot disable detection or redirect reporting.
Uninstall is the off switch.

Requires .NET Framework 4.8. Run as Administrator.
"@

if (Test-Path $gh) {
    & $gh release create v2.5.4 $installer --title "Sentinel 2.5.4" --notes $notes -R CroatiaSecurity/Sentinel
} else {
    Write-Host "gh.exe not found - installer is at $installer and releases\2.5.4\"
}
