$env:PATH = "C:\Program Files\Git\cmd;C:\Program Files\Git\bin;" + $env:PATH
$gh = "C:\Program Files\GitHub CLI\gh.exe"
$installer = "installer\SentinelSetup-2.5.1.exe"

$notes = @"
## v2.5.1 — DNS event process names

Webhook, mesh, and ThreatFox DNS detections resolve the live process
name when PID > 4 instead of logging ``unknown`` / ``SYSTEM``.

Requires .NET Framework 4.8. Run as Administrator.
"@

if (Test-Path $gh) {
    & $gh release create v2.5.1 $installer --title "Sentinel 2.5.1" --notes $notes -R CroatiaSecurity/Sentinel
} else {
    Write-Host "gh.exe not found - installer is at $installer and releases\2.5.1\"
}
