$env:PATH = "C:\Program Files\Git\cmd;C:\Program Files\Git\bin;" + $env:PATH
$gh = "C:\Program Files\GitHub CLI\gh.exe"
$installer = "installer\SentinelSetup-2.4.9.exe"

$notes = @"
## v2.4.9 — ETW category + UDP PID attribution

Patch on 2.4.8 protocol coverage.

- ``CategorizeDetection`` matches ETW as a token, not the letters inside
  ``network``, and not only at the start of the rule name. Mid-string names
  like ``process etw bypass`` stay SecurityEvasion; ``Network UDP:`` stays
  NetworkAnomaly.
- Kernel-Network UDP payload PID is used only when ``evt.ProcessId`` is
  missing. A live event PID is never overwritten.

Requires .NET Framework 4.8. Run as Administrator.
"@

if (Test-Path $gh) {
    & $gh release create v2.4.9 $installer --title "Sentinel 2.4.9" --notes $notes -R CroatiaSecurity/Sentinel
} else {
    Write-Host "gh.exe not found - installer is at $installer and releases\2.4.9\"
}
