$env:PATH = "C:\Program Files\Git\cmd;C:\Program Files\Git\bin;" + $env:PATH
$gh = "C:\Program Files\GitHub CLI\gh.exe"
$installer = "installer\SentinelSetup-2.2.0.exe"

$notes = @"
Honest remediations from a full source red-team. Controls that were advertised in 2.1.8/2.1.9 but not actually running are now wired — or the docs tell the truth.

## Security (v2.2.0)

- Dashboard auth is real: Referer is not proof of origin; token is not in GET /; tray opens with ?token=; WebSocket requires the token
- V217 monitors actually registered (AMSI, honeypot DLLs in honeypot\, decoy pipes, kernel module audit, token privileges, EDR-killer name observe)
- Game-path reputation skip no longer matches user-writable substrings
- ChainTracer no longer treats C:\Windows\Temp as OS-critical
- Agent watchdog: install-path liveness, publisher pin, CreateProcessAsUser image name
- DriverLoadMonitor scans real user profiles; Event 7045 PID; pre-existing RTCore64 logged
- Hardened-mode LGPO no longer disables passwords/audit/FIPS
- Worker RATE_LIMITER called after HMAC; MalwareBazaar report is an honest lookup
- Encrypted config HMAC envelope; leftover appsettings cannot disable ObserveUntilChain

## Installation
Requires .NET Framework 4.8. Run as Administrator.
Open the dashboard from the Sentinel tray icon (browser bookmark of localhost:19845 will not have the token).
"@

if (Test-Path $gh) {
    & $gh release create v2.2.0 $installer --title "Sentinel 2.2.0" --notes $notes
} else {
    Write-Host "gh.exe not found — installer is at $installer and releases\2.2.0\"
}
