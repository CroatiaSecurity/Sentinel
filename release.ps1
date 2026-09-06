$env:PATH = "C:\Program Files\Git\cmd;C:\Program Files\Git\bin;" + $env:PATH
$gh = "C:\Program Files\GitHub CLI\gh.exe"
$installer = "installer\SentinelSetup-2.5.0.exe"

$notes = @"
## v2.5.0 — webhook-shaped exfil (no TLS intercept)

Stealers that POST to Discord/Telegram/Slack webhooks or disposable
callback hosts (webhook.site, interact.sh, requestbin, canarytokens).

- ``CovertWebhookMonitor`` — dedicated-sink DNS + HTTPS from script hosts /
  Temp/Downloads. Comms-platform DNS is per-PID so Chrome looking up
  discord.com does not smear onto PowerShell. Official Discord/Slack/
  Telegram skipped.
- Command-line and PowerShell 4104 URL path matching expanded.
- Tier2 / LogOnly observe fuel. Never chain-nuke alone.

Requires .NET Framework 4.8. Run as Administrator.
"@

if (Test-Path $gh) {
    & $gh release create v2.5.0 $installer --title "Sentinel 2.5.0" --notes $notes -R CroatiaSecurity/Sentinel
} else {
    Write-Host "gh.exe not found - installer is at $installer and releases\2.5.0\"
}
