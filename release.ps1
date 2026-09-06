$env:PATH = "C:\Program Files\Git\cmd;C:\Program Files\Git\bin;" + $env:PATH
$gh = "C:\Program Files\GitHub CLI\gh.exe"
$installer = "installer\SentinelSetup-2.5.3.exe"

$notes = @"
## v2.5.3 — kill the rest of the 10

Same law as 2.5.2: Discord / Chrome / games / official Tailscale /
TeamViewer / powershell SSH are civilians. Potato, kernel-EoP loaders,
ClickFix, Hell's Gate, unmapped thread, Cobalt Strike pipes, classic
RAT ports, ngrok/chisel/tailcat tunnels, impostor AMSI, mesh and
webhook stealers are kill-grade: one attributed PID at ≥ 0.85.

Requires .NET Framework 4.8. Run as Administrator.
"@

if (Test-Path $gh) {
    & $gh release create v2.5.3 $installer --title "Sentinel 2.5.3" --notes $notes -R CroatiaSecurity/Sentinel
} else {
    Write-Host "gh.exe not found - installer is at $installer and releases\2.5.3\"
}
