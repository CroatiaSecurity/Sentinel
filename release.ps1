$env:PATH = "C:\Program Files\Git\cmd;C:\Program Files\Git\bin;" + $env:PATH
$gh = "C:\Program Files\GitHub CLI\gh.exe"
$installer = "installer\SentinelSetup-2.2.9.exe"

$notes = @"
## v2.2.9 — Unified Web Dashboard

The native WinForms settings window has been replaced with the embedded web dashboard.
Opening Settings from the tray icon now shows the same modern HTML/CSS/JS dashboard
that was previously only available via a browser, but hosted inside a native window
(no external browser launch required).

### What changed

- **AgentDashboardForm** rewritten as a thin WebBrowser shell hosting localhost:19845
- **WebDashboardService** re-enabled as a hosted service (serves REST API + HTML on localhost)
- Sidebar navigation, live event stream, system scan, quarantine view, ops metrics,
  report-to-police workflow, safety page, and hardened mode toggle all work exactly
  as in the web dashboard
- **BrowserLauncher.cs** removed — no more external browser dependency
- IE11 Edge emulation mode set via registry for CSS grid/flexbox support
- Avoids the broken http:// protocol handler issue that caused the v2.2.2 revert

### Previous (v2.2.8) WMI improvements are still included

- WMI persistence triple snapshot (Filter + Consumer + Binding)
- Hostile CommandLine/ActiveScript consumer detection
- WmiPrvSE module enumeration
- Policy hive attribution to WMI processes
- ETW provider #10 for WMI-Activity

## Installation
Requires .NET Framework 4.8. Run as Administrator.
Open Settings from the Sentinel tray icon.
"@

if (Test-Path $gh) {
    & $gh release create v2.2.9 $installer --title "Sentinel 2.2.9" --notes $notes -R CroatiaSecurity/Sentinel
} else {
    Write-Host "gh.exe not found - installer is at $installer and releases\2.2.9\"
}
