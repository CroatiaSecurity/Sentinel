
$env:PATH = "C:\Program Files\Git\cmd;C:\Program Files\Git\bin;" + $env:PATH
$gh = "C:\Program Files\GitHub CLI\gh.exe"
$installer = "installer\SentinelSetup-2.3.2.exe"

$notes = @"
## v2.3.2 — Dashboard Monitor Health + Live Events Fixes

Fixes the dashboard so the monitor health panel and the live event stream reflect
the actually-running system.

### Bug Fixes

- **Dashboard: "0/0 monitors running"**
  - The MonitorRegistry that feeds Service Status (/api/health, /api/ops) was never populated.
  - Monitors run via MonitorGroup hosted services and the SentinelService start loop, but
    neither registered them with the registry (the StartupSequencer/SentinelOrchestrator path
    that would have done so is not wired into service startup).
  - Detections/quarantine still showed counts because they read from events.jsonl and the
    quarantine folder directly — which made the 0/0 especially misleading.
  - Fix: MonitorGroup and SentinelService now register their monitors, mark them
    started/failed/stopped, and heartbeat running monitors so the registry watchdog keeps
    them marked Running.

- **Dashboard: Events page stuck on "Connected — waiting for events..."**
  - The WebSocket stream only broadcasts events appended AFTER connect, and the frontend
    never loaded existing history, so the page stayed empty even with logged detections.
  - Fix: added loadEventHistory() which seeds the buffer from /api/events on WebSocket open
    and whenever the Events page is opened.

### Technical Details

- `MonitorGroupConfig` gains a `Category` property; each group reports its category.
- SystemIntegrity/Peripheral group health-check intervals lowered to 45s to stay inside the
  registry watchdog's 3-minute critical timeout.
- `ProductInfo.Version` -> 2.3.2

## Installation
Requires .NET Framework 4.8. Run as Administrator.
Open Settings from the Sentinel tray icon.
"@

if (Test-Path $gh) {
    & $gh release create v2.3.2 $installer --title "Sentinel 2.3.2" --notes $notes -R CroatiaSecurity/Sentinel
} else {
    Write-Host "gh.exe not found - installer is at $installer and releases\2.3.2\"
}
