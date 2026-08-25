$env:PATH = "C:\Program Files\Git\cmd;C:\Program Files\Git\bin;" + $env:PATH
$gh = "C:\Program Files\GitHub CLI\gh.exe"
$installer = "installer\SentinelSetup-2.2.8.exe"

$notes = @"
WMI is a first-class persistence and policy-overwrite surface again. Consumer names are not the implant.

## What 2.2.8 does

- Snapshots the real T1546.003 triple: __EventFilter + EventConsumer + __FilterToConsumerBinding in root\subscription and root\default.
- Hostile CommandLine / ActiveScript consumers (powershell, mshta, rundll32, user-writable payloads) are a WmiPersistence terminal.
- Walks loaded modules in WmiPrvSE.exe and wmiadap.exe.
- Attributes SOFTWARE\Policies / CurrentVersion\Policies hive changes to WmiPrvSE, wmiadap, or scrcons (StdRegProv).
- Microsoft-Windows-WMI-Activity is ETW provider #10 (events 5859-5861). The 30s poller is the fallback.
- Composite: WMI Persistence + Policy Rewrite (0.94) when both legs hit the same PID.

## What it does not do

- Name-only new WMI consumers stay observe fuel.
- Does not delete WMI objects automatically. Observe-until-chain still wants two signals before a nuke.
- Still userland. Local admin / kernel implant still wins.

## Installation
Requires .NET Framework 4.8. Run as Administrator.
Open Settings from the Sentinel tray icon (built-in window, no browser).
"@

if (Test-Path $gh) {
    & $gh release create v2.2.8 $installer --title "Sentinel 2.2.8" --notes $notes -R CroatiaSecurity/Sentinel
} else {
    Write-Host "gh.exe not found - installer is at $installer and releases\2.2.8\"
}
