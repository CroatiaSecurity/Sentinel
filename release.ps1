$env:PATH = "C:\Program Files\Git\cmd;C:\Program Files\Git\bin;" + $env:PATH
$gh = "C:\Program Files\GitHub CLI\gh.exe"
$installer = "installer\SentinelSetup-2.0.3.exe"

$notes = @"
Fix duplicate tray icons.

## Changes
- Added single-instance mutex (``Global\SentinelAgentSingleInstance``) to Sentinel.Agent — prevents duplicate tray icons caused by race conditions between the installer, HKLM Run key, AgentWatchdog, and self-restart logic.

## Installation
Requires .NET Framework 4.8 (already present on most Windows 10/11 systems). Run as Administrator.
"@

& $gh release create v2.0.3 $installer --title "Sentinel 2.0.3" --notes $notes
