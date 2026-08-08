$env:PATH = "C:\Program Files\Git\cmd;C:\Program Files\Git\bin;" + $env:PATH
$gh = "C:\Program Files\GitHub CLI\gh.exe"
$installer = "installer\SentinelSetup-2.0.2.exe"

$notes = @"
Config audit fixes and documentation update.

## Changes
- Removed duplicate ``RestrictivePortHardening`` key from ``appsettings.json``
- Cleared machine-specific attacker IP from ``MitmDefense.KnownRogueCastIps`` — clean installs no longer pre-block an IP specific to a previous incident. MitM detection logic remains fully armed.
- Fixed README installer download link
- Bumped ``constraints.md``, ``design.md``, ``requirements.md`` to v2.0.2
- ``requirements.md`` fully rewritten from v1.8.5 to match 2.0.x codebase (FR-14 through FR-18, WeightedCorrelation, plugin architecture, IPC, ops metrics, work-first posture, MitmDefense suite)

## Installation
Requires .NET Framework 4.8 (already present on most Windows 10/11 systems). Run as Administrator.
"@

& $gh release create v2.0.2 $installer --title "Sentinel 2.0.2" --notes $notes
