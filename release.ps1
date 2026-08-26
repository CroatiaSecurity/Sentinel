
$env:PATH = "C:\Program Files\Git\cmd;C:\Program Files\Git\bin;" + $env:PATH
$gh = "C:\Program Files\GitHub CLI\gh.exe"
$installer = "installer\SentinelSetup-2.3.1.exe"

$notes = @"
## v2.3.1 — Game Protection + Dashboard Fixes + Always-On Policies

Critical fix for game interference (Football Manager / Denuvo titles crashing on launch)
and dashboard reliability improvements.

### Bug Fixes

- **Game Protection: Fixed Denuvo/anti-cheat crash on launch**
  - EphemeralProcessMonitor case-sensitivity bug: `FM.EXE` from Prefetch was not matched
    against lowercase game name list (`.EndsWith(".exe")` and `.Equals("fm")` both case-sensitive)
  - Added second-chance `IsGameOrAntiCheatPath` check after `FindExecutable` resolves binary
  - Games in recognized paths (Steam, Epic, GOG, etc.) will no longer trigger false ephemeral alerts

- **Dashboard: Events not loading after agent restart**
  - Root cause: stale bearer token in browser sessionStorage after agent restart
  - Fix: server now embeds current token directly in served HTML
  - Added `Cache-Control: no-store` to prevent browser caching stale auth
  - Added visible 401 error message instead of silent empty state

- **Dashboard: Ops metrics showing zero**
  - Frontend was referencing non-existent field names (EventsPerSecond, DetectionsPerMinute, DropRate)
  - Aligned with actual backend fields (TelemetryPerSecond, DetectionsPerSecond, CorrelationLatencyMsP50)
  - Fixed file-fallback not wrapping response in `{ok, ops}` envelope
  - Fixed `DetectionsTotal` counter: `EmitAsync` was not calling `RecordDetection()`

### New Features

- **Always-On Game Protection Policy** (`AlwaysOnPolicies.cs`)
  - Formalized as explicit policy checked BEFORE allowlist and observe-until-chain
  - Game processes forced to LogOnly regardless of detection confidence
  - Cannot be overridden by config, allowlist, or tier law changes
  - Only President's Law rules (actual confirmed injection INTO a game) can override

- **Always-On DLL Unload Policy** (`AlwaysOnPolicies.cs`)
  - Module identity enforcement formalized as permanent product law
  - DLL unload detections carry `AlwaysOnPolicy=DllUnload` metadata marker
  - Never demoted by tier law, never gated on ObserveUntilChain or ActiveResponse
  - Game processes excluded from DLL unload via `MayUnloadDllsFrom()` gate

### Technical Details

- New `AlwaysOnPolicies` static class: single source of truth for permanent product invariants
- `SecurityValidation.IsKnownGameProcessName()`: public API for name-only game checks
- Response engine integration: game protection fires before allowlist evaluation
- DLL unload: `ResponsePolicy.ApplyTierLaw` and `AdvancedResponseEngine` both route through AlwaysOnPolicies

## Installation
Requires .NET Framework 4.8. Run as Administrator.
Open Settings from the Sentinel tray icon.
"@

if (Test-Path $gh) {
    & $gh release create v2.3.1 $installer --title "Sentinel 2.3.1" --notes $notes -R CroatiaSecurity/Sentinel
} else {
    Write-Host "gh.exe not found - installer is at $installer and releases\2.3.1\"
}
