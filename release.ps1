$env:PATH = "C:\Program Files\Git\cmd;C:\Program Files\Git\bin;" + $env:PATH
$gh = "C:\Program Files\GitHub CLI\gh.exe"
$installer = "installer\SentinelSetup-2.0.6.exe"

$notes = @"
Fix games and DirectX installers killed by file reputation engine.

## Bug Fix (v2.0.6)

### Fixed — Games and DirectX/runtime redistributables blocked

**Root cause:** `DetectionEngine` file reputation path had no game/anti-cheat or DirectX guard. Game binaries (packed, high-entropy, unsigned, unknown to reputation DBs) scored HighRisk/Malicious, generating kill detections that could chain-confirm under multi-signal correlation.

**Fix:** Added early-return guards before reputation scanning:
- `SecurityValidation.IsGameOrAntiCheatPath` — skips Steam, Epic, GOG, EA, Ubisoft, Riot, Battle.net, Xbox, EAC/BattlEye/Vanguard/Denuvo paths
- `InstallerHeuristics.IsDirectXOrRuntimeRedist` — skips DXSETUP, vcredist, XNA, OpenAL, PhysX and all runtime redist processes

Behavioral monitors still observe everything. If an actual attack uses a game path, rule-based detections fire normally through ObserveUntilChain.

## Installation
Requires .NET Framework 4.8 (already present on most Windows 10/11 systems). Run as Administrator.
"@

& $gh release create v2.0.6 $installer --title "Sentinel 2.0.6" --notes $notes
