$env:PATH = "C:\Program Files\Git\cmd;C:\Program Files\Git\bin;" + $env:PATH
$gh = "C:\Program Files\GitHub CLI\gh.exe"
$installer = "installer\SentinelSetup-2.3.6.exe"

$notes = @"
## v2.3.6 — AV false positive fix + GorstaksProtection detection improvements

### Fixed

- **Kaspersky false positive on Sentinel.Core.dll** (confirmed via Kaspersky report log):
  - ``NativeProcessMemory``: removed split-string runtime API resolution (``J("Open","Process")``
    pattern). All Win32 API calls now use standard ``[DllImport]`` declarations, making the
    binary fully transparent to security scanners.
  - ``HardeningModule``: ``LGPO.exe`` and ``GSecurity.inf`` are now shipped as plain files in the
    installation directory instead of being embedded in the assembly as resources. Extracting
    a PE from a DLL resource at runtime is a top AV dropper heuristic.
- **Installer heuristic profile reduced**: Pascal script now uses ``taskkill /F /IM`` instead
  of PowerShell ``-ExecutionPolicy Bypass`` + ``Stop-Process -Force`` for process termination.
  ``ResetInstallDirAcls`` reduced from 8 ``takeown``/``icacls`` calls to 2 targeted ``icacls``
  calls (no recursive ``takeown``).

### Added

- **ThreatFoxFeedService** — queries the ThreatFox API every 6 hours for hash/IP/domain IOCs
  with malware-family metadata. Loads an offline bundle on startup so detections work
  immediately. Domain hits surface as rule SENT-TF-001 in DnsQueryMonitor.
- **SlidingWindowRansomwareRule (SENT-SW-001)** — fires when a single process touches >50
  unique file extensions within 30 seconds. Complements the existing shadow-copy rule.
  Tier1 / KillProcessTree. Memory-safe per-PID idle eviction.
- **SlidingWindowMassDeletionRule (SENT-SW-002)** — fires on >100 file deletions within 10
  seconds. Wiper / backup-destruction pattern. Tier1 / KillProcessTree.
- **FullPathParentChildRule (SENT-003)** — Office/browser/PDF parent-child detection with
  full binary-path verification. Rejects a ``winword.exe`` living outside known install paths.
  Tier2 / LogOnly -> feeds correlation engine.
- **RuleId field on DetectionEvent** — stable per-rule identifiers for audit and dedup.
- **Pre-action audit log** — ``JsonlEventLogger`` now writes a mandatory PRE_ACTION entry to a
  daily-rotating ``audit-YYYY-MM-DD.jsonl`` (90-day retention) before every kill or block.

### Changed

- ``ProductInfo.Version`` -> 2.3.6

## Installation
Requires .NET Framework 4.8. Run as Administrator.
Open Settings from the Sentinel tray icon.
"@

if (Test-Path $gh) {
    & $gh release create v2.3.6 $installer --title "Sentinel 2.3.6" --notes $notes -R CroatiaSecurity/Sentinel
} else {
    Write-Host "gh.exe not found - installer is at $installer and releases\2.3.6\"
}
