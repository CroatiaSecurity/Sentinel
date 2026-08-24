$env:PATH = "C:\Program Files\Git\cmd;C:\Program Files\Git\bin;" + $env:PATH
$gh = "C:\Program Files\GitHub CLI\gh.exe"
$installer = "installer\SentinelSetup-2.2.4.exe"

$notes = @"
Generic CVE-class coverage plus a quarantine Explorer ACL fix. Sentinel does not patch kernel races. It hunts the userland shape of new EoP/RCE bugs, matches Windows OS-class CISA KEV entries, and tells you when the latest Patch Tuesday CU is missing.

## Detection (v2.2.4)

- Kernel-EoP loaders (AFD/WinSock class, not just Dream Job names), MSI repair from staging, winget/ms-appinstaller, VS Code encoded shells, ClickFix explorer paste, isolation-filter driver drops (unionfs), MOTW-strip PEs.
- CISA KEV: Windows OS vulnerabilities now match this workstation (no process named 'Windows' required). SharePoint/Exchange only if installed. No fake PoC hashes.
- Patch Tuesday posture: toast if last cumulative update is older than the latest second Tuesday (7-day grace).
- Named Dream Job / LegacyHive / Cloud Files coverage from 2.2.3 remains.

## Fixes

- Settings / tray Open Quarantine no longer hits 'insufficient permissions'. Interactive users can browse the folder; encrypted samples stay SYSTEM/Admin. Restart the Sentinel service once so the ACL is rewritten.

## Installation
Requires .NET Framework 4.8. Run as Administrator.
Open Settings from the Sentinel tray icon (built-in window, no browser).
"@

if (Test-Path $gh) {
    & $gh release create v2.2.4 $installer --title "Sentinel 2.2.4" --notes $notes
} else {
    Write-Host "gh.exe not found - installer is at $installer and releases\2.2.4\"
}
