
$env:PATH = "C:\Program Files\Git\cmd;C:\Program Files\Git\bin;" + $env:PATH
$gh = "C:\Program Files\GitHub CLI\gh.exe"
$installer = "installer\SentinelSetup-2.3.5.exe"

$notes = @"
## v2.3.5 — Delivery-vector coverage: script-dropper MOTW + WPAD/PAC proxy hijack

Closes two initial-access delivery gaps. DHCP does not deliver JavaScript, but DHCP
Option 252 delivers a PAC URL — JavaScript the auto-proxy resolver runs — and a drive-by
download can drop a script payload that never has to be a PE.

### Added

- **Script-dropper Mark-of-the-Web detection.** ``MotwBypassMonitor`` now flags script-class
  droppers (``.hta``, ``.js``, ``.vbs``, ``.wsf``, ``.ps1``, ``.bat``, ``.lnk``, ``.chm``, …)
  that land in Downloads/Desktop without a ``Zone.Identifier`` — not just PE files. New rule
  ``CVE Class: Script Dropper Missing Mark-of-the-Web`` (Tier2/LogOnly weak observe). Feeds the
  existing ``MOTW Bypass Execution Chain`` composite.
- **``WpadProxyMonitor``.** Watches the WPAD / Proxy Auto-Config (PAC) config — the host-side
  landing point for the DHCP Option 252 vector (CVE-2026-62755 class). A rogue DHCP server or
  malware that sets ``AutoConfigURL`` can MITM every browser. Baselines existing corporate PAC
  (does not fire), then emits on a PAC change, a remote/IP-literal PAC, or WPAD auto-detect +
  remote PAC. All Tier2/LogOnly.
- **``WPAD Proxy Hijack Chain`` composite** — a WPAD/PAC signal correlated with C2 or exfil
  promotes to 0.9. Does not revert the proxy setting.

### Changed

- ``ProductInfo.Version`` -> 2.3.5

Neither monitor kills or reverts settings — corporate PAC and game ISOs are legitimate.
These are observe fuel that only escalate on a corroborating execution or callback leg.
They do not patch the DHCP client or stop a PAC-engine RCE; patch the OS for that.

## Installation
Requires .NET Framework 4.8. Run as Administrator.
Open Settings from the Sentinel tray icon.
"@

if (Test-Path $gh) {
    & $gh release create v2.3.5 $installer --title "Sentinel 2.3.5" --notes $notes -R CroatiaSecurity/Sentinel
} else {
    Write-Host "gh.exe not found - installer is at $installer and releases\2.3.5\"
}
