$env:PATH = "C:\Program Files\Git\cmd;C:\Program Files\Git\bin;" + $env:PATH
$gh = "C:\Program Files\GitHub CLI\gh.exe"
$installer = "installer\SentinelSetup-2.2.3.exe"

$notes = @"
August 2026 Patch Tuesday userland coverage. Sentinel does not patch kernel races (afd.sys). It hunts the Lazarus campaign around the exploited zero-day, tells you when the KEV cumulative update is missing, and watches LegacyHive plus Cloud Files / ShieldBreak primitives.

## Detection (v2.2.3)

- Lazarus Operation Dream Job (CVE-2026-68820 campaign): SecurityPDF, FudModule/Afd4Eop12, libmupdf.dll sideload from Temp/Downloads, %TEMP%\new.exe from a PDF viewer, published C2 domains/IPs and SHA-256s. Composite: Lazarus Dream Job Chain.
- KEV patch posture: Win11 24H2/25H2 UBR below 9168 (KB5121003) → LogOnly + toast. Never force-patches. Reboot still required.
- LegacyHive (CVE-2026-62832): another user's registry hive loaded while they are not logged on; junctions onto NTUSER.DAT. Composite with token/UAC.
- Cloud Files / ShieldBreak (CVE-2026-62713): unknown CfApi sync roots; Cloud Files placeholders in Downloads/Desktop/Temp. OneDrive is not disabled.

## Installation
Requires .NET Framework 4.8. Run as Administrator.
Open Settings from the Sentinel tray icon (built-in window, no browser).
"@

if (Test-Path $gh) {
    & $gh release create v2.2.3 $installer --title "Sentinel 2.2.3" --notes $notes
} else {
    Write-Host "gh.exe not found — installer is at $installer and releases\2.2.3\"
}
