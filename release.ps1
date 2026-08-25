$env:PATH = "C:\Program Files\Git\cmd;C:\Program Files\Git\bin;" + $env:PATH
$gh = "C:\Program Files\GitHub CLI\gh.exe"
$installer = "installer\SentinelSetup-2.2.7.exe"

$notes = @"
Module identity unload is standing product law. Hijack-name plants (dbghelp.dll, version.dll, winmm.dll, ...) are quarantined on drop so the Windows loader cannot bind them — including a real Microsoft-signed copy next to Chrome or a Steam game. Mapped foreign modules are FreeLibrary'd immediately. Permanent Tier1. No config switch.

## What 2.2.7 does

- Every mapped PE is path+signer checked every 5 seconds. Foreign modules unload now.
- Hijack-name DLLs next to an exe are plants even if Microsoft-signed (search order).
- Those plants are quarantined on drop (file only). No process kill. No 0-byte stub that would still win search order.
- Game folders are included for disk quarantine. Sentinel still does not read live game memory (Denuvo).
- Chromium loading Edge DLLs is not injection. Count is not a signal.

## What it does not do

- In-memory inject / Hell's Gate into a running game is not visible (no VM_READ).
- Does not unload every unsigned plugin. Does not kill the host on a Program Files plant that will not unmap.

## Installation
Requires .NET Framework 4.8. Run as Administrator.
Open Settings from the Sentinel tray icon (built-in window, no browser).
"@

if (Test-Path $gh) {
    & $gh release create v2.2.7 $installer --title "Sentinel 2.2.7" --notes $notes -R CroatiaSecurity/Sentinel
} else {
    Write-Host "gh.exe not found - installer is at $installer and releases\2.2.7\"
}
