$env:PATH = "C:\Program Files\Git\cmd;C:\Program Files\Git\bin;" + $env:PATH
$gh = "C:\Program Files\GitHub CLI\gh.exe"
$installer = "installer\SentinelSetup-2.2.5.exe"

$notes = @"
Module identity is the EDR backbone again. Foreign mapped modules are unloaded immediately (path + Microsoft signature), not logged as 'module count +3'.

## Module identity (v2.2.5)

- Every mapped PE is allow/deny checked every 5 seconds: OS keep trees, process directory, Microsoft-signed Program Files.
- Denied and unloaded now: Temp/Downloads/Desktop drops, unsigned sideload plants (version.dll next to the exe), random folders (C:\Evil\helper.dll).
- explorer and svchost are scanned (inject targets). Never FreeLibrary lsass/csrss/wininit/DISM/NTLite.
- Unbacked RWX with an MZ header or compact shellcode has execute stripped. Large non-MZ JIT regions are ignored.
- Chromium loading 40 Edge DLLs is not treated as injection.

## Installation
Requires .NET Framework 4.8. Run as Administrator.
Open Settings from the Sentinel tray icon (built-in window, no browser).
"@

if (Test-Path $gh) {
    & $gh release create v2.2.5 $installer --title "Sentinel 2.2.5" --notes $notes -R CroatiaSecurity/Sentinel
} else {
    Write-Host "gh.exe not found - installer is at $installer and releases\2.2.5\"
}
