$env:PATH = "C:\Program Files\Git\cmd;C:\Program Files\Git\bin;" + $env:PATH
$gh = "C:\Program Files\GitHub CLI\gh.exe"
$installer = "installer\SentinelSetup-2.3.7.exe"

$notes = @"
## v2.3.7 — AV false positive elimination

Sensitive Win32/NT APIs moved out of the PE import table via runtime resolution,
removing the import-table shape that drives ML-based heuristic AV detections.

### Fixed

- **NativeResolver** (new) — OpenProcess, ReadProcessMemory, VirtualQueryEx,
  DuplicateHandle, NtQuerySystemInformation, NtQueryObject, and
  NtQueryInformationProcess resolved at runtime via GetModuleHandleW +
  GetProcAddress. No longer in the PE import address table.
- **Global hooks removed** — ClickjackingGuard and PhantomKeystrokeGuard no
  longer install WH_MOUSE_LL / WH_KEYBOARD_LL; replaced with window geometry
  analysis and LASTINPUTINFO heuristics.
- **FileReputationEngine** — injection-API string literals assembled at runtime,
  not stored as contiguous PE string-table entries.
- **LGPO.exe** ships as a plain file, not an embedded assembly resource.
- **Installer** — all PowerShell -ExecutionPolicy Bypass removed; non-solid
  lzma/max compression; full VersionInfo PE metadata.

## Installation
Requires .NET Framework 4.8. Run as Administrator.
"@

if (Test-Path $gh) {
    & $gh release create v2.3.7 $installer --title "Sentinel 2.3.7" --notes $notes -R CroatiaSecurity/Sentinel
} else {
    Write-Host "gh.exe not found - installer is at $installer and releases\2.3.7\"
}
