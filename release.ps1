$env:PATH = "C:\Program Files\Git\cmd;C:\Program Files\Git\bin;" + $env:PATH
$gh = "C:\Program Files\GitHub CLI\gh.exe"
$installer = "installer\SentinelSetup-2.4.1.exe"

$notes = @"
## v2.4.1 — tray icon visible after install

After ``Sentinel.Service.exe --install``, run the ``ShowAllTrayIcons`` scheduled
task so a newly created NotifyIconSettings entry is visible without a re-logon.
Silent no-op if the task is missing (hosts not provisioned via the GSecurity ISO).

Also fixes leftover 2.4.0 version-stamp drift: README and ProductInfo tests
still said 2.3.9. Installer ``build.ps1`` now stamps all Inno VersionInfo* fields
from ``version.txt``.

2.4.0 remains published (Kaspersky / VT 3/71 AV pass).

## Installation
Requires .NET Framework 4.8. Run as Administrator.
"@

if (Test-Path $gh) {
    & $gh release create v2.4.1 $installer --title "Sentinel 2.4.1" --notes $notes -R CroatiaSecurity/Sentinel
} else {
    Write-Host "gh.exe not found - installer is at $installer and releases\2.4.1\"
}
