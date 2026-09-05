$env:PATH = "C:\Program Files\Git\cmd;C:\Program Files\Git\bin;" + $env:PATH
$gh = "C:\Program Files\GitHub CLI\gh.exe"
$installer = "installer\SentinelSetup-2.4.6.exe"

$notes = @"
## v2.4.6 — cut measured I/O; revert WorkingSetGuard

v2.4.5 shipped a working-set pin (prefetch + 256 MB VirtualLock) that
was not attributed to a live PID and caused hard faults. This release
removes it.

Measured cuts that stay:

- MBA Authenticode / EnumModules: first-sight + ImageLoad, not every 5s
- Kernel-File ETW: NameCreate/NameDelete + SecurityFileScope only
- File watcher, TI poll, Prefetch/evtx poll: same scope
- ``--pagefault-watch <pid>`` for live HardFaultCount

Does **not** claim 0 hard pagefaults. Live leftover was still ~16-79
HardFaultCount per 5s after these cuts.

Requires .NET Framework 4.8. Run as Administrator.
"@

if (Test-Path $gh) {
    & $gh release create v2.4.6 $installer --title "Sentinel 2.4.6" --notes $notes -R CroatiaSecurity/Sentinel
} else {
    Write-Host "gh.exe not found - installer is at $installer and releases\2.4.6\"
}
