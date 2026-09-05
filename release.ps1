$env:PATH = "C:\Program Files\Git\cmd;C:\Program Files\Git\bin;" + $env:PATH
$gh = "C:\Program Files\GitHub CLI\gh.exe"
$installer = "installer\SentinelSetup-2.4.5.exe"

$notes = @"
## v2.4.5 — hard pagefault / LatencyMon fix

LatencyMon showed 1000+ hard pagefaults on ``Sentinel.Service`` in a few
minutes (working set ~1.6 GB). Isolated scan kernels were not the source.

- Raise memory priority, prefetch images, pin a 256 MB minimum working set
- Kernel-File ETW: only modules/scripts/installers/images enter fusion
- Kernel-Registry ETW: PID hint only (no path-less fusion flood)
- Fusion retention 10 min → 2 min
- WASAPI callback reuses buffers
- ``--pagefault-diag`` for LatencyMon-equivalent HardFaultCount attribution

Requires .NET Framework 4.8. Run as Administrator.
"@

if (Test-Path $gh) {
    & $gh release create v2.4.5 $installer --title "Sentinel 2.4.5" --notes $notes -R CroatiaSecurity/Sentinel
} else {
    Write-Host "gh.exe not found - installer is at $installer and releases\2.4.5\"
}
