$env:PATH = "C:\Program Files\Git\cmd;C:\Program Files\Git\bin;" + $env:PATH
$gh = "C:\Program Files\GitHub CLI\gh.exe"
$installer = "installer\SentinelSetup-2.4.8.exe"

$notes = @"
## v2.4.8 — userland protocol coverage + covert mesh (tailcat-class)

UDP, ICMP, WFP net-event subscription, VoIP heuristics, and userspace
WireGuard/DERP/STUN overlays — no kernel driver, no WinDivert.

- ``UdpFlowMonitor`` — UDP bind table + Kernel-Network UDP ETW
- ``IcmpAnomalyMonitor`` — ICMP type counters (flood / redirect / unreach)
- ``WfpNetEventMonitor`` — ``FwpmNetEventSubscribe0`` (GRE/ESP/AH/SCTP/L2TP)
- ``VoipSessionMonitor`` — SIP/STUN/RTP-like binds from unexpected processes
- ``CovertMeshMonitor`` — tailcat and copycats (UDP+HTTPS overlay, DERP DNS).
  Official Tailscale / Discord / browsers / games skipped.

All new signals are Tier2 / LogOnly observe fuel. Never chain-nuke alone.

Requires .NET Framework 4.8. Run as Administrator.
"@

if (Test-Path $gh) {
    & $gh release create v2.4.8 $installer --title "Sentinel 2.4.8" --notes $notes -R CroatiaSecurity/Sentinel
} else {
    Write-Host "gh.exe not found - installer is at $installer and releases\2.4.8\"
}
