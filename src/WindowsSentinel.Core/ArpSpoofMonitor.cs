using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core;

/// <summary>
/// ARP Spoof Detection Monitor (v3.6.0) â€” Detects ARP table manipulation.
///
/// ARP spoofing is the most common local network attack vector. An attacker
/// on the same LAN sends gratuitous ARP replies to associate their MAC address
/// with the gateway's IP, causing all traffic to route through them (MITM).
///
/// Detection strategy:
///   1. On startup, capture the gateway IP â†’ MAC binding as baseline.
///   2. Every 5 seconds, poll the ARP table via GetIpNetTable.
///   3. Alert if:
///      a) Gateway MAC changes (classic ARP spoof)
///      b) Multiple IPs share the same MAC (ARP poisoning indicator)
///      c) Gateway MAC is a known virtual/suspicious OUI (VM-based MITM)
///
/// This monitor runs in the SYSTEM service context â€” it has full access to
/// the system ARP table regardless of user session.
///
/// Requires: Windows Vista+ (GetIpNetTable)
/// </summary>
public sealed class ArpSpoofMonitor : BackgroundService
{
    private readonly DetectionEngine _detectionEngine;
    private readonly ILogger<ArpSpoofMonitor> _logger;

    // Baseline: gateway IP â†’ MAC mapping captured at startup
    private readonly ConcurrentDictionary<string, string> _gatewayBaseline = new();

    // Track all IP â†’ MAC mappings for duplicate detection
    private readonly ConcurrentDictionary<string, string> _arpTable = new();

    // Deduplication
    private readonly ConcurrentDictionary<string, DateTime> _alertedEvents = new();
    private static readonly TimeSpan AlertDedupeWindow = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(15);

    // Known virtual/suspicious MAC OUI prefixes (first 3 bytes)
    // These are legitimate in VMs but suspicious as a gateway MAC on physical hardware
    private static readonly string[] SuspiciousOuis =
    {
        "00:50:56", // VMware
        "00:0C:29", // VMware
        "08:00:27", // VirtualBox
        "52:54:00", // QEMU/KVM
        "00:16:3E", // Xen
        "00:15:5D", // Hyper-V
        "02:42:AC", // Docker
    };

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int GetIpNetTable(IntPtr pIpNetTable, ref int pdwSize, bool bOrder);

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_IPNETROW
    {
        public int dwIndex;
        public int dwPhysAddrLen;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] bPhysAddr;
        public uint dwAddr;
        public int dwType; // 1=Other, 2=Invalid, 3=Dynamic, 4=Static
    }

    public ArpSpoofMonitor(
        DetectionEngine detectionEngine,
        ILogger<ArpSpoofMonitor> logger)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("[ArpSpoofMonitor] Starting â€” ARP table integrity monitoring active");

        // Wait briefly for network to stabilize after boot
        await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken);

        // Capture baseline
        CaptureGatewayBaseline();

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await ScanArpTableAsync(stoppingToken);
                PruneAlertCache();
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogDebug(ex, "[ArpSpoofMonitor] Scan error");
            }

            await Task.Delay(PollInterval, stoppingToken);
        }
    }

    private void CaptureGatewayBaseline()
    {
        try
        {
            var gateways = GetDefaultGateways();
            var arpEntries = GetArpEntries();

            foreach (var gwIp in gateways)
            {
                if (arpEntries.TryGetValue(gwIp, out var mac))
                {
                    _gatewayBaseline[gwIp] = mac;
                    _logger.LogInformation(
                        "[ArpSpoofMonitor] Baseline captured â€” Gateway {Ip} â†’ MAC {Mac}",
                        gwIp, mac);
                }
            }

            if (_gatewayBaseline.IsEmpty)
            {
                _logger.LogWarning("[ArpSpoofMonitor] No gateway ARP entries found at startup. " +
                                   "Will capture on first successful poll.");
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[ArpSpoofMonitor] Failed to capture baseline");
        }
    }

    private async Task ScanArpTableAsync(CancellationToken ct)
    {
        var arpEntries = GetArpEntries();
        if (arpEntries.Count == 0) return;

        // Update current ARP table snapshot
        _arpTable.Clear();
        foreach (var kvp in arpEntries)
            _arpTable[kvp.Key] = kvp.Value;

        var gateways = GetDefaultGateways();

        // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
        // CHECK 1: Gateway MAC changed from baseline
        // This is the primary ARP spoof indicator.
        // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
        foreach (var gwIp in gateways)
        {
            if (!arpEntries.TryGetValue(gwIp, out var currentMac)) continue;

            // If we don't have a baseline yet, capture it now
            if (!_gatewayBaseline.ContainsKey(gwIp))
            {
                _gatewayBaseline[gwIp] = currentMac;
                _logger.LogInformation("[ArpSpoofMonitor] Late baseline â€” Gateway {Ip} â†’ MAC {Mac}", gwIp, currentMac);
                continue;
            }

            var baselineMac = _gatewayBaseline[gwIp];
            if (!string.Equals(currentMac, baselineMac, StringComparison.OrdinalIgnoreCase))
            {
                var dedupeKey = $"gw_mac_change:{gwIp}:{currentMac}";
                if (_alertedEvents.ContainsKey(dedupeKey)) continue;
                _alertedEvents.TryAdd(dedupeKey, DateTime.UtcNow);

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Network Hijack: Gateway MAC Changed (ARP Spoof)",
                    Evidence = $"Gateway {gwIp} MAC changed from {baselineMac} to {currentMac}. " +
                               "This indicates an ARP spoofing attack â€” an attacker on the local network " +
                               "is redirecting traffic through their machine.",
                    Reasoning = "The default gateway's MAC address has changed since Sentinel started. " +
                                "In normal operation, a gateway's MAC is stable. A change means either: " +
                                "(1) ARP spoofing attack (most likely), (2) router replacement (rare), or " +
                                "(3) failover event (enterprise only). This is a critical network integrity violation.",
                    Confidence = 0.92,
                    Tier = DetectionTier.Tier1Behavioral,
                    ProcessName = "Network",
                    ProcessId = 0,
                    Timestamp = DateTime.UtcNow,
                    Metadata = new Dictionary<string, string>
                    {
                        ["gateway_ip"] = gwIp,
                        ["baseline_mac"] = baselineMac,
                        ["current_mac"] = currentMac,
                        ["technique"] = "T1557.002 - ARP Cache Poisoning",
                        ["attack_type"] = "arp_spoof"
                    }
                }, ct);
            }
        }

        // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
        // CHECK 2: Multiple IPs sharing the same MAC (ARP poisoning)
        // If the gateway MAC appears on multiple IPs, someone is poisoning.
        // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
        var macToIps = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var kvp in arpEntries)
        {
            if (!macToIps.ContainsKey(kvp.Value))
                macToIps[kvp.Value] = new List<string>();
            macToIps[kvp.Value].Add(kvp.Key);
        }

        foreach (var kvp in macToIps)
        {
            // Skip broadcast/multicast MACs
            if (kvp.Key.StartsWith("FF:FF:FF", StringComparison.OrdinalIgnoreCase)) continue;
            if (kvp.Value.Count <= 2) continue; // 2 is borderline, 3+ is suspicious

            // Only alert if one of the IPs is a gateway
            var isGatewayMac = gateways.Any(gw =>
                arpEntries.TryGetValue(gw, out var gwMac) &&
                string.Equals(gwMac, kvp.Key, StringComparison.OrdinalIgnoreCase));

            if (!isGatewayMac) continue;

            var dedupeKey = $"mac_dup:{kvp.Key}";
            if (_alertedEvents.ContainsKey(dedupeKey)) continue;
            _alertedEvents.TryAdd(dedupeKey, DateTime.UtcNow);

            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "Network Hijack: ARP Table Poisoning (MAC Duplication)",
                Evidence = $"MAC {kvp.Key} is associated with {kvp.Value.Count} IPs: " +
                           $"{string.Join(", ", kvp.Value.Take(10))}. " +
                           "Gateway MAC appearing on multiple IPs indicates active ARP poisoning.",
                Reasoning = "A single MAC address claiming multiple IP addresses (including the gateway) " +
                            "is a hallmark of ARP cache poisoning. The attacker's NIC responds to ARP " +
                            "requests for multiple IPs, positioning itself as a man-in-the-middle.",
                Confidence = 0.88,
                Tier = DetectionTier.Tier1Behavioral,
                ProcessName = "Network",
                ProcessId = 0,
                Timestamp = DateTime.UtcNow,
                Metadata = new Dictionary<string, string>
                {
                    ["mac_address"] = kvp.Key,
                    ["ip_count"] = kvp.Value.Count.ToString(),
                    ["ips"] = string.Join(";", kvp.Value.Take(10)),
                    ["technique"] = "T1557.002 - ARP Cache Poisoning",
                    ["attack_type"] = "arp_poisoning"
                }
            }, ct);
        }

        // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
        // CHECK 3: Gateway MAC is a known virtual OUI
        // Suspicious on physical hardware â€” could indicate VM-based MITM.
        // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
        foreach (var gwIp in gateways)
        {
            if (!arpEntries.TryGetValue(gwIp, out var gwMac)) continue;

            var isVirtualOui = SuspiciousOuis.Any(oui =>
                gwMac.StartsWith(oui, StringComparison.OrdinalIgnoreCase));

            if (!isVirtualOui) continue;

            var dedupeKey = $"virtual_gw:{gwIp}:{gwMac}";
            if (_alertedEvents.ContainsKey(dedupeKey)) continue;
            _alertedEvents.TryAdd(dedupeKey, DateTime.UtcNow);

            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "Network Hijack: Gateway Has Virtual MAC (Possible MITM Appliance)",
                Evidence = $"Gateway {gwIp} has MAC {gwMac} which belongs to a virtualization vendor OUI. " +
                           "On physical hardware, this may indicate a rogue VM-based MITM appliance.",
                Reasoning = "Virtual MAC OUIs (VMware, VirtualBox, QEMU) on a gateway are normal in " +
                            "virtualized environments but suspicious on physical networks. An attacker " +
                            "could be running a transparent bridge VM to intercept traffic.",
                Confidence = 0.55,
                Tier = DetectionTier.Tier2Indicator,
                ProcessName = "Network",
                ProcessId = 0,
                Timestamp = DateTime.UtcNow,
                Metadata = new Dictionary<string, string>
                {
                    ["gateway_ip"] = gwIp,
                    ["gateway_mac"] = gwMac,
                    ["technique"] = "T1557 - Adversary-in-the-Middle",
                    ["attack_type"] = "virtual_gateway"
                }
            }, ct);
        }
    }

    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    // HELPERS
    // â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    private static List<string> GetDefaultGateways()
    {
        var gateways = new List<string>();
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up) continue;
                if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

                var props = nic.GetIPProperties();
                foreach (var gw in props.GatewayAddresses)
                {
                    if (gw.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        var gwStr = gw.Address.ToString();
                        if (gwStr != "0.0.0.0" && !gateways.Contains(gwStr))
                            gateways.Add(gwStr);
                    }
                }
            }
        }
        catch { }
        return gateways;
    }

    private static Dictionary<string, string> GetArpEntries()
    {
        var entries = new Dictionary<string, string>();

        int bufferSize = 0;
        GetIpNetTable(IntPtr.Zero, ref bufferSize, false);
        if (bufferSize == 0) return entries;

        var buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            if (GetIpNetTable(buffer, ref bufferSize, false) != 0) return entries;

            int numEntries = Marshal.ReadInt32(buffer);
            var rowSize = Marshal.SizeOf<MIB_IPNETROW>();

            for (int i = 0; i < numEntries; i++)
            {
                var row = Marshal.PtrToStructure<MIB_IPNETROW>(buffer + 4 + (i * rowSize));

                // Skip invalid entries (type 2 = invalid)
                if (row.dwType == 2) continue;

                var ip = new IPAddress(row.dwAddr).ToString();
                if (ip == "0.0.0.0" || ip == "255.255.255.255") continue;

                // Format MAC address
                var mac = FormatMac(row.bPhysAddr, row.dwPhysAddrLen);
                if (mac == "00:00:00:00:00:00") continue;

                entries[ip] = mac;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return entries;
    }

    private static string FormatMac(byte[] bytes, int length)
    {
        if (bytes == null || length <= 0) return "00:00:00:00:00:00";
        return string.Join(":", bytes.Take(length).Select(b => b.ToString("X2")));
    }

    private void PruneAlertCache()
    {
        var cutoff = DateTime.UtcNow - AlertDedupeWindow;
        foreach (var kvp in _alertedEvents)
        {
            if (kvp.Value < cutoff)
                _alertedEvents.TryRemove(kvp.Key, out _);
        }
    }
}
