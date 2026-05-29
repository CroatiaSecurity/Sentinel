using System.Collections.Concurrent;
using System.Net;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Monitors;

/// <summary>
/// Route Table Monitor (v3.6.0) — Detects unauthorized routing table modifications.
///
/// Malware and attackers can add static routes to redirect specific traffic
/// (e.g., banking sites, update servers, C2 infrastructure) through attacker-
/// controlled gateways without changing the default route.
///
/// Detection strategy:
///   1. On startup, snapshot the entire IPv4 routing table via GetIpForwardTable.
///   2. Every 10 seconds, re-scan and diff against baseline.
///   3. Alert on:
///      a) New routes added (especially host routes /32 and specific subnets)
///      b) Default route (0.0.0.0/0) changed
///      c) Routes pointing to non-gateway next-hops (traffic redirection)
///
/// Legitimate route additions (VPN, Docker, Hyper-V) are filtered by checking
/// if the route's interface belongs to a known virtual adapter.
///
/// Requires: Windows Vista+ (GetIpForwardTable)
/// </summary>
public sealed class RouteTableMonitor : BackgroundService
{
    private readonly IDetectionEngine _detectionEngine;
    private readonly ILogger<RouteTableMonitor> _logger;

    // Baseline routing table: key = "destination/mask", value = route info
    private readonly ConcurrentDictionary<string, RouteEntry> _baselineRoutes = new();
    private bool _baselineCaptured;

    // Deduplication
    private readonly ConcurrentDictionary<string, DateTimeOffset> _alertedEvents = new();
    private static readonly TimeSpan AlertDedupeWindow = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(10);

    // Known virtual adapter name fragments (routes from these are expected)
    private static readonly string[] VirtualAdapterFragments =
    {
        "VPN", "TAP", "TUN", "WireGuard", "OpenVPN",
        "Hyper-V", "vEthernet", "Docker", "WSL",
        "VMware", "VirtualBox", "Cisco AnyConnect",
        "Fortinet", "Pulse Secure", "GlobalProtect",
        "NordVPN", "ExpressVPN", "Surfshark",
    };

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int GetIpForwardTable(IntPtr pIpForwardTable, ref int pdwSize, bool bOrder);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int DeleteIpForwardEntry(ref MIB_IPFORWARDROW pRoute);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int CreateIpForwardEntry(ref MIB_IPFORWARDROW pRoute);

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_IPFORWARDROW
    {
        public uint dwForwardDest;
        public uint dwForwardMask;
        public int dwForwardPolicy;
        public uint dwForwardNextHop;
        public int dwForwardIfIndex;
        public int dwForwardType;    // 3=local, 4=remote
        public int dwForwardProto;   // 2=local, 3=netmgmt, 4=icmp, 8=rip, 13=ospf, 14=bgp
        public int dwForwardAge;
        public int dwForwardNextHopAS;
        public int dwForwardMetric1;
        public int dwForwardMetric2;
        public int dwForwardMetric3;
        public int dwForwardMetric4;
        public int dwForwardMetric5;
    }

    public RouteTableMonitor(
        IDetectionEngine detectionEngine,
        ILogger<RouteTableMonitor> logger)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("[RouteTableMonitor] Starting — routing table integrity monitoring active");

        // Wait for network to stabilize
        await Task.Delay(TimeSpan.FromSeconds(15), stoppingToken);

        // Capture baseline
        CaptureBaseline();

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(PollInterval, stoppingToken);
                await ScanRouteTableAsync(stoppingToken);
                PruneAlertCache();
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogDebug(ex, "[RouteTableMonitor] Scan error");
            }
        }
    }

    private void CaptureBaseline()
    {
        var routes = GetRouteTable();
        foreach (var route in routes)
        {
            _baselineRoutes[route.Key] = route;
        }
        _baselineCaptured = true;

        _logger.LogInformation("[RouteTableMonitor] Baseline captured — {Count} routes", _baselineRoutes.Count);
    }

    private async Task ScanRouteTableAsync(CancellationToken ct)
    {
        if (!_baselineCaptured) return;

        var currentRoutes = GetRouteTable();
        var currentKeys = new HashSet<string>(currentRoutes.Select(r => r.Key));
        var baselineKeys = new HashSet<string>(_baselineRoutes.Keys);

        // ═══════════════════════════════════════════════════════════════════
        // CHECK 1: New routes added (not in baseline)
        // ═══════════════════════════════════════════════════════════════════
        var addedRoutes = currentRoutes.Where(r => !baselineKeys.Contains(r.Key)).ToList();

        foreach (var route in addedRoutes)
        {
            // Skip routes from known virtual adapters (VPN, Docker, etc.)
            if (IsVirtualAdapterRoute(route.InterfaceIndex)) continue;

            // Skip link-local and multicast routes
            if (route.Destination.StartsWith("169.254.") || route.Destination.StartsWith("224.")) continue;
            if (route.Destination == "255.255.255.255") continue;

            var isHostRoute = route.Mask == "255.255.255.255"; // /32 — targeting specific IP
            var isDefaultRoute = route.Destination == "0.0.0.0" && route.Mask == "0.0.0.0";

            // v4.0.0: Immediately remediate malicious host routes
            if (isHostRoute && route.Protocol == "netmgmt")
            {
                RemediateMaliciousRoutes(new List<RouteEntry> { route });
            }

            var confidence = isDefaultRoute ? 0.90 : isHostRoute ? 0.85 : 0.72;
            var tier = isDefaultRoute || isHostRoute ? DetectionTier.Tier1Behavioral : DetectionTier.Tier2Indicator;

            var dedupeKey = $"route_add:{route.Key}";
            if (_alertedEvents.ContainsKey(dedupeKey)) continue;
            _alertedEvents.TryAdd(dedupeKey, DateTimeOffset.UtcNow);

            var ruleName = isDefaultRoute
                ? "Network Hijack: Default Route Changed"
                : isHostRoute
                    ? "Network Hijack: Host Route Added (Traffic Redirection)"
                    : "Network Integrity: New Route Added";

            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = ruleName,
                Evidence = $"New route detected: {route.Destination}/{route.Mask} → {route.NextHop} " +
                           $"(interface {route.InterfaceIndex}, protocol {route.Protocol}, metric {route.Metric}). " +
                           (isHostRoute ? "Host route (/32) targets a specific IP — possible selective traffic redirection. " : "") +
                           (isDefaultRoute ? "DEFAULT ROUTE CHANGED — all traffic now routes through a different gateway. " : ""),
                Reasoning = isDefaultRoute
                    ? "The default route (0.0.0.0/0) was changed. This redirects ALL internet traffic through " +
                      "a different gateway. Unless the user initiated a VPN connection, this indicates a network " +
                      "hijack — all traffic is now visible to the new gateway operator."
                    : isHostRoute
                        ? "A host-specific route (/32) was added, redirecting traffic to a single IP through " +
                          "a non-standard gateway. Attackers use this to selectively intercept traffic to " +
                          "specific targets (banking sites, update servers, C2 infrastructure) without " +
                          "changing the default route (which is more visible)."
                        : "A new network route was added to the routing table. While this can be legitimate " +
                          "(VPN, network configuration), unexpected routes can redirect traffic through " +
                          "attacker-controlled infrastructure.",
                Confidence = confidence,
                Tier = tier,
                ProcessName = "Network",
                ProcessId = 0,
                Timestamp = DateTimeOffset.UtcNow,
                Metadata = new Dictionary<string, string>
                {
                    ["destination"] = route.Destination,
                    ["mask"] = route.Mask,
                    ["next_hop"] = route.NextHop,
                    ["interface_index"] = route.InterfaceIndex.ToString(),
                    ["protocol"] = route.Protocol,
                    ["metric"] = route.Metric.ToString(),
                    ["is_host_route"] = isHostRoute.ToString(),
                    ["is_default_route"] = isDefaultRoute.ToString(),
                    ["technique"] = "T1565.002 - Data Manipulation: Transmitted Data Manipulation",
                    ["attack_type"] = isDefaultRoute ? "default_route_hijack" : isHostRoute ? "selective_redirect" : "route_addition"
                }
            }, ct);
        }

        // ═══════════════════════════════════════════════════════════════════
        // CHECK 2: Existing routes modified (same destination, different next-hop)
        // ═══════════════════════════════════════════════════════════════════
        foreach (var route in currentRoutes)
        {
            if (!_baselineRoutes.TryGetValue(route.Key, out var baselineRoute)) continue;

            // Check if next-hop changed for the same destination
            if (!string.Equals(baselineRoute.NextHop, route.NextHop, StringComparison.OrdinalIgnoreCase))
            {
                if (IsVirtualAdapterRoute(route.InterfaceIndex)) continue;

                // Skip multicast (224.0.0.0/240.0.0.0) and broadcast (255.255.255.255) routes —
                // these fluctuate normally during DHCP renewal / network reconnection.
                if (route.Destination == "224.0.0.0" && route.Mask == "240.0.0.0") continue;
                if (route.Destination == "255.255.255.255") continue;
                if (route.NextHop == "127.0.0.1" &&
                    (route.Destination == "224.0.0.0" || route.Destination == "255.255.255.255" ||
                     route.Destination.StartsWith("224."))) continue;

                var dedupeKey = $"route_mod:{route.Key}:{route.NextHop}";
                if (_alertedEvents.ContainsKey(dedupeKey)) continue;
                _alertedEvents.TryAdd(dedupeKey, DateTimeOffset.UtcNow);

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Network Hijack: Route Next-Hop Modified",
                    Evidence = $"Route {route.Destination}/{route.Mask} next-hop changed from " +
                               $"{baselineRoute.NextHop} to {route.NextHop}. " +
                               "Traffic to this destination is now routed through a different gateway.",
                    Reasoning = "An existing route's next-hop was modified, redirecting traffic for that " +
                                "destination through a different gateway. This is a targeted traffic " +
                                "interception technique — the attacker modifies specific routes to capture " +
                                "traffic to high-value destinations while leaving other traffic untouched.",
                    Confidence = 0.85,
                    Tier = DetectionTier.Tier1Behavioral,
                    ProcessName = "Network",
                    ProcessId = 0,
                    Timestamp = DateTimeOffset.UtcNow,
                    Metadata = new Dictionary<string, string>
                    {
                        ["destination"] = route.Destination,
                        ["mask"] = route.Mask,
                        ["baseline_next_hop"] = baselineRoute.NextHop,
                        ["current_next_hop"] = route.NextHop,
                        ["technique"] = "T1557 - Adversary-in-the-Middle",
                        ["attack_type"] = "route_modification"
                    }
                }, ct);
            }
        }

        // Update baseline with current state (so we detect the NEXT change)
        // But only for routes we've already alerted on
        foreach (var route in currentRoutes)
        {
            _baselineRoutes[route.Key] = route;
        }

        // Remove routes that no longer exist
        foreach (var key in baselineKeys.Except(currentKeys))
        {
            _baselineRoutes.TryRemove(key, out _);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // HELPERS
    // ═══════════════════════════════════════════════════════════════════════

    private static List<RouteEntry> GetRouteTable()
    {
        var routes = new List<RouteEntry>();

        int bufferSize = 0;
        GetIpForwardTable(IntPtr.Zero, ref bufferSize, true);
        if (bufferSize == 0) return routes;

        var buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            if (GetIpForwardTable(buffer, ref bufferSize, true) != 0) return routes;

            int numEntries = Marshal.ReadInt32(buffer);
            var rowSize = Marshal.SizeOf<MIB_IPFORWARDROW>();

            for (int i = 0; i < numEntries; i++)
            {
                var row = Marshal.PtrToStructure<MIB_IPFORWARDROW>(buffer + 4 + (i * rowSize));

                var dest = new IPAddress(row.dwForwardDest).ToString();
                var mask = new IPAddress(row.dwForwardMask).ToString();
                var nextHop = new IPAddress(row.dwForwardNextHop).ToString();

                var protocol = row.dwForwardProto switch
                {
                    2 => "local",
                    3 => "netmgmt",
                    4 => "icmp",
                    8 => "rip",
                    13 => "ospf",
                    14 => "bgp",
                    _ => $"proto_{row.dwForwardProto}"
                };

                var entry = new RouteEntry
                {
                    Destination = dest,
                    Mask = mask,
                    NextHop = nextHop,
                    InterfaceIndex = row.dwForwardIfIndex,
                    Protocol = protocol,
                    Metric = row.dwForwardMetric1,
                    Type = row.dwForwardType
                };

                routes.Add(entry);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return routes;
    }

    private static bool IsVirtualAdapterRoute(int interfaceIndex)
    {
        try
        {
            foreach (var nic in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
            {
                var ipProps = nic.GetIPProperties().GetIPv4Properties();
                if (ipProps == null) continue;

                if (ipProps.Index == interfaceIndex)
                {
                    var name = nic.Name + " " + nic.Description;
                    foreach (var fragment in VirtualAdapterFragments)
                    {
                        if (name.Contains(fragment, StringComparison.OrdinalIgnoreCase))
                            return true;
                    }
                    return false;
                }
            }
        }
        catch { }
        return false;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // v4.0.0: ROUTE REMEDIATION — Actively delete malicious persistent routes
    // ═══════════════════════════════════════════════════════════════════════

    /// <summary>
    /// v4.0.0: Deletes suspicious persistent /32 host routes that were not in the baseline.
    /// These are the routes used in the 2026-05-25 attack to redirect traffic to specific
    /// IPs through a local MITM interceptor.
    ///
    /// Only deletes routes that are:
    ///   - Host routes (/32, mask 255.255.255.255)
    ///   - Not from virtual adapters (VPN, Docker, etc.)
    ///   - Not in the startup baseline
    ///   - Added via "netmgmt" protocol (manually added, not by routing protocols)
    /// </summary>
    private int RemediateMaliciousRoutes(List<RouteEntry> suspiciousRoutes)
    {
        int removed = 0;

        foreach (var route in suspiciousRoutes)
        {
            // Only remediate /32 host routes added via netmgmt (manual/persistent)
            if (route.Mask != "255.255.255.255") continue;
            if (route.Protocol != "netmgmt") continue;
            if (IsVirtualAdapterRoute(route.InterfaceIndex)) continue;

            try
            {
                var row = new MIB_IPFORWARDROW
                {
                    dwForwardDest = BitConverter.ToUInt32(IPAddress.Parse(route.Destination).GetAddressBytes(), 0),
                    dwForwardMask = BitConverter.ToUInt32(IPAddress.Parse(route.Mask).GetAddressBytes(), 0),
                    dwForwardNextHop = BitConverter.ToUInt32(IPAddress.Parse(route.NextHop).GetAddressBytes(), 0),
                    dwForwardIfIndex = route.InterfaceIndex,
                    dwForwardType = route.Type,
                    dwForwardProto = 3, // netmgmt
                    dwForwardMetric1 = route.Metric
                };

                int result = DeleteIpForwardEntry(ref row);
                if (result == 0)
                {
                    removed++;
                    _logger.LogCritical(
                        "[RouteTableMonitor] REMEDIATED: Deleted malicious route {Dest} → {NextHop}",
                        route.Destination, route.NextHop);
                }
                else
                {
                    _logger.LogWarning(
                        "[RouteTableMonitor] Failed to delete route {Dest} (error {Err})",
                        route.Destination, result);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[RouteTableMonitor] Route deletion error for {Dest}", route.Destination);
            }
        }

        return removed;
    }

    /// <summary>
    /// v4.0.0: Called on startup to clean up any pre-existing malicious persistent routes.
    /// Addresses the scenario where routes were planted before Sentinel started.
    /// </summary>
    public int CleanupExistingMaliciousRoutes()
    {
        var routes = GetRouteTable();

        // Find suspicious /32 host routes that are persistent (netmgmt protocol)
        // and not from virtual adapters
        var suspicious = routes.Where(r =>
            r.Mask == "255.255.255.255" &&
            r.Protocol == "netmgmt" &&
            !IsVirtualAdapterRoute(r.InterfaceIndex) &&
            r.Destination != "255.255.255.255" && // broadcast
            !r.Destination.StartsWith("224.") &&   // multicast
            !r.Destination.StartsWith("169.254.") && // link-local
            !r.Destination.StartsWith("127.") // loopback
        ).ToList();

        if (suspicious.Count == 0) return 0;

        // Heuristic: If there are more than 10 suspicious /32 routes, this is almost
        // certainly an attack (legitimate use rarely has more than a handful).
        if (suspicious.Count > 10)
        {
            _logger.LogCritical(
                "[RouteTableMonitor] v4.0.0: Found {Count} suspicious persistent /32 host routes on startup. " +
                "This matches the traffic interception pattern. Remediating ALL.",
                suspicious.Count);

            return RemediateMaliciousRoutes(suspicious);
        }

        // For smaller counts, log but don't auto-remediate (could be legitimate)
        _logger.LogWarning(
            "[RouteTableMonitor] Found {Count} persistent /32 host routes on startup. " +
            "Count is below auto-remediation threshold (10). Monitoring only.",
            suspicious.Count);

        return 0;
    }

    private void PruneAlertCache()
    {
        var cutoff = DateTimeOffset.UtcNow - AlertDedupeWindow;
        foreach (var kvp in _alertedEvents)
        {
            if (kvp.Value < cutoff)
                _alertedEvents.TryRemove(kvp.Key, out _);
        }
    }

    private sealed class RouteEntry
    {
        public required string Destination { get; init; }
        public required string Mask { get; init; }
        public required string NextHop { get; init; }
        public required int InterfaceIndex { get; init; }
        public required string Protocol { get; init; }
        public required int Metric { get; init; }
        public required int Type { get; init; }

        public string Key => $"{Destination}/{Mask}";
    }
}
