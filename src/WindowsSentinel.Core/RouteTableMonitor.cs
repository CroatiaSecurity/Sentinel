using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    public class RouteTableMonitor : IDisposable
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<RouteTableMonitor> _logger;
        private readonly System.Threading.Timer _timer;

        private readonly ConcurrentDictionary<string, RouteEntry> _baselineRoutes = new();
        private bool _baselineCaptured;

        private readonly ConcurrentDictionary<string, DateTime> _alertedEvents = new();
        private static readonly TimeSpan AlertDedupeWindow = TimeSpan.FromMinutes(10);

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

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_IPFORWARDROW
        {
            public uint dwForwardDest;
            public uint dwForwardMask;
            public int dwForwardPolicy;
            public uint dwForwardNextHop;
            public int dwForwardIfIndex;
            public int dwForwardType;
            public int dwForwardProto;
            public int dwForwardAge;
            public int dwForwardNextHopAS;
            public int dwForwardMetric1;
            public int dwForwardMetric2;
            public int dwForwardMetric3;
            public int dwForwardMetric4;
            public int dwForwardMetric5;
        }

        public RouteTableMonitor(
            DetectionEngine detectionEngine,
            ILogger<RouteTableMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;

            // Wait 15 seconds before capturing baseline to let network stabilize
            _timer = new System.Threading.Timer(InitializeAndPoll, null, TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(30));
        }

        private void InitializeAndPoll(object? state)
        {
            try
            {
                if (!_baselineCaptured)
                {
                    CaptureBaseline();
                    CleanupExistingMaliciousRoutes();
                    return;
                }

                ScanRouteTable();
                PruneAlertCache();
            }
            catch (Exception ex)
            {
                _logger.LogDebug($"RouteTableMonitor poll error: {ex.Message}");
            }
        }

        private void CaptureBaseline()
        {
            try
            {
                var routes = GetRouteTable();
                foreach (var route in routes)
                {
                    _baselineRoutes[route.Key] = route;
                }
                _baselineCaptured = true;
                _logger.LogInformation($"[RouteTableMonitor] Baseline captured — {_baselineRoutes.Count} routes");
            }
            catch (Exception ex)
            {
                _logger.LogError($"[RouteTableMonitor] Failed to capture baseline: {ex.Message}");
            }
        }

        private void ScanRouteTable()
        {
            if (!_baselineCaptured) return;

            var currentRoutes = GetRouteTable();
            var currentKeys = new HashSet<string>(currentRoutes.Select(r => r.Key));
            var baselineKeys = new HashSet<string>(_baselineRoutes.Keys);

            // Check for new routes
            var addedRoutes = currentRoutes.Where(r => !baselineKeys.Contains(r.Key)).ToList();
            foreach (var route in addedRoutes)
            {
                if (IsVirtualAdapterRoute(route.InterfaceIndex)) continue;
                if (route.Destination.StartsWith("169.254.") || route.Destination.StartsWith("224.")) continue;
                if (route.Destination == "255.255.255.255") continue;

                var isHostRoute = route.Mask == "255.255.255.255";
                var isDefaultRoute = route.Destination == "0.0.0.0" && route.Mask == "0.0.0.0";

                if (isHostRoute && route.Protocol == "netmgmt")
                {
                    RemediateMaliciousRoutes(new List<RouteEntry> { route });
                }

                var dedupeKey = $"route_add:{route.Key}";
                if (_alertedEvents.ContainsKey(dedupeKey)) continue;
                _alertedEvents[dedupeKey] = DateTime.UtcNow;

                var ruleName = isDefaultRoute
                    ? "Network Hijack: Default Route Changed"
                    : isHostRoute
                        ? "Network Hijack: Host Route Added (Traffic Redirection)"
                        : "Network Integrity: New Route Added";

                var alert = new DetectionEvent
                {
                    RuleName = ruleName,
                    ProcessName = "Network",
                    ProcessId = 0,
                    Confidence = isDefaultRoute ? 0.90 : isHostRoute ? 0.85 : 0.72,
                    Tier = (isDefaultRoute || isHostRoute) ? DetectionTier.Tier1Behavioral : DetectionTier.Tier2Indicator,
                    Evidence = $"New route detected: {route.Destination}/{route.Mask} → {route.NextHop} (interface {route.InterfaceIndex}, protocol {route.Protocol}, metric {route.Metric}). " +
                               (isHostRoute ? "Host route (/32) targets a specific IP — possible selective traffic redirection. " : "") +
                               (isDefaultRoute ? "DEFAULT ROUTE CHANGED — all traffic now routes through a different gateway. " : ""),
                    Reasoning = isDefaultRoute
                        ? "The default route (0.0.0.0/0) was changed. This redirects ALL internet traffic through a different gateway."
                        : isHostRoute
                            ? "A host-specific route (/32) was added, redirecting traffic to a single IP through a non-standard gateway."
                            : "A new network route was added to the routing table.",
                    Timestamp = DateTime.UtcNow,
                    Metadata = new Dictionary<string, string>
                    {
                        { "destination", route.Destination },
                        { "mask", route.Mask },
                        { "next_hop", route.NextHop },
                        { "interface_index", route.InterfaceIndex.ToString() },
                        { "protocol", route.Protocol },
                        { "metric", route.Metric.ToString() },
                        { "is_host_route", isHostRoute.ToString() },
                        { "is_default_route", isDefaultRoute.ToString() },
                        { "technique", "T1565.002 - Data Manipulation: Transmitted Data Manipulation" }
                    }
                };

                _ = _detectionEngine.EmitAsync(alert);
            }

            // Check for modified routes
            foreach (var route in currentRoutes)
            {
                if (!_baselineRoutes.TryGetValue(route.Key, out var baselineRoute)) continue;

                if (!string.Equals(baselineRoute.NextHop, route.NextHop, StringComparison.OrdinalIgnoreCase))
                {
                    if (IsVirtualAdapterRoute(route.InterfaceIndex)) continue;

                    if (route.Destination == "224.0.0.0" && route.Mask == "240.0.0.0") continue;
                    if (route.Destination == "255.255.255.255") continue;
                    if (route.NextHop == "127.0.0.1" && (route.Destination == "224.0.0.0" || route.Destination == "255.255.255.255" || route.Destination.StartsWith("224."))) continue;

                    var dedupeKey = $"route_mod:{route.Key}:{route.NextHop}";
                    if (_alertedEvents.ContainsKey(dedupeKey)) continue;
                    _alertedEvents[dedupeKey] = DateTime.UtcNow;

                    var alert = new DetectionEvent
                    {
                        RuleName = "Network Hijack: Route Next-Hop Modified",
                        ProcessName = "Network",
                        ProcessId = 0,
                        Confidence = 0.85,
                        Tier = DetectionTier.Tier1Behavioral,
                        Evidence = $"Route {route.Destination}/{route.Mask} next-hop changed from {baselineRoute.NextHop} to {route.NextHop}.",
                        Reasoning = "An existing route's next-hop was modified, redirecting traffic for that destination through a different gateway.",
                        Timestamp = DateTime.UtcNow,
                        Metadata = new Dictionary<string, string>
                        {
                            { "destination", route.Destination },
                            { "mask", route.Mask },
                            { "baseline_next_hop", baselineRoute.NextHop },
                            { "current_next_hop", route.NextHop },
                            { "technique", "T1557 - Adversary-in-the-Middle" }
                        }
                    };

                    _ = _detectionEngine.EmitAsync(alert);
                }
            }

            // Update baseline
            foreach (var route in currentRoutes)
            {
                _baselineRoutes[route.Key] = route;
            }

            foreach (var key in baselineKeys.Except(currentKeys))
            {
                _baselineRoutes.TryRemove(key, out _);
            }
        }

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
                    var row = Marshal.PtrToStructure<MIB_IPFORWARDROW>(buffer + sizeof(int) + (i * rowSize));

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
                foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
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

        private int RemediateMaliciousRoutes(List<RouteEntry> suspiciousRoutes)
        {
            int removed = 0;

            foreach (var route in suspiciousRoutes)
            {
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
                        dwForwardProto = 3,
                        dwForwardMetric1 = route.Metric
                    };

                    int result = DeleteIpForwardEntry(ref row);
                    if (result == 0)
                    {
                        removed++;
                        _logger.LogCritical($"[RouteTableMonitor] REMEDIATED: Deleted malicious route {route.Destination} → {route.NextHop}");
                    }
                }
                catch { }
            }

            return removed;
        }

        public int CleanupExistingMaliciousRoutes()
        {
            try
            {
                var routes = GetRouteTable();
                var suspicious = routes.Where(r =>
                    r.Mask == "255.255.255.255" &&
                    r.Protocol == "netmgmt" &&
                    !IsVirtualAdapterRoute(r.InterfaceIndex) &&
                    r.Destination != "255.255.255.255" &&
                    !r.Destination.StartsWith("224.") &&
                    !r.Destination.StartsWith("169.254.") &&
                    !r.Destination.StartsWith("127.")
                ).ToList();

                if (suspicious.Count == 0) return 0;

                if (suspicious.Count > 10)
                {
                    _logger.LogCritical($"[RouteTableMonitor] Found {suspicious.Count} suspicious persistent /32 host routes on startup. Remediating ALL.");
                    return RemediateMaliciousRoutes(suspicious);
                }

                _logger.LogWarning($"[RouteTableMonitor] Found {suspicious.Count} persistent /32 host routes on startup. Monitoring only.");
            }
            catch (Exception ex)
            {
                _logger.LogDebug($"[RouteTableMonitor] Startup cleanup error: {ex.Message}");
            }
            return 0;
        }

        private void PruneAlertCache()
        {
            var cutoff = DateTime.UtcNow - AlertDedupeWindow;
            foreach (var kvp in _alertedEvents)
            {
                if (kvp.Value < cutoff)
                {
                    _alertedEvents.TryRemove(kvp.Key, out _);
                }
            }
        }

        public void Dispose()
        {
            _timer.Dispose();
            GC.SuppressFinalize(this);
        }

        private class RouteEntry
        {
            public string Destination { get; set; } = string.Empty;
            public string Mask { get; set; } = string.Empty;
            public string NextHop { get; set; } = string.Empty;
            public int InterfaceIndex { get; set; }
            public string Protocol { get; set; } = string.Empty;
            public int Metric { get; set; }
            public int Type { get; set; }

            public string Key => $"{Destination}/{Mask}";
        }
    }
}
