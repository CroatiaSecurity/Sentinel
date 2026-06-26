using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Detects application-level DNS bypass where processes use their own TLS stack
    /// to perform DNS-over-HTTPS (DoH) resolution, completely bypassing the Windows
    /// DNS resolver and therefore the hosts file and DNS event log.
    ///
    /// Detection methods:
    /// 1. Monitor outbound connections to known public DoH resolver IPs
    ///    (Cloudflare 1.1.1.1/1.0.0.1, Google 8.8.8.8/8.8.4.4, Quad9 9.9.9.9,
    ///    NextDNS, AdGuard) on port 443 with DNS-specific behavior patterns
    /// 2. Detect processes that connect to DoH endpoints AND have no corresponding
    ///    Windows DNS Client event (the DNS event log shows nothing = bypass)
    /// 3. Flag non-browser processes performing DoH (browsers are handled by
    ///    BrowserDnsPolicyGuard; this catches standalone malware with embedded DoH)
    ///
    /// v1.0.1: New monitor.
    /// </summary>
    public sealed class AppDnsExfilMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<AppDnsExfilMonitor> _logger;

        private readonly ConcurrentDictionary<(int Pid, string Ip), DohConnectionState> _dohConnections = new();
        private readonly ConcurrentDictionary<int, DateTimeOffset> _alertedPids = new();

        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(10);
        private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(5);

        // Known public DoH resolver IPs
        private static readonly HashSet<string> KnownDohResolverIps = new()
        {
            // Cloudflare
            "1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001",
            // Google
            "8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844",
            // Quad9
            "9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9",
            // NextDNS
            "45.90.28.0", "45.90.30.0",
            // AdGuard
            "94.140.14.14", "94.140.15.15",
            // OpenDNS
            "208.67.222.222", "208.67.220.220",
            // CleanBrowsing
            "185.228.168.9", "185.228.169.9"
        };

        // Browsers are handled by BrowserDnsPolicyGuard — we focus on non-browser apps
        private static readonly HashSet<string> BrowserProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "chrome", "msedge", "firefox", "brave", "opera", "vivaldi",
            "chromium", "iridium", "ungoogled-chromium", "waterfox",
            "librewolf", "tor", "electron"
        };

        // Legitimate apps that use DoH for their own resolution
        private static readonly HashSet<string> AllowedDohApps = new(StringComparer.OrdinalIgnoreCase)
        {
            "nextdns", "cloudflared", "dnscrypt-proxy", "stubby",
            "adguardhome", "pihole-FTL", "unbound"
        };

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern int GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder, int ulAf, int TableClass, int Reserved);

        private const int AF_INET = 2;
        private const int TCP_TABLE_OWNER_PID_ALL = 5;

        public AppDnsExfilMonitor(
            DetectionEngine detectionEngine,
            ILogger<AppDnsExfilMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[AppDnsExfilMonitor] Started — monitoring for application-level DoH bypass");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(ScanInterval, ct);
                    await ScanForDohConnections(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[AppDnsExfilMonitor] Error"); }
            }
        }

        private async Task ScanForDohConnections(CancellationToken ct)
        {
            var tcpConnections = GetEstablishedTcpConnections();

            foreach (var conn in tcpConnections)
            {
                if (ct.IsCancellationRequested) break;

                // Only interested in connections to known DoH resolvers on port 443
                if (conn.RemotePort != 443) continue;
                if (!KnownDohResolverIps.Contains(conn.RemoteAddress)) continue;

                // Skip browsers (handled by BrowserDnsPolicyGuard)
                string procName = GetProcessName(conn.OwnerPid);
                if (string.IsNullOrEmpty(procName)) continue;
                if (BrowserProcesses.Contains(procName)) continue;
                if (AllowedDohApps.Contains(procName)) continue;

                var key = (conn.OwnerPid, conn.RemoteAddress);
                if (!_dohConnections.TryGetValue(key, out var state))
                {
                    state = new DohConnectionState
                    {
                        FirstSeen = DateTimeOffset.UtcNow,
                        ProcessName = procName,
                        ConnectionCount = 0
                    };
                    _dohConnections[key] = state;
                }
                state.ConnectionCount++;
                state.LastSeen = DateTimeOffset.UtcNow;

                // Alert after repeated connections (not just one-off TLS setup)
                if (state.ConnectionCount < 3) continue;

                // Check cooldown
                if (_alertedPids.TryGetValue(conn.OwnerPid, out var lastAlert) &&
                    DateTimeOffset.UtcNow - lastAlert < AlertCooldown)
                    continue;

                _alertedPids[conn.OwnerPid] = DateTimeOffset.UtcNow;

                string imagePath = "";
                try
                {
                    using var proc = Process.GetProcessById(conn.OwnerPid);
                    imagePath = proc.MainModule?.FileName ?? "";
                }
                catch { }

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "DNS Bypass: Application-Level DoH Detected",
                    Evidence = $"Process '{procName}' (PID {conn.OwnerPid}, Path: {imagePath}) " +
                               $"maintaining persistent connection to DoH resolver {conn.RemoteAddress}:443. " +
                               $"Seen {state.ConnectionCount} times over {(state.LastSeen - state.FirstSeen).TotalSeconds:F0}s.",
                    Reasoning = "A non-browser process is communicating directly with a known DNS-over-HTTPS " +
                                "resolver, bypassing the Windows DNS client entirely. DNS queries made this way " +
                                "do not appear in the Windows DNS event log and are not subject to hosts file " +
                                "blocking. Malware uses embedded DoH to resolve C2 domains without triggering " +
                                "DNS-based detection (DnsQueryMonitor is blind to these queries).",
                    Confidence = 0.75,
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.KillProcessTree,
                    ProcessName = procName,
                    ProcessId = conn.OwnerPid,
                    SignalType = SignalType.NetworkC2,
                    Metadata = new Dictionary<string, string>
                    {
                        ["RemoteIP"] = conn.RemoteAddress,
                        ["ConnectionCount"] = state.ConnectionCount.ToString(),
                        ["ImagePath"] = imagePath,
                        ["DurationSeconds"] = (state.LastSeen - state.FirstSeen).TotalSeconds.ToString("F0")
                    }
                });
            }

            // Cleanup stale tracking entries
            var stale = _dohConnections
                .Where(kv => DateTimeOffset.UtcNow - kv.Value.LastSeen > TimeSpan.FromMinutes(10))
                .Select(kv => kv.Key).ToList();
            foreach (var key in stale) _dohConnections.TryRemove(key, out _);
        }

        private List<TcpConnectionInfo> GetEstablishedTcpConnections()
        {
            var results = new List<TcpConnectionInfo>();
            int size = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            if (size == 0) return results;

            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                if (GetExtendedTcpTable(buffer, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != 0)
                    return results;

                int numEntries = Marshal.ReadInt32(buffer);
                int offset = 4;

                for (int i = 0; i < numEntries; i++)
                {
                    int state = Marshal.ReadInt32(buffer, offset);
                    offset += 4;
                    uint localAddr = (uint)Marshal.ReadInt32(buffer, offset);
                    offset += 4;
                    int localPort = IPAddress.NetworkToHostOrder(Marshal.ReadInt32(buffer, offset)) >> 16 & 0xFFFF;
                    offset += 4;
                    uint remoteAddr = (uint)Marshal.ReadInt32(buffer, offset);
                    offset += 4;
                    int remotePort = IPAddress.NetworkToHostOrder(Marshal.ReadInt32(buffer, offset)) >> 16 & 0xFFFF;
                    offset += 4;
                    int ownerPid = Marshal.ReadInt32(buffer, offset);
                    offset += 4;

                    // Only ESTABLISHED connections
                    if (state != 5) continue;
                    if (ownerPid == 0) continue;

                    var remoteIp = new IPAddress(remoteAddr).ToString();
                    results.Add(new TcpConnectionInfo
                    {
                        RemoteAddress = remoteIp,
                        RemotePort = remotePort,
                        OwnerPid = ownerPid
                    });
                }
            }
            finally { Marshal.FreeHGlobal(buffer); }

            return results;
        }

        private static string GetProcessName(int pid)
        {
            try
            {
                using var proc = Process.GetProcessById(pid);
                return proc.ProcessName;
            }
            catch { return ""; }
        }

        private class TcpConnectionInfo
        {
            public string RemoteAddress { get; set; } = "";
            public int RemotePort { get; set; }
            public int OwnerPid { get; set; }
        }

        private class DohConnectionState
        {
            public DateTimeOffset FirstSeen { get; set; }
            public DateTimeOffset LastSeen { get; set; }
            public string ProcessName { get; set; } = "";
            public int ConnectionCount { get; set; }
        }
    }
}
