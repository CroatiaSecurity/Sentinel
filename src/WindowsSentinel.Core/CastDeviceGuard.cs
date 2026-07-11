using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
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
    /// Kills ALL browser connections to Cast protocol ports (8008/8009) on the LAN
    /// unless the target IP is in the explicit allowlist.
    ///
    /// No baseline. No OUI trust. No "probably legitimate" logic.
    /// Empty allowlist = every Cast port connection on the LAN gets killed.
    ///
    /// If you have a real Chromecast, add its IP to appsettings.json:
    ///   "Sentinel": { "TrustedCastDevices": ["192.168.1.50"] }
    ///
    /// v1.0.4: Rewritten from baseline-based to allowlist-only.
    /// </summary>
    public sealed class CastDeviceGuard : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly SentinelConfig _config;
        private readonly ILogger<CastDeviceGuard> _logger;

        private readonly ConcurrentDictionary<string, DateTimeOffset> _alertedConnections = new();
        private readonly ConcurrentDictionary<string, string> _blockedIps = new();

        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(5);
        private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(5);
        private static readonly int[] CastPorts = { 8008, 8009 };

        private static readonly HashSet<string> BrowserProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "chrome", "msedge", "brave", "vivaldi", "opera", "chromium"
        };

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize,
            bool bOrder, int ulAf, int tableClass, uint reserved);

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID
        {
            public uint state;
            public uint localAddr;
            public uint localPort;
            public uint remoteAddr;
            public uint remotePort;
            public uint owningPid;
        }

        public CastDeviceGuard(
            DetectionEngine detectionEngine,
            SentinelConfig config,
            ILogger<CastDeviceGuard> logger)
        {
            _detectionEngine = detectionEngine;
            _config = config;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            var trusted = _config.TrustedCastDevices ?? Array.Empty<string>();
            _logger.LogInformation(
                "[CastDeviceGuard] Started — allowlist mode. Trusted: {Count} ({IPs})",
                trusted.Length,
                trusted.Length > 0 ? string.Join(", ", trusted) : "NONE — all Cast connections killed");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(ScanInterval, ct);
                    await ScanAndKillCastConnections(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[CastDeviceGuard] Error"); }
            }
        }

        private async Task ScanAndKillCastConnections(CancellationToken ct)
        {
            var trusted = _config.TrustedCastDevices ?? Array.Empty<string>();
            var connections = GetEstablishedTcpConnections();

            foreach (var conn in connections)
            {
                if (ct.IsCancellationRequested) break;
                if (!CastPorts.Contains(conn.RemotePort)) continue;
                if (!IsPrivateIp(conn.RemoteAddress)) continue;

                // Explicitly trusted by user? Leave it alone.
                if (trusted.Contains(conn.RemoteAddress, StringComparer.OrdinalIgnoreCase))
                    continue;

                // NOT trusted. Block at firewall and alert.
                string procName;
                try
                {
                    using var proc = Process.GetProcessById(conn.OwnerPid);
                    procName = proc.ProcessName;
                }
                catch { continue; }

                await EnsureFirewallBlock(conn.RemoteAddress);

                var alertKey = $"{conn.RemoteAddress}:{conn.RemotePort}";
                if (_alertedConnections.TryGetValue(alertKey, out var lastAlert) &&
                    DateTimeOffset.UtcNow - lastAlert < AlertCooldown)
                    continue;

                _alertedConnections[alertKey] = DateTimeOffset.UtcNow;
                bool isBrowser = BrowserProcesses.Contains(procName);

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Cast Device Guard: Unauthorized Cast Connection Killed",
                    Evidence = $"Process '{procName}' (PID {conn.OwnerPid}) → " +
                               $"{conn.RemoteAddress}:{conn.RemotePort}. " +
                               $"NOT in TrustedCastDevices. Firewall block applied.",
                    Reasoning = "A process connected to a LAN device on Cast port (8008/8009). " +
                                "The IP is not in the explicit allowlist. All unapproved Cast " +
                                "connections are killed — rogue LAN devices use Cast protocol " +
                                "to stream screen content and relay C2 through the browser.",
                    Confidence = 0.92,
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.LogOnly,
                    ProcessName = procName,
                    ProcessId = conn.OwnerPid,
                    SignalType = SignalType.NetworkC2,
                    Metadata = new Dictionary<string, string>
                    {
                        ["RemoteIP"] = conn.RemoteAddress,
                        ["RemotePort"] = conn.RemotePort.ToString(),
                        ["IsBrowser"] = isBrowser.ToString(),
                        ["FirewallBlocked"] = "True"
                    }
                });
            }
        }

        private async Task EnsureFirewallBlock(string ip)
        {
            if (_blockedIps.ContainsKey(ip)) return;
            try
            {
                var ruleName = $"Sentinel-CastGuard-Block-{ip.Replace('.', '_')}";
                var psi = new ProcessStartInfo("netsh",
                    $"advfirewall firewall add rule name=\"{ruleName}-OUT\" dir=out action=block remoteip={ip} enable=yes")
                {
                    UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true
                };
                using (var proc = Process.Start(psi))
                { if (proc != null) await proc.WaitForExitAsync(); }

                psi.Arguments = $"advfirewall firewall add rule name=\"{ruleName}-IN\" dir=in action=block remoteip={ip} enable=yes";
                using (var proc = Process.Start(psi))
                { if (proc != null) await proc.WaitForExitAsync(); }

                _blockedIps[ip] = ruleName;
                _logger.LogInformation("[CastDeviceGuard] Firewall block: {IP}", ip);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[CastDeviceGuard] Firewall rule failed for {IP}", ip);
            }
        }

        private static bool IsPrivateIp(string ip)
        {
            if (ip.StartsWith("10.")) return true;
            if (ip.StartsWith("192.168.")) return true;
            if (ip.StartsWith("172."))
            {
                var parts = ip.Split('.');
                if (parts.Length >= 2 && int.TryParse(parts[1], out int second))
                    return second >= 16 && second <= 31;
            }
            return false;
        }

        private List<TcpConnectionInfo> GetEstablishedTcpConnections()
        {
            var results = new List<TcpConnectionInfo>();
            int size = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref size, false, 2, 5, 0);
            if (size == 0) return results;
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                if (GetExtendedTcpTable(buffer, ref size, false, 2, 5, 0) != 0) return results;
                int numEntries = Marshal.ReadInt32(buffer);
                int structSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
                for (int i = 0; i < numEntries; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(
                        IntPtr.Add(buffer, 4 + i * structSize));
                    if (row.state != 5 || row.owningPid <= 4) continue;
                    var remoteIp = new IPAddress(BitConverter.GetBytes(row.remoteAddr)).ToString();
                    var remotePort = (int)((row.remotePort >> 8) | ((row.remotePort & 0xFF) << 8));
                    results.Add(new TcpConnectionInfo
                    { OwnerPid = (int)row.owningPid, RemoteAddress = remoteIp, RemotePort = remotePort });
                }
            }
            finally { Marshal.FreeHGlobal(buffer); }
            return results;
        }

        private class TcpConnectionInfo
        {
            public int OwnerPid { get; set; }
            public string RemoteAddress { get; set; } = "";
            public int RemotePort { get; set; }
        }
    }
}
