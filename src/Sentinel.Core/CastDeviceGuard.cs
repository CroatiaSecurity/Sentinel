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

namespace Sentinel.Core
{
    /// <summary>
    /// Watches browser connections to Cast protocol ports (8008/8009) on the LAN.
    ///
    /// v1.8.3 observe-first:
    ///   - Empty TrustedCastDevices → LogOnly (do not firewall-block). Normal Chromecast works.
    ///   - Non-empty TrustedCastDevices → enforce allowlist (block unknown LAN Cast IPs).
    ///
    /// Post-incident zero-trust: list only known device IPs (or leave empty to observe).
    /// Inbound "Cast to Device" OS rules are still removed (attack surface; not user traffic).
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
        private bool _legacyCastBlocksCleaned;

        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(5);
        private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(5);
        private static readonly int[] CastPorts = { 8008, 8009 };
        private const string CastBlockRulePrefix = "Sentinel-CastGuard-Block-";

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
            bool enforce = trusted.Length > 0;
            _logger.LogInformation(
                "[CastDeviceGuard] Started — mode={Mode}. Trusted: {Count} ({IPs})",
                enforce ? "ENFORCE-ALLOWLIST" : "OBSERVE-ONLY",
                trusted.Length,
                trusted.Length > 0 ? string.Join(", ", trusted) : "none — log Cast traffic, no preemptive blocks");

            // v1.4.2: Delete Windows built-in "Cast to Device" inbound firewall rules.
            // These allow ANY LAN device to push RTSP/HTTP streams INTO this machine.
            // A rogue Cast device uses exactly these rules to connect inbound.
            DeleteCastToDeviceInboundRules();

            // v1.8.3: empty allowlist must not leave residual CastGuard blocks from older builds
            if (!enforce && !_legacyCastBlocksCleaned)
            {
                RemoveLegacyCastGuardBlocks();
                _legacyCastBlocksCleaned = true;
            }

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

        /// <summary>
        /// Removes Sentinel-CastGuard-Block-* rules when running in observe-only mode
        /// so upgrades stop obstructing normal Chromecast use.
        /// </summary>
        private void RemoveLegacyCastGuardBlocks()
        {
            try
            {
                var policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                if (policyType == null) return;
                dynamic? policy = Activator.CreateInstance(policyType);
                if (policy == null) return;

                var toRemove = new List<string>();
                foreach (dynamic rule in policy.Rules)
                {
                    try
                    {
                        string? name = rule.Name as string;
                        if (name != null && name.StartsWith(CastBlockRulePrefix))
                            toRemove.Add(name);
                    }
                    catch { }
                }

                foreach (var name in toRemove)
                {
                    try { policy.Rules.Remove(name); } catch { }
                }

                if (toRemove.Count > 0)
                {
                    _logger.LogWarning(
                        "[CastDeviceGuard] Removed {Count} leftover CastGuard firewall rules (observe-only mode)",
                        toRemove.Count);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[CastDeviceGuard] Legacy Cast block cleanup failed");
            }
        }

        /// <summary>
        /// Deletes all Windows built-in "Cast to Device" inbound firewall rules and
        /// "Media Center Extenders" rules. These allow any LAN device to connect inbound
        /// on RTSP/HTTP streaming ports — the exact attack surface for rogue Cast relays.
        /// Self-healing: runs every service start in case Windows Update re-creates them.
        /// </summary>
        private void DeleteCastToDeviceInboundRules()
        {
            try
            {
                var policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                if (policyType == null) return;
                dynamic? policy = Activator.CreateInstance(policyType);
                if (policy == null) return;

                var toDelete = new List<string>();
                foreach (dynamic rule in policy.Rules)
                {
                    string name = (string)rule.Name;
                    int direction = (int)rule.Direction; // 1 = Inbound

                    if (direction == 1 &&
                        (name.Contains("Cast to Device") ||
                         name.Contains("Media Center Extenders") ||
                         name.Contains("RTSP-Streaming-In") ||
                         name.Contains("HTTP-Streaming-In") ||
                         name.Contains("RTCP-Streaming-In")))
                    {
                        toDelete.Add(name);
                    }
                }

                foreach (var name in toDelete)
                {
                    try { policy.Rules.Remove(name); } catch { }
                }

                if (toDelete.Count > 0)
                {
                    _logger.LogWarning("[CastDeviceGuard] DELETED {Count} inbound Cast/Media streaming firewall rules (attack surface removal)",
                        toDelete.Count);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[CastDeviceGuard] Failed to delete Cast inbound rules");
            }
        }

        private async Task ScanAndKillCastConnections(CancellationToken ct)
        {
            var trusted = _config.TrustedCastDevices ?? Array.Empty<string>();
            bool enforceAllowlist = trusted.Length > 0;
            var connections = GetEstablishedTcpConnections();

            foreach (var conn in connections)
            {
                if (ct.IsCancellationRequested) break;
                if (!CastPorts.Contains(conn.RemotePort)) continue;
                if (!IsPrivateIp(conn.RemoteAddress)) continue;

                // Explicitly trusted by user? Leave it alone.
                if (enforceAllowlist &&
                    trusted.Contains(conn.RemoteAddress, StringComparer.OrdinalIgnoreCase))
                    continue;

                // Observe-only when no allowlist configured — do not obstruct normal Cast.
                if (!enforceAllowlist)
                {
                    var observeKey = $"obs:{conn.RemoteAddress}:{conn.RemotePort}";
                    if (_alertedConnections.TryGetValue(observeKey, out var lastObs) &&
                        DateTimeOffset.UtcNow - lastObs < AlertCooldown)
                        continue;
                    _alertedConnections[observeKey] = DateTimeOffset.UtcNow;

                    string obsProc;
                    try
                    {
                        using var proc = Process.GetProcessById(conn.OwnerPid);
                        obsProc = proc.ProcessName;
                    }
                    catch { continue; }

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Cast Device Guard: Cast Connection Observed",
                        Evidence = $"Process '{obsProc}' (PID {conn.OwnerPid}) → " +
                                   $"{conn.RemoteAddress}:{conn.RemotePort}. " +
                                   "TrustedCastDevices empty — observe-only (no firewall block).",
                        Reasoning = "Cast-port traffic on the LAN was observed. With an empty allowlist " +
                                    "Sentinel logs only so Chromecast/Nest casting keeps working. " +
                                    "Set TrustedCastDevices to known IPs to enforce an allowlist after " +
                                    "a rogue Cast/phantom device incident.",
                        Confidence = 0.55,
                        Tier = DetectionTier.Tier2Indicator,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = obsProc,
                        ProcessId = conn.OwnerPid,
                        SignalType = SignalType.NetworkC2,
                        Metadata = new Dictionary<string, string>
                        {
                            ["RemoteIP"] = conn.RemoteAddress,
                            ["RemotePort"] = conn.RemotePort.ToString(),
                            ["Mode"] = "observe-only",
                            ["FirewallBlocked"] = "False"
                        }
                    });
                    continue;
                }

                // Enforce mode: NOT in allowlist → block at firewall and alert.
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
                    RuleName = "Cast Device Guard: Unauthorized Cast Connection Blocked",
                    Evidence = $"Process '{procName}' (PID {conn.OwnerPid}) → " +
                               $"{conn.RemoteAddress}:{conn.RemotePort}. " +
                               $"NOT in TrustedCastDevices. Firewall block applied.",
                    Reasoning = "A process connected to a LAN device on Cast port (8008/8009). " +
                                "TrustedCastDevices is non-empty and this IP is not listed. " +
                                "Rogue LAN devices use Cast protocol as a C2 relay through the browser.",
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
                        ["Mode"] = "enforce-allowlist",
                        ["FirewallBlocked"] = "True"
                    }
                });
            }
        }

        private async Task EnsureFirewallBlock(string ip)
        {
            // v1.6.0: Strict IP validation before interpolating into netsh
            if (!System.Net.IPAddress.TryParse(ip, out var parsed) ||
                System.Net.IPAddress.IsLoopback(parsed) ||
                parsed.Equals(System.Net.IPAddress.Any) ||
                parsed.Equals(System.Net.IPAddress.IPv6Any) ||
                parsed.Equals(System.Net.IPAddress.Broadcast))
            {
                _logger.LogDebug("[CastDeviceGuard] Refusing firewall block for invalid IP: {IP}", ip);
                return;
            }

            // Normalize to canonical form (strips any junk that TryParse accepted)
            ip = parsed.ToString();
            if (_blockedIps.ContainsKey(ip)) return;
            try
            {
                var safeLabel = ip.Replace('.', '_').Replace(':', '_');
                var ruleName = $"Sentinel-CastGuard-Block-{safeLabel}";
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
