using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Monitors active TCP connections for behavioral anomalies:
    /// - Connections to non-standard ports from system binaries
    /// - High-frequency outbound connections (beaconing)
    /// - Connections from processes running in suspicious paths
    /// Purely behavioral — no domain/IP blocklists.
    /// </summary>
    public sealed class NetworkMonitor : IDisposable
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly TelemetryFusionEngine _fusionEngine;
        private readonly ProcessAncestryCache _ancestryCache;
        private readonly BeaconingDetector _beaconingDetector;
        private readonly ILogger<NetworkMonitor> _logger;
        private readonly BehavioralBaselineService? _behavioralBaseline;
        private readonly System.Threading.Timer _timer;
        private readonly ConcurrentDictionary<string, int> _connectionCounts = new();

        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(15);

        private static readonly HashSet<string> ShellProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "cmd", "powershell", "pwsh", "mshta", "wscript", "cscript", "rundll32", "regsvr32", "bash", "sh"
        };

        private static readonly HashSet<int> StandardPorts = new() { 80, 443, 53, 8080, 8443 };

        public NetworkMonitor(
            DetectionEngine detectionEngine,
            TelemetryFusionEngine fusionEngine,
            ProcessAncestryCache ancestryCache,
            BeaconingDetector beaconingDetector,
            ILogger<NetworkMonitor> logger,
            BehavioralBaselineService? behavioralBaseline = null)
        {
            _detectionEngine = detectionEngine;
            _fusionEngine = fusionEngine;
            _ancestryCache = ancestryCache;
            _beaconingDetector = beaconingDetector;
            _behavioralBaseline = behavioralBaseline;
            _logger = logger;
            _timer = new System.Threading.Timer(ScanConnections, null, ScanInterval, ScanInterval);
        }

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

        private enum TCP_TABLE_CLASS
        {
            TCP_TABLE_BASIC_LISTENER,
            TCP_TABLE_BASIC_CONNECTIONS,
            TCP_TABLE_BASIC_ALL,
            TCP_TABLE_OWNER_PID_LISTENER,
            TCP_TABLE_OWNER_PID_CONNECTIONS,
            TCP_TABLE_OWNER_PID_ALL,
            TCP_TABLE_OWNER_MODULE_LISTENER,
            TCP_TABLE_OWNER_MODULE_CONNECTIONS,
            TCP_TABLE_OWNER_MODULE_ALL
        }

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(
            IntPtr pTcpTable,
            ref int pdwSize,
            bool bOrder,
            uint ulAf,
            TCP_TABLE_CLASS tableClass,
            uint reserved);

        private static int GetPort(uint portDword)
        {
            return (int)((portDword & 0xFF) << 8 | (portDword & 0xFF00) >> 8);
        }

        private static bool IsOutbound(string ipStr)
        {
            if (string.IsNullOrEmpty(ipStr)) return false;
            if (ipStr == "0.0.0.0" || ipStr == "255.255.255.255") return false;
            if (IPAddress.TryParse(ipStr, out var ip))
            {
                if (IPAddress.IsLoopback(ip)) return false;
                return true;
            }
            return false;
        }

        private static bool IsSuspiciousPath(string? path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            var lower = path.ToLowerInvariant();
            return lower.Contains(@"\temp\") || lower.Contains(@"\downloads\");
        }

        private static bool IsKnownBrowser(string? processName)
        {
            if (string.IsNullOrEmpty(processName)) return false;
            var lower = processName.ToLowerInvariant();
            return lower == "chrome" || lower == "chrome.exe" ||
                   lower == "msedge" || lower == "msedge.exe" ||
                   lower == "firefox" || lower == "firefox.exe" ||
                   lower == "brave" || lower == "brave.exe" ||
                   lower == "opera" || lower == "opera.exe" ||
                   lower == "vivaldi" || lower == "vivaldi.exe" ||
                   lower == "safari" || lower == "safari.exe";
        }

        private static string? GetProcessImagePath(int pid)
        {
            return SecurityValidation.GetProcessImagePath(pid);
        }

        private void ScanConnections(object? state)
        {
            try
            {
                int size = 0;
                uint ret = GetExtendedTcpTable(IntPtr.Zero, ref size, true, 2, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
                if (ret != 122) // ERROR_INSUFFICIENT_BUFFER
                {
                    _logger.LogWarning("[NetworkMonitor] GetExtendedTcpTable failed to get size: {Ret}", ret);
                    return;
                }

                IntPtr buffer = Marshal.AllocHGlobal(size);
                try
                {
                    ret = GetExtendedTcpTable(buffer, ref size, true, 2, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
                    if (ret != 0)
                    {
                        _logger.LogWarning("[NetworkMonitor] GetExtendedTcpTable failed: {Ret}", ret);
                        return;
                    }

                    int numEntries = Marshal.ReadInt32(buffer);
                    int structSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
                    int myPid = Environment.ProcessId;

                    var currentCounts = new Dictionary<string, int>();

                    for (int i = 0; i < numEntries; i++)
                    {
                        IntPtr rowPtr = IntPtr.Add(buffer, 4 + i * structSize);
                        var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);

                        // State == 5 (Established)
                        if (row.state != 5) continue;
                        if (row.owningPid <= 4 || row.owningPid == myPid) continue;

                        var localIp = new IPAddress(BitConverter.GetBytes(row.localAddr)).ToString();
                        var remoteIp = new IPAddress(BitConverter.GetBytes(row.remoteAddr)).ToString();
                        var localPort = GetPort(row.localPort);
                        var remotePort = GetPort(row.remotePort);

                        var key = $"{remoteIp}:{remotePort}";
                        currentCounts[key] = currentCounts.GetValueOrDefault(key) + 1;

                        if (IsOutbound(remoteIp))
                        {
                            var processName = "unknown";
                            var (parentPid, name) = _ancestryCache.GetParent((int)row.owningPid);
                            if (name != "unknown")
                            {
                                processName = name;
                            }
                            else
                            {
                                try
                                {
                                    using var p = Process.GetProcessById((int)row.owningPid);
                                    processName = p.ProcessName;
                                }
                                catch
                                {
                                    // Ignore
                                }
                            }

                             var imagePath = GetProcessImagePath((int)row.owningPid);

                             // 1. Record connection in statistical beaconing detector
                             _beaconingDetector.RecordConnection(remoteIp, remotePort, (int)row.owningPid, processName, imagePath, "Established");
 
                             // 1.5. Record connection in behavioral baseline
                             _behavioralBaseline?.RecordNetworkConnection(processName, remoteIp, remotePort);
 
                             // 2. Behavioral checks
                            // A. Shell process outbound to non-standard port
                            if (ShellProcesses.Contains(processName) && !StandardPorts.Contains(remotePort))
                            {
                                _ = _detectionEngine.EmitAsync(new DetectionEvent
                                {
                                    RuleName = "Reverse Shell: Suspicious Outbound Connection",
                                    Evidence = $"Shell process '{processName}' (PID {row.owningPid}) connected to non-standard remote port {remotePort} ({remoteIp}:{remotePort})",
                                    Reasoning = "A shell process initiated an outbound network connection to a non-standard port, indicating a potential active reverse shell or remote access tool session.",
                                    Confidence = 0.85,
                                    Tier = DetectionTier.Tier1Behavioral,
                                    AuthorizedResponse = ResponseAction.KillProcessTree,
                                    ProcessName = processName,
                                    ProcessId = (int)row.owningPid,
                                    Metadata = new Dictionary<string, string>
                                    {
                                        { "RemoteAddress", remoteIp },
                                        { "RemotePort", remotePort.ToString() },
                                        { "LocalAddress", localIp },
                                        { "LocalPort", localPort.ToString() }
                                    }
                                });
                            }

                            // B. Outbound connection from temp/downloads path
                            // Demoted to Tier2/LogOnly — too many false positives on legitimate portable tools
                            // (aria2c, RogueKiller, portable browsers, etc.)
                            // Real threats from Downloads will be caught by:
                            // - FileVerdictScanner (hash reputation check + Deny Execute ACL)
                            // - BeaconingDetector (statistical C2 pattern)
                            // - BehavioralCorrelationEngine (multi-signal composite)
                            if (IsSuspiciousPath(imagePath) && !IsKnownBrowser(processName))
                            {
                                _ = _detectionEngine.EmitAsync(new DetectionEvent
                                {
                                    RuleName = "Attack Tool: Connection from Suspicious Path",
                                    Evidence = $"Process '{processName}' (PID {row.owningPid}) running from '{imagePath}' connected to {remoteIp}:{remotePort}",
                                    Reasoning = "A binary running from a temporary or downloads directory initiated an outbound network connection. Logged as an indicator — legitimate portable tools also do this. Kill only if corroborated by hash reputation (Unsafe) or additional behavioral signals.",
                                    Confidence = 0.50,
                                    Tier = DetectionTier.Tier2Indicator,
                                    AuthorizedResponse = ResponseAction.LogOnly,
                                    ProcessName = processName,
                                    ProcessId = (int)row.owningPid,
                                    Metadata = new Dictionary<string, string>
                                    {
                                        { "ImagePath", imagePath ?? "" },
                                        { "RemoteAddress", remoteIp },
                                        { "RemotePort", remotePort.ToString() },
                                        { "LocalAddress", localIp },
                                        { "LocalPort", localPort.ToString() }
                                    }
                                });
                            }

                            // 3. Submit network telemetry context to telemetry pipeline
                            var telemetry = new NetworkTelemetry
                            {
                                Type = "NetworkConnection",
                                ProcessId = (int)row.owningPid,
                                ProcessName = processName,
                                LocalAddress = localIp,
                                LocalPort = localPort,
                                RemoteAddress = remoteIp,
                                RemotePort = remotePort,
                                Protocol = "TCP",
                                State = "ESTABLISHED",
                                Timestamp = DateTime.UtcNow
                            };
                            var context = _fusionEngine.FeedEvent(telemetry);
                            _detectionEngine.SubmitTelemetry(context);
                        }
                    }

                    foreach (var (key, count) in currentCounts)
                    {
                        _connectionCounts[key] = count;
                    }

                    // Prune stale entries
                    var staleKeys = _connectionCounts.Keys.Except(currentCounts.Keys).ToList();
                    foreach (var k in staleKeys)
                    {
                        _connectionCounts.TryRemove(k, out _);
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[NetworkMonitor] Scan error");
            }
        }

        public void Dispose()
        {
            _timer.Dispose();
        }
    }
}
