using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

using System.Runtime.InteropServices;

namespace WindowsSentinel.Core
{
    public class AppNetworkPolicyMonitor : IDisposable
    {
        private readonly DateTime _startTime = DateTime.UtcNow;
        private readonly ConcurrentDictionary<string, HashSet<string>> _processSubnets = new();
        private readonly DetectionEngine _detectionEngine;
        private readonly ProcessAncestryCache _ancestryCache;
        private readonly SignerTrustService? _signerTrust;
        private readonly System.Threading.Timer _timer;

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID
        {
            public uint dwState;
            public uint dwLocalAddr;
            public uint dwLocalPort;
            public uint dwRemoteAddr;
            public uint dwRemotePort;
            public uint dwOwningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCP6ROW_OWNER_PID
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] ucLocalAddr;
            public uint dwLocalScopeId;
            public uint dwLocalPort;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] ucRemoteAddr;
            public uint dwRemoteScopeId;
            public uint dwRemotePort;
            public uint dwState;
            public uint dwOwningPid;
        }

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(
            IntPtr pTcpTable,
            ref uint pdwSize,
            bool bOrder,
            uint ulAf,
            int tableClass,
            uint reserved = 0);

        private const int AF_INET = 2;
        private const int TCP_TABLE_OWNER_PID_ALL = 5;
        private const int MIB_TCP_STATE_ESTAB = 5;

        private const int LearningPhaseDurationMinutes = 30;
        private const int MaxSubnetsPerProcess = 1000;
        private const int MaxProcesses = 5000;

        private static readonly HashSet<string> NetworkAllowlist = new(StringComparer.OrdinalIgnoreCase)
        {
            // Browsers
            "chrome", "msedge", "firefox", "brave", "opera", "vivaldi", "msedgewebview2",
            // Windows system
            "svchost", "lsass", "sihost", "taskhostw", "RuntimeBroker", "SystemSettings",
            "SearchHost", "backgroundTaskHost", "usocoreworker", "System",
            "StartMenuExperienceHost", "ShellExperienceHost", "WidgetService", "widgets",
            // Microsoft services
            "MsMpEng", "MpDefenderCoreService", "NisSrv", "SgrmBroker",
            "OneDrive", "OneDriveStandaloneUpdater",
            "MicrosoftStartFeedProvider",
            // Dev tools & Electron apps
            "code", "cursor", "Devin", "kiro", "Antigravity IDE",
            "Slack", "Discord", "Teams", "Spotify",
            "steamwebhelper", "steam",
            // Hardware / GPU
            "NVDisplay.Container", "nvcontainer",
            "RazerCentralService", "CorsairService",
            // Windows Sentinel itself
            "WindowsSentinel.Service", "WindowsSentinel.Agent"
        };

        public AppNetworkPolicyMonitor(DetectionEngine detectionEngine, ProcessAncestryCache ancestryCache, SignerTrustService? signerTrust = null)
        {
            _detectionEngine = detectionEngine;
            _ancestryCache = ancestryCache;
            _signerTrust = signerTrust;
            // Scan TCP connections every 500 milliseconds to prevent TOCTOU gaps
            _timer = new System.Threading.Timer(ScanNetworkConnections, null, TimeSpan.FromMilliseconds(500), TimeSpan.FromMilliseconds(500));
        }

        private void ScanNetworkConnections(object? state)
        {
            try
            {
                // Helper to resolve process name and register the connection
                void ProcessEstabConnection(int pid, string remoteIp)
                {
                    if (pid <= 0) return;

                    string processName = "unknown";
                    var ancestry = _ancestryCache.GetParent(pid);
                    if (ancestry.name != "unknown")
                    {
                        processName = ancestry.name;
                    }
                    else
                    {
                        try
                        {
                            using var proc = System.Diagnostics.Process.GetProcessById(pid);
                            processName = proc.ProcessName;
                        }
                        catch
                        {
                            // Ignore access denied / terminated
                        }
                    }

                    RegisterConnection(pid, processName + ".exe", remoteIp);
                }

                // 1. Scan IPv4 connections
                uint size4 = 0;
                uint ret = GetExtendedTcpTable(IntPtr.Zero, ref size4, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
                if (ret == 122) // ERROR_INSUFFICIENT_BUFFER
                {
                    IntPtr pTable = Marshal.AllocHGlobal((int)size4);
                    try
                    {
                        ret = GetExtendedTcpTable(pTable, ref size4, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
                        if (ret == 0) // NO_ERROR
                        {
                            int numEntries = Marshal.ReadInt32(pTable);
                            IntPtr rowPtr = pTable + Marshal.SizeOf<int>();
                            int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

                            for (int i = 0; i < numEntries; i++)
                            {
                                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                                rowPtr += rowSize;

                                if (row.dwState == MIB_TCP_STATE_ESTAB)
                                {
                                    var remoteIp = new System.Net.IPAddress(row.dwRemoteAddr).ToString();
                                    ProcessEstabConnection((int)row.dwOwningPid, remoteIp);
                                }
                            }
                        }
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(pTable);
                    }
                }

                // 2. Scan IPv6 connections
                uint size6 = 0;
                ret = GetExtendedTcpTable(IntPtr.Zero, ref size6, true, 23 /* AF_INET6 */, TCP_TABLE_OWNER_PID_ALL, 0);
                if (ret == 122) // ERROR_INSUFFICIENT_BUFFER
                {
                    IntPtr pTable = Marshal.AllocHGlobal((int)size6);
                    try
                    {
                        ret = GetExtendedTcpTable(pTable, ref size6, true, 23, TCP_TABLE_OWNER_PID_ALL, 0);
                        if (ret == 0) // NO_ERROR
                        {
                            int numEntries = Marshal.ReadInt32(pTable);
                            IntPtr rowPtr = pTable + Marshal.SizeOf<int>();
                            int rowSize = Marshal.SizeOf<MIB_TCP6ROW_OWNER_PID>();

                            for (int i = 0; i < numEntries; i++)
                            {
                                var row = Marshal.PtrToStructure<MIB_TCP6ROW_OWNER_PID>(rowPtr);
                                rowPtr += rowSize;

                                if (row.dwState == MIB_TCP_STATE_ESTAB)
                                {
                                    var remoteIp = new System.Net.IPAddress(row.ucRemoteAddr).ToString();
                                    ProcessEstabConnection((int)row.dwOwningPid, remoteIp);
                                }
                            }
                        }
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(pTable);
                    }
                }
            }
            catch
            {
                // Degrade gracefully
            }
        }

        public void RegisterConnection(int pid, string processName, string remoteAddress)
        {
            if (string.IsNullOrWhiteSpace(remoteAddress)) return;

            var stem = processName.Replace(".exe", "", StringComparison.OrdinalIgnoreCase);
            if (string.IsNullOrWhiteSpace(stem) || stem.Equals("unknown", StringComparison.OrdinalIgnoreCase)) return;

            if (NetworkAllowlist.Contains(stem)) return;

            // Determine /24 subnet (IPv4) or /32 prefix (IPv6)
            string subnet;
            if (remoteAddress.Contains(':'))
            {
                // IPv6 subnet determination (take first two segments for a /32 subnet equivalent)
                var parts = remoteAddress.Split(':');
                if (parts.Length >= 2)
                {
                    subnet = $"{parts[0]}:{parts[1]}::/32";
                }
                else
                {
                    subnet = remoteAddress;
                }
            }
            else
            {
                // IPv4 subnet determination
                var parts = remoteAddress.Split('.');
                if (parts.Length == 4)
                {
                    subnet = $"{parts[0]}.{parts[1]}.{parts[2]}.0";
                }
                else
                {
                    return;
                }
            }

            if (_processSubnets.Count >= MaxProcesses && !_processSubnets.ContainsKey(processName))
            {
                // Prune or reject new processes to prevent memory exhaustion
                return;
            }

            var subnets = _processSubnets.GetOrAdd(processName, _ => new HashSet<string>());

            lock (subnets)
            {
                if (DateTime.UtcNow - _startTime < TimeSpan.FromMinutes(LearningPhaseDurationMinutes))
                {
                    // Learning phase: record subnet
                    if (subnets.Count < MaxSubnetsPerProcess)
                    {
                        subnets.Add(subnet);
                    }
                }
                else
                {
                    // Enforcement phase: alert on new subnet
                    if (!subnets.Contains(subnet))
                    {
                        EmitPolicyAlert(pid, processName, remoteAddress, subnet);
                        
                        // Add it to prevent alert flood
                        if (subnets.Count < MaxSubnetsPerProcess)
                        {
                            subnets.Add(subnet);
                        }
                    }
                }
            }
        }

        private void EmitPolicyAlert(int pid, string processName, string ipAddress, string subnet)
        {
            // Base confidence for unknown subnet connection
            double confidence = 0.55;

            // If the binary is signed, lower confidence — signed software connecting
            // to new subnets is less suspicious (games, updaters, etc.) but still tracked.
            if (_signerTrust != null && pid > 4)
            {
                confidence = _signerTrust.AdjustConfidence(confidence, pid);
            }

            var alert = new DetectionEvent
            {
                RuleName = "Network Policy: Unusual Destination",
                ProcessName = processName,
                ProcessId = pid,
                Confidence = confidence,
                Tier = DetectionTier.Tier2Indicator,
                Evidence = $"Process '{processName}' connected to unfamiliar /24 subnet: {subnet} (IP: {ipAddress})",
                Reasoning = "Outbound network connection to a subnet not baselined during the initial 30-minute learning phase.",
                Metadata = new Dictionary<string, string>
                {
                    { "RemoteIp", ipAddress },
                    { "Subnet", subnet }
                }
            };

            _ = _detectionEngine.EmitAsync(alert);
        }

        public void Dispose()
        {
            _timer.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}
