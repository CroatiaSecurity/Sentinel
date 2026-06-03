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
            "code", "cursor", "Devin", "kiro",
            "Slack", "Discord", "Teams", "Spotify",
            "steamwebhelper", "steam",
            // Hardware / GPU
            "NVDisplay.Container", "nvcontainer",
            "RazerCentralService", "CorsairService",
            // Windows Sentinel itself
            "WindowsSentinel.Service", "WindowsSentinel.Agent"
        };

        public AppNetworkPolicyMonitor(DetectionEngine detectionEngine, ProcessAncestryCache ancestryCache)
        {
            _detectionEngine = detectionEngine;
            _ancestryCache = ancestryCache;
            // Scan TCP connections every 30 seconds
            _timer = new System.Threading.Timer(ScanNetworkConnections, null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
        }

        private void ScanNetworkConnections(object? state)
        {
            try
            {
                uint size = 0;
                uint ret = GetExtendedTcpTable(IntPtr.Zero, ref size, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
                if (ret != 122) // ERROR_INSUFFICIENT_BUFFER
                {
                    return;
                }

                IntPtr pTable = Marshal.AllocHGlobal((int)size);
                try
                {
                    ret = GetExtendedTcpTable(pTable, ref size, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
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
                                int pid = (int)row.dwOwningPid;
                                if (pid <= 0) continue;

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

                                var remoteIp = new System.Net.IPAddress(row.dwRemoteAddr).ToString();
                                RegisterConnection(pid, processName + ".exe", remoteIp);
                            }
                        }
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(pTable);
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
            if (NetworkAllowlist.Contains(stem)) return;

            // Determine /24 subnet
            var parts = remoteAddress.Split('.');
            if (parts.Length != 4) return; // IPv4 only for simple learning
            var subnet = $"{parts[0]}.{parts[1]}.{parts[2]}.0";

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
            var alert = new DetectionEvent
            {
                RuleName = "Network Policy: Unusual Destination",
                ProcessName = processName,
                ProcessId = pid,
                Confidence = 0.55,
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
