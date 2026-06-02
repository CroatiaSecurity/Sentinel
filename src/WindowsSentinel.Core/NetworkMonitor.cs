using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;

namespace WindowsSentinel.Core
{
    public class NetworkMonitor : IDisposable
    {
        private readonly TelemetryFusionEngine _fusionEngine;
        private readonly DetectionEngine _detectionEngine;
        private readonly ProcessAncestryCache _ancestryCache;
        private readonly System.Threading.Timer _timer;

        private readonly ConcurrentDictionary<string, DateTime> _alertedConnections = new();
        private static readonly TimeSpan AlertDedupeWindow = TimeSpan.FromMinutes(5);

        private static readonly HashSet<int> SuspiciousPorts = new()
        {
            4444, 4445, 4446, 4447, 4448,
            1337, 31337,
            5555, 6666, 7777, 8888, 9001, 9002, 9003,
            50050,   // Cobalt Strike team-server
            40056,   // Havoc C2
            1234,    // Empire / Starkiller
            65535, 65000, 60000
        };

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

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_UDPROW_OWNER_PID
        {
            public uint dwLocalAddr;
            public uint dwLocalPort;
            public uint dwOwningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_UDP6ROW_OWNER_PID
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] ucLocalAddr;
            public uint dwLocalScopeId;
            public uint dwLocalPort;
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

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedUdpTable(
            IntPtr pUdpTable,
            ref uint pdwSize,
            bool bOrder,
            uint ulAf,
            int tableClass,
            uint reserved = 0);

        private const int AF_INET = 2;
        private const int AF_INET6 = 23;
        private const int TCP_TABLE_OWNER_PID_ALL = 5;
        private const int UDP_TABLE_OWNER_PID = 1;
        private const int MIB_TCP_STATE_ESTAB = 5;

        public NetworkMonitor(
            TelemetryFusionEngine fusionEngine,
            DetectionEngine detectionEngine,
            ProcessAncestryCache ancestryCache)
        {
            _fusionEngine = fusionEngine;
            _detectionEngine = detectionEngine;
            _ancestryCache = ancestryCache;

            // Poll connections every 5 seconds
            _timer = new System.Threading.Timer(PollConnections, null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));
        }

        private void PollConnections(object? state)
        {
            try
            {
                PruneAlertCache();

                var tcpConnections = GetTcpConnections();
                var udpConnections = GetUdpConnections();

                foreach (var conn in tcpConnections.Concat(udpConnections))
                {
                    if (!SuspiciousPorts.Contains(conn.RemotePort))
                    {
                        continue;
                    }

                    var alertKey = $"{conn.ProcessId}:{conn.RemoteAddress}:{conn.RemotePort}";
                    if (_alertedConnections.ContainsKey(alertKey))
                    {
                        continue;
                    }

                    _alertedConnections[alertKey] = DateTime.UtcNow;

                    var name = "unknown";
                    var ancestry = _ancestryCache.GetParent(conn.ProcessId);
                    if (ancestry.name != "unknown")
                    {
                        name = ancestry.name;
                    }
                    else
                    {
                        try
                        {
                            using var proc = Process.GetProcessById(conn.ProcessId);
                            name = proc.ProcessName;
                        }
                        catch { }
                    }

                    var telemetry = new NetworkTelemetry
                    {
                        Type = "network",
                        Timestamp = DateTime.UtcNow,
                        ProcessId = conn.ProcessId,
                        ProcessName = name,
                        LocalAddress = conn.LocalAddress,
                        LocalPort = conn.LocalPort,
                        RemoteAddress = conn.RemoteAddress,
                        RemotePort = conn.RemotePort,
                        Protocol = conn.Protocol,
                        State = conn.State
                    };

                    var context = _fusionEngine.FeedEvent(telemetry);
                    _detectionEngine.SubmitTelemetry(context);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"NetworkMonitor error: {ex.Message}");
            }
        }

        private List<ConnectionInfo> GetTcpConnections()
        {
            var list = new List<ConnectionInfo>();
            
            // IPv4 TCP
            uint size = 0;
            uint ret = GetExtendedTcpTable(IntPtr.Zero, ref size, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            if (ret == 122) // ERROR_INSUFFICIENT_BUFFER
            {
                IntPtr pTable = Marshal.AllocHGlobal((int)size);
                try
                {
                    if (GetExtendedTcpTable(pTable, ref size, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == 0)
                    {
                        int numEntries = Marshal.ReadInt32(pTable);
                        IntPtr rowPtr = pTable + sizeof(int);
                        int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
                        for (int i = 0; i < numEntries; i++)
                        {
                            var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                            rowPtr += rowSize;

                            if (row.dwState == MIB_TCP_STATE_ESTAB)
                            {
                                list.Add(new ConnectionInfo
                                {
                                    Protocol = "TCP",
                                    LocalAddress = new IPAddress(row.dwLocalAddr).ToString(),
                                    LocalPort = NetworkToHostOrder(row.dwLocalPort),
                                    RemoteAddress = new IPAddress(row.dwRemoteAddr).ToString(),
                                    RemotePort = NetworkToHostOrder(row.dwRemotePort),
                                    ProcessId = (int)row.dwOwningPid,
                                    State = "ESTABLISHED"
                                });
                            }
                        }
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(pTable);
                }
            }

            // IPv6 TCP
            size = 0;
            ret = GetExtendedTcpTable(IntPtr.Zero, ref size, true, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
            if (ret == 122)
            {
                IntPtr pTable = Marshal.AllocHGlobal((int)size);
                try
                {
                    if (GetExtendedTcpTable(pTable, ref size, true, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == 0)
                    {
                        int numEntries = Marshal.ReadInt32(pTable);
                        IntPtr rowPtr = pTable + sizeof(int);
                        int rowSize = Marshal.SizeOf<MIB_TCP6ROW_OWNER_PID>();
                        for (int i = 0; i < numEntries; i++)
                        {
                            var row = Marshal.PtrToStructure<MIB_TCP6ROW_OWNER_PID>(rowPtr);
                            rowPtr += rowSize;

                            if (row.dwState == MIB_TCP_STATE_ESTAB)
                            {
                                list.Add(new ConnectionInfo
                                {
                                    Protocol = "TCP6",
                                    LocalAddress = new IPAddress(row.ucLocalAddr).ToString(),
                                    LocalPort = NetworkToHostOrder(row.dwLocalPort),
                                    RemoteAddress = new IPAddress(row.ucRemoteAddr).ToString(),
                                    RemotePort = NetworkToHostOrder(row.dwRemotePort),
                                    ProcessId = (int)row.dwOwningPid,
                                    State = "ESTABLISHED"
                                });
                            }
                        }
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(pTable);
                }
            }

            return list;
        }

        private List<ConnectionInfo> GetUdpConnections()
        {
            var list = new List<ConnectionInfo>();

            // IPv4 UDP
            uint size = 0;
            uint ret = GetExtendedUdpTable(IntPtr.Zero, ref size, true, AF_INET, UDP_TABLE_OWNER_PID, 0);
            if (ret == 122)
            {
                IntPtr pTable = Marshal.AllocHGlobal((int)size);
                try
                {
                    if (GetExtendedUdpTable(pTable, ref size, true, AF_INET, UDP_TABLE_OWNER_PID, 0) == 0)
                    {
                        int numEntries = Marshal.ReadInt32(pTable);
                        IntPtr rowPtr = pTable + sizeof(int);
                        int rowSize = Marshal.SizeOf<MIB_UDPROW_OWNER_PID>();
                        for (int i = 0; i < numEntries; i++)
                        {
                            var row = Marshal.PtrToStructure<MIB_UDPROW_OWNER_PID>(rowPtr);
                            rowPtr += rowSize;

                            list.Add(new ConnectionInfo
                            {
                                Protocol = "UDP",
                                LocalAddress = new IPAddress(row.dwLocalAddr).ToString(),
                                LocalPort = NetworkToHostOrder(row.dwLocalPort),
                                RemoteAddress = "0.0.0.0",
                                RemotePort = 0,
                                ProcessId = (int)row.dwOwningPid,
                                State = "LISTEN"
                            });
                        }
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(pTable);
                }
            }

            // IPv6 UDP
            size = 0;
            ret = GetExtendedUdpTable(IntPtr.Zero, ref size, true, AF_INET6, UDP_TABLE_OWNER_PID, 0);
            if (ret == 122)
            {
                IntPtr pTable = Marshal.AllocHGlobal((int)size);
                try
                {
                    if (GetExtendedUdpTable(pTable, ref size, true, AF_INET6, UDP_TABLE_OWNER_PID, 0) == 0)
                    {
                        int numEntries = Marshal.ReadInt32(pTable);
                        IntPtr rowPtr = pTable + sizeof(int);
                        int rowSize = Marshal.SizeOf<MIB_UDP6ROW_OWNER_PID>();
                        for (int i = 0; i < numEntries; i++)
                        {
                            var row = Marshal.PtrToStructure<MIB_UDP6ROW_OWNER_PID>(rowPtr);
                            rowPtr += rowSize;

                            list.Add(new ConnectionInfo
                            {
                                Protocol = "UDP6",
                                LocalAddress = new IPAddress(row.ucLocalAddr).ToString(),
                                LocalPort = NetworkToHostOrder(row.dwLocalPort),
                                RemoteAddress = "::",
                                RemotePort = 0,
                                ProcessId = (int)row.dwOwningPid,
                                State = "LISTEN"
                            });
                        }
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(pTable);
                }
            }

            return list;
        }

        private static int NetworkToHostOrder(uint networkPort)
        {
            byte[] bytes = BitConverter.GetBytes(networkPort);
            return (bytes[0] << 8) | bytes[1];
        }

        private void PruneAlertCache()
        {
            var cutoff = DateTime.UtcNow - AlertDedupeWindow;
            foreach (var kvp in _alertedConnections)
            {
                if (kvp.Value < cutoff)
                {
                    _alertedConnections.TryRemove(kvp.Key, out _);
                }
            }
        }

        public void Dispose()
        {
            _timer.Dispose();
            GC.SuppressFinalize(this);
        }

        private class ConnectionInfo
        {
            public string Protocol { get; set; } = string.Empty;
            public string LocalAddress { get; set; } = string.Empty;
            public int LocalPort { get; set; }
            public string RemoteAddress { get; set; } = string.Empty;
            public int RemotePort { get; set; }
            public int ProcessId { get; set; }
            public string State { get; set; } = string.Empty;
        }
    }
}
