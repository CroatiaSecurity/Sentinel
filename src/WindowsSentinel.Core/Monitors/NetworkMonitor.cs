using System.Collections.Concurrent;
using System.Net;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Engine;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Monitors;

/// <summary>
/// Polls active TCP (IPv4 + IPv6) and UDP connections using P/Invoke.
/// Detects reverse-shell / C2 outbound connections on suspicious ports.
///
/// APIs used:
///   GetExtendedTcpTable  — IPv4 TCP with owner PID
///   GetExtendedTcpTable  — IPv6 TCP with owner PID (AF_INET6)
///   GetExtendedUdpTable  — IPv4 UDP with owner PID
///   GetExtendedUdpTable  — IPv6 UDP with owner PID (AF_INET6)
///
/// Deduplication: a seen-set keyed on (ProcessId, RemoteAddress, RemotePort)
/// prevents the same connection from firing multiple times across poll cycles.
/// The set is pruned every 5 minutes to handle long-lived connections that
/// eventually close and re-open.
/// </summary>
public sealed class NetworkMonitor : INetworkMonitor
{
    public string Name => "Network Monitor";

    private readonly IDetectionEngine _detectionEngine;
    private readonly ILogger<NetworkMonitor> _logger;
    private readonly ConcurrentDictionary<string, NetworkConnection> _knownConnections = new();
    private BeaconingDetector? _beaconingDetector;
    private readonly TelemetryFusionEngine? _fusionEngine;

    // Deduplication: track which (pid, remote) pairs we've already alerted on.
    private readonly ConcurrentDictionary<string, DateTimeOffset> _alertedConnections = new();
    private DateTimeOffset _lastPrune = DateTimeOffset.UtcNow;
    private static readonly TimeSpan AlertDedupeWindow = TimeSpan.FromMinutes(5);

    private Task? _pollTask;

    // Well-known reverse-shell / C2 ports (kept in sync with ReverseShellRule).
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

    public NetworkMonitor(
        IDetectionEngine detectionEngine,
        ILogger<NetworkMonitor> logger,
        BeaconingDetector? beaconingDetector = null,
        TelemetryFusionEngine? fusionEngine = null)
    {
        _detectionEngine   = detectionEngine;
        _logger            = logger;
        _beaconingDetector = beaconingDetector;
        _fusionEngine      = fusionEngine;
    }

    public IReadOnlyList<NetworkConnection> GetCurrentConnections() =>
        _knownConnections.Values.ToList().AsReadOnly();

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("[{Monitor}] Starting (IPv4+IPv6 TCP/UDP).", Name);
        _pollTask = PollLoopAsync(cancellationToken);
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("[{Monitor}] Stopping.", Name);
        return Task.CompletedTask;
    }

    private async Task PollLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                PruneAlertCache();

                var connections = new List<NetworkConnection>();
                connections.AddRange(GetTcpConnections(ipv6: false));
                connections.AddRange(GetTcpConnections(ipv6: true));
                connections.AddRange(GetUdpConnections(ipv6: false));
                connections.AddRange(GetUdpConnections(ipv6: true));

                _knownConnections.Clear();
                foreach (var conn in connections)
                {
                    var key = $"{conn.Protocol}:{conn.ProcessId}:{conn.LocalPort}->{conn.RemoteAddress}:{conn.RemotePort}";
                    _knownConnections[key] = conn;

                    if (!SuspiciousPorts.Contains(conn.RemotePort))
                    {
                        // Still feed to beaconing detector even for non-suspicious ports
                        // — beaconing can happen on any port
                        _beaconingDetector?.RecordConnection(conn, conn.ProcessId.ToString());
                        continue;
                    }

                    _beaconingDetector?.RecordConnection(conn, conn.ProcessId.ToString());

                    // Deduplicate — don't re-alert on the same connection every 5 s
                    var alertKey = $"{conn.ProcessId}:{conn.RemoteAddress}:{conn.RemotePort}";
                    if (_alertedConnections.ContainsKey(alertKey)) continue;
                    _alertedConnections[alertKey] = DateTimeOffset.UtcNow;

                    // Feed telemetry fusion engine (enriches event graph)
                    _fusionEngine?.IngestNetwork(conn.ProcessId, conn.ProcessId.ToString(),
                        conn.RemoteAddress, conn.RemotePort, DateTimeOffset.UtcNow);

                    var telemetry = new NetworkTelemetry
                    {
                        Connection = conn,
                        Reason     = $"Outbound {conn.Protocol} connection to suspicious port {conn.RemotePort}",
                        Timestamp  = DateTimeOffset.UtcNow
                    };
                    await _detectionEngine.ProcessAsync(telemetry, cancellationToken);
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogError(ex, "[{Monitor}] Error during network poll.", Name);
            }

            await Task.Delay(TimeSpan.FromSeconds(5), cancellationToken);
        }
    }

    private void PruneAlertCache()
    {
        if (DateTimeOffset.UtcNow - _lastPrune < AlertDedupeWindow) return;
        _lastPrune = DateTimeOffset.UtcNow;

        var cutoff = DateTimeOffset.UtcNow - AlertDedupeWindow;
        foreach (var kvp in _alertedConnections)
        {
            if (kvp.Value < cutoff)
                _alertedConnections.TryRemove(kvp.Key, out _);
        }
    }

    // ── IPv4 TCP ─────────────────────────────────────────────────────────────

    private static List<NetworkConnection> GetTcpConnections(bool ipv6)
    {
        var connections = new List<NetworkConnection>();
        int af = ipv6 ? 23 : 2; // AF_INET6 = 23, AF_INET = 2
        // TCP_TABLE_OWNER_PID_ALL = 5
        int tableClass = 5;

        int bufferSize = 0;
        NativeMethods.GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, af, tableClass, 0);
        if (bufferSize <= 0) return connections;

        var buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            int result = NativeMethods.GetExtendedTcpTable(buffer, ref bufferSize, true, af, tableClass, 0);
            if (result != 0) return connections;

            int numEntries = Marshal.ReadInt32(buffer);
            IntPtr rowPtr  = buffer + 4;

            if (ipv6)
            {
                int rowSize = Marshal.SizeOf<NativeMethods.MibTcp6RowOwnerPid>();
                for (int i = 0; i < numEntries; i++)
                {
                    var row = Marshal.PtrToStructure<NativeMethods.MibTcp6RowOwnerPid>(rowPtr);
                    connections.Add(new NetworkConnection
                    {
                        Protocol      = "TCP6",
                        LocalAddress  = new IPAddress(row.LocalAddr).ToString(),
                        LocalPort     = NetworkToHostOrder(row.LocalPort),
                        RemoteAddress = new IPAddress(row.RemoteAddr).ToString(),
                        RemotePort    = NetworkToHostOrder(row.RemotePort),
                        ProcessId     = (int)row.OwningPid,
                        State         = ((TcpState)row.State).ToString()
                    });
                    rowPtr += rowSize;
                }
            }
            else
            {
                int rowSize = Marshal.SizeOf<NativeMethods.MibTcpRowOwnerPid>();
                for (int i = 0; i < numEntries; i++)
                {
                    var row = Marshal.PtrToStructure<NativeMethods.MibTcpRowOwnerPid>(rowPtr);
                    connections.Add(new NetworkConnection
                    {
                        Protocol      = "TCP",
                        LocalAddress  = new IPAddress(row.LocalAddr).ToString(),
                        LocalPort     = NetworkToHostOrder(row.LocalPort),
                        RemoteAddress = new IPAddress(row.RemoteAddr).ToString(),
                        RemotePort    = NetworkToHostOrder(row.RemotePort),
                        ProcessId     = (int)row.OwningPid,
                        State         = ((TcpState)row.State).ToString()
                    });
                    rowPtr += rowSize;
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return connections;
    }

    // ── UDP ──────────────────────────────────────────────────────────────────

    private static List<NetworkConnection> GetUdpConnections(bool ipv6)
    {
        var connections = new List<NetworkConnection>();
        int af = ipv6 ? 23 : 2;
        // UDP_TABLE_OWNER_PID = 1
        int tableClass = 1;

        int bufferSize = 0;
        NativeMethods.GetExtendedUdpTable(IntPtr.Zero, ref bufferSize, true, af, tableClass, 0);
        if (bufferSize <= 0) return connections;

        var buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            int result = NativeMethods.GetExtendedUdpTable(buffer, ref bufferSize, true, af, tableClass, 0);
            if (result != 0) return connections;

            int numEntries = Marshal.ReadInt32(buffer);
            IntPtr rowPtr  = buffer + 4;

            if (ipv6)
            {
                int rowSize = Marshal.SizeOf<NativeMethods.MibUdp6RowOwnerPid>();
                for (int i = 0; i < numEntries; i++)
                {
                    var row = Marshal.PtrToStructure<NativeMethods.MibUdp6RowOwnerPid>(rowPtr);
                    connections.Add(new NetworkConnection
                    {
                        Protocol      = "UDP6",
                        LocalAddress  = new IPAddress(row.LocalAddr).ToString(),
                        LocalPort     = NetworkToHostOrder(row.LocalPort),
                        RemoteAddress = "::",
                        RemotePort    = 0,
                        ProcessId     = (int)row.OwningPid,
                        State         = "Listen"
                    });
                    rowPtr += rowSize;
                }
            }
            else
            {
                int rowSize = Marshal.SizeOf<NativeMethods.MibUdpRowOwnerPid>();
                for (int i = 0; i < numEntries; i++)
                {
                    var row = Marshal.PtrToStructure<NativeMethods.MibUdpRowOwnerPid>(rowPtr);
                    connections.Add(new NetworkConnection
                    {
                        Protocol      = "UDP",
                        LocalAddress  = new IPAddress(row.LocalAddr).ToString(),
                        LocalPort     = NetworkToHostOrder(row.LocalPort),
                        RemoteAddress = "0.0.0.0",
                        RemotePort    = 0,
                        ProcessId     = (int)row.OwningPid,
                        State         = "Listen"
                    });
                    rowPtr += rowSize;
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return connections;
    }

    private static int NetworkToHostOrder(uint networkPort)
    {
        byte[] bytes = BitConverter.GetBytes(networkPort);
        return (bytes[0] << 8) | bytes[1];
    }

    public async ValueTask DisposeAsync()
    {
        if (_pollTask is not null)
        {
            try { await _pollTask.WaitAsync(TimeSpan.FromSeconds(3)); }
            catch { /* best-effort */ }
        }
    }

    private enum TcpState
    {
        Closed = 1, Listen, SynSent, SynReceived, Established,
        FinWait1, FinWait2, CloseWait, Closing, LastAck, TimeWait, DeleteTcb
    }
}

public sealed class NetworkTelemetry
{
    public required NetworkConnection Connection { get; init; }
    public required string Reason               { get; init; }
    public required DateTimeOffset Timestamp    { get; init; }
}

internal static class NativeMethods
{
    [DllImport("iphlpapi.dll", SetLastError = true)]
    internal static extern int GetExtendedTcpTable(
        IntPtr pTcpTable, ref int dwSize, bool sort,
        int ipVersion, int tableClass, int reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    internal static extern int GetExtendedUdpTable(
        IntPtr pUdpTable, ref int dwSize, bool sort,
        int ipVersion, int tableClass, int reserved);

    // IPv4 TCP row
    [StructLayout(LayoutKind.Sequential)]
    internal struct MibTcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
        public uint OwningPid;
    }

    // IPv6 TCP row
    [StructLayout(LayoutKind.Sequential)]
    internal struct MibTcp6RowOwnerPid
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] LocalAddr;
        public uint   LocalScopeId;
        public uint   LocalPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] RemoteAddr;
        public uint   RemoteScopeId;
        public uint   RemotePort;
        public uint   State;
        public uint   OwningPid;
    }

    // IPv4 UDP row
    [StructLayout(LayoutKind.Sequential)]
    internal struct MibUdpRowOwnerPid
    {
        public uint LocalAddr;
        public uint LocalPort;
        public uint OwningPid;
    }

    // IPv6 UDP row
    [StructLayout(LayoutKind.Sequential)]
    internal struct MibUdp6RowOwnerPid
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] LocalAddr;
        public uint   LocalScopeId;
        public uint   LocalPort;
        public uint   OwningPid;
    }
}


