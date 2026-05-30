using System.Collections.Concurrent;
using System.Net;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Monitors;

/// <summary>
/// Per-Application Network Policy Monitor — Learns and enforces per-app network destinations.
///
/// Behavior:
///   1. Learning phase (first 30 minutes): records which /24 subnets each process connects to
///   2. Enforcement phase: alerts when a process connects to a subnet it has never used before
///   3. Broad allowlist excludes browsers, system processes, and known-noisy apps
///
/// Uses GetExtendedTcpTable (same P/Invoke as NetworkMonitor) to poll connections every 15 seconds.
/// Stores learned baselines as ConcurrentDictionary&lt;processName, HashSet&lt;/24 subnet&gt;&gt;.
/// </summary>
public sealed class AppNetworkPolicyMonitor : BackgroundService
{
    private readonly IDetectionEngine _detectionEngine;
    private readonly ILogger<AppNetworkPolicyMonitor> _logger;

    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan LearningDuration = TimeSpan.FromMinutes(30);
    private static readonly TimeSpan PruneInterval = TimeSpan.FromHours(1);

    private const int MaxEntriesPerProcess = 1000;
    private const int MaxTotalProcesses = 5000;

    // Learned baselines: processName (lowercase) → set of /24 subnets
    private readonly ConcurrentDictionary<string, ProcessNetworkBaseline> _baselines = new();

    private DateTimeOffset _startTime;
    private DateTimeOffset _lastPrune;

    // Broad allowlist — processes that connect to many destinations by nature
    private static readonly HashSet<string> Allowlist = new(StringComparer.OrdinalIgnoreCase)
    {
        "chrome", "msedge", "firefox", "brave", "opera", "vivaldi",
        "svchost", "system",
        "searchhost", "msedgewebview2",
        "steam", "discord",
        "kiro", "dotnet",
        "sentinelservice", "sentinelagent",
    };

    // P/Invoke for GetExtendedTcpTable
    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int GetExtendedTcpTable(
        IntPtr pTcpTable, ref int dwSize, bool sort,
        int ipVersion, int tableClass, int reserved);

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
        public uint OwningPid;
    }

    private const int AF_INET = 2;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;

    // TCP states
    private const uint MIB_TCP_STATE_ESTAB = 5;

    public AppNetworkPolicyMonitor(
        IDetectionEngine detectionEngine,
        ILogger<AppNetworkPolicyMonitor> logger)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("=== App Network Policy Monitor starting (30-min learning phase) ===");

        // Initial delay
        await Task.Delay(TimeSpan.FromSeconds(20), stoppingToken);

        _startTime = DateTimeOffset.UtcNow;
        _lastPrune = _startTime;

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await PollConnectionsAsync(stoppingToken);

                // Periodic pruning
                var now = DateTimeOffset.UtcNow;
                if (now - _lastPrune > PruneInterval)
                {
                    PruneStaleProcesses(now);
                    _lastPrune = now;
                }

                await Task.Delay(PollInterval, stoppingToken);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogError(ex, "AppNetworkPolicyMonitor: Poll error");
                await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken);
            }
        }
    }

    private async Task PollConnectionsAsync(CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;
        bool isLearning = (now - _startTime) < LearningDuration;

        var connections = GetEstablishedTcpConnections();

        foreach (var (pid, remoteIp) in connections)
        {
            // Skip loopback and link-local
            if (IsLocalAddress(remoteIp))
                continue;

            string? processName = GetProcessName(pid);
            if (processName == null)
                continue;

            var processKey = processName.ToLowerInvariant();

            // Skip allowlisted processes
            if (Allowlist.Contains(processKey))
                continue;

            // Compute /24 subnet
            var subnet = GetSubnet24(remoteIp);
            if (subnet == null)
                continue;

            // Enforce total process cap
            if (!_baselines.ContainsKey(processKey) && _baselines.Count >= MaxTotalProcesses)
                continue;

            var baseline = _baselines.GetOrAdd(processKey, _ => new ProcessNetworkBaseline());
            baseline.LastSeen = now;

            // Check if this is a new subnet for this process
            if (baseline.KnownSubnets.Contains(subnet))
                continue;

            // Cap per-process entries
            if (baseline.KnownSubnets.Count >= MaxEntriesPerProcess)
                continue;

            baseline.KnownSubnets.Add(subnet);

            // During learning phase, just record
            if (isLearning)
                continue;

            // Enforcement phase: new destination detected
            await EmitUnusualDestination(processName, pid, remoteIp, subnet, baseline.KnownSubnets.Count, ct);
        }
    }

    private async Task EmitUnusualDestination(string processName, int pid, string remoteIp, string subnet, int knownCount, CancellationToken ct)
    {
        _logger.LogWarning(
            "Network Policy: '{Process}' (PID {Pid}) connected to new subnet {Subnet} (IP: {Ip}) — " +
            "{Known} known subnets for this process",
            processName, pid, subnet, remoteIp, knownCount);

        await _detectionEngine.EmitAsync(new DetectionEvent
        {
            RuleName = "Network Policy: Unusual Destination",
            Evidence = $"Process '{processName}' (PID {pid}) established a TCP connection to {remoteIp} " +
                      $"(subnet {subnet}), which has never been observed for this application. " +
                      $"The process has {knownCount} known destination subnets in its baseline.",
            Reasoning = "After a 30-minute learning phase, this process connected to a network destination " +
                       "it has never used before. This can indicate: C2 communication to a new server, " +
                       "lateral movement attempts, data exfiltration to an unusual endpoint, or a " +
                       "compromised process reaching out to attacker infrastructure. Legitimate software " +
                       "typically connects to a stable set of destinations.",
            Confidence = 0.55,
            Tier = DetectionTier.Tier2Indicator,
            ProcessName = processName,
            ProcessId = pid,
            Timestamp = DateTimeOffset.UtcNow,
            Metadata = new Dictionary<string, string>
            {
                ["remote_ip"] = remoteIp,
                ["subnet"] = subnet,
                ["known_subnet_count"] = knownCount.ToString(),
                ["technique"] = "T1071 - Application Layer Protocol"
            }
        }, ct);
    }

    private List<(int Pid, string RemoteIp)> GetEstablishedTcpConnections()
    {
        var results = new List<(int, string)>();

        int bufferSize = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (bufferSize <= 0) return results;

        var buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            int result = GetExtendedTcpTable(buffer, ref bufferSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            if (result != 0) return results;

            int numEntries = Marshal.ReadInt32(buffer);
            var rowPtr = buffer + 4;
            int rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();

            for (int i = 0; i < numEntries; i++)
            {
                var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(rowPtr);

                // Only established connections
                if (row.State == MIB_TCP_STATE_ESTAB && row.RemoteAddr != 0)
                {
                    var remoteIp = new IPAddress(row.RemoteAddr).ToString();
                    results.Add(((int)row.OwningPid, remoteIp));
                }

                rowPtr += rowSize;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return results;
    }

    private static string? GetSubnet24(string ipAddress)
    {
        if (!IPAddress.TryParse(ipAddress, out var ip))
            return null;

        var bytes = ip.GetAddressBytes();
        if (bytes.Length != 4)
            return null; // Only IPv4

        return $"{bytes[0]}.{bytes[1]}.{bytes[2]}.0/24";
    }

    private static bool IsLocalAddress(string ipAddress)
    {
        if (!IPAddress.TryParse(ipAddress, out var ip))
            return true;

        var bytes = ip.GetAddressBytes();
        if (bytes.Length != 4)
            return true; // Skip IPv6 for simplicity

        // Loopback (127.x.x.x)
        if (bytes[0] == 127) return true;

        // Link-local (169.254.x.x)
        if (bytes[0] == 169 && bytes[1] == 254) return true;

        // 0.0.0.0
        if (bytes[0] == 0 && bytes[1] == 0 && bytes[2] == 0 && bytes[3] == 0) return true;

        return false;
    }

    private static string? GetProcessName(int pid)
    {
        try
        {
            var process = System.Diagnostics.Process.GetProcessById(pid);
            return process.ProcessName;
        }
        catch
        {
            return null;
        }
    }

    private void PruneStaleProcesses(DateTimeOffset now)
    {
        var cutoff = now - PruneInterval;

        foreach (var kvp in _baselines)
        {
            if (kvp.Value.LastSeen < cutoff)
                _baselines.TryRemove(kvp.Key, out _);
        }
    }

    private sealed class ProcessNetworkBaseline
    {
        public HashSet<string> KnownSubnets { get; } = new(StringComparer.OrdinalIgnoreCase);
        public DateTimeOffset LastSeen { get; set; } = DateTimeOffset.UtcNow;
    }
}
