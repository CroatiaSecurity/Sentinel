using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;
using WindowsSentinel.Core.Monitors;

namespace WindowsSentinel.Core.Engine;

/// <summary>
/// Statistical C2 beaconing detector.
///
/// C2 frameworks beacon at regular intervals with added jitter to avoid
/// detection. The key statistical property: the inter-connection intervals
/// have LOW coefficient of variation (CV = stddev/mean) compared to
/// legitimate software, which connects irregularly.
///
/// Algorithm:
///   1. Track outbound connection timestamps per (ProcessId, RemoteAddress).
///   2. After N observations, compute the CV of inter-arrival intervals.
///   3. If CV < threshold AND mean interval is in the beacon range (5s–30min),
///      fire a detection.
///   4. Jitter-aware: even with 30% jitter, CV stays below ~0.35 for beacons.
///      Legitimate software typically has CV > 1.0.
///
/// Why commercial tools struggle with this:
///   - At fleet scale, the false positive rate on legitimate software with
///     periodic connections (telemetry, update checks) is unacceptable.
///   - At single-user scale, you know your own software. Anything beaconing
///     to an unknown IP at regular intervals is suspicious.
///
/// Minimum observations before firing: 5 (to avoid false positives on
/// software that happens to connect twice at similar intervals).
/// </summary>
public sealed class BeaconingDetector : IAsyncDisposable
{
    private readonly IDetectionEngine _detectionEngine;
    private readonly ILogger<BeaconingDetector> _logger;

    // Key: "ProcessId:RemoteAddress:RemotePort"
    private readonly ConcurrentDictionary<string, ConnectionHistory> _history = new();

    private Task? _analysisTask;

    // Tuning parameters
    private const int    MinObservations      = 5;
    private const double MaxBeaconCv          = 0.40;  // CV below this = regular = beacon
    private const double MinBeaconIntervalSec = 5.0;   // faster than 5s = not a beacon
    private const double MaxBeaconIntervalSec = 1800.0; // slower than 30min = not a beacon
    private const int    MaxHistoryPerKey     = 50;    // cap memory per connection

    // Known-legitimate periodic connectors — skip these to reduce noise
    private static readonly HashSet<string> LegitimatePeriodicProcesses =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "MsMpEng.exe", "SgrmBroker.exe", "WaaSMedicAgent.exe",
            "svchost.exe",  // Windows Update, telemetry — too broad to flag
            "SearchIndexer.exe", "OneDrive.exe", "Teams.exe",
            "Slack.exe", "Discord.exe", "chrome.exe", "msedge.exe", "firefox.exe"
        };

    public BeaconingDetector(
        IDetectionEngine detectionEngine,
        ILogger<BeaconingDetector> logger)
    {
        _detectionEngine = detectionEngine;
        _logger          = logger;
    }

    public void Start(CancellationToken cancellationToken)
    {
        _analysisTask = AnalysisLoopAsync(cancellationToken);
    }

    /// <summary>
    /// Called by NetworkMonitor for every observed connection.
    /// Records the timestamp for statistical analysis.
    /// </summary>
    public void RecordConnection(NetworkConnection conn, string processName)
    {
        // Skip known-legitimate periodic processes
        if (LegitimatePeriodicProcesses.Contains(processName)) return;

        // Only track established outbound connections (not listening sockets)
        if (conn.State != "Established") return;
        if (conn.RemotePort is 80 or 443) return; // HTTP/HTTPS too noisy

        var key = $"{conn.ProcessId}:{conn.RemoteAddress}:{conn.RemotePort}";
        var history = _history.GetOrAdd(key, _ => new ConnectionHistory(
            conn.ProcessId, processName, conn.RemoteAddress, conn.RemotePort));

        history.Record(DateTimeOffset.UtcNow);
    }

    private async Task AnalysisLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(30), cancellationToken);
                await AnalyzeAllAsync(cancellationToken);
                PruneStaleHistory();
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[BeaconingDetector] Analysis error.");
            }
        }
    }

    private async Task AnalyzeAllAsync(CancellationToken cancellationToken)
    {
        foreach (var kvp in _history)
        {
            var history = kvp.Value;
            if (history.HasFired) continue;

            var intervals = history.GetIntervals();
            if (intervals.Count < MinObservations) continue;

            double mean   = intervals.Average();
            double stddev = StdDev(intervals, mean);
            double cv     = mean > 0 ? stddev / mean : double.MaxValue;

            // Check beacon criteria
            if (cv     > MaxBeaconCv)          continue;
            if (mean   < MinBeaconIntervalSec) continue;
            if (mean   > MaxBeaconIntervalSec) continue;

            history.HasFired = true;

            _logger.LogWarning(
                "[BeaconingDetector] Beacon detected: PID {Pid} → {Remote}:{Port} " +
                "interval={Mean:F1}s CV={Cv:F3} observations={Count}",
                history.ProcessId, history.RemoteAddress, history.RemotePort,
                mean, cv, intervals.Count);

            var telemetry = new BeaconingTelemetry
            {
                ProcessId      = history.ProcessId,
                ProcessName    = history.ProcessName,
                RemoteAddress  = history.RemoteAddress,
                RemotePort     = history.RemotePort,
                MeanIntervalSec = mean,
                StdDevSec      = stddev,
                CoefficientOfVariation = cv,
                ObservationCount = intervals.Count,
                Timestamp      = DateTimeOffset.UtcNow
            };

            await _detectionEngine.ProcessAsync(telemetry, cancellationToken);
        }
    }

    private void PruneStaleHistory()
    {
        var cutoff = DateTimeOffset.UtcNow - TimeSpan.FromHours(2);
        foreach (var key in _history.Keys.ToList())
        {
            if (_history.TryGetValue(key, out var h) && h.LastSeen < cutoff)
                _history.TryRemove(key, out _);
        }
    }

    private static double StdDev(IReadOnlyList<double> values, double mean)
    {
        if (values.Count < 2) return 0;
        double variance = values.Sum(v => (v - mean) * (v - mean)) / (values.Count - 1);
        return Math.Sqrt(variance);
    }

    public async ValueTask DisposeAsync()
    {
        if (_analysisTask is not null)
        {
            try { await _analysisTask.WaitAsync(TimeSpan.FromSeconds(3)); }
            catch { /* best-effort */ }
        }
    }
}

// ── Supporting types ──────────────────────────────────────────────────────────

public sealed class ConnectionHistory
{
    private readonly List<DateTimeOffset> _timestamps = new();
    private readonly object _lock = new();
    private const int MaxHistory = 50;

    public int    ProcessId     { get; }
    public string ProcessName   { get; }
    public string RemoteAddress { get; }
    public int    RemotePort    { get; }
    public bool   HasFired      { get; set; }
    public DateTimeOffset LastSeen { get; private set; } = DateTimeOffset.UtcNow;

    public ConnectionHistory(int pid, string name, string remote, int port)
    {
        ProcessId     = pid;
        ProcessName   = name;
        RemoteAddress = remote;
        RemotePort    = port;
    }

    public void Record(DateTimeOffset timestamp)
    {
        lock (_lock)
        {
            _timestamps.Add(timestamp);
            LastSeen = timestamp;
            if (_timestamps.Count > MaxHistory)
                _timestamps.RemoveAt(0);
        }
    }

    /// <summary>Returns inter-arrival intervals in seconds.</summary>
    public IReadOnlyList<double> GetIntervals()
    {
        lock (_lock)
        {
            if (_timestamps.Count < 2) return Array.Empty<double>();
            var sorted = _timestamps.OrderBy(t => t).ToList();
            return sorted
                .Zip(sorted.Skip(1), (a, b) => (b - a).TotalSeconds)
                .ToList();
        }
    }
}

public sealed class BeaconingTelemetry
{
    public required int    ProcessId               { get; init; }
    public required string ProcessName             { get; init; }
    public required string RemoteAddress           { get; init; }
    public required int    RemotePort              { get; init; }
    public required double MeanIntervalSec         { get; init; }
    public required double StdDevSec               { get; init; }
    public required double CoefficientOfVariation  { get; init; }
    public required int    ObservationCount        { get; init; }
    public required DateTimeOffset Timestamp       { get; init; }
}


