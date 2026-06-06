using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Statistical C2 beaconing detector.
    ///
    /// C2 frameworks beacon at regular intervals with added jitter.
    /// Key property: inter-connection intervals have LOW coefficient of variation
    /// (CV = stddev/mean) compared to legitimate software which connects irregularly.
    ///
    /// Algorithm:
    ///   1. Track outbound connection timestamps per (ProcessId, RemoteAddress, RemotePort).
    ///   2. After N observations, compute CV of inter-arrival intervals.
    ///   3. If CV &lt; threshold AND mean interval is in beacon range (5s–30min), fire detection.
    ///   4. Jitter-aware: even with 30% jitter, CV stays below ~0.35 for beacons.
    ///      Legitimate software typically has CV &gt; 1.0.
    /// </summary>
    public sealed class BeaconingDetector : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<BeaconingDetector> _logger;

        private readonly ConcurrentDictionary<string, ConnectionHistory> _history = new();

        private const int MinObservations = 5;
        private const double MaxBeaconCv = 0.40;
        private const double MinBeaconIntervalSec = 5.0;
        private const double MaxBeaconIntervalSec = 1800.0;
        private const int MaxHistoryPerKey = 50;

        private static readonly HashSet<string> LegitimatePeriodicProcesses =
            new(StringComparer.OrdinalIgnoreCase)
            {
                "MsMpEng", "SgrmBroker", "WaaSMedicAgent",
                "svchost", "SearchIndexer", "OneDrive", "Teams",
                "Slack", "Discord", "chrome", "msedge", "firefox",
                "MpDefenderCoreService", "NisSrv", "SecurityHealthService",
                "backgroundTaskHost", "BackgroundTransferHost",
                "widgets", "WidgetService",
                "PhoneExperienceHost", "YourPhone",
                "GameBarPresenceWriter",
                "usocoreworker", "sihost", "taskhostw",
                "NVDisplay.Container", "nvcontainer",
                "Spotify", "brave", "opera", "vivaldi",
                "steamwebhelper", "steam",
                "Windsurf", "code", "cursor",
            };

        private readonly BehavioralBaselineService? _baseline;

        public BeaconingDetector(DetectionEngine de, ILogger<BeaconingDetector> l, BehavioralBaselineService? baseline = null)
        {
            _detectionEngine = de;
            _logger = l;
            _baseline = baseline;
        }

        /// <summary>
        /// Called by NetworkMonitor for every observed connection.
        /// Records the timestamp for statistical analysis.
        /// </summary>
        public void RecordConnection(string remoteAddress, int remotePort, int processId, string processName, string state)
        {
            if (LegitimatePeriodicProcesses.Contains(processName)) return;
            if (state != "Established") return;
            if (remotePort is 80 or 443) return;

            if (_baseline != null && _baseline.IsKnownNetworkDestination(processName, remoteAddress, remotePort))
            {
                return;
            }

            var key = $"{processId}:{remoteAddress}:{remotePort}";
            var history = _history.GetOrAdd(key, _ => new ConnectionHistory(
                processId, processName, remoteAddress, remotePort));

            history.Record(DateTimeOffset.UtcNow);
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[BeaconingDetector] Started");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(30_000, ct);
                    await AnalyzeAllAsync();
                    PruneStaleHistory();
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[BeaconingDetector] Analysis error"); }
            }
        }

        private async Task AnalyzeAllAsync()
        {
            foreach (var kvp in _history)
            {
                var history = kvp.Value;
                if (history.HasFired) continue;

                var intervals = history.GetIntervals();
                if (intervals.Count < MinObservations) continue;

                double mean = intervals.Average();
                double stddev = StdDev(intervals, mean);
                double cv = mean > 0 ? stddev / mean : double.MaxValue;

                if (cv > MaxBeaconCv) continue;
                if (mean < MinBeaconIntervalSec) continue;
                if (mean > MaxBeaconIntervalSec) continue;

                history.HasFired = true;

                double cvFactor = Math.Max(0, 1.0 - cv / 0.40);
                double countFactor = Math.Min(1.0, intervals.Count / 20.0);
                double confidence = Math.Min(0.95, 0.70 + cvFactor * 0.20 + countFactor * 0.08);

                string intervalDesc = mean < 60 ? $"{mean:F1}s" : $"{mean / 60:F1}min";

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "C2 Beaconing Behavior (Statistical)",
                    Evidence = $"Process '{history.ProcessName}' (PID {history.ProcessId}) beaconing to " +
                               $"{history.RemoteAddress}:{history.RemotePort} every ~{intervalDesc} " +
                               $"(CV={cv:F3}, n={intervals.Count})",
                    Reasoning = $"Statistical analysis of {intervals.Count} connection intervals: " +
                                $"mean={intervalDesc}, stddev={stddev:F1}s, CV={cv:F3}. " +
                                "CV below 0.40 indicates highly regular timing consistent with C2 beacon behavior. " +
                                "Legitimate software connects irregularly (CV > 1.0). " +
                                "This detection is signature-independent.",
                    Confidence = confidence,
                    Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.NetworkIsolate,
                    ProcessName = history.ProcessName,
                    ProcessId = history.ProcessId,
                    Metadata = new()
                    {
                        ["TargetIP"] = history.RemoteAddress,
                        ["RemoteAddress"] = history.RemoteAddress,
                        ["RemotePort"] = history.RemotePort.ToString(),
                        ["MeanIntervalSec"] = mean.ToString("F2"),
                        ["CoefficientOfVariation"] = cv.ToString("F4"),
                        ["ObservationCount"] = intervals.Count.ToString()
                    }
                });
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
    }

    public sealed class ConnectionHistory
    {
        private readonly List<DateTimeOffset> _timestamps = new();
        private readonly object _lock = new();
        private const int MaxHistory = 50;

        public int ProcessId { get; }
        public string ProcessName { get; }
        public string RemoteAddress { get; }
        public int RemotePort { get; }
        public bool HasFired { get; set; }
        public DateTimeOffset LastSeen { get; private set; } = DateTimeOffset.UtcNow;

        public ConnectionHistory(int pid, string name, string remote, int port)
        {
            ProcessId = pid;
            ProcessName = name;
            RemoteAddress = remote;
            RemotePort = port;
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
}
