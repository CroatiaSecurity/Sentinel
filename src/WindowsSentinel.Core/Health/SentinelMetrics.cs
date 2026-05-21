using System.Collections.Concurrent;
using System.Diagnostics;

namespace WindowsSentinel.Core.Health;

/// <summary>
/// Sentinel Metrics — Tracks key performance indicators for the EDR system.
///
/// Metrics tracked:
///   - Detection rate (detections per minute)
///   - False positive rate (user-restored files / total quarantines)
///   - Response latency (time from detection to kill)
///   - Deception success rate
///   - Monitor throughput (events processed per second)
///   - Memory usage trends
///   - API call success/failure rates
///
/// Thread-safe. All operations use Interlocked or ConcurrentDictionary.
/// </summary>
public sealed class SentinelMetrics
{
    private readonly ConcurrentDictionary<string, MetricCounter> _counters = new();
    private readonly ConcurrentDictionary<string, MetricHistogram> _histograms = new();
    private readonly ConcurrentDictionary<string, MetricGauge> _gauges = new();
    private readonly DateTime _startTime = DateTime.UtcNow;

    // ── Counter Operations ──────────────────────────────────────────────────

    /// <summary>
    /// Increments a counter metric by 1.
    /// </summary>
    public void IncrementCounter(string name)
    {
        var counter = _counters.GetOrAdd(name, _ => new MetricCounter { Name = name });
        Interlocked.Increment(ref counter.Value);
        counter.LastUpdated = DateTime.UtcNow;
    }

    /// <summary>
    /// Increments a counter metric by a specified amount.
    /// </summary>
    public void IncrementCounter(string name, long amount)
    {
        var counter = _counters.GetOrAdd(name, _ => new MetricCounter { Name = name });
        Interlocked.Add(ref counter.Value, amount);
        counter.LastUpdated = DateTime.UtcNow;
    }

    /// <summary>
    /// Gets the current value of a counter.
    /// </summary>
    public long GetCounter(string name)
    {
        return _counters.TryGetValue(name, out var counter) ? Interlocked.Read(ref counter.Value) : 0;
    }

    // ── Histogram Operations ────────────────────────────────────────────────

    /// <summary>
    /// Records a value in a histogram (for latency, duration, etc.).
    /// </summary>
    public void RecordHistogram(string name, double value)
    {
        var histogram = _histograms.GetOrAdd(name, _ => new MetricHistogram { Name = name });
        lock (histogram.Lock)
        {
            histogram.Count++;
            histogram.Sum += value;
            histogram.Min = Math.Min(histogram.Min, value);
            histogram.Max = Math.Max(histogram.Max, value);
            histogram.LastValue = value;
            histogram.LastUpdated = DateTime.UtcNow;

            // Keep last 100 values for percentile calculation
            histogram.RecentValues.Enqueue(value);
            while (histogram.RecentValues.Count > 100)
                histogram.RecentValues.Dequeue();
        }
    }

    /// <summary>
    /// Records a duration using a Stopwatch.
    /// </summary>
    public void RecordDuration(string name, Stopwatch stopwatch)
    {
        RecordHistogram(name, stopwatch.Elapsed.TotalMilliseconds);
    }

    /// <summary>
    /// Gets histogram statistics for a metric.
    /// </summary>
    public HistogramStats? GetHistogramStats(string name)
    {
        if (!_histograms.TryGetValue(name, out var histogram))
            return null;

        lock (histogram.Lock)
        {
            var values = histogram.RecentValues.OrderBy(v => v).ToList();
            return new HistogramStats
            {
                Name = name,
                Count = histogram.Count,
                Sum = histogram.Sum,
                Min = histogram.Min,
                Max = histogram.Max,
                Average = histogram.Count > 0 ? histogram.Sum / histogram.Count : 0,
                P50 = GetPercentile(values, 0.50),
                P90 = GetPercentile(values, 0.90),
                P95 = GetPercentile(values, 0.95),
                P99 = GetPercentile(values, 0.99),
                LastValue = histogram.LastValue,
                LastUpdated = histogram.LastUpdated
            };
        }
    }

    // ── Gauge Operations ────────────────────────────────────────────────────

    /// <summary>
    /// Sets a gauge metric to a specific value.
    /// </summary>
    public void SetGauge(string name, double value)
    {
        var gauge = _gauges.GetOrAdd(name, _ => new MetricGauge { Name = name });
        gauge.Value = value;
        gauge.LastUpdated = DateTime.UtcNow;
    }

    /// <summary>
    /// Gets the current value of a gauge.
    /// </summary>
    public double GetGauge(string name)
    {
        return _gauges.TryGetValue(name, out var gauge) ? gauge.Value : 0;
    }

    // ── Convenience Methods ─────────────────────────────────────────────────

    /// <summary>
    /// Records a detection event.
    /// </summary>
    public void RecordDetection(string ruleName, string tier, double confidence)
    {
        IncrementCounter("detections.total");
        IncrementCounter($"detections.{tier}");
        IncrementCounter($"detections.rule.{ruleName}");
        RecordHistogram("detections.confidence", confidence);
    }

    /// <summary>
    /// Records a response action.
    /// </summary>
    public void RecordResponse(string action, TimeSpan duration, bool success)
    {
        IncrementCounter("responses.total");
        IncrementCounter($"responses.{action}");
        
        if (success)
            IncrementCounter("responses.success");
        else
            IncrementCounter("responses.failure");

        RecordHistogram("responses.duration_ms", duration.TotalMilliseconds);
    }

    /// <summary>
    /// Records a deception tactic execution.
    /// </summary>
    public void RecordDeception(string tacticName, TimeSpan duration, bool success)
    {
        IncrementCounter("deception.total");
        IncrementCounter($"deception.{tacticName}");
        
        if (success)
            IncrementCounter("deception.success");
        else
            IncrementCounter("deception.failure");

        RecordHistogram("deception.duration_ms", duration.TotalMilliseconds);
    }

    /// <summary>
    /// Records a false positive (user-restored quarantined file).
    /// </summary>
    public void RecordFalsePositive(string ruleName)
    {
        IncrementCounter("false_positives.total");
        IncrementCounter($"false_positives.rule.{ruleName}");
    }

    /// <summary>
    /// Records a threat intelligence report.
    /// </summary>
    public void RecordThreatReport(string platform, bool success)
    {
        IncrementCounter("threat_reports.total");
        IncrementCounter($"threat_reports.{platform}");
        
        if (success)
            IncrementCounter("threat_reports.success");
        else
            IncrementCounter("threat_reports.failure");
    }

    /// <summary>
    /// Records a monitor event processed.
    /// </summary>
    public void RecordMonitorEvent(string monitorName)
    {
        IncrementCounter("monitor_events.total");
        IncrementCounter($"monitor_events.{monitorName}");
    }

    // ── Reporting ───────────────────────────────────────────────────────────

    /// <summary>
    /// Gets a full metrics report.
    /// </summary>
    public MetricsReport GetReport()
    {
        return new MetricsReport
        {
            Uptime = DateTime.UtcNow - _startTime,
            Counters = _counters.Values.Select(c => new CounterReport
            {
                Name = c.Name,
                Value = Interlocked.Read(ref c.Value),
                LastUpdated = c.LastUpdated
            }).OrderBy(c => c.Name).ToList(),
            Histograms = _histograms.Keys.Select(k => GetHistogramStats(k)!)
                .Where(h => h != null)
                .OrderBy(h => h.Name).ToList(),
            Gauges = _gauges.Values.Select(g => new GaugeReport
            {
                Name = g.Name,
                Value = g.Value,
                LastUpdated = g.LastUpdated
            }).OrderBy(g => g.Name).ToList(),
            Timestamp = DateTime.UtcNow
        };
    }

    /// <summary>
    /// Gets the detection rate (detections per minute over the last hour).
    /// </summary>
    public double GetDetectionRate()
    {
        var total = GetCounter("detections.total");
        var uptime = (DateTime.UtcNow - _startTime).TotalMinutes;
        return uptime > 0 ? total / uptime : 0;
    }

    /// <summary>
    /// Gets the false positive rate.
    /// </summary>
    public double GetFalsePositiveRate()
    {
        var totalDetections = GetCounter("detections.total");
        var falsePositives = GetCounter("false_positives.total");
        return totalDetections > 0 ? (double)falsePositives / totalDetections : 0;
    }

    /// <summary>
    /// Resets all metrics.
    /// </summary>
    public void Reset()
    {
        _counters.Clear();
        _histograms.Clear();
        _gauges.Clear();
    }

    // ── Private Helpers ─────────────────────────────────────────────────────

    private static double GetPercentile(List<double> sortedValues, double percentile)
    {
        if (sortedValues.Count == 0) return 0;
        var index = (int)Math.Ceiling(percentile * sortedValues.Count) - 1;
        return sortedValues[Math.Max(0, Math.Min(index, sortedValues.Count - 1))];
    }

    // ── Internal Types ──────────────────────────────────────────────────────

    private sealed class MetricCounter
    {
        public string Name = "";
        public long Value;
        public DateTime LastUpdated;
    }

    private sealed class MetricHistogram
    {
        public string Name = "";
        public long Count;
        public double Sum;
        public double Min = double.MaxValue;
        public double Max = double.MinValue;
        public double LastValue;
        public DateTime LastUpdated;
        public Queue<double> RecentValues = new();
        public object Lock = new();
    }

    private sealed class MetricGauge
    {
        public string Name = "";
        public double Value;
        public DateTime LastUpdated;
    }
}

// ── Report Types ────────────────────────────────────────────────────────────

/// <summary>Full metrics report.</summary>
public sealed class MetricsReport
{
    /// <summary>Service uptime.</summary>
    public TimeSpan Uptime { get; set; }
    /// <summary>All counter metrics.</summary>
    public List<CounterReport> Counters { get; set; } = new();
    /// <summary>All histogram metrics.</summary>
    public List<HistogramStats> Histograms { get; set; } = new();
    /// <summary>All gauge metrics.</summary>
    public List<GaugeReport> Gauges { get; set; } = new();
    /// <summary>Report timestamp.</summary>
    public DateTime Timestamp { get; set; }
}

/// <summary>Counter metric report.</summary>
public sealed class CounterReport
{
    /// <summary>Counter name.</summary>
    public string Name { get; set; } = "";
    /// <summary>Counter value.</summary>
    public long Value { get; set; }
    /// <summary>Last update time.</summary>
    public DateTime LastUpdated { get; set; }
}

/// <summary>Histogram statistics.</summary>
public sealed class HistogramStats
{
    /// <summary>Histogram name.</summary>
    public string Name { get; set; } = "";
    /// <summary>Total number of observations.</summary>
    public long Count { get; set; }
    /// <summary>Sum of all observations.</summary>
    public double Sum { get; set; }
    /// <summary>Minimum observed value.</summary>
    public double Min { get; set; }
    /// <summary>Maximum observed value.</summary>
    public double Max { get; set; }
    /// <summary>Average value.</summary>
    public double Average { get; set; }
    /// <summary>50th percentile (median).</summary>
    public double P50 { get; set; }
    /// <summary>90th percentile.</summary>
    public double P90 { get; set; }
    /// <summary>95th percentile.</summary>
    public double P95 { get; set; }
    /// <summary>99th percentile.</summary>
    public double P99 { get; set; }
    /// <summary>Most recent value.</summary>
    public double LastValue { get; set; }
    /// <summary>Last update time.</summary>
    public DateTime LastUpdated { get; set; }
}

/// <summary>Gauge metric report.</summary>
public sealed class GaugeReport
{
    /// <summary>Gauge name.</summary>
    public string Name { get; set; } = "";
    /// <summary>Current value.</summary>
    public double Value { get; set; }
    /// <summary>Last update time.</summary>
    public DateTime LastUpdated { get; set; }
}