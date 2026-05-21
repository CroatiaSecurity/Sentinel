using System.Collections.Concurrent;
using System.Diagnostics;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core.Health;

/// <summary>
/// Sentinel Health Check Service — Provides structured health checks for all components.
///
/// Monitors:
///   - Monitor status (running, stopped, errored)
///   - Detection engine throughput
///   - Response engine availability
///   - Memory and handle usage
///   - ETW session health
///   - Log file accessibility
///   - Quarantine directory health
///
/// Reports health status via logging and exposes status for the Agent watchdog.
/// </summary>
public sealed class SentinelHealthCheck : BackgroundService
{
    private readonly ILogger<SentinelHealthCheck> _logger;
    private readonly ConcurrentDictionary<string, ComponentHealth> _componentHealth = new();
    private readonly ConcurrentDictionary<string, PerformanceMetric> _metrics = new();
    private DateTime _startTime;
    private int _totalHealthChecks;
    private int _failedHealthChecks;

    /// <summary>
    /// Interval between health check cycles.
    /// </summary>
    private static readonly TimeSpan HealthCheckInterval = TimeSpan.FromSeconds(60);

    public SentinelHealthCheck(ILogger<SentinelHealthCheck> logger)
    {
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _startTime = DateTime.UtcNow;
        _logger.LogInformation("SentinelHealthCheck: Starting health monitoring");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(HealthCheckInterval, stoppingToken);
                await PerformHealthChecksAsync(stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "SentinelHealthCheck: Error during health check cycle");
            }
        }

        _logger.LogInformation("SentinelHealthCheck: Stopping");
    }

    private async Task PerformHealthChecksAsync(CancellationToken ct)
    {
        _totalHealthChecks++;
        var sw = Stopwatch.StartNew();
        var failedChecks = new List<string>();

        // Check process health
        CheckProcessHealth();

        // Check memory usage
        CheckMemoryHealth();

        // Check handle count
        CheckHandleHealth();

        // Check log file accessibility
        await CheckLogFileHealthAsync(ct);

        // Check quarantine directory
        CheckQuarantineHealth();

        // Check thread pool health
        CheckThreadPoolHealth();

        sw.Stop();

        // Record health check duration
        RecordMetric("HealthCheckDuration", sw.ElapsedMilliseconds);

        // Log summary
        var unhealthyComponents = _componentHealth.Values
            .Where(c => c.Status != HealthStatus.Healthy)
            .ToList();

        if (unhealthyComponents.Count > 0)
        {
            _failedHealthChecks++;
            _logger.LogWarning(
                "SentinelHealthCheck: {Unhealthy}/{Total} components unhealthy: {Components}",
                unhealthyComponents.Count,
                _componentHealth.Count,
                string.Join(", ", unhealthyComponents.Select(c => $"{c.Name}({c.Status})")));
        }
        else
        {
            _logger.LogDebug(
                "SentinelHealthCheck: All {Count} components healthy (check #{Total}, duration: {Duration}ms)",
                _componentHealth.Count, _totalHealthChecks, sw.ElapsedMilliseconds);
        }
    }

    private void CheckProcessHealth()
    {
        try
        {
            using var process = Process.GetCurrentProcess();
            var cpuTime = process.TotalProcessorTime;
            var workingSet = process.WorkingSet64;
            var threads = process.Threads.Count;

            RecordMetric("CpuTimeMs", (long)cpuTime.TotalMilliseconds);
            RecordMetric("WorkingSetMB", workingSet / (1024 * 1024));
            RecordMetric("ThreadCount", threads);

            UpdateComponentHealth("Process", HealthStatus.Healthy, 
                $"CPU: {cpuTime.TotalSeconds:F1}s, RAM: {workingSet / (1024 * 1024)}MB, Threads: {threads}");
        }
        catch (Exception ex)
        {
            UpdateComponentHealth("Process", HealthStatus.Warning, $"Error: {ex.Message}");
        }
    }

    private void CheckMemoryHealth()
    {
        try
        {
            var gcInfo = GC.GetGCMemoryInfo();
            var totalMemory = GC.GetTotalMemory(false);
            var gen0 = GC.CollectionCount(0);
            var gen1 = GC.CollectionCount(1);
            var gen2 = GC.CollectionCount(2);

            RecordMetric("ManagedMemoryMB", totalMemory / (1024 * 1024));
            RecordMetric("GC_Gen0", gen0);
            RecordMetric("GC_Gen1", gen1);
            RecordMetric("GC_Gen2", gen2);

            // Warn if managed memory exceeds 500MB
            var status = totalMemory > 500 * 1024 * 1024 
                ? HealthStatus.Warning 
                : HealthStatus.Healthy;

            UpdateComponentHealth("Memory", status,
                $"Managed: {totalMemory / (1024 * 1024)}MB, GC: {gen0}/{gen1}/{gen2}");
        }
        catch (Exception ex)
        {
            UpdateComponentHealth("Memory", HealthStatus.Warning, $"Error: {ex.Message}");
        }
    }

    private void CheckHandleHealth()
    {
        try
        {
            using var process = Process.GetCurrentProcess();
            var handleCount = process.HandleCount;

            RecordMetric("HandleCount", handleCount);

            // Warn if handle count exceeds 5000 (potential leak)
            var status = handleCount > 5000 
                ? HealthStatus.Warning 
                : HealthStatus.Healthy;

            if (handleCount > 10000)
                status = HealthStatus.Critical;

            UpdateComponentHealth("Handles", status, $"Count: {handleCount}");

            if (status != HealthStatus.Healthy)
            {
                _logger.LogWarning(
                    "SentinelHealthCheck: High handle count ({Count}) — possible handle leak",
                    handleCount);
            }
        }
        catch (Exception ex)
        {
            UpdateComponentHealth("Handles", HealthStatus.Warning, $"Error: {ex.Message}");
        }
    }

    private async Task CheckLogFileHealthAsync(CancellationToken ct)
    {
        var logPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "WindowsSentinel", "events.jsonl");

        try
        {
            if (File.Exists(logPath))
            {
                var fi = new FileInfo(logPath);
                RecordMetric("LogFileSizeMB", fi.Length / (1024 * 1024));

                // Check if log file is writable
                await using var stream = File.Open(logPath, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);
                
                UpdateComponentHealth("LogFile", HealthStatus.Healthy, 
                    $"Size: {fi.Length / (1024 * 1024)}MB, Path: {logPath}");
            }
            else
            {
                UpdateComponentHealth("LogFile", HealthStatus.Warning, "Log file does not exist");
            }
        }
        catch (IOException ex)
        {
            UpdateComponentHealth("LogFile", HealthStatus.Warning, $"Access error: {ex.Message}");
        }
        catch (Exception ex)
        {
            UpdateComponentHealth("LogFile", HealthStatus.Critical, $"Error: {ex.Message}");
        }
    }

    private void CheckQuarantineHealth()
    {
        var quarantinePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "WindowsSentinel", "Quarantine");

        try
        {
            if (Directory.Exists(quarantinePath))
            {
                var files = Directory.GetFiles(quarantinePath, "*.quarantined");
                var totalSize = files.Sum(f => new FileInfo(f).Length);

                RecordMetric("QuarantineFileCount", files.Length);
                RecordMetric("QuarantineSizeMB", totalSize / (1024 * 1024));

                UpdateComponentHealth("Quarantine", HealthStatus.Healthy,
                    $"Files: {files.Length}, Size: {totalSize / (1024 * 1024)}MB");
            }
            else
            {
                UpdateComponentHealth("Quarantine", HealthStatus.Warning, "Directory does not exist");
            }
        }
        catch (Exception ex)
        {
            UpdateComponentHealth("Quarantine", HealthStatus.Warning, $"Error: {ex.Message}");
        }
    }

    private void CheckThreadPoolHealth()
    {
        ThreadPool.GetAvailableThreads(out int workerThreads, out int completionPortThreads);
        ThreadPool.GetMaxThreads(out int maxWorkerThreads, out int maxCompletionPortThreads);

        var workerUtilization = 1.0 - ((double)workerThreads / maxWorkerThreads);
        var ioUtilization = 1.0 - ((double)completionPortThreads / maxCompletionPortThreads);

        RecordMetric("ThreadPoolWorkerUtilization", (long)(workerUtilization * 100));
        RecordMetric("ThreadPoolIOUtilization", (long)(ioUtilization * 100));

        var status = workerUtilization > 0.9 || ioUtilization > 0.9
            ? HealthStatus.Warning
            : HealthStatus.Healthy;

        UpdateComponentHealth("ThreadPool", status,
            $"Worker: {workerUtilization:P0}, IO: {ioUtilization:P0}");
    }

    // ── Public API ──────────────────────────────────────────────────────────

    /// <summary>
    /// Registers a component's health status (called by other services).
    /// </summary>
    public void ReportHealth(string componentName, HealthStatus status, string? details = null)
    {
        UpdateComponentHealth(componentName, status, details ?? "");
    }

    /// <summary>
    /// Records a performance metric.
    /// </summary>
    public void RecordMetric(string name, long value)
    {
        _metrics.AddOrUpdate(name,
            _ => new PerformanceMetric { Name = name, Value = value, LastUpdated = DateTime.UtcNow },
            (_, existing) =>
            {
                existing.Value = value;
                existing.Min = Math.Min(existing.Min, value);
                existing.Max = Math.Max(existing.Max, value);
                existing.SampleCount++;
                existing.LastUpdated = DateTime.UtcNow;
                return existing;
            });
    }

    /// <summary>
    /// Gets the overall health status.
    /// </summary>
    public OverallHealthStatus GetOverallHealth()
    {
        var components = _componentHealth.Values.ToList();
        var metrics = _metrics.Values.ToList();

        var overallStatus = HealthStatus.Healthy;
        if (components.Any(c => c.Status == HealthStatus.Critical))
            overallStatus = HealthStatus.Critical;
        else if (components.Any(c => c.Status == HealthStatus.Warning))
            overallStatus = HealthStatus.Warning;

        return new OverallHealthStatus
        {
            Status = overallStatus,
            Components = components,
            Metrics = metrics,
            Uptime = DateTime.UtcNow - _startTime,
            TotalChecks = _totalHealthChecks,
            FailedChecks = _failedHealthChecks,
            Timestamp = DateTime.UtcNow
        };
    }

    private void UpdateComponentHealth(string name, HealthStatus status, string details)
    {
        _componentHealth.AddOrUpdate(name,
            _ => new ComponentHealth { Name = name, Status = status, Details = details, LastChecked = DateTime.UtcNow },
            (_, existing) =>
            {
                existing.Status = status;
                existing.Details = details;
                existing.LastChecked = DateTime.UtcNow;
                return existing;
            });
    }
}

/// <summary>
/// Individual component health status.
/// </summary>
public sealed class ComponentHealth
{
    /// <summary>Component name.</summary>
    public string Name { get; set; } = "";
    /// <summary>Current health status.</summary>
    public HealthStatus Status { get; set; }
    /// <summary>Human-readable details.</summary>
    public string Details { get; set; } = "";
    /// <summary>Time of last health check.</summary>
    public DateTime LastChecked { get; set; }
}

/// <summary>
/// Performance metric.
/// </summary>
public sealed class PerformanceMetric
{
    /// <summary>Metric name.</summary>
    public string Name { get; set; } = "";
    /// <summary>Current value.</summary>
    public long Value { get; set; }
    /// <summary>Minimum observed value.</summary>
    public long Min { get; set; } = long.MaxValue;
    /// <summary>Maximum observed value.</summary>
    public long Max { get; set; } = long.MinValue;
    /// <summary>Number of samples recorded.</summary>
    public long SampleCount { get; set; } = 1;
    /// <summary>Time of last update.</summary>
    public DateTime LastUpdated { get; set; }
}

/// <summary>
/// Overall health status summary.
/// </summary>
public sealed class OverallHealthStatus
{
    /// <summary>Overall status.</summary>
    public HealthStatus Status { get; set; }
    /// <summary>Individual component statuses.</summary>
    public List<ComponentHealth> Components { get; set; } = new();
    /// <summary>Performance metrics.</summary>
    public List<PerformanceMetric> Metrics { get; set; } = new();
    /// <summary>Service uptime.</summary>
    public TimeSpan Uptime { get; set; }
    /// <summary>Total health checks performed.</summary>
    public int TotalChecks { get; set; }
    /// <summary>Number of failed health checks.</summary>
    public int FailedChecks { get; set; }
    /// <summary>Timestamp of this report.</summary>
    public DateTime Timestamp { get; set; }
}
