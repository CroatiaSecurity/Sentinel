using System.Diagnostics;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Health;

/// <summary>
/// Heartbeat Service - Generates periodic heartbeat events for monitoring.
/// </summary>
public sealed class HeartbeatService : BackgroundService
{
    private readonly IEventLogger _eventLogger;
    private readonly ILogger<HeartbeatService> _logger;
    private readonly DateTimeOffset _startTime;
    private long _detectionCount = 0;
    private long _responseCount = 0;

    public HeartbeatService(
        IEventLogger eventLogger,
        ILogger<HeartbeatService> logger)
    {
        _eventLogger = eventLogger;
        _logger = logger;
        _startTime = DateTimeOffset.UtcNow;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("=== Heartbeat Service starting ===");

        // Send initial heartbeat
        await SendHeartbeatAsync(stoppingToken);

        // Start fast watchdog heartbeat (file-based, for Agent cross-process monitoring)
        var watchdogTask = RunWatchdogHeartbeatAsync(stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromHours(1), stoppingToken);
                await SendHeartbeatAsync(stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Heartbeat: Error sending heartbeat");
            }
        }

        // Send final heartbeat on shutdown
        await SendHeartbeatAsync(stoppingToken, isFinal: true);
    }

    /// <summary>
    /// Writes a timestamp to a watchdog file every 30 seconds.
    /// The Agent process monitors this file — if it goes stale (>90 seconds old),
    /// the Agent knows the service was killed/compromised and can restart it.
    /// This is a cross-process integrity check that survives in-process injection.
    /// </summary>
    private async Task RunWatchdogHeartbeatAsync(CancellationToken stoppingToken)
    {
        var watchdogPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "WindowsSentinel", "watchdog.heartbeat");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                // Write current timestamp + PID + integrity token
                var payload = $"{DateTimeOffset.UtcNow:O}|{Environment.ProcessId}|{_detectionCount}";
                await File.WriteAllTextAsync(watchdogPath, payload, stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Heartbeat: Watchdog file write failed");
            }

            try
            {
                await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }

        // Clean up on graceful shutdown
        try { File.Delete(watchdogPath); } catch { }
    }

    /// <summary>
    /// Sends a heartbeat event.
    /// </summary>
    private async Task SendHeartbeatAsync(CancellationToken cancellationToken, bool isFinal = false)
    {
        try
        {
            var now = DateTimeOffset.UtcNow;
            var uptime = now - _startTime;
            var proc = Process.GetCurrentProcess();

            var heartbeat = new HeartbeatEvent
            {
                Type = isFinal ? "final" : "hourly",
                Timestamp = now,
                Uptime = uptime,
                ProcessId = proc.Id,
                MemoryUsageMB = proc.WorkingSet64 / (1024 * 1024),
                ThreadCount = proc.Threads.Count,
                HandleCount = proc.HandleCount,
                DetectionCount = _detectionCount,
                ResponseCount = _responseCount,
                IsElevated = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator),
                IsFinal = isFinal
            };

            // Log as detection event with special type
            await _eventLogger.LogDetectionAsync(new DetectionEvent
            {
                RuleName = $"Heartbeat: {(isFinal ? "Service Stopping" : "Service Active")}",
                Evidence = $"Uptime: {uptime:hh\\:mm\\:ss}, Memory: {heartbeat.MemoryUsageMB}MB, Detections: {_detectionCount}",
                Reasoning = "Periodic heartbeat indicating Sentinel is operational",
                Confidence = 1.0,
                Tier = DetectionTier.Tier2Indicator,
                ProcessName = "Sentinel",
                ProcessId = proc.Id,
                Timestamp = now,
                Metadata = new Dictionary<string, string>
                {
                    ["type"] = "heartbeat",
                    ["heartbeat_type"] = heartbeat.Type,
                    ["uptime_seconds"] = ((long)uptime.TotalSeconds).ToString(),
                    ["memory_mb"] = heartbeat.MemoryUsageMB.ToString(),
                    ["thread_count"] = heartbeat.ThreadCount.ToString(),
                    ["detection_count"] = _detectionCount.ToString(),
                    ["response_count"] = _responseCount.ToString(),
                    ["is_elevated"] = heartbeat.IsElevated.ToString()
                }
            }, cancellationToken);

            _logger.LogDebug(
                "Heartbeat: {Type} - Uptime: {Uptime:hh\\:mm\\:ss}, Memory: {Memory}MB",
                heartbeat.Type, uptime, heartbeat.MemoryUsageMB);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Heartbeat: Failed to send heartbeat");
        }
    }

    /// <summary>
    /// Records a detection occurrence.
    /// </summary>
    public void RecordDetection() => Interlocked.Increment(ref _detectionCount);

    /// <summary>
    /// Records a response occurrence.
    /// </summary>
    public void RecordResponse() => Interlocked.Increment(ref _responseCount);

    /// <summary>
    /// Gets current heartbeat statistics.
    /// </summary>
    public HeartbeatStatistics GetStatistics()
    {
        var uptime = DateTimeOffset.UtcNow - _startTime;
        var proc = Process.GetCurrentProcess();

        return new HeartbeatStatistics
        {
            StartTime = _startTime,
            Uptime = uptime,
            CurrentMemoryMB = proc.WorkingSet64 / (1024 * 1024),
            TotalDetections = _detectionCount,
            TotalResponses = _responseCount,
            IsElevated = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator)
        };
    }
}

/// <summary>
/// Heartbeat event data.
/// </summary>
public sealed class HeartbeatEvent
{
    public string Type { get; set; } = "";
    public DateTimeOffset Timestamp { get; set; }
    public TimeSpan Uptime { get; set; }
    public int ProcessId { get; set; }
    public long MemoryUsageMB { get; set; }
    public int ThreadCount { get; set; }
    public int HandleCount { get; set; }
    public long DetectionCount { get; set; }
    public long ResponseCount { get; set; }
    public bool IsElevated { get; set; }
    public bool IsFinal { get; set; }

    public string ToJson() => JsonSerializer.Serialize(this, new JsonSerializerOptions
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false
    });
}

/// <summary>
/// Heartbeat statistics.
/// </summary>
public sealed class HeartbeatStatistics
{
    public DateTimeOffset StartTime { get; set; }
    public TimeSpan Uptime { get; set; }
    public long CurrentMemoryMB { get; set; }
    public long TotalDetections { get; set; }
    public long TotalResponses { get; set; }
    public bool IsElevated { get; set; }

    public double DetectionsPerHour => Uptime.TotalHours > 0 ? TotalDetections / Uptime.TotalHours : 0;
    public string Status => Uptime.TotalMinutes > 0 ? "Running" : "Starting";
}
