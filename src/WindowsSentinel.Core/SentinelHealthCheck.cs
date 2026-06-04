using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Periodic health check: process stats, memory, handles, log file size,
    /// quarantine count, thread pool availability.
    /// </summary>
    public sealed class SentinelHealthCheck : BackgroundService
    {
        private readonly ILogger<SentinelHealthCheck> _logger;
        private readonly JsonlEventLogger _eventLogger;
        private readonly SentinelMetrics _metrics;
        private static readonly TimeSpan Interval = TimeSpan.FromMinutes(5);

        public SentinelHealthCheck(
            ILogger<SentinelHealthCheck> logger,
            JsonlEventLogger eventLogger,
            SentinelMetrics metrics)
        {
            _logger = logger;
            _eventLogger = eventLogger;
            _metrics = metrics;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[SentinelHealthCheck] Started (interval: {Interval})", Interval);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(Interval, ct);

                    using var proc = Process.GetCurrentProcess();
                    var workingSetMb = proc.WorkingSet64 / (1024 * 1024);
                    var handleCount = proc.HandleCount;
                    var threadCount = proc.Threads.Count;

                    // Log file size
                    long logFileSizeMb = 0;
                    var logPath = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                        "WindowsSentinel", "events.jsonl");
                    if (File.Exists(logPath))
                    {
                        logFileSizeMb = new FileInfo(logPath).Length / (1024 * 1024);
                    }

                    // Quarantine count
                    int quarantineCount = 0;
                    var quarantineDir = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                        "WindowsSentinel", "Quarantine");
                    if (Directory.Exists(quarantineDir))
                    {
                        quarantineCount = Directory.GetFiles(quarantineDir).Length;
                    }

                    // Thread pool
                    ThreadPool.GetAvailableThreads(out int workerThreads, out int ioThreads);

                    var health = new
                    {
                        WorkingSetMB = workingSetMb,
                        HandleCount = handleCount,
                        ThreadCount = threadCount,
                        LogFileSizeMB = logFileSizeMb,
                        QuarantinedFiles = quarantineCount,
                        AvailableWorkerThreads = workerThreads,
                        AvailableIOThreads = ioThreads,
                        Uptime = (DateTime.UtcNow - proc.StartTime.ToUniversalTime()).ToString(@"d\.hh\:mm\:ss"),
                        DetectionsTotal = _metrics.GetDetectionsCount(),
                        ResponsesTotal = _metrics.GetResponsesCount()
                    };

                    await _eventLogger.LogEventAsync("health", health);

                    // Warn if resources are getting high
                    if (workingSetMb > 500)
                        _logger.LogWarning("[SentinelHealthCheck] High memory usage: {MB}MB", workingSetMb);
                    if (handleCount > 5000)
                        _logger.LogWarning("[SentinelHealthCheck] High handle count: {Handles}", handleCount);
                    if (logFileSizeMb > 40)
                        _logger.LogWarning("[SentinelHealthCheck] Log file approaching rotation threshold: {MB}MB", logFileSizeMb);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[SentinelHealthCheck] Error"); }
            }
        }
    }
}
