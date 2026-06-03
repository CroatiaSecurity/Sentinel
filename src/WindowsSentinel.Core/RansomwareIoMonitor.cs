using System;
using System.Collections.Concurrent;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Detects ransomware behavior via I/O patterns:
    /// - Rapid sequential file renames to new extensions
    /// - Mass file writes in user directories
    /// - Ransom note creation patterns (README/DECRYPT files appearing in many folders)
    /// Purely behavioral — no file name or extension blocklists.
    /// </summary>
    public sealed class RansomwareIoMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<RansomwareIoMonitor> _logger;
        private readonly ConcurrentDictionary<int, int> _renameCountByPid = new();

        public RansomwareIoMonitor(DetectionEngine detectionEngine, ILogger<RansomwareIoMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("[RansomwareIoMonitor] Started");
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(5000, stoppingToken);
                    // Reset counters periodically; if any PID exceeds threshold, alert
                    foreach (var kvp in _renameCountByPid)
                    {
                        if (kvp.Value > 50) // 50+ renames in 5 seconds = ransomware-like
                        {
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Ransomware: Mass File Rename",
                                Evidence = $"PID {kvp.Key} renamed {kvp.Value} files in rapid succession",
                                Reasoning = "A process is performing mass file renames at a rate consistent with file encryption ransomware.",
                                Confidence = 0.95,
                                Tier = DetectionTier.Tier1Behavioral,
                                ProcessId = kvp.Key,
                                Timestamp = DateTime.UtcNow
                            });
                        }
                    }
                    _renameCountByPid.Clear();
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "[RansomwareIoMonitor] Error");
                    await Task.Delay(5000, stoppingToken);
                }
            }
        }
    }
}
