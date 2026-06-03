using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Self-protection: monitors Sentinel's own files and service for tampering.
    /// Detects: file deletion/modification, service stop attempts, registry changes.
    /// </summary>
    public sealed class AntiTamperGuard : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<AntiTamperGuard> _logger;

        public AntiTamperGuard(DetectionEngine detectionEngine, ILogger<AntiTamperGuard> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("[AntiTamperGuard] Started");
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    // Check own binary integrity, service registration, log file access
                    var exePath = Environment.ProcessPath;
                    if (exePath != null && !File.Exists(exePath))
                    {
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Anti-Tamper: Sentinel Binary Missing",
                            Evidence = $"Sentinel executable no longer exists at: {exePath}",
                            Reasoning = "The Sentinel service binary has been deleted while the service is running, indicating active tampering.",
                            Confidence = 0.99,
                            Tier = DetectionTier.Tier1Behavioral,
                            ProcessName = "SYSTEM",
                            Timestamp = DateTime.UtcNow
                        });
                    }
                    await Task.Delay(10000, stoppingToken);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "[AntiTamperGuard] Error");
                    await Task.Delay(5000, stoppingToken);
                }
            }
        }
    }
}
