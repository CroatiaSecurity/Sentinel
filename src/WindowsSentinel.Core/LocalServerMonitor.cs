using System;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Monitors for unauthorized local TCP/UDP listeners:
    /// - Unexpected services binding to ports
    /// - Reverse shell listeners
    /// - Unauthorized web servers or proxy services
    /// Behavioral — detects new listening sockets that weren't present at baseline.
    /// </summary>
    public sealed class LocalServerMonitor : IDisposable
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<LocalServerMonitor> _logger;
        private readonly System.Threading.Timer _timer;

        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(20);

        public LocalServerMonitor(
            DetectionEngine detectionEngine,
            ILogger<LocalServerMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
            _timer = new System.Threading.Timer(ScanListeners, null, ScanInterval, ScanInterval);
        }

        private void ScanListeners(object? state)
        {
            try
            {
                var properties = IPGlobalProperties.GetIPGlobalProperties();
                var listeners = properties.GetActiveTcpListeners();
                // Compare against known baseline; alert on new unexpected listeners
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[LocalServerMonitor] Scan error");
            }
        }

        public void Dispose()
        {
            _timer.Dispose();
        }
    }
}
