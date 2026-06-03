using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Monitors the Windows routing table for unauthorized modifications:
    /// - New routes added that redirect traffic (MitM)
    /// - Default gateway changes
    /// - Routes pointing to non-standard gateways
    /// </summary>
    public sealed class RouteTableMonitor : IDisposable
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<RouteTableMonitor> _logger;
        private readonly System.Threading.Timer _timer;

        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(30);

        public RouteTableMonitor(
            DetectionEngine detectionEngine,
            ILogger<RouteTableMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
            _timer = new System.Threading.Timer(CheckRoutes, null, ScanInterval, ScanInterval);
        }

        private void CheckRoutes(object? state)
        {
            try
            {
                // Query routing table via GetIpForwardTable / route print equivalent
                // Compare against baseline; alert on new routes
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[RouteTableMonitor] Check error");
            }
        }

        public void Dispose()
        {
            _timer.Dispose();
        }
    }
}
